"""Per-launch PKI and mutual TLS for the separated control plane.

Each launch issues a fresh ECDSA P-256 CA, one server certificate per service
and one runtime client certificate, all valid for CERT_LIFETIME_SECONDS. The
CA private key is never written to disk, so nothing can mint further
certificates for this launch. Clients also pin each server's public key.
There is no automatic rotation: restart the plane at least daily.
"""
import datetime
import hashlib
import ipaddress
import os
import secrets
import ssl
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .security import SecurityError

CERT_LIFETIME_SECONDS = 24 * 3600
CA_NAME = 'teamlab-plane-ca'
CLIENT_NAME = 'teamlab-runtime'
DOMAIN = 'teamlab.internal'
# Services reached over loopback TCP by URL also carry an IP SAN so hostname
# checking stays on for https://127.0.0.1:<port>.
LOOPBACK_SERVICES = ('model-proxy',)


def hostname(service):
    return service + '.' + DOMAIN


def spki_pin(certificate):
    der = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(data)
    os.chmod(path, 0o600)


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _cert_pem(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


def _builder(common_name, public_key, issuer, issuer_key, start, end):
    return (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))


def _leaf(common_name, usage, ca_name, ca_key, start, end, sans=()):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (_builder(common_name, key.public_key(), ca_name, ca_key, start, end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def issue_plane_pki(directory: Path, services: tuple[str, ...], now: float | None = None) -> dict:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    issued = time.time() if now is None else now
    start = datetime.datetime.fromtimestamp(issued, datetime.timezone.utc)
    end = datetime.datetime.fromtimestamp(issued + CERT_LIFETIME_SECONDS, datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    ca = (_builder(CA_NAME, ca_key.public_key(), ca_name, ca_key, start, end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256()))
    ca_path = directory / 'ca.pem'
    ca_path.write_bytes(_cert_pem(ca))
    servers = {}
    for service in services:
        sans = [x509.DNSName(hostname(service))]
        if service in LOOPBACK_SERVICES:
            sans.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        key, certificate = _leaf(hostname(service), ExtendedKeyUsageOID.SERVER_AUTH, ca_name, ca_key, start, end, sans)
        cert_path, key_path = directory / (service + '.pem'), directory / (service + '.key')
        cert_path.write_bytes(_cert_pem(certificate))
        _write_private(key_path, _key_pem(key))
        servers[service] = {'cert': str(cert_path), 'key': str(key_path), 'pin': spki_pin(certificate)}
    key, certificate = _leaf(CLIENT_NAME, ExtendedKeyUsageOID.CLIENT_AUTH, ca_name, ca_key, start, end)
    client_cert, client_key = directory / 'client.pem', directory / 'client.key'
    client_cert.write_bytes(_cert_pem(certificate))
    _write_private(client_key, _key_pem(key))
    return {'ca': str(ca_path), 'client_cert': str(client_cert), 'client_key': str(client_key), 'servers': servers}


def server_context(cert, key, ca) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(cert), str(key))
    context.load_verify_locations(cafile=str(ca))
    return context


def client_context(client_cert, client_key, ca) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(ca))
    context.load_cert_chain(str(client_cert), str(client_key))
    return context


def check_pin(ssl_socket, expected_pin: str) -> None:
    der = ssl_socket.getpeercert(binary_form=True)
    presented = spki_pin(x509.load_der_x509_certificate(der)) if der else ''
    if not isinstance(expected_pin, str) or not secrets.compare_digest(presented, expected_pin):
        raise SecurityError('server key pin mismatch')
