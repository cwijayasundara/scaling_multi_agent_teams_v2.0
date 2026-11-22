"""Ed25519-signed configuration files, verified before use.

Each signed config ships with `<name>.sig`: canonical JSON naming the file, the
SHA-256 of its bytes, the signer's key id and a signature over
canonical({"file", "sha256"}). The trust anchor is the signer list named by
TEAMLAB_CONFIG_SIGNERS, or the packaged config_signers.json when it is unset.
The packaged list detects tampering with the configs, not an attacker who can
also edit the signer list; production points the variable at an
operator-controlled file outside the repository.
"""
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .analytics import canonical
from .identity import _b64, _unb64, key_id_for, verify_signature

PACKAGE_DIR = Path(__file__).parent
SIGNED_CONFIGS = ("behavior_profiles.json", "sandbox_policy.yaml", "access_policy.json")
SIGNERS_ENV = "TEAMLAB_CONFIG_SIGNERS"
PACKAGED_SIGNERS = PACKAGE_DIR / "config_signers.json"


class ConfigIntegrityError(ValueError):
    """A config file failed signature verification; refuse to use it."""


def _sig_path(path: Path) -> Path:
    return path.with_name(path.name + ".sig")


def generate_key(path: Path, label: str = "teamlab-dev") -> dict:
    """Write a raw 32-byte Ed25519 private key (0600, never overwritten); return its signer entry."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    public_key = _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return {"key_id": key_id_for(public_key), "public_key": public_key, "label": label}


def sign_file(path: Path, key_path: Path) -> Path:
    """Write <path>.sig for the file's current bytes; return the .sig path."""
    path = Path(path)
    key = Ed25519PrivateKey.from_private_bytes(Path(key_path).read_bytes())
    public_key = _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    claim = {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    record = {"alg": "ed25519", **claim, "key_id": key_id_for(public_key),
              "signature": _b64(key.sign(canonical(claim).encode()))}
    sig = _sig_path(path)
    sig.write_text(canonical(record))
    return sig


def trusted_signers() -> dict[str, str]:
    """Key id -> base64url public key, from TEAMLAB_CONFIG_SIGNERS or the packaged list."""
    source = Path(os.environ[SIGNERS_ENV]) if os.environ.get(SIGNERS_ENV) else PACKAGED_SIGNERS
    try:
        entries = json.loads(source.read_bytes())["signers"]
        signers = {entry["key_id"]: entry["public_key"] for entry in entries}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ConfigIntegrityError(f"signer list {source} is unreadable or malformed") from exc
    try:
        mismatched = any(not isinstance(k, str) or not isinstance(v, str) or key_id_for(v) != k for k, v in signers.items())
    except (ValueError, TypeError) as exc:  # undecodable public key
        raise ConfigIntegrityError(f"invalid signer entry in {source}") from exc
    if mismatched:
        raise ConfigIntegrityError(f"invalid signer entry in {source}: key id does not match its key")
    return signers


def _verify(path: Path, data: bytes, signers: dict | None) -> str:
    try:
        record = json.loads(_sig_path(path).read_bytes())
    except FileNotFoundError:
        raise ConfigIntegrityError("missing signature") from None
    except (OSError, ValueError):
        raise ConfigIntegrityError("bad signature") from None
    if not isinstance(record, dict) or record.get("alg") != "ed25519":
        raise ConfigIntegrityError("bad signature")
    if record.get("file") != path.name:
        raise ConfigIntegrityError("signature names another file")
    if record.get("sha256") != hashlib.sha256(data).hexdigest():
        raise ConfigIntegrityError("config file changed after signing")
    signers = trusted_signers() if signers is None else signers
    key_id = record.get("key_id")
    if not isinstance(key_id, str) or key_id not in signers:
        raise ConfigIntegrityError("unknown signer")
    signature = record.get("signature")
    claim = {"file": record["file"], "sha256": record["sha256"]}
    if not isinstance(signature, str) or not verify_signature(signers[key_id], claim, signature):
        raise ConfigIntegrityError("bad signature")
    return key_id


def verify_file(path: Path, signers: dict | None = None) -> str:
    """Verify path against its .sig; return the signer key id or raise ConfigIntegrityError."""
    path = Path(path)
    return _verify(path, path.read_bytes(), signers)


def read_verified(path: Path) -> tuple[bytes, str]:
    """Read once, verify those bytes, and return them, so callers parse exactly what was verified."""
    path = Path(path)
    data = path.read_bytes()
    return data, _verify(path, data, None)


def verify_all() -> dict[str, str]:
    """Verify every shipped signed config; return {file: signer key id}."""
    signers = trusted_signers()
    return {name: verify_file(PACKAGE_DIR / name, signers) for name in SIGNED_CONFIGS}
