"""Per-agent Ed25519 identities that sign every gateway request.

Keys live in the same trusted process as the gateway. This gives attribution
and log-forgery detection, not protection against compromise of that process.
"""

import base64
import hashlib
import json
from pathlib import Path
from threading import Lock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .analytics import canonical


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id_for(public_key_b64: str) -> str:
    return hashlib.sha256(_unb64(public_key_b64)).hexdigest()[:32]


class Credential:
    """Opaque holder of an agent's session token and signing key."""

    def __init__(self, agent_id: str, token: str, expires_at: float, private_key: Ed25519PrivateKey):
        self._agent_id = agent_id
        self._token = token
        self._expires_at = expires_at
        self._private_key = private_key
        self._public_key_b64 = _b64(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self._key_id = key_id_for(self._public_key_b64)
        self._lock = Lock()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def token(self) -> str:
        return self._token

    @property
    def expires_at(self) -> float:
        return self._expires_at

    def sign(self, envelope: dict) -> str:
        return _b64(self._private_key.sign(canonical(envelope).encode()))

    def public_key_b64(self) -> str:
        return self._public_key_b64

    def _rotate(self, token: str, expires_at: float):
        self._token = token
        self._expires_at = expires_at

    def __repr__(self) -> str:
        return f"Credential(agent_id={self._agent_id}, key_id={self._key_id})"

    def __reduce__(self):
        raise TypeError("credentials cannot be serialized")

    def __getstate__(self):
        raise TypeError("credentials cannot be serialized")


def new_credential(agent_id: str, token: str, expires_at: float) -> Credential:
    return Credential(agent_id, token, expires_at, Ed25519PrivateKey.generate())


def verify_signature(public_key_b64: str, envelope: dict, signature: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(_unb64(public_key_b64))
        key.verify(_unb64(signature), canonical(envelope).encode())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_journal_signatures(journal_path: Path, store) -> int:
    from .security import SecurityError
    count = 0
    if not journal_path.exists():
        return 0
    with journal_path.open() as stream:
        for line in stream:
            record = json.loads(line)["record"]
            envelope, key_id, signature = record.get("request"), record.get("key_id"), record.get("signature")
            if not isinstance(envelope, dict) or not key_id or not signature:
                raise SecurityError("unsigned audit record")
            with store.connect() as db:
                row = db.execute("SELECT run_id,agent_id,public_key FROM agent_keys WHERE key_id=?", (key_id,)).fetchone()
            if row is None or row["run_id"] != envelope.get("run_id") or row["agent_id"] != envelope.get("agent_id"):
                raise SecurityError("audit signature verification failed: key not registered to this agent")
            if any(record.get(k) != envelope.get(k) for k in ("operation_id", "run_id", "agent_id", "action", "args_hash", "epoch")):
                raise SecurityError("audit signature verification failed: record differs from signed request")
            # Records from before request tracing carry neither field.
            if ("parent_id" in envelope or "trace" in record) and (
                    not isinstance(record.get("trace"), dict) or record["trace"].get("parent_id") != envelope.get("parent_id")):
                raise SecurityError("audit signature verification failed: record differs from signed request")
            if not verify_signature(row["public_key"], envelope, signature):
                raise SecurityError("audit signature verification failed: bad signature")
            count += 1
    return count
