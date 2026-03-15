"""Detached signing for files and text payloads."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from securecomm.constants import ALG_SIGNATURE, ENVELOPE_TYPE_SIGNATURE, SCHEMA_VERSION
from securecomm.crypto.primitives import CryptoPrimitives
from securecomm.crypto.randoms import now_epoch
from securecomm.utils.encoding import b64d, b64e, canonical_json_bytes
from securecomm.utils.files import file_sha256, read_bytes


@dataclass(slots=True)
class SignatureEnvelope:
    """Detached signature payload schema."""

    version: str
    envelope_type: str
    signature_algorithm: str
    created_at: int
    signer_id: str
    object_type: str
    object_name: str
    object_sha256: str
    signature: str

    def to_dict(self) -> dict[str, str | int]:
        """Serialize dataclass to dictionary."""
        return {
            "version": self.version,
            "envelope_type": self.envelope_type,
            "signature_algorithm": self.signature_algorithm,
            "created_at": self.created_at,
            "signer_id": self.signer_id,
            "object_type": self.object_type,
            "object_name": self.object_name,
            "object_sha256": self.object_sha256,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(data: dict[str, str | int]) -> "SignatureEnvelope":
        """Create dataclass from dictionary."""
        return SignatureEnvelope(
            version=str(data["version"]),
            envelope_type=str(data["envelope_type"]),
            signature_algorithm=str(data["signature_algorithm"]),
            created_at=int(data["created_at"]),
            signer_id=str(data["signer_id"]),
            object_type=str(data["object_type"]),
            object_name=str(data["object_name"]),
            object_sha256=str(data["object_sha256"]),
            signature=str(data["signature"]),
        )


class DetachedSigner:
    """Create and verify detached Ed25519 signatures."""

    def sign_bytes(self, signer_id: str, name: str, payload: bytes, private_key: ed25519.Ed25519PrivateKey) -> SignatureEnvelope:
        """Create detached signature envelope for binary payload."""
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        envelope_wo_sig = {
            "version": SCHEMA_VERSION,
            "envelope_type": ENVELOPE_TYPE_SIGNATURE,
            "signature_algorithm": ALG_SIGNATURE,
            "created_at": now_epoch(),
            "signer_id": signer_id,
            "object_type": "bytes",
            "object_name": name,
            "object_sha256": digest,
        }
        signed_blob = canonical_json_bytes(envelope_wo_sig)
        signature = CryptoPrimitives.sign_data(private_key, signed_blob)

        full = dict(envelope_wo_sig)
        full["signature"] = b64e(signature)
        return SignatureEnvelope.from_dict(full)

    def verify_bytes(self, envelope: SignatureEnvelope, payload: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify detached signature against payload and metadata."""
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        if digest != envelope.object_sha256:
            return False

        env_dict = envelope.to_dict()
        sign_raw = b64d(str(env_dict["signature"]))
        env_no_sig = dict(env_dict)
        env_no_sig.pop("signature", None)
        signed_blob = canonical_json_bytes(env_no_sig)
        return CryptoPrimitives.verify_data(public_key, signature=sign_raw, message=signed_blob)

    def sign_file(self, signer_id: str, path: Path, private_key: ed25519.Ed25519PrivateKey) -> SignatureEnvelope:
        """Create detached signature for file content and metadata."""
        envelope_wo_sig = {
            "version": SCHEMA_VERSION,
            "envelope_type": ENVELOPE_TYPE_SIGNATURE,
            "signature_algorithm": ALG_SIGNATURE,
            "created_at": now_epoch(),
            "signer_id": signer_id,
            "object_type": "file",
            "object_name": path.name,
            "object_sha256": file_sha256(path),
        }
        sign_blob = canonical_json_bytes(envelope_wo_sig)
        signature = CryptoPrimitives.sign_data(private_key, sign_blob)
        full = dict(envelope_wo_sig)
        full["signature"] = b64e(signature)
        return SignatureEnvelope.from_dict(full)

    def verify_file(self, envelope: SignatureEnvelope, path: Path, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify detached file signature."""
        if not path.exists():
            return False
        digest = file_sha256(path)
        if digest != envelope.object_sha256:
            return False

        env_dict = envelope.to_dict()
        signature = b64d(str(env_dict["signature"]))
        env_dict.pop("signature", None)
        sign_blob = canonical_json_bytes(env_dict)
        return CryptoPrimitives.verify_data(public_key, signature=signature, message=sign_blob)

    def signature_report(self, envelope: SignatureEnvelope) -> dict[str, str | int]:
        """Summary for CLI/reporting."""
        return {
            "signer": envelope.signer_id,
            "object": envelope.object_name,
            "object_type": envelope.object_type,
            "digest": envelope.object_sha256,
            "created_at": envelope.created_at,
            "algorithm": envelope.signature_algorithm,
        }

    def load_and_verify_file(self, envelope: SignatureEnvelope, path: Path, public_key: ed25519.Ed25519PublicKey) -> tuple[bool, dict[str, str | int]]:
        """Verify file and return diagnostic details."""
        exists = path.exists()
        digest = file_sha256(path) if exists else ""
        ok = exists and self.verify_file(envelope, path, public_key)
        detail = {
            "exists": int(exists),
            "actual_sha256": digest,
            "expected_sha256": envelope.object_sha256,
            "verified": int(ok),
        }
        return ok, detail

    def sign_text(self, signer_id: str, text: str, private_key: ed25519.Ed25519PrivateKey) -> SignatureEnvelope:
        """Sign text payload using detached signature."""
        payload = text.encode("utf-8")
        return self.sign_bytes(signer_id=signer_id, name="text", payload=payload, private_key=private_key)

    def verify_text(self, envelope: SignatureEnvelope, text: str, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify text detached signature."""
        return self.verify_bytes(envelope=envelope, payload=text.encode("utf-8"), public_key=public_key)

    def sign_path_payload(self, signer_id: str, path: Path, private_key: ed25519.Ed25519PrivateKey) -> SignatureEnvelope:
        """Alias method used by service layer for generic files."""
        payload = read_bytes(path)
        return self.sign_bytes(signer_id=signer_id, name=path.name, payload=payload, private_key=private_key)