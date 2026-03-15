"""Password-based encryption for local secure vault data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from securecomm.constants import ALG_PASSWORD, ENVELOPE_TYPE_VAULT, SCHEMA_VERSION
from securecomm.crypto.kdf import derive_password_key, restore_password_key
from securecomm.crypto.primitives import CryptoPrimitives
from securecomm.crypto.randoms import now_epoch
from securecomm.errors import VaultError
from securecomm.utils.encoding import b64d, b64e, canonical_json_bytes, from_json, to_json


@dataclass(slots=True)
class VaultEnvelope:
    """Encrypted vault payload schema."""

    version: str
    envelope_type: str
    algorithm: str
    created_at: int
    kdf_algorithm: str
    kdf_params: dict[str, int]
    salt: str
    nonce: str
    aad: str
    ciphertext: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize dataclass to dictionary."""
        return {
            "version": self.version,
            "envelope_type": self.envelope_type,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "kdf_algorithm": self.kdf_algorithm,
            "kdf_params": self.kdf_params,
            "salt": self.salt,
            "nonce": self.nonce,
            "aad": self.aad,
            "ciphertext": self.ciphertext,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "VaultEnvelope":
        """Create dataclass from dictionary."""
        return VaultEnvelope(
            version=str(data["version"]),
            envelope_type=str(data["envelope_type"]),
            algorithm=str(data["algorithm"]),
            created_at=int(data["created_at"]),
            kdf_algorithm=str(data["kdf_algorithm"]),
            kdf_params=dict(data["kdf_params"]),
            salt=str(data["salt"]),
            nonce=str(data["nonce"]),
            aad=str(data["aad"]),
            ciphertext=str(data["ciphertext"]),
        )


class PasswordCipher:
    """Encrypt/decrypt structured JSON payloads using password-derived keys."""

    def encrypt_json(self, payload: dict[str, Any], password: str, prefer_argon2: bool = True) -> VaultEnvelope:
        """Encrypt dictionary payload with password-based key."""
        algo, salt, key, params = derive_password_key(password=password, prefer_argon2=prefer_argon2, length=32)
        aad = canonical_json_bytes(
            {
                "version": SCHEMA_VERSION,
                "envelope_type": ENVELOPE_TYPE_VAULT,
                "algorithm": ALG_PASSWORD,
                "kdf_algorithm": algo,
            }
        )
        plaintext = to_json(payload, indent=0).encode("utf-8")
        cipher = CryptoPrimitives.aes_gcm_encrypt(key=key, plaintext=plaintext, aad=aad)
        return VaultEnvelope(
            version=SCHEMA_VERSION,
            envelope_type=ENVELOPE_TYPE_VAULT,
            algorithm=ALG_PASSWORD,
            created_at=now_epoch(),
            kdf_algorithm=algo,
            kdf_params=params,
            salt=b64e(salt),
            nonce=b64e(cipher.nonce),
            aad=b64e(aad),
            ciphertext=b64e(cipher.ciphertext),
        )

    def decrypt_json(self, envelope: VaultEnvelope, password: str) -> dict[str, Any]:
        """Decrypt password envelope back into dictionary payload."""
        try:
            salt = b64d(envelope.salt)
            nonce = b64d(envelope.nonce)
            aad = b64d(envelope.aad)
            ciphertext = b64d(envelope.ciphertext)
            key = restore_password_key(
                password=password,
                algorithm=envelope.kdf_algorithm,
                salt=salt,
                params=envelope.kdf_params,
                length=32,
            )
            plain = CryptoPrimitives.aes_gcm_decrypt(key=key, nonce=nonce, ciphertext=ciphertext, aad=aad)
            return from_json(plain.decode("utf-8"))
        except Exception as exc:
            raise VaultError("vault decryption failed") from exc

    def serialize(self, envelope: VaultEnvelope) -> dict[str, Any]:
        """Convert envelope to dictionary for JSON persistence."""
        return envelope.to_dict()

    def deserialize(self, data: dict[str, Any]) -> VaultEnvelope:
        """Load envelope dataclass from dictionary."""
        try:
            return VaultEnvelope.from_dict(data)
        except Exception as exc:
            raise VaultError("invalid vault envelope data") from exc

    def describe(self, envelope: VaultEnvelope) -> dict[str, Any]:
        """Human-readable vault metadata."""
        return {
            "created_at": envelope.created_at,
            "algorithm": envelope.algorithm,
            "kdf": envelope.kdf_algorithm,
            "version": envelope.version,
        }

    def rotate_password(
        self,
        envelope: VaultEnvelope,
        old_password: str,
        new_password: str,
        prefer_argon2: bool = True,
    ) -> VaultEnvelope:
        """Decrypt with old password and re-encrypt with new password."""
        payload = self.decrypt_json(envelope=envelope, password=old_password)
        return self.encrypt_json(payload=payload, password=new_password, prefer_argon2=prefer_argon2)

    def encrypt_text(self, text: str, password: str, prefer_argon2: bool = True) -> VaultEnvelope:
        """Convenience method for encrypting plain text."""
        payload = {"kind": "text", "content": text}
        return self.encrypt_json(payload=payload, password=password, prefer_argon2=prefer_argon2)

    def decrypt_text(self, envelope: VaultEnvelope, password: str) -> str:
        """Decrypt text payload and validate schema."""
        payload = self.decrypt_json(envelope=envelope, password=password)
        if payload.get("kind") != "text":
            raise VaultError("vault payload is not text")
        content = payload.get("content")
        if not isinstance(content, str):
            raise VaultError("vault text content invalid")
        return content