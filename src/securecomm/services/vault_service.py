"""Service layer for password-protected secure vault operations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from securecomm.constants import VAULT_EXT
from securecomm.crypto.password_crypto import PasswordCipher, VaultEnvelope
from securecomm.errors import VaultError
from securecomm.utils.encoding import read_json, write_json
from securecomm.utils.validation import normalize_extension, require_non_empty_text, require_password


class VaultService:
    """Create and open password-protected vault files."""

    def __init__(self) -> None:
        self.cipher = PasswordCipher()

    def encrypt_text(
        self,
        text: str,
        password: str,
        output_path: Path | None = None,
        prefer_argon2: bool = True,
    ) -> dict[str, Any]:
        """Encrypt text using password-derived key."""
        plain = require_non_empty_text(text, "text")
        pwd = require_password(password)

        envelope = self.cipher.encrypt_text(text=plain, password=pwd, prefer_argon2=prefer_argon2)
        data = envelope.to_dict()

        target = None
        if output_path is not None:
            target = normalize_extension(output_path, VAULT_EXT)
            write_json(target, data)

        return {
            "algorithm": data["algorithm"],
            "kdf": data["kdf_algorithm"],
            "envelope": data,
            "output_path": str(target) if target else None,
        }

    def decrypt_text(self, password: str, envelope_input: dict[str, Any] | Path) -> dict[str, Any]:
        """Decrypt vault envelope and return plaintext text."""
        pwd = require_password(password)
        raw = read_json(envelope_input) if isinstance(envelope_input, Path) else dict(envelope_input)
        envelope = VaultEnvelope.from_dict(raw)

        text = self.cipher.decrypt_text(envelope=envelope, password=pwd)
        return {
            "text": text,
            "created_at": envelope.created_at,
            "kdf": envelope.kdf_algorithm,
        }

    def rotate_password(
        self,
        old_password: str,
        new_password: str,
        envelope_input: dict[str, Any] | Path,
        output_path: Path | None = None,
        prefer_argon2: bool = True,
    ) -> dict[str, Any]:
        """Re-encrypt vault with new password."""
        old_pwd = require_password(old_password)
        new_pwd = require_password(new_password)

        raw = read_json(envelope_input) if isinstance(envelope_input, Path) else dict(envelope_input)
        envelope = VaultEnvelope.from_dict(raw)

        rotated = self.cipher.rotate_password(
            envelope=envelope,
            old_password=old_pwd,
            new_password=new_pwd,
            prefer_argon2=prefer_argon2,
        )
        data = rotated.to_dict()

        target = None
        if output_path is not None:
            target = normalize_extension(output_path, VAULT_EXT)
            write_json(target, data)

        return {
            "rotated": True,
            "output_path": str(target) if target else None,
            "envelope": data,
        }

    def validate(self, password: str, envelope_input: dict[str, Any] | Path) -> dict[str, Any]:
        """Validate password can unlock vault without exposing data."""
        try:
            result = self.decrypt_text(password=password, envelope_input=envelope_input)
        except VaultError:
            return {"valid": False}
        return {
            "valid": True,
            "length": len(result["text"]),
            "created_at": result["created_at"],
        }