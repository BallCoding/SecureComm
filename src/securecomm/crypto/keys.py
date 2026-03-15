"""Key generation, serialization, and local key storage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from securecomm.constants import DEFAULT_KEY_ROOT
from securecomm.errors import KeyErrorSecure
from securecomm.utils.files import ensure_dir
from securecomm.utils.validation import require_user_id


@dataclass(slots=True)
class UserPaths:
    """Filesystem paths for one user's key files."""

    root: Path
    user_root: Path
    encryption_private: Path
    encryption_public: Path
    signing_private: Path
    signing_public: Path
    metadata: Path


@dataclass(slots=True)
class UserPublicKeys:
    """Public key materials used by peers."""

    user_id: str
    enc_public: x25519.X25519PublicKey
    sign_public: ed25519.Ed25519PublicKey


@dataclass(slots=True)
class UserPrivateKeys:
    """Private key materials owned by local user."""

    user_id: str
    enc_private: x25519.X25519PrivateKey
    sign_private: ed25519.Ed25519PrivateKey


@dataclass(slots=True)
class UserKeyPair:
    """Combined key data for encryption and signatures."""

    user_id: str
    enc_private: x25519.X25519PrivateKey
    enc_public: x25519.X25519PublicKey
    sign_private: ed25519.Ed25519PrivateKey
    sign_public: ed25519.Ed25519PublicKey


class KeyStore:
    """Local filesystem-backed key management service."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = ensure_dir(root or DEFAULT_KEY_ROOT)

    def user_paths(self, user_id: str) -> UserPaths:
        """Compute all key file paths for user."""
        uid = require_user_id(user_id)
        user_root = ensure_dir(self.root / uid)
        return UserPaths(
            root=self.root,
            user_root=user_root,
            encryption_private=user_root / "enc_private.pem",
            encryption_public=user_root / "enc_public.pem",
            signing_private=user_root / "sign_private.pem",
            signing_public=user_root / "sign_public.pem",
            metadata=user_root / "user.json",
        )

    def exists(self, user_id: str) -> bool:
        """Check whether all required key files exist for user."""
        paths = self.user_paths(user_id)
        return all(
            p.exists()
            for p in [
                paths.encryption_private,
                paths.encryption_public,
                paths.signing_private,
                paths.signing_public,
            ]
        )

    def generate_user(self, user_id: str, overwrite: bool = False) -> UserKeyPair:
        """Generate new X25519 and Ed25519 key pairs for user."""
        paths = self.user_paths(user_id)
        if self.exists(user_id) and not overwrite:
            raise KeyErrorSecure(f"keys already exist for user: {user_id}")

        enc_private = x25519.X25519PrivateKey.generate()
        enc_public = enc_private.public_key()
        sign_private = ed25519.Ed25519PrivateKey.generate()
        sign_public = sign_private.public_key()

        self._write_private_key(paths.encryption_private, enc_private)
        self._write_public_key(paths.encryption_public, enc_public)
        self._write_private_key(paths.signing_private, sign_private)
        self._write_public_key(paths.signing_public, sign_public)

        metadata = {
            "user_id": user_id,
            "keys": {
                "encryption": "X25519",
                "signature": "Ed25519",
            },
        }
        paths.metadata.write_text(json.dumps(metadata, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")

        return UserKeyPair(
            user_id=user_id,
            enc_private=enc_private,
            enc_public=enc_public,
            sign_private=sign_private,
            sign_public=sign_public,
        )

    def load_public(self, user_id: str) -> UserPublicKeys:
        """Load peer public keys."""
        paths = self.user_paths(user_id)
        enc_public = self._read_x25519_public(paths.encryption_public)
        sign_public = self._read_ed25519_public(paths.signing_public)
        return UserPublicKeys(user_id=user_id, enc_public=enc_public, sign_public=sign_public)

    def load_private(self, user_id: str) -> UserPrivateKeys:
        """Load local private keys."""
        paths = self.user_paths(user_id)
        enc_private = self._read_x25519_private(paths.encryption_private)
        sign_private = self._read_ed25519_private(paths.signing_private)
        return UserPrivateKeys(user_id=user_id, enc_private=enc_private, sign_private=sign_private)

    def load_all(self, user_id: str) -> UserKeyPair:
        """Load both private and public keys for local user."""
        priv = self.load_private(user_id)
        pub = self.load_public(user_id)
        return UserKeyPair(
            user_id=user_id,
            enc_private=priv.enc_private,
            enc_public=pub.enc_public,
            sign_private=priv.sign_private,
            sign_public=pub.sign_public,
        )

    def list_users(self) -> list[str]:
        """List users that have key directories."""
        users: list[str] = []
        for child in self.root.iterdir():
            if child.is_dir():
                users.append(child.name)
        users.sort()
        return users

    def export_public_bundle(self, user_id: str) -> dict[str, str]:
        """Export user public keys to text bundle for sharing."""
        pub = self.load_public(user_id)
        enc_bytes = pub.enc_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        sign_bytes = pub.sign_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "user_id": user_id,
            "encryption_public_raw_hex": enc_bytes.hex(),
            "signature_public_raw_hex": sign_bytes.hex(),
        }

    def import_public_bundle(self, bundle: dict[str, str]) -> None:
        """Import peer public keys from bundle dictionary."""
        user_id = require_user_id(bundle["user_id"])
        enc_hex = bundle["encryption_public_raw_hex"]
        sign_hex = bundle["signature_public_raw_hex"]

        try:
            enc_bytes = bytes.fromhex(enc_hex)
            sign_bytes = bytes.fromhex(sign_hex)
        except Exception as exc:
            raise KeyErrorSecure("invalid hex in public bundle") from exc

        try:
            enc_key = x25519.X25519PublicKey.from_public_bytes(enc_bytes)
            sign_key = ed25519.Ed25519PublicKey.from_public_bytes(sign_bytes)
        except Exception as exc:
            raise KeyErrorSecure("invalid public key bytes in bundle") from exc

        paths = self.user_paths(user_id)
        self._write_public_key(paths.encryption_public, enc_key)
        self._write_public_key(paths.signing_public, sign_key)

    def describe_user(self, user_id: str) -> dict[str, Any]:
        """Return user key metadata useful for CLI output."""
        paths = self.user_paths(user_id)
        return {
            "user_id": user_id,
            "exists": self.exists(user_id),
            "path": str(paths.user_root),
            "enc_public": str(paths.encryption_public),
            "sign_public": str(paths.signing_public),
        }

    def _write_private_key(self, path: Path, key: Any) -> None:
        """Write private key in PKCS8 PEM without encryption.

        Private-key-at-rest encryption is provided by vault service if user requests.
        """
        data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(data)

    def _write_public_key(self, path: Path, key: Any) -> None:
        """Write public key in SubjectPublicKeyInfo PEM."""
        data = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        path.write_bytes(data)

    def _read_x25519_private(self, path: Path) -> x25519.X25519PrivateKey:
        """Load X25519 private key from PEM file."""
        try:
            data = path.read_bytes()
            key = serialization.load_pem_private_key(data, password=None)
        except Exception as exc:
            raise KeyErrorSecure(f"failed to read private key: {path}") from exc
        if not isinstance(key, x25519.X25519PrivateKey):
            raise KeyErrorSecure(f"invalid X25519 private key file: {path}")
        return key

    def _read_ed25519_private(self, path: Path) -> ed25519.Ed25519PrivateKey:
        """Load Ed25519 private key from PEM file."""
        try:
            data = path.read_bytes()
            key = serialization.load_pem_private_key(data, password=None)
        except Exception as exc:
            raise KeyErrorSecure(f"failed to read private key: {path}") from exc
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise KeyErrorSecure(f"invalid Ed25519 private key file: {path}")
        return key

    def _read_x25519_public(self, path: Path) -> x25519.X25519PublicKey:
        """Load X25519 public key from PEM file."""
        try:
            data = path.read_bytes()
            key = serialization.load_pem_public_key(data)
        except Exception as exc:
            raise KeyErrorSecure(f"failed to read public key: {path}") from exc
        if not isinstance(key, x25519.X25519PublicKey):
            raise KeyErrorSecure(f"invalid X25519 public key file: {path}")
        return key

    def _read_ed25519_public(self, path: Path) -> ed25519.Ed25519PublicKey:
        """Load Ed25519 public key from PEM file."""
        try:
            data = path.read_bytes()
            key = serialization.load_pem_public_key(data)
        except Exception as exc:
            raise KeyErrorSecure(f"failed to read public key: {path}") from exc
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise KeyErrorSecure(f"invalid Ed25519 public key file: {path}")
        return key
