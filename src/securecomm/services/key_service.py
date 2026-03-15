"""High-level key management service used by CLI and third-party integrations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from securecomm.crypto.keys import KeyStore
from securecomm.errors import KeyErrorSecure
from securecomm.utils.encoding import read_json, write_json
from securecomm.utils.validation import require_user_id


class KeyService:
    """Application-level facade for key operations."""

    def __init__(self, key_root: Path | None = None) -> None:
        self.keystore = KeyStore(root=key_root)

    def create_user(self, user_id: str, overwrite: bool = False) -> dict[str, Any]:
        """Create new user with encryption and signature keypairs."""
        uid = require_user_id(user_id)
        self.keystore.generate_user(uid, overwrite=overwrite)
        pub_bundle = self.keystore.export_public_bundle(uid)
        return {
            "user_id": uid,
            "created": True,
            "enc_public_hex": pub_bundle["encryption_public_raw_hex"],
            "sign_public_hex": pub_bundle["signature_public_raw_hex"],
            "path": str(self.keystore.user_paths(uid).user_root),
            "algorithms": {
                "encryption": "X25519",
                "signature": "Ed25519",
            },
        }

    def user_exists(self, user_id: str) -> bool:
        """Return whether user keys exist."""
        uid = require_user_id(user_id)
        return self.keystore.exists(uid)

    def list_users(self) -> list[str]:
        """Return list of users with key directories."""
        return self.keystore.list_users()

    def export_public_keys(self, user_id: str, output_path: Path | None = None) -> dict[str, str]:
        """Export user public keys as dictionary and optional JSON file."""
        uid = require_user_id(user_id)
        bundle = self.keystore.export_public_bundle(uid)
        if output_path is not None:
            write_json(output_path, bundle)
        return bundle

    def import_public_keys(self, payload: dict[str, str] | Path) -> dict[str, Any]:
        """Import peer public keys from dict or JSON file."""
        if isinstance(payload, Path):
            data = read_json(payload)
        else:
            data = dict(payload)
        self.keystore.import_public_bundle(data)
        user_id = require_user_id(str(data["user_id"]))
        return {
            "imported": True,
            "user_id": user_id,
            "path": str(self.keystore.user_paths(user_id).user_root),
        }

    def describe_user(self, user_id: str) -> dict[str, Any]:
        """Return user metadata and whether private keys are present."""
        uid = require_user_id(user_id)
        info = self.keystore.describe_user(uid)
        info["has_private_keys"] = (
            Path(info["path"]).joinpath("enc_private.pem").exists()
            and Path(info["path"]).joinpath("sign_private.pem").exists()
        )
        return info

    def require_private(self, user_id: str) -> None:
        """Ensure user has private keys available locally."""
        uid = require_user_id(user_id)
        paths = self.keystore.user_paths(uid)
        missing = []
        if not paths.encryption_private.exists():
            missing.append(str(paths.encryption_private))
        if not paths.signing_private.exists():
            missing.append(str(paths.signing_private))
        if missing:
            raise KeyErrorSecure("missing private key files: " + ", ".join(missing))

    def require_public(self, user_id: str) -> None:
        """Ensure user has public keys available locally."""
        uid = require_user_id(user_id)
        paths = self.keystore.user_paths(uid)
        missing = []
        if not paths.encryption_public.exists():
            missing.append(str(paths.encryption_public))
        if not paths.signing_public.exists():
            missing.append(str(paths.signing_public))
        if missing:
            raise KeyErrorSecure("missing public key files: " + ", ".join(missing))

    def reset_user(self, user_id: str) -> dict[str, Any]:
        """Regenerate user keys by overwriting existing files."""
        uid = require_user_id(user_id)
        self.keystore.generate_user(uid, overwrite=True)
        return {
            "reset": True,
            "user_id": uid,
        }

    def load_public_bundle(self, path: Path) -> dict[str, str]:
        """Load public-key bundle JSON from path."""
        data = read_json(path)
        expected = {"user_id", "encryption_public_raw_hex", "signature_public_raw_hex"}
        missing = expected - set(data)
        if missing:
            raise KeyErrorSecure("invalid public bundle: missing fields")
        return {
            "user_id": str(data["user_id"]),
            "encryption_public_raw_hex": str(data["encryption_public_raw_hex"]),
            "signature_public_raw_hex": str(data["signature_public_raw_hex"]),
        }
