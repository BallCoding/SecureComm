"""Service layer for file encryption/decryption and signature workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from securecomm.constants import FILE_ENVELOPE_EXT, SIGNATURE_EXT
from securecomm.crypto.file_crypto import FileEnvelope, HybridFileCipher
from securecomm.crypto.keys import KeyStore
from securecomm.crypto.signing import DetachedSigner, SignatureEnvelope
from securecomm.errors import CryptoError
from securecomm.utils.encoding import read_json, write_json
from securecomm.utils.files import file_sha256
from securecomm.utils.validation import normalize_extension, require_existing_file, require_user_id


class FileService:
    """Application-level interface for file encryption and signing."""

    def __init__(self, key_root: Path | None = None) -> None:
        self.keystore = KeyStore(root=key_root)
        self.file_cipher = HybridFileCipher()
        self.signer = DetachedSigner()

    def encrypt_file(
        self,
        sender_id: str,
        recipient_id: str,
        input_path: Path,
        output_path: Path | None = None,
        chunk_size: int = 64 * 1024,
    ) -> dict[str, Any]:
        """Encrypt arbitrary binary file into secure envelope."""
        sender = require_user_id(sender_id)
        recipient = require_user_id(recipient_id)
        source = require_existing_file(input_path)

        sender_priv = self.keystore.load_private(sender)
        recipient_pub = self.keystore.load_public(recipient)

        envelope = self.file_cipher.encrypt_file(
            input_path=source,
            sender_id=sender,
            recipient_id=recipient,
            sender_sign_private=sender_priv.sign_private,
            recipient_enc_public=recipient_pub.enc_public,
            chunk_size=chunk_size,
        )
        data = envelope.to_dict()

        target = None
        if output_path is not None:
            target = normalize_extension(output_path, FILE_ENVELOPE_EXT)
            write_json(target, data)

        return {
            "sender": sender,
            "recipient": recipient,
            "source": str(source),
            "source_sha256": file_sha256(source),
            "envelope": data,
            "output_path": str(target) if target else None,
        }

    def decrypt_file(
        self,
        recipient_id: str,
        sender_id: str,
        envelope_input: dict[str, Any] | Path,
        output_path: Path,
    ) -> dict[str, Any]:
        """Decrypt file envelope and reconstruct plaintext file."""
        recipient = require_user_id(recipient_id)
        sender = require_user_id(sender_id)

        raw = read_json(envelope_input) if isinstance(envelope_input, Path) else dict(envelope_input)
        envelope = FileEnvelope.from_dict(raw)
        self.file_cipher.validate_envelope(envelope)

        if envelope.recipient_id != recipient:
            raise CryptoError("recipient id mismatch")
        if envelope.sender_id != sender:
            raise CryptoError("sender id mismatch")

        recipient_priv = self.keystore.load_private(recipient)
        sender_pub = self.keystore.load_public(sender)

        report = self.file_cipher.decrypt_file(
            envelope=envelope,
            recipient_enc_private=recipient_priv.enc_private,
            sender_sign_public=sender_pub.sign_public,
            output_path=output_path,
        )
        report["sender"] = sender
        report["recipient"] = recipient
        return report

    def sign_file(self, signer_id: str, input_path: Path, output_path: Path | None = None) -> dict[str, Any]:
        """Create detached signature for file."""
        signer = require_user_id(signer_id)
        source = require_existing_file(input_path)
        signer_priv = self.keystore.load_private(signer)

        envelope = self.signer.sign_file(signer_id=signer, path=source, private_key=signer_priv.sign_private)
        data = envelope.to_dict()

        target = None
        if output_path is not None:
            target = normalize_extension(output_path, SIGNATURE_EXT)
            write_json(target, data)

        return {
            "signer": signer,
            "source": str(source),
            "sha256": data["object_sha256"],
            "signature": data,
            "output_path": str(target) if target else None,
        }

    def verify_file_signature(
        self,
        signer_id: str,
        input_path: Path,
        signature_input: dict[str, Any] | Path,
    ) -> dict[str, Any]:
        """Verify detached file signature."""
        signer = require_user_id(signer_id)
        source = require_existing_file(input_path)
        raw_sig = read_json(signature_input) if isinstance(signature_input, Path) else dict(signature_input)
        envelope = SignatureEnvelope.from_dict(raw_sig)

        signer_pub = self.keystore.load_public(signer)
        verified = self.signer.verify_file(envelope=envelope, path=source, public_key=signer_pub.sign_public)

        return {
            "verified": verified,
            "signer": signer,
            "source": str(source),
            "expected_sha256": envelope.object_sha256,
            "actual_sha256": file_sha256(source),
        }

    def encrypt_and_sign(
        self,
        sender_id: str,
        recipient_id: str,
        input_path: Path,
        output_envelope: Path,
        output_signature: Path,
        chunk_size: int = 64 * 1024,
    ) -> dict[str, Any]:
        """Encrypt file and produce detached signature for resulting envelope."""
        enc = self.encrypt_file(
            sender_id=sender_id,
            recipient_id=recipient_id,
            input_path=input_path,
            output_path=output_envelope,
            chunk_size=chunk_size,
        )

        env_path_raw = enc.get("output_path")
        if not env_path_raw:
            raise CryptoError("failed to write encrypted envelope")

        env_path = Path(env_path_raw)
        signed = self.sign_file(signer_id=sender_id, input_path=env_path, output_path=output_signature)

        return {
            "encrypted": enc,
            "signature": signed,
        }

    def decrypt_and_verify(
        self,
        recipient_id: str,
        sender_id: str,
        envelope_path: Path,
        output_path: Path,
        signature_path: Path | None = None,
    ) -> dict[str, Any]:
        """Optional detached signature verification + decryption."""
        verify_result = None
        if signature_path is not None:
            verify_result = self.verify_file_signature(
                signer_id=sender_id,
                input_path=envelope_path,
                signature_input=signature_path,
            )
            if not verify_result["verified"]:
                raise CryptoError("detached signature verify failed; stop decrypt")

        dec = self.decrypt_file(
            recipient_id=recipient_id,
            sender_id=sender_id,
            envelope_input=envelope_path,
            output_path=output_path,
        )
        return {
            "verified_signature": verify_result,
            "decrypted": dec,
        }