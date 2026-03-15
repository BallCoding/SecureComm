"""Service layer for text-message encryption/decryption workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from securecomm.constants import TEXT_ENVELOPE_EXT
from securecomm.crypto.hybrid import HybridMessageCipher, MessageEnvelope
from securecomm.crypto.keys import KeyStore
from securecomm.errors import CryptoError, SignatureError
from securecomm.utils.encoding import from_json, maybe_decode_text, read_json, to_json, write_json
from securecomm.utils.validation import normalize_extension, require_non_empty_text, require_user_id


class MessageService:
    """High-level text encryption interface for CLI and library usage."""

    def __init__(self, key_root: Path | None = None) -> None:
        self.keystore = KeyStore(root=key_root)
        self.cipher = HybridMessageCipher()

    def encrypt_text(
        self,
        sender_id: str,
        recipient_id: str,
        text: str,
        output_path: Path | None = None,
        aad_text: str | None = None,
    ) -> dict[str, Any]:
        """Encrypt text for recipient and optionally write envelope file."""
        sender = require_user_id(sender_id)
        recipient = require_user_id(recipient_id)
        plain_text = require_non_empty_text(text, "text")

        sender_keys = self.keystore.load_private(sender)
        recipient_pub = self.keystore.load_public(recipient)

        envelope = self.cipher.encrypt(
            sender_id=sender,
            recipient_id=recipient,
            plaintext=plain_text.encode("utf-8"),
            sender_sign_private=sender_keys.sign_private,
            recipient_enc_public=recipient_pub.enc_public,
            aad_extra=(aad_text or "").encode("utf-8"),
        )

        data = envelope.to_dict()
        target = None
        if output_path is not None:
            target = normalize_extension(output_path, TEXT_ENVELOPE_EXT)
            write_json(target, data)

        return {
            "sender": sender,
            "recipient": recipient,
            "algorithm": data["algorithm"],
            "created_at": data["created_at"],
            "envelope": data,
            "output_path": str(target) if target else None,
        }

    def decrypt_text(
        self,
        recipient_id: str,
        sender_id: str,
        envelope_data: dict[str, Any] | Path,
    ) -> dict[str, Any]:
        """Decrypt text envelope and return plaintext plus metadata."""
        recipient = require_user_id(recipient_id)
        sender = require_user_id(sender_id)

        if isinstance(envelope_data, Path):
            raw = read_json(envelope_data)
        else:
            raw = dict(envelope_data)

        envelope = MessageEnvelope.from_dict(raw)
        self.cipher.validate_envelope(envelope)

        recipient_private = self.keystore.load_private(recipient)
        sender_public = self.keystore.load_public(sender)

        if envelope.recipient_id != recipient:
            raise CryptoError("recipient id mismatch")
        if envelope.sender_id != sender:
            raise SignatureError("sender id mismatch")

        plaintext = self.cipher.decrypt(
            envelope=envelope,
            recipient_enc_private=recipient_private.enc_private,
            sender_sign_public=sender_public.sign_public,
        )
        return {
            "sender": envelope.sender_id,
            "recipient": envelope.recipient_id,
            "created_at": envelope.created_at,
            "text": maybe_decode_text(plaintext),
            "raw_bytes_len": len(plaintext),
        }

    def encrypt_to_file(
        self,
        sender_id: str,
        recipient_id: str,
        text: str,
        output_path: Path,
        aad_text: str | None = None,
    ) -> Path:
        """Encrypt text and force writing envelope file."""
        result = self.encrypt_text(
            sender_id=sender_id,
            recipient_id=recipient_id,
            text=text,
            output_path=output_path,
            aad_text=aad_text,
        )
        out = result.get("output_path")
        if not out:
            raise CryptoError("failed to write envelope file")
        return Path(out)

    def decrypt_from_file(self, recipient_id: str, sender_id: str, input_path: Path) -> dict[str, Any]:
        """Decrypt envelope from file path."""
        return self.decrypt_text(recipient_id=recipient_id, sender_id=sender_id, envelope_data=input_path)

    def parse_envelope_text(self, text: str) -> dict[str, Any]:
        """Parse message envelope JSON text for debugging/integration."""
        return from_json(text)

    def serialize_envelope(self, envelope: dict[str, Any]) -> str:
        """Serialize message envelope dict to JSON string."""
        return to_json(envelope, indent=2)

    def summarize(self, envelope_data: dict[str, Any]) -> dict[str, Any]:
        """Return concise summary fields from envelope."""
        env = MessageEnvelope.from_dict(envelope_data)
        return {
            "sender": env.sender_id,
            "recipient": env.recipient_id,
            "created_at": env.created_at,
            "algorithm": env.algorithm,
            "signature_algorithm": env.signature_algorithm,
            "ciphertext_bytes": len(env.ciphertext),
        }

    def benchmark_encryptions(self, sender_id: str, recipient_id: str, rounds: int = 3) -> dict[str, Any]:
        """Run quick benchmark to provide runtime estimate for report."""
        import time

        elapsed: list[float] = []
        sample = "Benchmark text for securecomm." * 200
        for _ in range(rounds):
            start = time.perf_counter()
            self.encrypt_text(sender_id=sender_id, recipient_id=recipient_id, text=sample)
            elapsed.append(time.perf_counter() - start)
        avg = sum(elapsed) / len(elapsed)
        return {
            "rounds": rounds,
            "avg_seconds": avg,
            "min_seconds": min(elapsed),
            "max_seconds": max(elapsed),
        }