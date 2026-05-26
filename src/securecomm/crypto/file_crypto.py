"""File encryption for arbitrary binary files (images, docs, archives)."""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from securecomm.constants import (
    ALG_HYBRID,
    ALG_SIGNATURE,
    DEFAULT_FILE_CHUNK_SIZE,
    ENVELOPE_TYPE_FILE,
    SCHEMA_VERSION,
)
from securecomm.crypto.primitives import CryptoPrimitives
from securecomm.crypto.randoms import derive_nonce, now_epoch, random_bytes
from securecomm.errors import CryptoError, SignatureError
from securecomm.utils.encoding import b64d, b64e, canonical_json_bytes, copy_without_keys
from securecomm.utils.files import file_sha256
from securecomm.utils.validation import require_chunk_size


@dataclass(slots=True)
class FileChunkRecord:
    """One encrypted file chunk with per-chunk nonce."""

    index: int
    nonce: str
    ciphertext: str


@dataclass(slots=True)
class FileEnvelope:
    """Envelope containing encrypted file metadata and chunk list."""

    version: str
    envelope_type: str
    algorithm: str
    signature_algorithm: str
    created_at: int
    sender_id: str
    recipient_id: str
    file_name: str
    file_size: int
    file_sha256: str
    chunk_size: int
    chunk_count: int
    eph_public_key: str
    hkdf_salt: str
    nonce_seed: str
    chunks: list[dict[str, str | int]]
    signature: str

    def to_dict(self) -> dict[str, str | int | list[dict[str, str | int]]]:
        """Serialize dataclass to dictionary."""
        return {
            "version": self.version,
            "envelope_type": self.envelope_type,
            "algorithm": self.algorithm,
            "signature_algorithm": self.signature_algorithm,
            "created_at": self.created_at,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_sha256": self.file_sha256,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "eph_public_key": self.eph_public_key,
            "hkdf_salt": self.hkdf_salt,
            "nonce_seed": self.nonce_seed,
            "chunks": self.chunks,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> "FileEnvelope":
        """Construct dataclass from dictionary."""
        chunks = data.get("chunks", [])
        if not isinstance(chunks, list):
            raise CryptoError("file envelope chunks must be list")
        return FileEnvelope(
            version=str(data["version"]),
            envelope_type=str(data["envelope_type"]),
            algorithm=str(data["algorithm"]),
            signature_algorithm=str(data["signature_algorithm"]),
            created_at=int(data["created_at"]),
            sender_id=str(data["sender_id"]),
            recipient_id=str(data["recipient_id"]),
            file_name=str(data["file_name"]),
            file_size=int(data["file_size"]),
            file_sha256=str(data["file_sha256"]),
            chunk_size=int(data["chunk_size"]),
            chunk_count=int(data["chunk_count"]),
            eph_public_key=str(data["eph_public_key"]),
            hkdf_salt=str(data["hkdf_salt"]),
            nonce_seed=str(data["nonce_seed"]),
            chunks=[dict(item) for item in chunks],
            signature=str(data["signature"]),
        )


class HybridFileCipher:
    """Chunked file encryption with end-to-end signature verification."""

    def encrypt_file(
        self,
        input_path: Path,
        sender_id: str,
        recipient_id: str,
        sender_sign_private: ed25519.Ed25519PrivateKey,
        recipient_enc_public: x25519.X25519PublicKey,
        chunk_size: int = DEFAULT_FILE_CHUNK_SIZE,
    ) -> FileEnvelope:
        """Encrypt binary file and return signed file envelope."""
        checked_chunk = require_chunk_size(chunk_size)
        if not input_path.exists() or not input_path.is_file():
            raise CryptoError(f"input file not found: {input_path}")

        file_size = input_path.stat().st_size
        source_sha = file_sha256(input_path)

        ephemeral_private = x25519.X25519PrivateKey.generate()
        eph_public = ephemeral_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        shared_secret = CryptoPrimitives.x25519_agree(
            private_key=ephemeral_private,
            public_key=recipient_enc_public,
        )
        hkdf_salt = random_bytes(32)
        session_key = CryptoPrimitives.derive_session_key(shared_secret=shared_secret, salt=hkdf_salt)

        nonce_seed = random_bytes(12)
        encrypted_chunks: list[dict[str, str | int]] = []
        chunk_count = 0

        with input_path.open("rb") as fh:
            while True:
                plain_chunk = fh.read(checked_chunk)
                if not plain_chunk:
                    break

                chunk_nonce = derive_nonce(nonce_seed, chunk_count, size=12)
                aad = self._chunk_aad(sender_id, recipient_id, input_path.name, chunk_count)
                aes = CryptoPrimitives.aes_gcm_encrypt_with_nonce(
                    key=session_key,
                    nonce=chunk_nonce,
                    plaintext=plain_chunk,
                    aad=aad,
                )

                encrypted_chunks.append(
                    {
                        "index": chunk_count,
                        "nonce": b64e(chunk_nonce),
                        "ciphertext": b64e(aes.ciphertext),
                        "aad": b64e(aad),
                    }
                )
                chunk_count += 1

        envelope_wo_sig: dict[str, object] = {
            "version": SCHEMA_VERSION,
            "envelope_type": ENVELOPE_TYPE_FILE,
            "algorithm": ALG_HYBRID,
            "signature_algorithm": ALG_SIGNATURE,
            "created_at": now_epoch(),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "file_name": input_path.name,
            "file_size": file_size,
            "file_sha256": source_sha,
            "chunk_size": checked_chunk,
            "chunk_count": chunk_count,
            "eph_public_key": b64e(eph_public),
            "hkdf_salt": b64e(hkdf_salt),
            "nonce_seed": b64e(nonce_seed),
            "chunks": encrypted_chunks,
        }

        sign_blob = canonical_json_bytes(envelope_wo_sig)
        signature = CryptoPrimitives.sign_data(sender_sign_private, sign_blob)

        full = dict(envelope_wo_sig)
        full["signature"] = b64e(signature)
        return FileEnvelope.from_dict(full)

    def decrypt_file(
        self,
        envelope: FileEnvelope,
        recipient_enc_private: x25519.X25519PrivateKey,
        sender_sign_public: ed25519.Ed25519PublicKey,
        output_path: Path,
    ) -> dict[str, object]:
        """Decrypt file envelope and write reconstructed output file atomically."""
        self.validate_envelope(envelope)

        env_dict = envelope.to_dict()
        signature_b64 = str(env_dict["signature"])
        env_wo_sig = copy_without_keys(env_dict, {"signature"})
        signed_blob = canonical_json_bytes(env_wo_sig)
        signature = b64d(signature_b64)
        if not CryptoPrimitives.verify_data(sender_sign_public, signature=signature, message=signed_blob):
            raise SignatureError("file envelope signature is invalid")

        eph_public = x25519.X25519PublicKey.from_public_bytes(b64d(str(env_dict["eph_public_key"])))
        hkdf_salt = b64d(str(env_dict["hkdf_salt"]))
        nonce_seed = b64d(str(env_dict["nonce_seed"]))

        shared_secret = CryptoPrimitives.x25519_agree(recipient_enc_private, eph_public)
        session_key = CryptoPrimitives.derive_session_key(shared_secret=shared_secret, salt=hkdf_salt)

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Validate and sort chunk order before decrypt.
        normalized_chunks = self._normalize_and_validate_chunks(envelope.chunks, envelope.chunk_count)

        hasher = hashlib.sha256()
        total_written = 0

        tmp_name = ""
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=str(output_path.parent), prefix=".securecomm_tmp_") as tf:
            tmp_name = tf.name
            for raw_chunk in normalized_chunks:
                idx = int(raw_chunk["index"])
                stored_nonce = b64d(str(raw_chunk["nonce"]))
                expected_nonce = derive_nonce(nonce_seed, idx, size=12)
                if stored_nonce != expected_nonce:
                    raise CryptoError("chunk nonce mismatch; envelope tampered")

                aad = b64d(str(raw_chunk.get("aad", "")))
                cipher = b64d(str(raw_chunk["ciphertext"]))
                plain = CryptoPrimitives.aes_gcm_decrypt(session_key, stored_nonce, cipher, aad=aad)

                tf.write(plain)
                hasher.update(plain)
                total_written += len(plain)

        calculated_sha = hasher.hexdigest()
        if calculated_sha != envelope.file_sha256:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except Exception:
                pass
            raise CryptoError("decrypted file hash mismatch")

        Path(tmp_name).replace(output_path)

        return {
            "output_path": str(output_path),
            "size": total_written,
            "sha256": calculated_sha,
            "chunk_count": len(normalized_chunks),
        }

    def validate_envelope(self, envelope: FileEnvelope) -> None:
        """Validate file envelope metadata and structure."""
        if envelope.version != SCHEMA_VERSION:
            raise CryptoError("unsupported envelope version")
        if envelope.envelope_type != ENVELOPE_TYPE_FILE:
            raise CryptoError("wrong envelope type")
        if envelope.algorithm != ALG_HYBRID:
            raise CryptoError("wrong algorithm")
        if envelope.signature_algorithm != ALG_SIGNATURE:
            raise CryptoError("wrong signature algorithm")
        if envelope.chunk_size <= 0:
            raise CryptoError("invalid chunk size")
        if envelope.chunk_count != len(envelope.chunks):
            raise CryptoError("chunk_count does not match chunks list")
        if envelope.file_size < 0:
            raise CryptoError("invalid file_size")
        if len(envelope.file_sha256) != 64:
            raise CryptoError("invalid file_sha256 format")

    def _normalize_and_validate_chunks(self, chunks: list[dict[str, str | int]], expected_count: int) -> list[dict[str, str | int]]:
        """Validate chunk index integrity and return chunks sorted by index."""
        normalized: list[dict[str, str | int]] = []
        seen: set[int] = set()

        for item in chunks:
            if "index" not in item or "nonce" not in item or "ciphertext" not in item:
                raise CryptoError("invalid chunk item")
            idx = int(item["index"])
            if idx < 0:
                raise CryptoError("chunk index cannot be negative")
            if idx in seen:
                raise CryptoError("duplicate chunk index detected")
            seen.add(idx)
            normalized.append(item)

        if len(normalized) != expected_count:
            raise CryptoError("chunk count mismatch after normalization")

        normalized.sort(key=lambda x: int(x["index"]))
        for expected_idx, item in enumerate(normalized):
            if int(item["index"]) != expected_idx:
                raise CryptoError("chunk indices must be contiguous from 0")

        return normalized

    def _chunk_aad(self, sender_id: str, recipient_id: str, file_name: str, index: int) -> bytes:
        """Build deterministic AAD bytes for each chunk."""
        fields = [
            b"securecomm-file",
            sender_id.encode("utf-8"),
            recipient_id.encode("utf-8"),
            file_name.encode("utf-8"),
            str(index).encode("ascii"),
        ]
        return b"|".join(fields)

    def summarize(self, envelope: FileEnvelope) -> dict[str, object]:
        """Compact summary for CLI display."""
        return {
            "sender": envelope.sender_id,
            "recipient": envelope.recipient_id,
            "file_name": envelope.file_name,
            "file_size": envelope.file_size,
            "chunks": envelope.chunk_count,
            "algorithm": envelope.algorithm,
        }