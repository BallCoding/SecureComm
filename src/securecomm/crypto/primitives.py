"""Cryptographic primitives wrappers used by higher-level services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securecomm.constants import AES_KEY_SIZE, AES_NONCE_SIZE
from securecomm.crypto.kdf import hkdf_sha256
from securecomm.crypto.randoms import random_bytes
from securecomm.errors import CryptoError, SignatureError


@dataclass(slots=True)
class AeadCiphertext:
    """Container for AES-GCM output values."""

    nonce: bytes
    ciphertext: bytes
    aad: bytes


@dataclass(slots=True)
class SharedSecretResult:
    """Result of X25519 shared key agreement."""

    shared_secret: bytes
    ephemeral_public: bytes


class CryptoPrimitives:
    """Static cryptographic helper operations."""

    @staticmethod
    def _to_bytes(value: Any, field: str) -> bytes:
        """Normalize bytes-like values to bytes."""
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, memoryview):
            return value.tobytes()
        raise CryptoError(f"{field} must be bytes-like")

    @staticmethod
    def _require_length(data: bytes, expected: int, field: str) -> None:
        """Validate exact binary length."""
        if len(data) != expected:
            raise CryptoError(f"{field} must be {expected} bytes")

    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> AeadCiphertext:
        """Encrypt bytes with AES-256-GCM using random nonce."""
        key_b = CryptoPrimitives._to_bytes(key, "AES key")
        pt_b = CryptoPrimitives._to_bytes(plaintext, "plaintext")
        aad_b = CryptoPrimitives._to_bytes(aad, "aad")
        CryptoPrimitives._require_length(key_b, AES_KEY_SIZE, "AES key")
        nonce = random_bytes(AES_NONCE_SIZE)
        return CryptoPrimitives.aes_gcm_encrypt_with_nonce(key=key_b, nonce=nonce, plaintext=pt_b, aad=aad_b)

    @staticmethod
    def aes_gcm_encrypt_with_nonce(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> AeadCiphertext:
        """Encrypt bytes with AES-256-GCM using caller-provided nonce."""
        key_b = CryptoPrimitives._to_bytes(key, "AES key")
        nonce_b = CryptoPrimitives._to_bytes(nonce, "AES nonce")
        pt_b = CryptoPrimitives._to_bytes(plaintext, "plaintext")
        aad_b = CryptoPrimitives._to_bytes(aad, "aad")

        CryptoPrimitives._require_length(key_b, AES_KEY_SIZE, "AES key")
        CryptoPrimitives._require_length(nonce_b, AES_NONCE_SIZE, "AES nonce")

        aes = AESGCM(key_b)
        try:
            ciphertext = aes.encrypt(nonce_b, pt_b, aad_b)
        except Exception as exc:
            raise CryptoError("AES-GCM encryption failed") from exc
        return AeadCiphertext(nonce=nonce_b, ciphertext=ciphertext, aad=aad_b)

    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decrypt bytes with AES-256-GCM."""
        key_b = CryptoPrimitives._to_bytes(key, "AES key")
        nonce_b = CryptoPrimitives._to_bytes(nonce, "AES nonce")
        ct_b = CryptoPrimitives._to_bytes(ciphertext, "ciphertext")
        aad_b = CryptoPrimitives._to_bytes(aad, "aad")

        CryptoPrimitives._require_length(key_b, AES_KEY_SIZE, "AES key")
        CryptoPrimitives._require_length(nonce_b, AES_NONCE_SIZE, "AES nonce")

        aes = AESGCM(key_b)
        try:
            return aes.decrypt(nonce_b, ct_b, aad_b)
        except Exception as exc:
            raise CryptoError("AES-GCM decryption failed (tampered data or wrong key)") from exc

    @staticmethod
    def x25519_agree(private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey) -> bytes:
        """Perform X25519 ECDH shared-secret operation."""
        try:
            return private_key.exchange(public_key)
        except Exception as exc:
            raise CryptoError("X25519 key agreement failed") from exc

    @staticmethod
    def derive_session_key(shared_secret: bytes, salt: bytes, info: bytes = b"securecomm-session") -> bytes:
        """Derive 32-byte symmetric key from shared secret."""
        ss_b = CryptoPrimitives._to_bytes(shared_secret, "shared_secret")
        salt_b = CryptoPrimitives._to_bytes(salt, "salt")
        info_b = CryptoPrimitives._to_bytes(info, "info")
        try:
            return hkdf_sha256(key_material=ss_b, length=AES_KEY_SIZE, salt=salt_b, info=info_b)
        except Exception as exc:
            raise CryptoError("HKDF derivation failed") from exc

    @staticmethod
    def sign_data(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
        """Sign bytes with Ed25519."""
        msg_b = CryptoPrimitives._to_bytes(message, "message")
        try:
            return private_key.sign(msg_b)
        except Exception as exc:
            raise SignatureError("signature generation failed") from exc

    @staticmethod
    def verify_data(public_key: ed25519.Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
        """Verify Ed25519 signature, returning boolean result."""
        sig_b = CryptoPrimitives._to_bytes(signature, "signature")
        msg_b = CryptoPrimitives._to_bytes(message, "message")
        try:
            public_key.verify(sig_b, msg_b)
            return True
        except InvalidSignature:
            return False
        except Exception as exc:
            raise SignatureError("signature verification failed due to key/data error") from exc