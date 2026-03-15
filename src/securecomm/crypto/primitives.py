"""Cryptographic primitives wrappers used by higher-level services."""

from __future__ import annotations

from dataclasses import dataclass

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
    def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> AeadCiphertext:
        """Encrypt bytes with AES-256-GCM using random nonce."""
        if len(key) != AES_KEY_SIZE:
            raise CryptoError("AES key must be 32 bytes")
        nonce = random_bytes(AES_NONCE_SIZE)
        return CryptoPrimitives.aes_gcm_encrypt_with_nonce(key=key, nonce=nonce, plaintext=plaintext, aad=aad)

    @staticmethod
    def aes_gcm_encrypt_with_nonce(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> AeadCiphertext:
        """Encrypt bytes with AES-256-GCM using caller-provided nonce."""
        if len(key) != AES_KEY_SIZE:
            raise CryptoError("AES key must be 32 bytes")
        if len(nonce) != AES_NONCE_SIZE:
            raise CryptoError("AES-GCM nonce must be 12 bytes")
        aes = AESGCM(key)
        try:
            ciphertext = aes.encrypt(nonce, plaintext, aad)
        except Exception as exc:
            raise CryptoError("AES-GCM encryption failed") from exc
        return AeadCiphertext(nonce=nonce, ciphertext=ciphertext, aad=aad)

    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decrypt bytes with AES-256-GCM."""
        if len(key) != AES_KEY_SIZE:
            raise CryptoError("AES key must be 32 bytes")
        if len(nonce) != AES_NONCE_SIZE:
            raise CryptoError("AES-GCM nonce must be 12 bytes")
        aes = AESGCM(key)
        try:
            return aes.decrypt(nonce, ciphertext, aad)
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
        try:
            return hkdf_sha256(key_material=shared_secret, length=AES_KEY_SIZE, salt=salt, info=info)
        except Exception as exc:
            raise CryptoError("HKDF derivation failed") from exc

    @staticmethod
    def sign_data(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
        """Sign bytes with Ed25519."""
        try:
            return private_key.sign(message)
        except Exception as exc:
            raise SignatureError("signature generation failed") from exc

    @staticmethod
    def verify_data(public_key: ed25519.Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
        """Verify Ed25519 signature, returning boolean result."""
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception as exc:
            raise SignatureError("signature verification failed due to key/data error") from exc