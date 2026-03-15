"""Hybrid message encryption: X25519 + HKDF + AES-256-GCM + Ed25519 signature."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from securecomm.constants import ALG_HYBRID, ALG_SIGNATURE, ENVELOPE_TYPE_TEXT, SCHEMA_VERSION
from securecomm.crypto.primitives import CryptoPrimitives
from securecomm.crypto.randoms import now_epoch, random_bytes
from securecomm.errors import CryptoError, SignatureError
from securecomm.utils.encoding import b64d, b64e, canonical_json_bytes, copy_without_keys


@dataclass(slots=True)
class MessageEnvelope:
    """Encrypted text-message envelope schema."""

    version: str
    envelope_type: str
    algorithm: str
    signature_algorithm: str
    created_at: int
    sender_id: str
    recipient_id: str
    eph_public_key: str
    hkdf_salt: str
    nonce: str
    aad: str
    ciphertext: str
    signature: str

    def to_dict(self) -> dict[str, str | int]:
        """Serialize dataclass to dictionary."""
        return {
            "version": self.version,
            "envelope_type": self.envelope_type,
            "algorithm": self.algorithm,
            "signature_algorithm": self.signature_algorithm,
            "created_at": self.created_at,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "eph_public_key": self.eph_public_key,
            "hkdf_salt": self.hkdf_salt,
            "nonce": self.nonce,
            "aad": self.aad,
            "ciphertext": self.ciphertext,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(data: dict[str, str | int]) -> "MessageEnvelope":
        """Construct dataclass from dictionary."""
        return MessageEnvelope(
            version=str(data["version"]),
            envelope_type=str(data["envelope_type"]),
            algorithm=str(data["algorithm"]),
            signature_algorithm=str(data["signature_algorithm"]),
            created_at=int(data["created_at"]),
            sender_id=str(data["sender_id"]),
            recipient_id=str(data["recipient_id"]),
            eph_public_key=str(data["eph_public_key"]),
            hkdf_salt=str(data["hkdf_salt"]),
            nonce=str(data["nonce"]),
            aad=str(data["aad"]),
            ciphertext=str(data["ciphertext"]),
            signature=str(data["signature"]),
        )


class HybridMessageCipher:
    """Encrypt and decrypt text messages with authenticated signatures."""

    def encrypt(
        self,
        sender_id: str,
        recipient_id: str,
        plaintext: bytes,
        sender_sign_private: ed25519.Ed25519PrivateKey,
        recipient_enc_public: x25519.X25519PublicKey,
        aad_extra: bytes = b"",
    ) -> MessageEnvelope:
        """Encrypt plaintext and return signed envelope."""
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        shared_secret = CryptoPrimitives.x25519_agree(ephemeral_private, recipient_enc_public)
        hkdf_salt = random_bytes(32)
        session_key = CryptoPrimitives.derive_session_key(shared_secret=shared_secret, salt=hkdf_salt)

        aad = self._build_aad(
            sender_id=sender_id,
            recipient_id=recipient_id,
            eph_public=ephemeral_public.public_bytes(Encoding.Raw, PublicFormat.Raw),
            extra=aad_extra,
        )

        cipher = CryptoPrimitives.aes_gcm_encrypt(key=session_key, plaintext=plaintext, aad=aad)

        envelope_wo_sig = {
            "version": SCHEMA_VERSION,
            "envelope_type": ENVELOPE_TYPE_TEXT,
            "algorithm": ALG_HYBRID,
            "signature_algorithm": ALG_SIGNATURE,
            "created_at": now_epoch(),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "eph_public_key": b64e(ephemeral_public.public_bytes(Encoding.Raw, PublicFormat.Raw)),
            "hkdf_salt": b64e(hkdf_salt),
            "nonce": b64e(cipher.nonce),
            "aad": b64e(aad),
            "ciphertext": b64e(cipher.ciphertext),
        }
        to_sign = canonical_json_bytes(envelope_wo_sig)
        signature = CryptoPrimitives.sign_data(sender_sign_private, to_sign)

        full = dict(envelope_wo_sig)
        full["signature"] = b64e(signature)
        return MessageEnvelope.from_dict(full)

    def decrypt(
        self,
        envelope: MessageEnvelope,
        recipient_enc_private: x25519.X25519PrivateKey,
        sender_sign_public: ed25519.Ed25519PublicKey,
    ) -> bytes:
        """Verify signature and decrypt envelope payload."""
        data = envelope.to_dict()
        sig_value = data.get("signature")
        if not isinstance(sig_value, str):
            raise SignatureError("envelope missing signature")

        message_wo_sig = copy_without_keys(data, {"signature"})
        to_verify = canonical_json_bytes(message_wo_sig)
        signature = b64d(sig_value)

        if not CryptoPrimitives.verify_data(sender_sign_public, signature=signature, message=to_verify):
            raise SignatureError("signature verification failed")

        try:
            eph_pub = x25519.X25519PublicKey.from_public_bytes(b64d(str(data["eph_public_key"])))
        except Exception as exc:
            raise CryptoError("invalid ephemeral public key") from exc

        hkdf_salt = b64d(str(data["hkdf_salt"]))
        nonce = b64d(str(data["nonce"]))
        aad = b64d(str(data["aad"]))
        ciphertext = b64d(str(data["ciphertext"]))

        shared_secret = CryptoPrimitives.x25519_agree(recipient_enc_private, eph_pub)
        session_key = CryptoPrimitives.derive_session_key(shared_secret=shared_secret, salt=hkdf_salt)
        return CryptoPrimitives.aes_gcm_decrypt(key=session_key, nonce=nonce, ciphertext=ciphertext, aad=aad)

    def _build_aad(self, sender_id: str, recipient_id: str, eph_public: bytes, extra: bytes = b"") -> bytes:
        """Create AAD containing routing metadata and optional extension."""
        fields = [
            b"securecomm",
            sender_id.encode("utf-8"),
            recipient_id.encode("utf-8"),
            eph_public,
            extra,
        ]
        return b"|".join(fields)

    def validate_envelope(self, envelope: MessageEnvelope) -> None:
        """Validate basic envelope consistency before decrypting."""
        if envelope.version != SCHEMA_VERSION:
            raise CryptoError(f"unsupported envelope version: {envelope.version}")
        if envelope.envelope_type != ENVELOPE_TYPE_TEXT:
            raise CryptoError(f"invalid envelope type: {envelope.envelope_type}")
        if envelope.algorithm != ALG_HYBRID:
            raise CryptoError(f"invalid algorithm: {envelope.algorithm}")
        if envelope.signature_algorithm != ALG_SIGNATURE:
            raise CryptoError(f"invalid signature algorithm: {envelope.signature_algorithm}")
        if not envelope.sender_id or not envelope.recipient_id:
            raise CryptoError("sender/recipient id missing")

    def rotate_aad(self, envelope: MessageEnvelope, extra: bytes) -> MessageEnvelope:
        """Return copied envelope with modified AAD for testing negative cases."""
        updated = envelope.to_dict()
        updated["aad"] = b64e(extra)
        return MessageEnvelope.from_dict(updated)