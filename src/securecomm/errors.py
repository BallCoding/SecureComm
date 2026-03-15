"""Custom exceptions used by securecomm."""


class SecureCommError(Exception):
    """Base exception for all securecomm-specific errors."""


class ValidationError(SecureCommError):
    """Raised when user input or envelope schema is invalid."""


class KeyErrorSecure(SecureCommError):
    """Raised for key read/write/generation failures."""


class CryptoError(SecureCommError):
    """Raised when encryption or decryption operations fail."""


class SignatureError(SecureCommError):
    """Raised when signature creation or verification fails."""


class EnvelopeError(SecureCommError):
    """Raised when envelope parse/serialization fails."""


class VaultError(SecureCommError):
    """Raised when vault encryption/decryption fails."""