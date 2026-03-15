"""Random and token utilities."""

from __future__ import annotations

import os
import secrets
import time
import uuid


def random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return os.urandom(length)


def random_token(length: int = 32) -> str:
    """Generate URL-safe random token."""
    return secrets.token_urlsafe(length)


def now_epoch() -> int:
    """Current unix timestamp in seconds."""
    return int(time.time())


def now_epoch_ms() -> int:
    """Current unix timestamp in milliseconds."""
    return int(time.time() * 1000)


def new_id(prefix: str = "id") -> str:
    """Generate unique id with prefix."""
    return f"{prefix}-{uuid.uuid4().hex}"


def derive_nonce(base: bytes, counter: int, size: int = 12) -> bytes:
    """Derive deterministic nonce from random base and counter."""
    if size < 8:
        raise ValueError("nonce size must be >= 8")
    counter_bytes = counter.to_bytes(4, "big", signed=False)
    head = base[: size - 4]
    if len(head) < size - 4:
        head = (head + b"\x00" * size)[: size - 4]
    return head + counter_bytes


def clamp_positive(value: int, fallback: int) -> int:
    """Return positive value or fallback."""
    if value <= 0:
        return fallback
    return value


def random_choice(values: list[str]) -> str:
    """Return random item from list."""
    if not values:
        raise ValueError("values cannot be empty")
    index = secrets.randbelow(len(values))
    return values[index]


def masked(value: str, keep: int = 4) -> str:
    """Mask sensitive string for logs."""
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]