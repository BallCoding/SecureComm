"""Validation helpers for args, paths, identifiers and envelopes."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from securecomm.constants import MAX_FILE_CHUNK_SIZE
from securecomm.errors import ValidationError

_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


def require_user_id(user_id: str) -> str:
    """Validate user id; restrict to safe characters for path operations."""
    if not user_id:
        raise ValidationError("user id cannot be empty")
    if not _NAME_PATTERN.match(user_id):
        raise ValidationError("user id must match [a-zA-Z0-9._-]{1,64}")
    return user_id


def require_non_empty_text(value: str, field: str) -> str:
    """Ensure text exists and is not whitespace-only."""
    if value is None:
        raise ValidationError(f"{field} is required")
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text")
    if not value.strip():
        raise ValidationError(f"{field} cannot be empty")
    return value


def require_positive_int(value: int, field: str) -> int:
    """Ensure integer is positive."""
    if not isinstance(value, int):
        raise ValidationError(f"{field} must be integer")
    if value <= 0:
        raise ValidationError(f"{field} must be > 0")
    return value


def require_chunk_size(value: int) -> int:
    """Validate safe file chunk size."""
    require_positive_int(value, "chunk_size")
    if value > MAX_FILE_CHUNK_SIZE:
        raise ValidationError(f"chunk_size too large; max is {MAX_FILE_CHUNK_SIZE}")
    return value


def require_existing_file(path: Path) -> Path:
    """Ensure input path exists and is file."""
    if not path.exists():
        raise ValidationError(f"file does not exist: {path}")
    if not path.is_file():
        raise ValidationError(f"path is not file: {path}")
    return path


def require_parent_dir(path: Path) -> Path:
    """Ensure parent directory exists."""
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    return path


def require_fields(obj: dict[str, Any], fields: Iterable[str], section: str = "object") -> None:
    """Ensure dictionary contains all expected keys."""
    missing = [f for f in fields if f not in obj]
    if missing:
        raise ValidationError(f"{section} missing required fields: {', '.join(missing)}")


def require_type(value: Any, expected: type, field: str) -> None:
    """Ensure value is of expected type."""
    if not isinstance(value, expected):
        raise ValidationError(f"{field} must be {expected.__name__}")


def require_dict(value: Any, field: str) -> dict[str, Any]:
    """Ensure value is dict."""
    if not isinstance(value, dict):
        raise ValidationError(f"{field} must be object")
    return value


def require_list(value: Any, field: str) -> list[Any]:
    """Ensure value is list."""
    if not isinstance(value, list):
        raise ValidationError(f"{field} must be list")
    return value


def require_bytes(value: bytes, field: str) -> bytes:
    """Ensure bytes for binary operations."""
    if not isinstance(value, (bytes, bytearray)):
        raise ValidationError(f"{field} must be bytes")
    return bytes(value)


def maybe_path(value: str | Path) -> Path:
    """Normalize text/path values to Path."""
    if isinstance(value, Path):
        return value
    if isinstance(value, str):
        return Path(value)
    raise ValidationError("invalid path value")


def require_in_choices(value: str, field: str, choices: set[str]) -> str:
    """Ensure value is among known options."""
    if value not in choices:
        ordered = ", ".join(sorted(choices))
        raise ValidationError(f"{field} must be one of: {ordered}")
    return value


def optional_text(value: str | None) -> str | None:
    """Normalize optional text values by stripping whitespace."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("optional text must be string")
    trimmed = value.strip()
    return trimmed or None


def normalize_extension(path: Path, expected_ext: str) -> Path:
    """Ensure output path has expected extension."""
    if path.suffix.lower() == expected_ext.lower():
        return path
    return path.with_suffix(expected_ext)


def ensure_not_same_path(path_a: Path, path_b: Path, msg: str) -> None:
    """Guard destructive overwrite scenarios."""
    if path_a.resolve() == path_b.resolve():
        raise ValidationError(msg)


def require_password(password: str) -> str:
    """Basic password policy."""
    require_non_empty_text(password, "password")
    if len(password) < 10:
        raise ValidationError("password must be at least 10 chars")
    if password.lower() == password or password.upper() == password:
        raise ValidationError("password should mix lower and upper case")
    if not any(ch.isdigit() for ch in password):
        raise ValidationError("password should contain at least one digit")
    return password


def split_csv(values: str) -> list[str]:
    """Split comma-separated text into normalized non-empty tokens."""
    result: list[str] = []
    for piece in values.split(","):
        token = piece.strip()
        if token:
            result.append(token)
    return result


def safe_int(value: str, default: int) -> int:
    """Parse integer with fallback default."""
    try:
        return int(value)
    except Exception:
        return default