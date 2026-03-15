"""Encoding helpers for bytes/text/json and filesystem interactions."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from securecomm.errors import EnvelopeError


def b64e(data: bytes) -> str:
    """Encode bytes to url-safe base64 string without stripping padding."""
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    """Decode url-safe base64 string to bytes."""
    try:
        return base64.urlsafe_b64decode(data.encode("ascii"))
    except Exception as exc:
        raise EnvelopeError("invalid base64 payload") from exc


def to_json(data: dict[str, Any], indent: int = 2) -> str:
    """Serialize dictionary to deterministic json for signing."""
    try:
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, indent=indent)
    except Exception as exc:
        raise EnvelopeError("failed to serialize json") from exc


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serialize dictionary to canonical json bytes for authenticated/signature use."""
    try:
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except Exception as exc:
        raise EnvelopeError("failed to canonicalize json") from exc
    return payload.encode("utf-8")


def from_json(payload: str) -> dict[str, Any]:
    """Load dictionary from json string."""
    try:
        parsed = json.loads(payload)
    except Exception as exc:
        raise EnvelopeError("invalid json payload") from exc
    if not isinstance(parsed, dict):
        raise EnvelopeError("json root must be object")
    return parsed


def write_json(path: Path, data: dict[str, Any]) -> None:
    """Write dictionary to UTF-8 json file."""
    text = to_json(data, indent=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    """Read dictionary from UTF-8 json file."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise EnvelopeError(f"json file not found: {path}") from exc
    except OSError as exc:
        raise EnvelopeError(f"cannot read json file: {path}") from exc
    return from_json(text)


def maybe_decode_text(data: bytes) -> str:
    """Best-effort decode for user display after decryption."""
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    raise EnvelopeError("decrypted bytes cannot be decoded as text")


def as_bytes(text: str) -> bytes:
    """Encode text to bytes with UTF-8."""
    try:
        return text.encode("utf-8")
    except Exception as exc:
        raise EnvelopeError("failed to encode text") from exc


def as_text(data: bytes) -> str:
    """Decode bytes with UTF-8."""
    try:
        return data.decode("utf-8")
    except Exception as exc:
        raise EnvelopeError("failed to decode text") from exc


def copy_without_keys(source: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    """Return shallow copy excluding specified keys."""
    return {k: v for k, v in source.items() if k not in keys}


def deep_sort_dict(value: Any) -> Any:
    """Recursively sort dict keys for stable display and testing."""
    if isinstance(value, dict):
        return {k: deep_sort_dict(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [deep_sort_dict(item) for item in value]
    return value