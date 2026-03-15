"""Filesystem utility functions for securecomm."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable

from securecomm.errors import SecureCommError


def ensure_dir(path: Path) -> Path:
    """Create directory recursively if needed."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_bytes(path: Path) -> bytes:
    """Read file bytes with controlled exceptions."""
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise SecureCommError(f"file not found: {path}") from exc
    except OSError as exc:
        raise SecureCommError(f"cannot read file: {path}") from exc


def write_bytes(path: Path, data: bytes) -> None:
    """Write file bytes and ensure parent exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_bytes(data)
    except OSError as exc:
        raise SecureCommError(f"cannot write file: {path}") from exc


def read_text(path: Path) -> str:
    """Read text file as UTF-8."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SecureCommError(f"file not found: {path}") from exc
    except OSError as exc:
        raise SecureCommError(f"cannot read text file: {path}") from exc


def write_text(path: Path, text: str) -> None:
    """Write UTF-8 text and create parent directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise SecureCommError(f"cannot write text file: {path}") from exc


def file_sha256(path: Path, chunk_size: int = 64 * 1024) -> str:
    """Compute SHA256 digest of file by streaming chunks."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
    except FileNotFoundError as exc:
        raise SecureCommError(f"file not found: {path}") from exc
    except OSError as exc:
        raise SecureCommError(f"cannot hash file: {path}") from exc
    return h.hexdigest()


def file_size(path: Path) -> int:
    """Return file size in bytes."""
    try:
        return path.stat().st_size
    except FileNotFoundError as exc:
        raise SecureCommError(f"file not found: {path}") from exc
    except OSError as exc:
        raise SecureCommError(f"cannot get size: {path}") from exc


def split_file(path: Path, chunk_size: int) -> list[bytes]:
    """Read full file and split into chunks."""
    chunks: list[bytes] = []
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)
    except FileNotFoundError as exc:
        raise SecureCommError(f"file not found: {path}") from exc
    except OSError as exc:
        raise SecureCommError(f"cannot split file: {path}") from exc
    return chunks


def join_chunks(path: Path, chunks: Iterable[bytes]) -> None:
    """Write sequence of chunks to destination file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("wb") as fh:
            for chunk in chunks:
                fh.write(chunk)
    except OSError as exc:
        raise SecureCommError(f"cannot write merged file: {path}") from exc


def list_files(path: Path, recursive: bool = False) -> list[Path]:
    """List files in directory, optionally recursive."""
    if not path.exists():
        return []
    if not path.is_dir():
        return [path]
    if recursive:
        return [p for p in path.rglob("*") if p.is_file()]
    return [p for p in path.iterdir() if p.is_file()]


def ensure_abs(path: Path) -> Path:
    """Resolve path to absolute path without requiring existence."""
    return path.expanduser().resolve()


def unique_path(path: Path) -> Path:
    """Create non-existing path by appending numeric suffix if needed."""
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    parent = path.parent
    index = 1
    while True:
        candidate = parent / f"{stem}_{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1


def secure_delete(path: Path) -> None:
    """Best-effort secure delete by overwrite and remove."""
    if not path.exists() or not path.is_file():
        return
    size = path.stat().st_size
    try:
        with path.open("r+b") as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        pass
    try:
        path.unlink()
    except Exception:
        pass


def describe_path(path: Path) -> str:
    """Human-readable path description with existence and size."""
    exists = path.exists()
    if not exists:
        return f"{path} (missing)"
    if path.is_dir():
        count = len(list(path.iterdir()))
        return f"{path} (directory, {count} entries)"
    return f"{path} (file, {path.stat().st_size} bytes)"