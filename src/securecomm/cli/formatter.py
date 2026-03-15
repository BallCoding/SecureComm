"""CLI formatting helpers for consistent terminal output."""

from __future__ import annotations

import json
from typing import Any


def print_json(data: dict[str, Any]) -> None:
    """Print dictionary as pretty JSON."""
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def print_error(message: str) -> None:
    """Print error message in standard format."""
    print(f"[ERROR] {message}")


def print_ok(message: str) -> None:
    """Print success message in standard format."""
    print(f"[OK] {message}")


def print_title(text: str) -> None:
    """Print title separator."""
    line = "=" * len(text)
    print(line)
    print(text)
    print(line)


def print_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    """Print simple fixed-width table for short lists."""
    if not rows:
        print("(empty)")
        return

    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            widths[col] = max(widths[col], len(str(row.get(col, ""))))

    header = " | ".join(col.ljust(widths[col]) for col in columns)
    sep = "-+-".join("-" * widths[col] for col in columns)
    print(header)
    print(sep)
    for row in rows:
        line = " | ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns)
        print(line)


def ask(prompt: str) -> str:
    """Read one line user input for interactive mode."""
    return input(prompt).strip()


def ask_non_empty(prompt: str) -> str:
    """Read non-empty input, re-prompting once if needed."""
    value = input(prompt).strip()
    if value:
        return value
    value = input(prompt).strip()
    if value:
        return value
    raise ValueError("input cannot be empty")


def divider() -> None:
    """Print compact divider line."""
    print("-" * 48)