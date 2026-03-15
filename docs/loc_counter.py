"""Count non-empty non-comment Python lines under src/securecomm."""

from __future__ import annotations

from pathlib import Path


def count_loc(root: Path) -> tuple[int, list[tuple[str, int]]]:
    total = 0
    per_file: list[tuple[str, int]] = []

    for path in sorted(root.rglob("*.py")):
        count = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            count += 1
        per_file.append((str(path), count))
        total += count

    return total, per_file


def main() -> int:
    root = Path("src") / "securecomm"
    total, per_file = count_loc(root)
    print(f"Root: {root}")
    for path, count in per_file:
        print(f"{count:5d}  {path}")
    print("-" * 60)
    print(f"Total LOC (non-empty, non-comment): {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
