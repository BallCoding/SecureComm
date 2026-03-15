"""Local launcher for running securecomm without installation."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
VENDOR = ROOT / "vendor"

if str(VENDOR) not in sys.path and VENDOR.exists():
    sys.path.insert(0, str(VENDOR))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from securecomm.main import run


if __name__ == "__main__":
    raise SystemExit(run())
