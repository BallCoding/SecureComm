"""Secure communication toolkit package."""

from __future__ import annotations

import os
import site
import sys
from pathlib import Path

_project_root = Path(__file__).resolve().parents[2]
_vendor = _project_root / "vendor"
if _vendor.exists() and str(_vendor) not in sys.path:
    sys.path.insert(0, str(_vendor))

# Some Windows Python setups disable user-site path by default.
_user_site = site.getusersitepackages()
if os.path.isdir(_user_site) and _user_site not in sys.path:
    site.addsitedir(_user_site)

from securecomm.services.file_service import FileService
from securecomm.services.key_service import KeyService
from securecomm.services.message_service import MessageService
from securecomm.services.vault_service import VaultService

__all__ = [
    "KeyService",
    "MessageService",
    "FileService",
    "VaultService",
]
