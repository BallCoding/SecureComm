"""Audit logging and operation history utilities."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from securecomm.utils.files import ensure_dir


@dataclass(slots=True)
class AuditEntry:
    """Single audit log entry."""

    timestamp: int
    action: str
    actor: str
    status: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for persistence."""
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "status": self.status,
            "details": self.details,
        }


class AuditService:
    """Append-only JSONL audit logger."""

    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path or Path("output") / "audit.log.jsonl"
        ensure_dir(self.log_path.parent)

    def append(self, entry: AuditEntry) -> None:
        """Append entry as single line JSON object."""
        line = json.dumps(entry.to_dict(), sort_keys=True, ensure_ascii=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def record(self, action: str, actor: str, status: str, details: dict[str, Any], timestamp: int) -> AuditEntry:
        """Create and append one entry."""
        entry = AuditEntry(
            timestamp=timestamp,
            action=action,
            actor=actor,
            status=status,
            details=details,
        )
        self.append(entry)
        return entry

    def read_all(self) -> list[AuditEntry]:
        """Read entire audit history from JSONL file."""
        if not self.log_path.exists():
            return []

        entries: list[AuditEntry] = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                text = line.strip()
                if not text:
                    continue
                obj = json.loads(text)
                entries.append(
                    AuditEntry(
                        timestamp=int(obj["timestamp"]),
                        action=str(obj["action"]),
                        actor=str(obj["actor"]),
                        status=str(obj["status"]),
                        details=dict(obj.get("details", {})),
                    )
                )
        return entries

    def filter_by_actor(self, actor: str) -> list[AuditEntry]:
        """Filter entries by actor id."""
        return [entry for entry in self.read_all() if entry.actor == actor]

    def filter_by_action(self, action: str) -> list[AuditEntry]:
        """Filter entries by action name."""
        return [entry for entry in self.read_all() if entry.action == action]

    def latest(self, limit: int = 20) -> list[AuditEntry]:
        """Return latest N entries."""
        entries = self.read_all()
        return entries[-limit:]

    def summarize(self) -> dict[str, Any]:
        """Return aggregate statistics from audit log."""
        entries = self.read_all()
        by_action: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for entry in entries:
            by_action[entry.action] = by_action.get(entry.action, 0) + 1
            by_status[entry.status] = by_status.get(entry.status, 0) + 1

        return {
            "total": len(entries),
            "by_action": by_action,
            "by_status": by_status,
            "path": str(self.log_path),
        }

    def clear(self) -> None:
        """Clear audit log file."""
        if self.log_path.exists():
            self.log_path.unlink()