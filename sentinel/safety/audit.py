"""Cryptographically chained append-only audit logger."""

from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_AUDIT_LOG = Path(".sentinel_audit.log")


class AuditLogger:
    """Maintains an append-only, SHA-256 chained audit log for security accountability."""

    def __init__(self, log_path: Path | str | None = None):
        self.log_path = Path(log_path) if log_path else DEFAULT_AUDIT_LOG

    def _get_last_entry_hash(self) -> str:
        """Reads the hash of the last entry in the log to maintain the cryptographic chain."""
        if not self.log_path.exists():
            return "0" * 64

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    return "0" * 64
                last_record = json.loads(lines[-1])
                return last_record.get("entry_hash", "0" * 64)
        except Exception:
            return "0" * 64

    def log(
        self,
        event_type: str,
        actor: str = "sentinel-core",
        target: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Appends a new verified event to the audit log."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        prev_hash = self._get_last_entry_hash()
        timestamp = datetime.now(timezone.utc).isoformat()

        record = {
            "timestamp": timestamp,
            "event_type": event_type,
            "actor": actor,
            "target": target,
            "details": details or {},
            "prev_hash": prev_hash,
        }

        # Compute deterministic entry hash
        serialized = json.dumps(record, sort_keys=True)
        entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        record["entry_hash"] = entry_hash

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        return record

    def read_entries(self) -> List[Dict[str, Any]]:
        """Reads all audit entries."""
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return entries

    def verify_integrity(self) -> Tuple[bool, str]:
        """Validates that the hash chain is unbroken and untampered."""
        entries = self.read_entries()
        if not entries:
            return True, "Audit log is empty."

        expected_prev = "0" * 64
        for idx, entry in enumerate(entries):
            logged_hash = entry.get("entry_hash")
            logged_prev = entry.get("prev_hash")

            if logged_prev != expected_prev:
                return False, f"Broken chain link at index {idx}: expected prev {expected_prev}, found {logged_prev}"

            # Verify sha256
            verification_dict = {
                "timestamp": entry.get("timestamp"),
                "event_type": entry.get("event_type"),
                "actor": entry.get("actor"),
                "target": entry.get("target"),
                "details": entry.get("details"),
                "prev_hash": logged_prev,
            }
            computed_hash = hashlib.sha256(json.dumps(verification_dict, sort_keys=True).encode("utf-8")).hexdigest()
            if computed_hash != logged_hash:
                return False, f"Tampered entry detected at index {idx}: computed {computed_hash} != {logged_hash}"

            expected_prev = logged_hash

        return True, f"Audit log verified: {len(entries)} chained events intact."
