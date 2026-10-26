"""In-memory IP blocklist with automatic TTL expiry and unblock controls."""

from __future__ import annotations
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


class BlocklistManager:
    """Thread-safe blocklist manager with automatic expiry."""

    def __init__(self, default_ttl_seconds: int = 900):
        self.default_ttl = default_ttl_seconds
        self._blocks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.total_blocked_counter = 0

    def block_ip(self, ip: str, reason: str, ttl_seconds: Optional[int] = None) -> None:
        duration = ttl_seconds or self.default_ttl
        now = time.time()
        with self._lock:
            self._blocks[ip] = {
                "ip": ip,
                "reason": reason,
                "blocked_at": now,
                "expires_at": now + duration,
            }
            self.total_blocked_counter += 1

    def is_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        now = time.time()
        with self._lock:
            entry = self._blocks.get(ip)
            if not entry:
                return False, None
            if now > entry["expires_at"]:
                # Expired
                del self._blocks[ip]
                return False, None
            return True, entry["reason"]

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocks:
                del self._blocks[ip]
                return True
            return False

    def list_blocked(self) -> List[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            active = []
            for ip, entry in list(self._blocks.items()):
                if now <= entry["expires_at"]:
                    active.append({**entry, "remaining_seconds": int(entry["expires_at"] - now)})
                else:
                    del self._blocks[ip]
            return active

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "active_blocks": len(self._blocks),
                "total_blocks_lifetime": self.total_blocked_counter,
            }
