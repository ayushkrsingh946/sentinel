"""ASGI / FastAPI background guard middleware for live attack detection."""

from __future__ import annotations
import json
import time
from typing import Any, Callable, Dict, List, Optional
from sentinel.guard.blocklist import BlocklistManager
from sentinel.guard.fast_rules import FastRuleEngine
from sentinel.safety.audit import AuditLogger


class SentinelGuardMiddleware:
    """
    Lightweight security middleware for FastAPI / Starlette / ASGI apps.
    Default mode: 'monitor' (detects and logs without disrupting traffic).
    """

    def __init__(
        self,
        app: Any,
        mode: str = "monitor",
        block_threshold: int = 70,
        allowlist_ips: Optional[List[str]] = None,
        audit_path: Optional[str] = None,
    ):
        self.app = app
        self.mode = mode.lower()  # 'monitor' or 'block'
        self.block_threshold = block_threshold
        self.allowlist_ips = set(allowlist_ips or ["127.0.0.1", "::1", "localhost"])
        self.blocklist = BlocklistManager(default_ttl_seconds=900)
        self.audit_logger = AuditLogger(audit_path)
        self.events: List[Dict[str, Any]] = []

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_host = scope.get("client", ("0.0.0.0", 0))[0]
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        query_string = scope.get("query_string", b"").decode("utf-8", errors="replace")

        headers = {k.decode("utf-8").lower(): v.decode("utf-8") for k, v in scope.get("headers", [])}
        user_agent = headers.get("user-agent", "")

        # 1. Check IP blocklist
        if client_host not in self.allowlist_ips:
            is_blocked, block_reason = self.blocklist.is_blocked(client_host)
            if is_blocked and self.mode == "block":
                response_body = json.dumps(
                    {
                        "error": "Forbidden",
                        "sentinel_shield": "Access temporarily restricted by Sentinel Guard",
                        "reason": block_reason,
                    }
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"x-sentinel-guard", b"blocked"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": response_body})
                return

        # 2. Fast rules inspection
        score, triggered = FastRuleEngine.inspect(
            method=method,
            path=path,
            query=query_string,
            body="",
            user_agent=user_agent,
        )

        if score > 0:
            event = {
                "timestamp": time.time(),
                "client_ip": client_host,
                "method": method,
                "path": path,
                "score": score,
                "triggered": triggered,
                "mode": self.mode,
                "action": "MONITORED",
            }

            if score >= self.block_threshold and client_host not in self.allowlist_ips:
                if self.mode == "block":
                    self.blocklist.block_ip(
                        client_host,
                        reason=f"Triggered high anomaly rules: {', '.join(triggered)}",
                        ttl_seconds=900,
                    )
                    event["action"] = "BLOCKED"
                    self.audit_logger.log("GUARD_IP_BLOCKED", actor="sentinel-guard", target=client_host, details=event)
                    self.events.append(event)

                    response_body = json.dumps(
                        {"error": "Forbidden", "sentinel_shield": "Threat blocked by Sentinel Guard"}
                    ).encode("utf-8")
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 403,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"x-sentinel-guard", b"blocked"),
                            ],
                        }
                    )
                    await send({"type": "http.response.body", "body": response_body})
                    return
                else:
                    event["action"] = "FLAGGED_MONITOR_ONLY"

            self.events.append(event)
            self.audit_logger.log("GUARD_ANOMALY_DETECTED", actor="sentinel-guard", target=f"{method} {path}", details=event)

        # 3. Pass through
        await self.app(scope, receive, send)
