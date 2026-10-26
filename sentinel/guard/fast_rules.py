"""Fast regex rule engine and anomaly scoring for request inspection."""

from __future__ import annotations
import re
from typing import Dict, List, Tuple


class FastRuleEngine:
    """Sub-millisecond regex rules and anomaly scoring engine."""

    RULES: List[Tuple[str, re.Pattern[str], int]] = [
        # Path traversal
        ("path_traversal", re.compile(r"""(?i)(\.\./|\.\.\\|etc/(?:passwd|shadow)|windows/win\.ini)"""), 35),
        # SQL Injection
        (
            "sql_injection",
            re.compile(r"""(?i)(union\s+select|select\s+.*\s+from|'\s+or\s+['0-9]+=['0-9]+|;\s*drop\s+table|waitfor\s+delay)"""),
            40,
        ),
        # OS Command Injection
        ("cmd_injection", re.compile(r"""(?i)(\||;|`|\$\()\s*(?:cat|ls|whoami|curl|wget|id|nc|bash|sh)\b"""), 45),
        # XSS Script injection
        ("xss_injection", re.compile(r"""(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie)"""), 30),
        # Scanner Fingerprints
        ("scanner_fingerprint", re.compile(r"""(?i)(sqlmap|nikto|nuclei|acunetix|masscan|zgrab|nessus)"""), 30),
        # Spring / Log4j exploits
        ("log4j_exploit", re.compile(r"""(?i)\$\{jndi:(?:ldap|rmi|dns):"""), 50),
    ]

    @classmethod
    def inspect(cls, method: str, path: str, query: str, body: str, user_agent: str) -> Tuple[int, List[str]]:
        """
        Inspects request parts and computes an anomaly score (0-100).
        Returns (score, list_of_triggered_rules).
        """
        combined = f"{method} {path} ? {query} {body} {user_agent}"
        score = 0
        triggered: List[str] = []

        for rule_name, pattern, weight in cls.RULES:
            if pattern.search(combined):
                score += weight
                triggered.append(rule_name)

        return min(100, score), triggered
