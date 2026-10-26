"""Secret redactor to prevent leaking sensitive credentials into prompts."""

from __future__ import annotations
import re
from typing import Dict, List, Tuple


class SecretRedactor:
    """Scrubs sensitive credentials and tokens before passing source code to any model."""

    # Precompiled regex patterns for common credential leaks
    PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
        # AWS Access Key ID
        (
            "aws_access_key",
            re.compile(r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b"),
            "[REDACTED_AWS_KEY_ID]",
        ),
        # GitHub Personal / OAuth Access Token
        (
            "github_token",
            re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
            "[REDACTED_GITHUB_TOKEN]",
        ),
        # Slack API Token
        (
            "slack_token",
            re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
            "[REDACTED_SLACK_TOKEN]",
        ),
        # JSON Web Token (JWT)
        (
            "jwt_token",
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b"),
            "[REDACTED_JWT_TOKEN]",
        ),
        # RSA / OpenSSH / EC Private Keys
        (
            "private_key",
            re.compile(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                re.MULTILINE,
            ),
            "[REDACTED_PRIVATE_KEY_BLOCK]",
        ),
        # Database URI with passwords (postgres, mysql, mongodb, redis)
        (
            "database_url",
            re.compile(r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[a-zA-Z0-9_.-]+:)([^@/\s]+)(@[a-zA-Z0-9_.-]+)"),
            r"\1[REDACTED_DB_PASSWORD]\3",
        ),
        # Generic Secret / API Key assignment: key = "..."
        (
            "generic_api_key",
            re.compile(
                r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{8,128})["']"""
            ),
            r'\1 = "[REDACTED_SECRET]"',
        ),
        # Bearer tokens in headers
        (
            "bearer_token",
            re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9_\-\.]{16,})\b"),
            r"\1[REDACTED_BEARER_TOKEN]",
        ),
    ]

    @classmethod
    def redact(cls, text: str) -> Tuple[str, Dict[str, int]]:
        """Redacts sensitive credentials and returns the scrubbed text and count of redactions."""
        redacted_text = text
        stats: Dict[str, int] = {}

        for name, pattern, replacement in cls.PATTERNS:
            matches = len(pattern.findall(redacted_text))
            if matches > 0:
                stats[name] = matches
                redacted_text = pattern.sub(replacement, redacted_text)

        return redacted_text, stats
