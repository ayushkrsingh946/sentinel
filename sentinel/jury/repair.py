"""Robust JSON extraction and auto-repair harness for open-weight LLMs."""

from __future__ import annotations
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

VALID_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
VALID_CATEGORIES = [
    "INJECTION", "AUTH_SECRETS", "SUPPLY_CHAIN", "SSRF",
    "DESERIALIZATION", "WEAK_CRYPTO", "AUTH_BYPASS", "OBFUSCATION", "SECURITY_HEADERS"
]


class JSONRepairHarness:
    """Repairs and extracts structured JSON from imperfect LLM outputs."""

    @classmethod
    def clean_markdown_fences(cls, text: str) -> str:
        """Strips markdown code fences like ```json ... ```."""
        text = text.strip()
        fence_pattern = re.compile(r"^```(?:json)?\s*([\s\S]*?)\s*```$", re.MULTILINE)
        matches = fence_pattern.findall(text)
        if matches:
            return matches[0].strip()

        if "```" in text:
            blocks = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
            if blocks:
                return blocks[0].strip()

        return text

    @classmethod
    def extract_json_structure(cls, text: str) -> Optional[str]:
        """Finds the outermost JSON object `{...}` or array `[...]` in freeform text."""
        cleaned = cls.clean_markdown_fences(text)

        first_bracket = min(
            (pos for pos in [cleaned.find("{"), cleaned.find("[")] if pos != -1),
            default=-1,
        )
        if first_bracket == -1:
            return None

        is_array = cleaned[first_bracket] == "["
        close_char = "]" if is_array else "}"

        last_bracket = cleaned.rfind(close_char)
        if last_bracket == -1 or last_bracket <= first_bracket:
            candidate = cleaned[first_bracket:]
            open_count = candidate.count("[" if is_array else "{")
            close_count = candidate.count(close_char)
            if open_count > close_count:
                candidate += close_char * (open_count - close_count)
            return candidate

        return cleaned[first_bracket : last_bracket + 1]

    @classmethod
    def sanitize_common_json_errors(cls, raw: str) -> str:
        """Fixes trailing commas, single quotes, template placeholder repeats, and types."""
        # Remove trailing commas before } or ]
        s = re.sub(r",\s*([\}\]])", r"\1", raw)

        # Single quotes around keys to double quotes
        s = re.sub(r"(?<=[{\s,])'([A-Za-z0-9_]+)'\s*:", r'"\1":', s)

        # Clean model hallucinations echoing schema placeholder choices
        # e.g. "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO" -> "severity": "HIGH"
        s = re.sub(
            r'"severity"\s*:\s*"[^"]*CRITICAL[^"]*"',
            '"severity": "CRITICAL"',
            s,
        )
        s = re.sub(
            r'"category"\s*:\s*"[^"]*INJECTION[^"]*"',
            '"category": "INJECTION"',
            s,
        )

        # Fix python booleans or None to JSON
        s = re.sub(r"\bTrue\b", "true", s)
        s = re.sub(r"\bFalse\b", "false", s)
        s = re.sub(r"\bNone\b", "null", s)

        return s

    @classmethod
    def normalize_dict_fields(cls, data: Any) -> Any:
        """Recursively normalizes fields like severity and line numbers in parsed JSON dict."""
        if isinstance(data, list):
            return [cls.normalize_dict_fields(x) for x in data]
        if isinstance(data, dict):
            new_data = {}
            for k, v in data.items():
                if k == "severity" and isinstance(v, str):
                    v_upper = v.upper()
                    matched = next((sev for sev in VALID_SEVERITIES if sev in v_upper), "MEDIUM")
                    new_data[k] = matched
                elif k == "category" and isinstance(v, str):
                    v_upper = v.upper()
                    matched = next((cat for cat in VALID_CATEGORIES if cat in v_upper), "INJECTION")
                    new_data[k] = matched
                elif k in ("line_start", "line_end"):
                    try:
                        new_data[k] = int(v)
                    except (ValueError, TypeError):
                        new_data[k] = 1
                else:
                    new_data[k] = cls.normalize_dict_fields(v)
            return new_data
        return data

    @classmethod
    def parse_and_validate(
        cls,
        text: str,
        target_model: Type[T],
    ) -> Tuple[Optional[T], Optional[str]]:
        """Multi-stage parsing and schema validation with normalization."""
        candidate_strings = [
            text,
            cls.clean_markdown_fences(text),
            cls.extract_json_structure(text) or "",
        ]

        last_error = "No valid JSON structure found in text"

        for cand in candidate_strings:
            if not cand:
                continue

            for variant in [cand, cls.sanitize_common_json_errors(cand)]:
                try:
                    raw_dict = json.loads(variant)
                    normalized = cls.normalize_dict_fields(raw_dict)
                    validated = target_model.model_validate(normalized)
                    return validated, None
                except json.JSONDecodeError as jde:
                    last_error = f"JSON syntax error: {jde.msg}"
                except ValidationError as ve:
                    last_error = f"Schema validation error: {ve.error_count()} errors"

        return None, last_error
