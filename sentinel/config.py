"""Configuration management for Sentinel."""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict, List
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path("sentinel.config.json")


class JurorConfig(BaseModel):
    id: str
    name: str
    model: str
    role: str
    focus: str


class SentinelConfig(BaseModel):
    api_base_url: str = Field(default="http://localhost:11434/v1")
    api_key: str = Field(default="ollama")
    timeout_seconds: int = Field(default=45)
    max_retries: int = Field(default=2)
    cache_enabled: bool = Field(default=True)
    cache_dir: str = Field(default=".sentinel_cache")
    audit_log_path: str = Field(default=".sentinel_audit.log")
    jurors: List[JurorConfig] = Field(default_factory=list)
    judge_model: str = Field(default="llama3.2:3b")
    risk_threshold_ci: int = Field(default=60)
    offline_fallback_enabled: bool = Field(default=True)

    @classmethod
    def load(cls, config_path: Path | str | None = None) -> SentinelConfig:
        target_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        data: Dict[str, Any] = {}

        if target_path.exists():
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                print(f"[Sentinel Warning] Could not parse {target_path}: {e}")

        # Environment variable overrides
        if "SENTINEL_BASE_URL" in os.environ:
            data["api_base_url"] = os.environ["SENTINEL_BASE_URL"]
        if "MODEL_ACCESS_KEY" in os.environ:
            data["api_key"] = os.environ["MODEL_ACCESS_KEY"]
        elif "OPENAI_API_KEY" in os.environ:
            data["api_key"] = os.environ["OPENAI_API_KEY"]
        if "SENTINEL_JUDGE_MODEL" in os.environ:
            data["judge_model"] = os.environ["SENTINEL_JUDGE_MODEL"]
        if "SENTINEL_RISK_THRESHOLD" in os.environ:
            try:
                data["risk_threshold_ci"] = int(os.environ["SENTINEL_RISK_THRESHOLD"])
            except ValueError:
                pass

        if not data.get("jurors"):
            data["jurors"] = [
                {
                    "id": "juror-1",
                    "name": "Injection Specialist",
                    "model": "llama3.2:3b",
                    "role": "injection_specialist",
                    "focus": "SQL injection, command injection, path traversal, SSRF, insecure deserialization.",
                },
                {
                    "id": "juror-2",
                    "name": "Auth & Secrets Specialist",
                    "model": "qwen2.5:3b",
                    "role": "auth_secrets_specialist",
                    "focus": "Hardcoded keys, authentication bypass, broken access control, weak cryptography.",
                },
                {
                    "id": "juror-3",
                    "name": "Supply-Chain Specialist",
                    "model": "gemma2:2b",
                    "role": "supply_chain_specialist",
                    "focus": "Malicious install scripts, suspicious network calls, hidden subprocesses, obfuscated strings.",
                },
            ]

        return cls(**data)
