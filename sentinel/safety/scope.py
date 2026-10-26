"""Scope and target authorization enforcement."""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List
import urllib.parse

DEFAULT_SCOPE_PATH = Path("sentinel.scope.yml")


class ScopeViolationError(PermissionError):
    """Raised when an operation targets an unauthorized file, directory, or host."""


class ScopeGuard:
    def __init__(self, scope_path: Path | str | None = None):
        self.scope_path = Path(scope_path) if scope_path else DEFAULT_SCOPE_PATH
        self.allowed_targets: List[str] = ["localhost", "127.0.0.1", "0.0.0.0"]
        self.allowed_paths: List[str] = [".", "src", "app", "benchmark", "packages", "samples"]
        self.static_analysis_only: bool = True
        self.execute_untrusted_code: bool = False
        self.load_scope()

    def _parse_simple_yaml(self, content: str) -> Dict[str, Any]:
        """Fallback lightweight parser for basic YAML if yaml module is not present."""
        data: Dict[str, Any] = {"allowed_targets": [], "allowed_paths": []}
        current_list: str | None = None
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("allowed_targets:"):
                current_list = "allowed_targets"
                data[current_list] = []
            elif line.startswith("allowed_paths:"):
                current_list = "allowed_paths"
                data[current_list] = []
            elif line.startswith("safety_rules:"):
                current_list = None
            elif current_list and line.startswith("-"):
                val = line.lstrip("-").strip().strip('"').strip("'")
                data[current_list].append(val)
        return data

    def load_scope(self) -> None:
        if not self.scope_path.exists():
            # Strict fallback: default local only
            return

        try:
            try:
                import yaml  # type: ignore
                with open(self.scope_path, "r", encoding="utf-8") as f:
                    doc = yaml.safe_load(f) or {}
            except ImportError:
                with open(self.scope_path, "r", encoding="utf-8") as f:
                    doc = self._parse_simple_yaml(f.read())

            if "allowed_targets" in doc and isinstance(doc["allowed_targets"], list):
                self.allowed_targets = [str(t).lower() for t in doc["allowed_targets"]]
            if "allowed_paths" in doc and isinstance(doc["allowed_paths"], list):
                self.allowed_paths = [str(p) for p in doc["allowed_paths"]]
            if "safety_rules" in doc and isinstance(doc["safety_rules"], dict):
                rules = doc["safety_rules"]
                self.static_analysis_only = bool(rules.get("static_analysis_only", True))
                self.execute_untrusted_code = bool(rules.get("execute_untrusted_code", False))
        except Exception as e:
            print(f"[Sentinel Warning] Error parsing scope file {self.scope_path}: {e}")

    def validate_path(self, target_path: Path | str) -> Path:
        resolved = Path(target_path).resolve()
        cwd = Path.cwd().resolve()

        # Check if path is within authorized scopes
        is_allowed = False
        for allowed in self.allowed_paths:
            allowed_res = (cwd / allowed).resolve()
            try:
                # If target is inside allowed directory or is the allowed path
                if resolved == allowed_res or allowed_res in resolved.parents:
                    is_allowed = True
                    break
            except Exception:
                continue

        if not is_allowed:
            raise ScopeViolationError(
                f"Scope violation: Path '{target_path}' is not within authorized scope allowlist: {self.allowed_paths}. "
                f"Update {self.scope_path} to explicitly authorize this path."
            )
        return resolved

    def validate_host(self, url_or_host: str) -> str:
        parsed = urllib.parse.urlparse(url_or_host)
        host = (parsed.hostname or url_or_host).lower()
        if ":" in host:
            host = host.split(":")[0]

        is_allowed = any(
            host == allowed or host.endswith("." + allowed)
            for allowed in self.allowed_targets
        )

        if not is_allowed:
            raise ScopeViolationError(
                f"Scope violation: Host '{host}' is NOT authorized in {self.scope_path}. "
                f"Active probing is restricted strictly to authorized targets: {self.allowed_targets}"
            )
        return host
