"""Supply chain and dependency update diff scanner."""

from __future__ import annotations
import difflib
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

from sentinel.config import SentinelConfig
from sentinel.jury.judge import SentinelJudge
from sentinel.jury.jurors import Juror
from sentinel.jury.schema import Finding, JurorVerdict, JuryConsensus, Severity
from sentinel.safety.audit import AuditLogger
from sentinel.safety.redactor import SecretRedactor
from sentinel.safety.scope import ScopeGuard


class DiffScanner:
    """Specialized auditor for dependency updates and unified git diffs."""

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig.load()
        self.scope_guard = ScopeGuard()
        self.audit_logger = AuditLogger(self.config.audit_log_path)
        from sentinel.jury.client import ModelClient
        self.client = ModelClient(
            base_url=self.config.api_base_url,
            api_key=self.config.api_key,
            cache_dir=self.config.cache_dir,
            cache_enabled=self.config.cache_enabled,
            timeout=self.config.timeout_seconds,
        )
        self.jurors: List[Juror] = [
            Juror(j_cfg, self.client, fallback_enabled=self.config.offline_fallback_enabled)
            for j_cfg in self.config.jurors
        ]

    def _read_file_or_snippet(self, target: str | Path) -> str:
        p = Path(target)
        if p.exists() and p.is_file():
            self.scope_guard.validate_path(p)
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        return str(target)

    def scan_diff_text(self, diff_text: str, label: str = "dependency-diff") -> JuryConsensus:
        """Audits a unified diff string directly."""
        redacted_diff, _ = SecretRedactor.redact(diff_text)
        file_contents = {label: diff_text}

        all_verdicts: List[JurorVerdict] = []
        for juror in self.jurors:
            verdict = juror.review(label, redacted_diff)
            all_verdicts.append(verdict)

        consensus = SentinelJudge.reconcile_and_judge(
            target_name=label,
            file_contents=file_contents,
            verdicts=all_verdicts,
        )

        self.audit_logger.log(
            event_type="DIFF_AUDIT_COMPLETED",
            actor="sentinel-diff",
            target=label,
            details={
                "risk_score": consensus.overall_risk_score,
                "findings_count": len(consensus.findings),
                "disagreements": len(consensus.disagreements),
            },
        )
        return consensus

    def scan_two_versions(self, old_target: str | Path, new_target: str | Path) -> JuryConsensus:
        """Generates unified diff between two file paths or package versions and audits."""
        old_content = self._read_file_or_snippet(old_target)
        new_content = self._read_file_or_snippet(new_target)

        old_lines = old_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)

        diff_lines = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"old/{Path(old_target).name}",
                tofile=f"new/{Path(new_target).name}",
            )
        )
        diff_text = "".join(diff_lines)
        if not diff_text.strip():
            diff_text = new_content  # Fallback to inspecting new content directly

        label = f"diff:{Path(old_target).name}->{Path(new_target).name}"
        return self.scan_diff_text(diff_text, label=label)
