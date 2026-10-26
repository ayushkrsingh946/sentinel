"""Static code vulnerability scanner powered by the multi-model jury."""

from __future__ import annotations
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Optional, Set

from sentinel.config import SentinelConfig
from sentinel.jury.client import ModelClient
from sentinel.jury.judge import SentinelJudge
from sentinel.jury.jurors import Juror
from sentinel.jury.schema import Finding, JurorVerdict, JuryConsensus
from sentinel.safety.audit import AuditLogger
from sentinel.safety.redactor import SecretRedactor
from sentinel.safety.scope import ScopeGuard

IGNORE_EXTENSIONS = {
    ".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".zip", ".tar", ".gz", ".lock", ".sqlite", ".db", ".exe", ".bin"
}

IGNORE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".sentinel_cache",
    ".sentinel_patches", ".pytest_cache", "build", "dist"
}


class CodeScanner:
    """Recursively scans source files, scrubs secrets, runs jury evaluation, and generates consensus."""

    def __init__(self, config: Optional[SentinelConfig] = None):
        self.config = config or SentinelConfig.load()
        self.scope_guard = ScopeGuard()
        self.audit_logger = AuditLogger(self.config.audit_log_path)
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

    def _collect_files(self, target_path: Path) -> List[Path]:
        """Discovers all eligible code files to scan."""
        if target_path.is_file():
            return [target_path]

        collected: List[Path] = []
        for p in target_path.rglob("*"):
            if p.is_file():
                if any(ignored in p.parts for ignored in IGNORE_DIRS):
                    continue
                if p.suffix.lower() in IGNORE_EXTENSIONS:
                    continue
                # Skip files larger than 1MB
                try:
                    if p.stat().st_size > 1024 * 1024:
                        continue
                except OSError:
                    continue
                collected.append(p)
        return collected

    def scan_path(self, raw_path: Path | str) -> JuryConsensus:
        """Audits a path using the jury and returns verified consensus."""
        # Enforce scope guard
        validated_path = self.scope_guard.validate_path(raw_path)

        files = self._collect_files(validated_path)
        file_contents: Dict[str, str] = {}
        redaction_summary: Dict[str, int] = {}

        for f in files:
            rel_name = str(f.relative_to(Path.cwd()) if f.is_relative_to(Path.cwd()) else f.name)
            try:
                with open(f, "r", encoding="utf-8", errors="replace") as fh:
                    raw_content = fh.read()
                # Redact secrets before anything touches LLM prompts
                redacted, stats = SecretRedactor.redact(raw_content)
                file_contents[rel_name] = raw_content  # Store original for exact line verification
                for k, v in stats.items():
                    redaction_summary[k] = redaction_summary.get(k, 0) + v
            except Exception as e:
                print(f"[Sentinel Warning] Error reading {f}: {e}")

        # Execute reviews across Jurors
        all_verdicts: List[JurorVerdict] = []

        for juror in self.jurors:
            juror_findings: List[Finding] = []
            juror_latency = 0.0
            status = "SUCCESS"

            # Review each file with this juror
            for rel_name, content in file_contents.items():
                # Redact content sent to juror
                redacted_for_prompt, _ = SecretRedactor.redact(content)
                verdict = juror.review(rel_name, redacted_for_prompt)
                juror_findings.extend(verdict.findings)
                juror_latency += verdict.latency_ms
                if verdict.status != "SUCCESS":
                    status = verdict.status

            all_verdicts.append(
                JurorVerdict(
                    juror_id=juror.id,
                    juror_name=juror.name,
                    role=juror.role,
                    model=juror.model,
                    findings=juror_findings,
                    latency_ms=juror_latency,
                    status=status,
                )
            )

        # Judge reconciliation & strict evidence filtering
        consensus = SentinelJudge.reconcile_and_judge(
            target_name=str(raw_path),
            file_contents=file_contents,
            verdicts=all_verdicts,
        )

        consensus.metadata["scanned_files_count"] = len(files)
        consensus.metadata["secrets_redacted"] = redaction_summary

        # Audit log record
        self.audit_logger.log(
            event_type="SCAN_COMPLETED",
            actor="sentinel-cli",
            target=str(raw_path),
            details={
                "risk_score": consensus.overall_risk_score,
                "risk_level": consensus.overall_risk_level.value,
                "findings_count": len(consensus.findings),
                "discarded_count": len(consensus.discarded_findings),
                "disagreements_count": len(consensus.disagreements),
                "secrets_redacted_count": sum(redaction_summary.values()),
            },
        )

        return consensus
