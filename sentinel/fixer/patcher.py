"""Patch generator, policy approval engine, and rollback manager."""

from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from sentinel.jury.schema import Finding, Severity
from sentinel.safety.audit import AuditLogger

DEFAULT_PATCH_DIR = Path(".sentinel_patches")


class PatchManager:
    """Manages patch generation, test validation, approval policies, and rollbacks."""

    def __init__(self, patch_dir: Optional[Path | str] = None, policy_path: str = "sentinel.policy.yml"):
        self.patch_dir = Path(patch_dir) if patch_dir else DEFAULT_PATCH_DIR
        self.patch_dir.mkdir(parents=True, exist_ok=True)
        self.audit_logger = AuditLogger()
        self.approval_mode = "manual"
        self._load_policy(policy_path)

    def _load_policy(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                content = f.read()
                for line in content.splitlines():
                    if line.strip().startswith("approval_mode:"):
                        val = line.split(":", 1)[1].strip().strip('"').strip("'")
                        self.approval_mode = val
        except Exception:
            pass

    def can_auto_apply(self, finding: Finding) -> bool:
        """Determines if a patch can be auto-applied under current policy."""
        if self.approval_mode == "auto-all":
            return True
        if self.approval_mode == "auto-low-risk" and finding.severity in (Severity.LOW, Severity.INFO):
            return True
        return False

    def create_patch_record(self, finding: Finding) -> Path:
        """Saves a unified patch file to the patch directory."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        patch_file = self.patch_dir / f"{timestamp}_{finding.id}.patch"
        with open(patch_file, "w", encoding="utf-8") as f:
            f.write(f"# Sentinel Security Patch for {finding.id}\n")
            f.write(f"# Target: {finding.file} (Lines {finding.line_start}-{finding.line_end})\n")
            f.write(f"# Category: {finding.category} | Severity: {finding.severity.value}\n")
            f.write(f"# Explanation: {finding.explanation}\n\n")
            f.write(finding.suggested_patch or "# No patch diff provided\n")
        return patch_file

    def apply_patch(
        self,
        finding: Finding,
        force: bool = False,
        run_tests: bool = True,
        test_command: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Applies a patch with automatic backup and rollback on test failure.
        Returns: (success, message, rollback_id)
        """
        if not force and not self.can_auto_apply(finding):
            return (
                False,
                f"Policy requires manual approval (mode: {self.approval_mode}). Use --approve to apply.",
                None,
            )

        target_file = Path(finding.file)
        if not target_file.exists():
            return False, f"Target file '{finding.file}' does not exist.", None

        # 1. Create backup for rollback
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        rollback_id = f"rollback_{timestamp}_{finding.id}"
        backup_file = self.patch_dir / f"{rollback_id}_{target_file.name}.bak"
        shutil.copy2(target_file, backup_file)

        # 2. Save metadata for rollback
        meta = {
            "rollback_id": rollback_id,
            "target_file": str(target_file.resolve()),
            "backup_file": str(backup_file.resolve()),
            "finding_id": finding.id,
            "timestamp": timestamp,
        }
        with open(self.patch_dir / f"{rollback_id}.json", "w", encoding="utf-8") as f:
            json.dump(meta, f)

        # 3. Apply modification if patch has simple line replacement
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                content = f.read()

            evidence = finding.evidence_quote.strip()
            # If unified diff contains suggested replacement
            if finding.suggested_patch and "\n+ " in finding.suggested_patch:
                replacement_lines = [
                    line[2:] for line in finding.suggested_patch.splitlines() if line.startswith("+ ")
                ]
                replacement_text = "\n".join(replacement_lines)
                if evidence in content:
                    new_content = content.replace(evidence, replacement_text, 1)
                    with open(target_file, "w", encoding="utf-8") as f:
                        f.write(new_content)
        except Exception as e:
            # Revert immediately
            shutil.copy2(backup_file, target_file)
            return False, f"Failed applying patch: {e}", None

        # 4. Run test suite to verify patch didn't break functionality
        if run_tests and test_command:
            try:
                res = subprocess.run(
                    test_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if res.returncode != 0:
                    # Test failed: Automatic rollback!
                    shutil.copy2(backup_file, target_file)
                    self.audit_logger.log(
                        event_type="AUTO_ROLLBACK_TEST_FAILURE",
                        actor="sentinel-fixer",
                        target=str(target_file),
                        details={"rollback_id": rollback_id, "error": res.stderr[:300]},
                    )
                    return (
                        False,
                        f"Tests failed after applying patch! Automatically rolled back. (Test output: {res.stderr[:100]}...)",
                        rollback_id,
                    )
            except Exception as test_err:
                shutil.copy2(backup_file, target_file)
                return False, f"Test execution error, rolled back: {test_err}", rollback_id

        self.audit_logger.log(
            event_type="PATCH_APPLIED",
            actor="sentinel-fixer",
            target=str(target_file),
            details={"rollback_id": rollback_id, "finding_id": finding.id},
        )
        return True, f"Successfully applied fix for {finding.id}. Rollback ID: {rollback_id}", rollback_id

    def rollback(self, rollback_id: str) -> Tuple[bool, str]:
        """Restores a file to its state prior to patch application."""
        meta_file = self.patch_dir / f"{rollback_id}.json"
        if not meta_file.exists():
            return False, f"Rollback ID '{rollback_id}' not found in {self.patch_dir}."

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)

            target_file = Path(meta["target_file"])
            backup_file = Path(meta["backup_file"])

            if not backup_file.exists():
                return False, f"Backup file {backup_file} is missing."

            shutil.copy2(backup_file, target_file)

            self.audit_logger.log(
                event_type="ROLLBACK_EXECUTED",
                actor="sentinel-fixer",
                target=str(target_file),
                details={"rollback_id": rollback_id},
            )
            return True, f"Successfully rolled back {target_file.name} to pre-patch state."
        except Exception as e:
            return False, f"Rollback failed: {e}"
