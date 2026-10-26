"""Judge Step: Reconciles juror disagreements, verifies line evidence, and scores risk."""

from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple

from sentinel.jury.schema import Finding, JurorDisagreement, JurorVerdict, JuryConsensus, Severity


class SentinelJudge:
    """Judge engine that enforces evidence integrity, resolves juror disagreements, and calculates risk scores."""

    @classmethod
    def verify_line_evidence(cls, finding: Finding, file_content: str) -> bool:
        """
        Validates that finding.evidence_quote actually exists in the file.
        Discards hallucinations where the model fabricated lines.
        """
        if not file_content:
            return False

        lines = file_content.splitlines()
        total_lines = len(lines)
        if total_lines == 0:
            return False

        evidence = finding.evidence_quote.strip()
        if not evidence:
            return False

        # Direct containment check: if the exact evidence exists anywhere in the file/diff
        if evidence in file_content:
            return True

        # Normalized whitespace match across whole content
        norm_evidence = re.sub(r"\s+", " ", evidence).strip()
        norm_full = re.sub(r"\s+", " ", file_content).strip()
        if norm_evidence in norm_full:
            return True

        # Check line window (with 4-line tolerance buffer) if within file boundaries
        start_idx = max(0, finding.line_start - 4)
        end_idx = min(total_lines, finding.line_end + 3)
        if start_idx < total_lines:
            window_text = "\n".join(lines[start_idx:end_idx])
            norm_window = re.sub(r"\s+", " ", window_text).strip()
            if norm_evidence in norm_window:
                return True

        # Check first line of multi-line evidence
        first_line = evidence.splitlines()[0].strip()
        if len(first_line) > 5 and first_line in file_content:
            return True

        # Stripped quotes check: e.g. model quoted "postinstall": "curl..." inside a diff line "+ \"postinstall\"..."
        clean_code_token = evidence.strip('"+- \t')
        if len(clean_code_token) > 8 and clean_code_token in file_content:
            return True

        return False

    @classmethod
    def reconcile_and_judge(
        cls,
        target_name: str,
        file_contents: Dict[str, str],
        verdicts: List[JurorVerdict],
    ) -> JuryConsensus:
        """
        Merges juror findings, discards non-evidentiary claims, logs disagreements,
        and scores composite project risk.
        """
        accepted_findings: List[Finding] = []
        discarded_findings: List[Finding] = []
        disagreements: List[JurorDisagreement] = []

        finding_buckets: Dict[Tuple[str, str, int], List[Tuple[str, Finding]]] = {}

        for verdict in verdicts:
            for finding in verdict.findings:
                content = file_contents.get(finding.file, "")
                if not content:
                    for k, v in file_contents.items():
                        if k.endswith(finding.file) or finding.file.endswith(k) or Path(k).name == Path(finding.file).name:
                            content = v
                            break

                if not cls.verify_line_evidence(finding, content):
                    discarded_findings.append(finding)
                    continue

                bucket_key = (finding.file, finding.category, max(1, finding.line_start // 4))
                if bucket_key not in finding_buckets:
                    finding_buckets[bucket_key] = []
                finding_buckets[bucket_key].append((verdict.juror_name, finding))

        all_juror_names = [v.juror_name for v in verdicts]

        for bucket_key, group in finding_buckets.items():
            reporting_jurors = list(dict.fromkeys(item[0] for item in group))
            dissenting_jurors = [name for name in all_juror_names if name not in reporting_jurors]

            canonical = max(
                (item[1] for item in group),
                key=lambda f: (len(f.suggested_patch or ""), len(f.explanation)),
            )
            accepted_findings.append(canonical)

            if dissenting_jurors:
                disagreements.append(
                    JurorDisagreement(
                        category=canonical.category,
                        file=canonical.file,
                        line_range=f"L{canonical.line_start}-L{canonical.line_end}",
                        reporting_jurors=reporting_jurors,
                        dissenting_jurors=dissenting_jurors,
                        reconciliation_reason=(
                            f"Verified line-level evidence in {canonical.file}. "
                            f"Consensus approved finding backed by {', '.join(reporting_jurors)}."
                        ),
                        accepted=True,
                    )
                )

        raw_score = sum(f.severity.weight for f in accepted_findings)
        risk_score = min(100.0, float(raw_score))

        if risk_score >= 70:
            risk_level = Severity.CRITICAL
        elif risk_score >= 40:
            risk_level = Severity.HIGH
        elif risk_score >= 20:
            risk_level = Severity.MEDIUM
        elif risk_score > 0:
            risk_level = Severity.LOW
        else:
            risk_level = Severity.INFO

        timestamp = datetime.now(timezone.utc).isoformat()

        return JuryConsensus(
            target=target_name,
            timestamp=timestamp,
            findings=accepted_findings,
            discarded_findings=discarded_findings,
            disagreements=disagreements,
            overall_risk_score=risk_score,
            overall_risk_level=risk_level,
            juror_verdicts=verdicts,
            metadata={
                "total_jurors": len(verdicts),
                "total_initial_findings": sum(len(v.findings) for v in verdicts),
                "discarded_unverified_count": len(discarded_findings),
                "accepted_count": len(accepted_findings),
            },
        )
