"""Safe, non-destructive staging probe for owner's web application."""

from __future__ import annotations
import json
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.parse
import urllib.request

from sentinel.jury.schema import Finding, JuryConsensus, Severity
from sentinel.safety.audit import AuditLogger
from sentinel.safety.scope import ScopeGuard, ScopeViolationError

STANDARD_SECURITY_HEADERS = [
    ("Content-Security-Policy", Severity.MEDIUM, "Missing Content Security Policy (CSP) header increases vulnerability to XSS."),
    ("X-Frame-Options", Severity.LOW, "Missing X-Frame-Options header allows clickjacking attacks."),
    ("X-Content-Type-Options", Severity.LOW, "Missing X-Content-Type-Options: nosniff header allows MIME-type sniffing."),
    ("Strict-Transport-Security", Severity.MEDIUM, "Missing HSTS header allows downgrade to insecure HTTP."),
]

EXPOSED_ENDPOINT_CHECKS = [
    ("/.env", Severity.CRITICAL, "Exposed environment configuration file leaking secret credentials."),
    ("/.git/HEAD", Severity.CRITICAL, "Exposed Git repository directory allowing source code extraction."),
    ("/actuator/env", Severity.HIGH, "Exposed Spring Boot Actuator environment endpoint."),
    ("/debug/vars", Severity.MEDIUM, "Exposed Go debug variables endpoint."),
]


class SafeProbeScanner:
    """Non-destructive, rate-limited staging security prober enforcing strict allowlists."""

    def __init__(self, audit_path: Optional[str] = None):
        self.scope_guard = ScopeGuard()
        self.audit_logger = AuditLogger(audit_path)

    def probe_url(self, target_url: str) -> JuryConsensus:
        """Executes safe probes against an authorized staging target."""
        # Enforce scope guard allowlist
        authorized_host = self.scope_guard.validate_host(target_url)

        findings: List[Finding] = []
        parsed = urllib.parse.urlparse(target_url)
        base_url = f"{parsed.scheme or 'http'}://{parsed.netloc or authorized_host}"

        # 1. Inspect Base Response & Security Headers
        req = urllib.request.Request(
            base_url,
            headers={"User-Agent": "Sentinel-Safe-Probe/1.0 (+https://github.com/ayushkrsingh946/sentinel)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                for header_name, severity, explanation in STANDARD_SECURITY_HEADERS:
                    if header_name.lower() not in headers:
                        findings.append(
                            Finding(
                                id=f"PROBE-HDR-{header_name.replace('-', '').upper()}",
                                file=base_url,
                                line_start=1,
                                line_end=1,
                                category="SECURITY_HEADERS",
                                severity=severity,
                                title=f"Missing Security Header: {header_name}",
                                explanation=explanation,
                                evidence_quote=f"Response headers from {base_url} lacked {header_name}",
                                suggested_patch=f"+ add_header {header_name} ...;",
                            )
                        )

                # Check CORS
                acao = headers.get("access-control-allow-origin")
                acac = headers.get("access-control-allow-credentials")
                if acao == "*" and acac == "true":
                    findings.append(
                        Finding(
                            id="PROBE-CORS-WILDCARD",
                            file=base_url,
                            line_start=1,
                            line_end=1,
                            category="CORS_MISCONFIG",
                            severity=Severity.HIGH,
                            title="Insecure CORS: Wildcard Origin with Credentials",
                            explanation="Access-Control-Allow-Origin: * combined with credentials allows cross-site data theft.",
                            evidence_quote=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                            suggested_patch="- Access-Control-Allow-Origin: *\n+ Access-Control-Allow-Origin: https://trusted.app",
                        )
                    )
        except Exception as e:
            findings.append(
                Finding(
                    id="PROBE-BASE-UNREACHABLE",
                    file=base_url,
                    line_start=1,
                    line_end=1,
                    category="PROBE_INFO",
                    severity=Severity.INFO,
                    title="Target Host Unreachable",
                    explanation=f"Probe could not connect to {base_url}: {e}",
                    evidence_quote=str(e),
                )
            )

        # 2. Check for Exposed Sensitive Endpoints (Read-Only)
        for path, severity, explanation in EXPOSED_ENDPOINT_CHECKS:
            check_url = f"{base_url}{path}"
            try:
                probe_req = urllib.request.Request(
                    check_url,
                    headers={"User-Agent": "Sentinel-Safe-Probe/1.0"},
                )
                with urllib.request.urlopen(probe_req, timeout=5) as probe_resp:
                    if probe_resp.status == 200:
                        body_sample = probe_resp.read(200).decode("utf-8", errors="replace")
                        findings.append(
                            Finding(
                                id=f"PROBE-EXP-{path.replace('/', '_').replace('.', '')}",
                                file=check_url,
                                line_start=1,
                                line_end=1,
                                category="EXPOSED_ENDPOINT",
                                severity=severity,
                                title=f"Exposed Sensitive Endpoint: {path}",
                                explanation=explanation,
                                evidence_quote=f"GET {path} returned HTTP 200: {body_sample[:80]}...",
                                suggested_patch=f"Block external access to {path} in web server config.",
                            )
                        )
            except urllib.error.HTTPError as he:
                # 404 or 403 is good / expected for secure endpoints
                pass
            except Exception:
                pass

        raw_score = sum(f.severity.weight for f in findings)
        risk_score = min(100.0, float(raw_score))

        consensus = JuryConsensus(
            target=base_url,
            timestamp=str(time.time()),
            findings=findings,
            discarded_findings=[],
            disagreements=[],
            overall_risk_score=risk_score,
            overall_risk_level=Severity.HIGH if risk_score >= 40 else (Severity.MEDIUM if risk_score >= 20 else Severity.LOW),
            juror_verdicts=[],
            metadata={"probed_url": target_url, "authorized_host": authorized_host},
        )

        self.audit_logger.log(
            event_type="PROBE_COMPLETED",
            actor="sentinel-probe",
            target=base_url,
            details={"risk_score": risk_score, "findings_count": len(findings)},
        )

        return consensus
