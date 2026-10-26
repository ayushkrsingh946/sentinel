"""Deterministic local juror simulation engine for offline evaluations, CI, and fallback."""

from __future__ import annotations
import re
from typing import Dict, List, Optional
from sentinel.jury.schema import Finding, Severity


class MockJurorEngine:
    """Provides high-accuracy deterministic static analysis simulating specialized juror personas."""

    @classmethod
    def evaluate_role(cls, role: str, filename: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        if role == "injection_specialist":
            findings.extend(cls._detect_injection(filename, lines))
        elif role == "auth_secrets_specialist":
            findings.extend(cls._detect_auth_secrets(filename, lines))
        elif role == "supply_chain_specialist":
            findings.extend(cls._detect_supply_chain(filename, lines))
        else:
            findings.extend(cls._detect_injection(filename, lines))
            findings.extend(cls._detect_auth_secrets(filename, lines))
            findings.extend(cls._detect_supply_chain(filename, lines))

        return findings

    @classmethod
    def _detect_injection(cls, filename: str, lines: List[str]) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            # SQL Injection
            if re.search(r"""(?i)(select\s+.*from|update\s+.*set|delete\s+.*from).*(?:%|\+|\.format|f['"])""", line) or \
               re.search(r"""execute\(\s*f["'].*SELECT""", line, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"SENT-INJ-SQL-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="INJECTION",
                        severity=Severity.HIGH,
                        title="Potential SQL Injection via Unparameterized Query",
                        explanation="Query string is constructed using string interpolation rather than parameterized placeholders.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ cursor.execute('SELECT ... WHERE id = ?', (user_input,))",
                    )
                )

            # Command Injection
            if re.search(r"""(?i)(os\.system|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\(.*shell\s*=\s*True""", line) or \
               re.search(r"""os\.system\s*\(\s*f["'].*""", line):
                findings.append(
                    Finding(
                        id=f"SENT-INJ-CMD-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="INJECTION",
                        severity=Severity.CRITICAL,
                        title="OS Command Injection via Shell Execution",
                        explanation="Executing shell commands with unescaped user parameters allows arbitrary command execution.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ subprocess.run(['ls', safe_param], check=True, shell=False)",
                    )
                )

            # Path Traversal
            if re.search(r"""(?i)open\s*\(\s*(?:os\.path\.join\([^)]+\)|["'].*["']\s*\+\s*[a-zA-Z0-9_]+)""", line) and ".." not in line:
                if "user" in line.lower() or "param" in line.lower() or "filename" in line.lower():
                    findings.append(
                        Finding(
                            id=f"SENT-INJ-TRAV-{idx}",
                            file=filename,
                            line_start=idx,
                            line_end=idx,
                            category="INJECTION",
                            severity=Severity.HIGH,
                            title="Path Traversal via Unvalidated File Path",
                            explanation="User-controlled path concatenation allows accessing files outside intended directory using '../'.",
                            evidence_quote=line.strip(),
                            suggested_patch=f"- {line.strip()}\n+ safe_path = os.path.abspath(target)\n+ if not safe_path.startswith(BASE_DIR): raise ValueError('Path traversal')",
                        )
                    )

            # SSRF
            if re.search(r"""(?i)(requests\.get|urllib\.request\.urlopen|httpx\.get)\s*\(\s*(?:url|user_url|target_url|req\.args)""", line):
                findings.append(
                    Finding(
                        id=f"SENT-INJ-SSRF-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="SSRF",
                        severity=Severity.HIGH,
                        title="Server-Side Request Forgery (SSRF)",
                        explanation="Outbound HTTP request made to untrusted target allows probing internal cloud metadata and services.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ validate_internal_ip(url)\n+ requests.get(url, timeout=5)",
                    )
                )

            # Insecure Deserialization
            if re.search(r"""(?i)(pickle\.loads|yaml\.load\s*\([^,]+(?:\)|,\s*Loader\s*=\s*(?:yaml\.)?Loader)|eval\s*\(|exec\s*\()""", line):
                findings.append(
                    Finding(
                        id=f"SENT-INJ-DESER-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="DESERIALIZATION",
                        severity=Severity.CRITICAL,
                        title="Insecure Code Execution / Deserialization",
                        explanation="Unsafe deserialization allows remote code execution when parsing untrusted data.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ json.loads(payload)",
                    )
                )

        return findings

    @classmethod
    def _detect_auth_secrets(cls, filename: str, lines: List[str]) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            # Hardcoded API key or token
            if re.search(r"""(?i)(api_key|secret_key|jwt_secret|private_key|token)\s*=\s*["'][A-Za-z0-9_\-\.]{12,}["']""", line):
                findings.append(
                    Finding(
                        id=f"SENT-AUTH-SEC-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="AUTH_SECRETS",
                        severity=Severity.HIGH,
                        title="Hardcoded Credential or API Secret",
                        explanation="Hardcoded secrets in source control can be extracted by attackers or leaked publicly.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ secret = os.environ.get('SECRET_KEY')",
                    )
                )

            # Weak Hashing (MD5 or SHA1 for password)
            if re.search(r"""(?i)hashlib\.(md5|sha1)\s*\(""", line) and ("pass" in line.lower() or "auth" in line.lower() or "token" in line.lower()):
                findings.append(
                    Finding(
                        id=f"SENT-AUTH-HASH-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="WEAK_CRYPTO",
                        severity=Severity.MEDIUM,
                        title="Weak Hash Algorithm for Sensitive Material",
                        explanation="MD5 and SHA1 are cryptographically broken and vulnerable to fast collision attacks.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ hashlib.sha256(password.encode()).hexdigest()",
                    )
                )

            # JWT with None algorithm or no verify
            if re.search(r"""(?i)(jwt\.decode\s*\(.*verify\s*=\s*False|algorithms\s*=\s*\[\s*["']none["']\s*\])""", line):
                findings.append(
                    Finding(
                        id=f"SENT-AUTH-JWT-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="AUTH_BYPASS",
                        severity=Severity.CRITICAL,
                        title="JWT Signature Verification Disabled",
                        explanation="Disabling signature verification permits attackers to forge administrative tokens.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ jwt.decode(token, key, algorithms=['HS256'])",
                    )
                )

        return findings

    @classmethod
    def _detect_supply_chain(cls, filename: str, lines: List[str]) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            # Malicious preinstall/postinstall curl/wget/bash
            if re.search(r"""(?i)["'](postinstall|preinstall)["']\s*:\s*["'].*(curl|wget|bash|sh|powershell).*["']""", line) or \
               re.search(r"""(?i)(curl|wget)\s+.*(?:\.sh|\.exe|\.bin)\s*\|\s*(?:bash|sh)""", line):
                findings.append(
                    Finding(
                        id=f"SENT-SUPPLY-INSTALL-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="SUPPLY_CHAIN",
                        severity=Severity.CRITICAL,
                        title="Suspicious Remote Code Execution in Package Lifecycle Script",
                        explanation="Package lifecycle script downloads and executes unverified remote binaries during install.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ // Removed hazardous lifecycle script",
                    )
                )

            # Exfiltration of environment / secrets via network
            if (("process.env" in line or "os.environ" in line) and ("fetch" in line or "http" in line or "curl" in line or "socket" in line)) or \
               re.search(r"""(?i)requests\.post\s*\([^,]+,\s*data\s*=\s*(?:os\.environ|dict\(os\.environ\))""", line):
                findings.append(
                    Finding(
                        id=f"SENT-SUPPLY-EXFIL-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="SUPPLY_CHAIN",
                        severity=Severity.CRITICAL,
                        title="Potential Credential Exfiltration to External Endpoint",
                        explanation="Code reads local environment variables and transmits them outbound over HTTP/network.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ // Exfiltration pattern blocked",
                    )
                )

            # Obfuscated string execution
            if re.search(r"""(?i)(eval\s*\(\s*(?:Buffer\.from|atob|base64\.b64decode)|new\s+Function\s*\(\s*atob)""", line):
                findings.append(
                    Finding(
                        id=f"SENT-SUPPLY-OBF-{idx}",
                        file=filename,
                        line_start=idx,
                        line_end=idx,
                        category="OBFUSCATION",
                        severity=Severity.CRITICAL,
                        title="Obfuscated Payload Execution",
                        explanation="Payload is concealed in base64/hex encoding and dynamically evaluated at runtime.",
                        evidence_quote=line.strip(),
                        suggested_patch=f"- {line.strip()}\n+ // Obfuscated dynamic evaluation removed",
                    )
                )

        return findings
