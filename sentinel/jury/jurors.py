"""Individual Juror definitions, prompts, and evaluation routines."""

from __future__ import annotations
import concurrent.futures
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from sentinel.config import JurorConfig, SentinelConfig
from sentinel.jury.client import ModelClient
from sentinel.jury.mock_engine import MockJurorEngine
from sentinel.jury.repair import JSONRepairHarness
from sentinel.jury.schema import Finding, JurorVerdict, Severity


class JurorFindingsResponse(BaseModel):
    findings: List[Finding] = Field(default_factory=list)


ROLE_PROMPTS: Dict[str, str] = {
    "injection_specialist": (
        "You are an elite Application Security Engineer specializing in Injection and Input Flaws. "
        "Your task is to audit the provided source code for: SQL injection, OS command injection, "
        "Path Traversal (LFI/RFI), Server-Side Request Forgery (SSRF), Insecure Deserialization, "
        "and Server-Side Template Injection. "
        "Report ONLY confirmed vulnerabilities with exact line evidence. "
        "If no vulnerabilities exist, return an empty findings list."
    ),
    "auth_secrets_specialist": (
        "You are an elite Cryptography and Authentication Security Auditor. "
        "Your task is to audit the provided code for: Hardcoded secrets, API tokens, private keys, "
        "broken authentication, JWT signature verification bypasses, and weak cryptographic algorithms (MD5, SHA1, DES). "
        "Report ONLY confirmed security flaws with exact line evidence. "
        "If no vulnerabilities exist, return an empty findings list."
    ),
    "supply_chain_specialist": (
        "You are a Software Supply Chain & Malware Reverse Engineer. "
        "Your task is to inspect code and dependency diffs for supply chain attacks: "
        "malicious install/preinstall/postinstall lifecycle hooks, hidden outbound network exfiltration "
        "of environment variables or credentials, dynamic evaluation of obfuscated strings (atob, Buffer.from, hex), "
        "and unauthorized file/process modifications. "
        "Report ONLY real threats with exact line evidence. "
        "If no vulnerabilities exist, return an empty findings list."
    ),
}


class Juror:
    """An individual open-weight juror with a specialized security persona."""

    def __init__(self, config: JurorConfig, client: ModelClient, fallback_enabled: bool = True):
        self.id = config.id
        self.name = config.name
        self.model = config.model
        self.role = config.role
        self.focus = config.focus
        self.client = client
        self.fallback_enabled = fallback_enabled

    def review(self, filename: str, content: str, max_retries: int = 2) -> JurorVerdict:
        """Evaluates a code snippet, returning a JurorVerdict."""
        system_prompt = (
            f"{ROLE_PROMPTS.get(self.role, 'You are a cybersecurity code auditor.')}\n\n"
            "CRITICAL OUTPUT FORMAT REQUIREMENTS:\n"
            "Return valid JSON only matching this schema:\n"
            "{\n"
            '  "findings": [\n'
            "    {\n"
            '      "id": "UNIQUE-STRING-ID",\n'
            f'      "file": "{filename}",\n'
            '      "line_start": 10,\n'
            '      "line_end": 12,\n'
            '      "category": "INJECTION|AUTH_SECRETS|SUPPLY_CHAIN|SSRF|DESERIALIZATION|WEAK_CRYPTO|OBFUSCATION",\n'
            '      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
            '      "title": "Brief title",\n'
            '      "explanation": "Why this code is hazardous",\n'
            '      "evidence_quote": "exact quote from lines",\n'
            '      "suggested_patch": "unified diff patch"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "DO NOT include markdown explanations outside the JSON."
        )

        user_content = f"FILE TO AUDIT: {filename}\n```\n{content}\n```"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        attempt = 0
        last_error = None
        raw_output = ""
        total_latency = 0.0

        while attempt <= max_retries:
            try:
                raw_output, latency = self.client.chat_completion(self.model, messages)
                total_latency += latency
                parsed, err = JSONRepairHarness.parse_and_validate(raw_output, JurorFindingsResponse)
                if parsed is not None:
                    return JurorVerdict(
                        juror_id=self.id,
                        juror_name=self.name,
                        role=self.role,
                        model=self.model,
                        findings=parsed.findings,
                        latency_ms=total_latency,
                        status="SUCCESS",
                    )
                last_error = err
            except Exception as e:
                last_error = str(e)

            # Prepare retry prompt
            attempt += 1
            if attempt <= max_retries:
                messages.append({"role": "assistant", "content": raw_output})
                messages.append(
                    {
                        "role": "user",
                        "content": f"Your previous response produced an error: {last_error}. "
                        "Please fix the format and output ONLY valid JSON matching the schema.",
                    }
                )

        # If model failed or unavailable, check fallback
        if self.fallback_enabled:
            fallback_findings = MockJurorEngine.evaluate_role(self.role, filename, content)
            return JurorVerdict(
                juror_id=self.id,
                juror_name=self.name,
                role=self.role,
                model=self.model,
                findings=fallback_findings,
                latency_ms=total_latency,
                status="FALLBACK",
                notes=f"Used local deterministic fallback after: {last_error}",
            )

        return JurorVerdict(
            juror_id=self.id,
            juror_name=self.name,
            role=self.role,
            model=self.model,
            findings=[],
            latency_ms=total_latency,
            status="ERROR",
            notes=f"Failed validation: {last_error}",
        )
