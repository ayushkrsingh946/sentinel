"""Structured Pydantic schemas for Sentinel Jury and Findings."""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        return weights.get(self, 0)


class Finding(BaseModel):
    id: str = Field(description="Unique finding identifier, e.g. SENT-INJ-01")
    file: str = Field(description="Relative path of affected file")
    line_start: int = Field(description="Starting line number (1-indexed)")
    line_end: int = Field(description="Ending line number (1-indexed)")
    category: str = Field(description="Vulnerability category, e.g. INJECTION, SUPPLY_CHAIN, AUTH_SECRETS")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity rating")
    title: str = Field(description="Concise description of the vulnerability")
    explanation: str = Field(description="Plain-language explanation of why this is dangerous")
    evidence_quote: str = Field(description="Exact snippet quoted from the file that exhibits the vulnerability")
    suggested_patch: Optional[str] = Field(default=None, description="Unified diff patch fixing the issue")


class JurorVerdict(BaseModel):
    juror_id: str
    juror_name: str
    role: str
    model: str
    findings: List[Finding] = Field(default_factory=list)
    latency_ms: float = 0.0
    status: str = "SUCCESS"
    notes: Optional[str] = None


class JurorDisagreement(BaseModel):
    category: str
    file: str
    line_range: str
    reporting_jurors: List[str]
    dissenting_jurors: List[str]
    reconciliation_reason: str
    accepted: bool


class JuryConsensus(BaseModel):
    target: str
    timestamp: str
    findings: List[Finding] = Field(default_factory=list)
    discarded_findings: List[Finding] = Field(default_factory=list)
    disagreements: List[JurorDisagreement] = Field(default_factory=list)
    overall_risk_score: float = 0.0
    overall_risk_level: Severity = Severity.INFO
    juror_verdicts: List[JurorVerdict] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
