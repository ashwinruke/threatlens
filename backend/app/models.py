"""The shapes of data that move through ThreatLens.

Every investigation produces the same structure, whatever the input type,
so the frontend and (from Day 3) the AI report writer always know what to expect.
"""
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class IndicatorType(StrEnum):
    CVE = "cve"
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


class Indicator(BaseModel):
    """What the user entered, cleaned up and identified."""

    type: IndicatorType
    value: str  # normalized value, e.g. "CVE-2021-44228", "evil.com"
    original: str  # exactly what the user typed
    subtype: str | None = None  # "ipv4", "ipv6", "md5", "sha1", "sha256"
    refanged: bool = False  # True if we removed defanging like [.] or hxxp
    notes: list[str] = Field(default_factory=list)


class SourceStatus(StrEnum):
    OK = "ok"  # the source answered and had data
    NOT_FOUND = "not_found"  # the source answered: it knows nothing about this
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"  # not called, e.g. missing API key


class SourceResult(BaseModel):
    """What one intelligence source told us, in a normalized form."""

    source: str  # e.g. "VirusTotal"
    status: SourceStatus
    link: str | None = None  # page a human can open to verify
    facts: dict[str, Any] = Field(default_factory=dict)  # normalized, small
    message: str | None = None  # plain-language explanation for errors/skips
    duration_ms: int | None = None
    cached: bool = False
    fetched_at: datetime | None = None


class Signal(BaseModel):
    """One piece of evidence that moved the risk score."""

    id: str  # stable machine name, e.g. "kev_listed"
    label: str  # human text, e.g. "Listed in CISA KEV"
    points: int  # can be negative, e.g. known-good
    source: str  # where the evidence came from
    evidence: str  # the specific fact behind it


class Verdict(BaseModel):
    score: int  # 0-100
    level: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: str  # high, medium, low: how much evidence we could gather
    headline: str  # one plain sentence
    rules_applied: list[str] = Field(default_factory=list)  # e.g. score floors


class TraceStep(BaseModel):
    """One step of the investigation: what happened and why."""

    step: int
    kind: str  # detect, decide, fetch, score, verdict, save
    title: str
    reason: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    status: str = "ok"
    duration_ms: int | None = None


class CitedPoint(BaseModel):
    """One statement in the AI report, with the sources that support it."""

    text: str
    sources: list[str] = Field(default_factory=list)  # citation ids like "S1"


class Action(BaseModel):
    text: str
    priority: Literal["now", "soon", "later"] = "soon"
    sources: list[str] = Field(default_factory=list)


class Citation(BaseModel):
    id: str  # "S1"
    source: str  # "NVD"
    link: str | None = None  # always taken from ThreatLens's own data, never from the AI


class Report(BaseModel):
    """The AI-written explanation. The verdict and score never come from here."""

    status: Literal["ready", "unavailable"]
    summary: str = ""
    findings: list[CitedPoint] = Field(default_factory=list)
    affected: list[CitedPoint] = Field(default_factory=list)
    actions: list[Action] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    provider: str | None = None  # "Gemini" or "Groq"
    model: str | None = None
    duration_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    removed_claims: int = 0  # statements dropped because they had no valid source
    attempts: list[str] = Field(default_factory=list)  # what happened with each provider
    cached: bool = False
    message: str | None = None  # why it's unavailable


class Investigation(BaseModel):
    id: str | None = None
    query: str
    indicator: Indicator
    verdict: Verdict
    signals: list[Signal]
    sources: list[SourceResult]
    trace: list[TraceStep]
    report: Report | None = None
    created_at: datetime
    duration_ms: int


class InvestigateRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)


class InvestigationSummary(BaseModel):
    id: str
    query: str
    indicator_type: IndicatorType
    indicator_value: str
    score: int
    level: str
    created_at: datetime
