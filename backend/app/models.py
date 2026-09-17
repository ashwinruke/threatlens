from datetime import datetime
from enum import StrEnum
from typing import Any

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


class Investigation(BaseModel):
    id: str | None = None
    query: str
    indicator: Indicator
    verdict: Verdict
    signals: list[Signal]
    sources: list[SourceResult]
    trace: list[TraceStep]
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
