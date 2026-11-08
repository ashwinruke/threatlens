"""The rule-based fact check: are the specifics in an AI statement really in its cited sources?"""
import asyncio

import pytest

from app.ai.grounding import Evidence, extract_specifics, remove_invented_sentences
from app.investigate import investigate
from app.store import MemoryStore
from tests import fakes

PACKET = {
    "indicator": {"type": "cve", "value": "CVE-2021-44228", "notes": []},
    "verdict": {"level": "CRITICAL", "score": 95, "confidence": "high"},
    "scoring_signals (source S0 unless stated)": [{"label": "CVSS 10.0 (CRITICAL)", "points": 40}],
    "sources": [
        {"id": "S1", "source": "NVD", "facts": {"cvss": 10.0, "published": "2021-12-10", "weaknesses": ["CWE-502"],
                                                 "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features"}},
        {"id": "S2", "source": "CISA KEV", "facts": {"date_added": "2021-12-10", "ransomware": "Known"}},
        {"id": "S3", "source": "FIRST EPSS", "facts": {"epss": 0.99999, "percentile": 1.0}},
        {"id": "S4", "source": "AbuseIPDB", "facts": {"total_reports": 812, "distinct_reporters": 190, "ip": "45.95.147.236"}},
    ],
}


@pytest.fixture
def evidence():
    return Evidence(PACKET)


@pytest.mark.parametrize("text,cited,status", [
    ("NVD rates it CVSS 10.0.", ["S1"], "grounded"),
    ("Exploitation probability is 99.99%, top 100% percentile.", ["S3"], "grounded"),
    ("Reported 812 times by 190 people.", ["S4"], "grounded"),
    ("Reported by more than 800 people.", ["S4"], "grounded"),  # rounding with a qualifier is fine
    ("Affects versions up to 2.15.0.", ["S1"], "grounded"),
    ("Published in December 2021.", ["S1"], "grounded"),
    ("Linked to CWE-502.", ["S2"], "misattributed"),  # real fact, wrong source
    ("Fixed in 2.17.1.", ["S1"], "invented"),  # from memory, not in the evidence
    ("Also tracked as CVE-2021-45046.", ["S1"], "invented"),
    ("Uses technique T1190.", ["S1"], "invented"),
    ("Reported 900 times.", ["S4"], "invented"),
    ("Patch within 48 hours.", ["S1"], "no_specifics"),  # durations in advice aren't facts
    ("Its risk score is 95/100.", ["S0"], "no_specifics"),
    ("CVE-2021-44228 is critical.", ["S1"], "no_specifics"),  # the investigated indicator itself
    ("Used in ransomware campaigns.", ["S2"], "no_specifics"),
])
def test_statement_check(evidence, text, cited, status):
    assert evidence.check(text, cited).status == status


def test_only_ids_addresses_hashes_and_versions_are_strict(evidence):
    assert evidence.check("Fixed in 2.17.1.", ["S1"]).strict_invention
    assert evidence.check("Seen at 198.51.100.7.", ["S4"]).strict_invention
    assert not evidence.check("Reported 900 times.", ["S4"]).strict_invention  # a number may be rounding
    assert not evidence.check("Linked to CWE-502.", ["S2"]).strict_invention  # misattributed, not invented


def test_extracts_each_kind_once():
    kinds = [s.kind for s in extract_specifics(
        "CVE-2024-3400 (CWE-77, T1190) hit 203.0.113.9 with " + "a" * 64 + " on 4.2.1, CVSS 9.8, 94% likely, 812 reports, 2024")]
    assert kinds == ["cve", "cwe", "attack", "hash", "ip", "version", "percent", "decimal", "year", "integer"]


def test_numbers_off_switch_keeps_only_strict_kinds():
    assert [s.kind for s in extract_specifics("CVSS 9.8 in 2.17.1, 812 reports", numbers=False)] == ["version"]


def test_summary_sentences_with_invented_ids_are_dropped(evidence):
    summary, removed = remove_invented_sentences(
        "Log4Shell is critical. It is also tracked as CVE-2021-45046. Patch now.", evidence)
    assert summary == "Log4Shell is critical. Patch now."
    assert removed == 1


def test_report_writer_removes_invented_statements():
    report = {**fakes.GOOD_REPORT,
              "summary": "A critical flaw. Fixed in Log4j 2.17.1.",
              "findings": [{"text": "CISA lists it as exploited.", "sources": ["S2"]},
                           {"text": "Also tracked as CVE-2021-45046.", "sources": ["S1"]}]}
    settings = fakes.test_settings(gemini_api_key="g", groq_api_key="q")
    client = fakes.router({"gemini": (200, fakes.gemini_body(report))})
    result = asyncio.run(investigate(fakes.LOG4SHELL, settings, MemoryStore(), client)).report
    assert result.status == "ready"
    assert [f.text for f in result.findings] == ["CISA lists it as exploited."]
    assert result.summary == "A critical flaw."
    assert result.removed_invented == 2  # the CVE statement and the summary sentence


# Real answers from gpt-oss-120b that the first version of the check misread
@pytest.mark.parametrize("text,cited,status", [
    ("NVD has no record of CVE\u20112021\u201144228.", ["S1"], "no_specifics"),  # the indicator itself, non-breaking hyphens
    ("Added to CISA KEV on 2021‑12‑10", ["S2"], "grounded"),
    ("812 reports with 100\u202f% abuse confidence, last reported 2021-12-10", ["S4"], "misattributed"),  # the date is in NVD, not S4
    ("Linked to CWE‑502.", ["S1"], "grounded"),
])
def test_typographic_dashes_and_spaces(evidence, text, cited, status):
    assert evidence.check(text, cited).status == status


def test_guardrail_sees_ids_written_with_typographic_dashes(evidence):
    assert evidence.check("Also tracked as CVE‑2021‑45046.", ["S1"]).strict_invention
