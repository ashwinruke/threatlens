"""Checks that the specific facts in an AI statement really come from the evidence.

A "specific" is anything precise enough to check mechanically: a CVE, CWE or ATT&CK ID, an IP
address, a file hash, a version number, a score, a percentage, a count or a year. For each AI
statement, every specific is looked up in the sources that statement cites:

  grounded       every specific appears in a cited source
  misattributed  every specific appears somewhere in the evidence, but not all in the cited sources
                 (the fact is real, the citation points at the wrong source)
  invented       at least one specific appears nowhere in the evidence (the model made it up,
                 usually from its own memory, which the prompt forbids)
  no_specifics   nothing precise enough to check by rule (the evaluation's AI judge covers these)

The report writer uses this as a guardrail: statements with an invented ID, address, hash or
version are removed before anyone sees them. Numbers, percentages and years are only measured
by the evaluation, because a model may round them ("over 800 reports").
"""
import json
import re
from dataclasses import dataclass, field

# Kinds precise enough that a mismatch is certainly an invention, not rounding
STRICT_KINDS = {"cve", "cwe", "attack", "ip", "hash", "version"}

_PATTERNS = [
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)),
    ("cwe", re.compile(r"\bCWE-\d+\b", re.IGNORECASE)),
    ("attack", re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|G\d{4}|S\d{4}|C\d{4}|M\d{4})\b")),
    ("hash", re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")),
    ("ip", re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")),
    ("version", re.compile(r"\b\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*\b")),
    ("percent", re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)\s?%")),
    ("decimal", re.compile(r"(?<![\w.])\d+\.\d+(?![\w.]*\d)")),
    ("year", re.compile(r"\b(?:199\d|20[0-3]\d)\b")),
    ("integer", re.compile(r"(?<![\w.,/-])(\d{1,3}(?:,\d{3})+|\d{2,})(?![\w.,%]|/\d)")),
]
_APPROX = re.compile(r"(?:over|more than|nearly|about|around|approximately|almost|at least|roughly|~)\s*$", re.IGNORECASE)
_OUT_OF = re.compile(r"(?:out )?of\s*$", re.IGNORECASE)  # "14 of 94 engines": a total the model added up
_TIME_UNIT = re.compile(r"^\s*(?:hours?|days?|weeks?|months?|minutes?|seconds?|hrs?|business days?)\b", re.IGNORECASE)
_NUMBER = re.compile(r"\d+(?:\.\d+)?")  # unsigned: a date's "-12" is the number 12
# Models often write typographic dashes and spaces ("CVE‑2021‑44228" with non-breaking hyphens,
# "100 %" with a narrow space). Without this, an ID written that way isn't recognised as an ID.
_TYPOGRAPHY = str.maketrans({c: "-" for c in "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe63\uff0d"}
                            | {c: " " for c in "\u00a0\u2007\u2009\u200a\u202f\u205f\u3000"})


def normalize(text: str) -> str:
    return str(text).translate(_TYPOGRAPHY)


@dataclass
class Specific:
    kind: str
    text: str
    value: float | None = None
    decimals: int = 0
    approximate: bool = False


@dataclass
class ClaimCheck:
    status: str  # grounded | misattributed | invented | no_specifics
    specifics: list[str] = field(default_factory=list)
    invented: list[str] = field(default_factory=list)  # specifics found nowhere in the evidence
    misattributed: list[str] = field(default_factory=list)  # found in the evidence, not in a cited source

    @property
    def strict_invention(self) -> bool:
        """An invented ID, address, hash or version: certain enough to remove the statement."""
        return any(s.split(":", 1)[0] in STRICT_KINDS for s in self.invented)


def extract_specifics(text: str, *, numbers: bool = True) -> list[Specific]:
    """The checkable specifics in a piece of AI text. numbers=False keeps only IDs and the like."""
    text = normalize(text)
    found: list[Specific] = []
    taken: list[tuple[int, int]] = []  # spans already claimed by a more specific pattern

    def free(start: int, end: int) -> bool:
        return all(end <= a or start >= b for a, b in taken)

    for kind, pattern in _PATTERNS:
        if not numbers and kind not in STRICT_KINDS:
            continue
        for match in pattern.finditer(text):
            start, end = match.span()
            if not free(start, end):
                continue
            raw = match.group(1) if kind in ("percent", "integer") else match.group(0)
            spec = Specific(kind=kind, text=raw)
            if kind in ("percent", "decimal", "integer"):
                clean = raw.replace(",", "")
                spec.value = float(clean)
                spec.decimals = len(clean.split(".", 1)[1]) if "." in clean else 0
                spec.approximate = bool(_APPROX.search(text[max(0, start - 20):start]))
                if kind == "integer":
                    if (spec.value <= 10 or spec.value == 100 or _TIME_UNIT.match(text[end:])
                            or _OUT_OF.search(text[max(0, start - 8):start])):
                        taken.append((start, end))  # small counts, "out of 100" and durations: not checked
                        continue
            taken.append((start, end))
            found.append(spec)
    return found


def _numbers_in(text: str) -> list[float]:
    return [float(n) for n in _NUMBER.findall(text.replace(",", ""))]


class Evidence:
    """The evidence packet split by citation id, ready for lookups."""

    def __init__(self, packet: dict):
        self.by_id: dict[str, str] = {}
        verdict_part = {k: v for k, v in packet.items() if k not in ("sources",)}
        self.by_id["S0"] = normalize(json.dumps(verdict_part, ensure_ascii=False, default=str))
        for entry in packet.get("sources", []):
            self.by_id[entry["id"]] = normalize(json.dumps(entry, ensure_ascii=False, default=str))
        self.indicator = normalize((packet.get("indicator") or {}).get("value", ""))
        self.all_text = "\n".join(self.by_id.values())
        self._numbers = {cid: _numbers_in(text) for cid, text in self.by_id.items()}

    def _found(self, spec: Specific, ids: list[str]) -> bool:
        texts = [self.by_id[i] for i in ids if i in self.by_id]
        if spec.kind in ("percent", "decimal", "integer"):
            unit = 10 ** -spec.decimals
            for i in ids:
                for x in self._numbers.get(i, []):
                    candidates = [x, x * 100] if spec.kind == "percent" and 0 <= x <= 1 else [x]
                    for c in candidates:
                        if spec.approximate and c and abs(c - spec.value) <= 0.15 * abs(c):
                            return True
                        if abs(c - spec.value) < unit - 1e-9 or round(c, spec.decimals) == spec.value:
                            return True
            return False
        needle = spec.text.lower()
        return any(needle in t.lower() for t in texts)

    def check(self, text: str, cited: list[str] | None, *, numbers: bool = True) -> ClaimCheck:
        """Check one statement. cited=None means "anywhere in the evidence" (used for the summary)."""
        everything = list(self.by_id)
        cited_ids = everything if cited is None else [c.upper() for c in cited]
        # The investigated indicator itself (or part of it, like the IP inside a URL) is always grounded
        specifics = [s for s in extract_specifics(text, numbers=numbers)
                     if not (s.kind in STRICT_KINDS and s.text.lower() in self.indicator.lower())]
        labels = [f"{s.kind}:{s.text}" for s in specifics]
        if not specifics:
            return ClaimCheck(status="no_specifics")
        invented, misattributed = [], []
        for spec, label in zip(specifics, labels):
            if self._found(spec, cited_ids):
                continue
            if self._found(spec, everything):
                misattributed.append(label)
            else:
                invented.append(label)
        status = "invented" if invented else "misattributed" if misattributed else "grounded"
        return ClaimCheck(status=status, specifics=labels, invented=invented, misattributed=misattributed)


_SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")


def remove_invented_sentences(text: str, evidence: Evidence) -> tuple[str, int]:
    """Drop summary sentences that contain an invented ID, address, hash or version."""
    kept, removed = [], 0
    for sentence in _SENTENCE.split(text):  # the check itself normalizes; the shown text keeps its typography
        if evidence.check(sentence, None, numbers=False).strict_invention:
            removed += 1
        else:
            kept.append(sentence)
    return " ".join(kept).strip(), removed
