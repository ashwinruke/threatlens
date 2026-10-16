"""The investigation graph: two pictures of one saved investigation.

1. The decision map answers "why?". It runs left to right:
       sources  →  evidence (scoring signals, research steps)  →  verdict  →  AI statements
   Every arrow is a real link that ThreatLens recorded: a signal names its source, the score
   is the sum of the signals, and every AI statement cites source ids (S0, S1, ...).
   Click any statement and the chain behind it lights up.

2. The connections graph answers "what is this connected to?". The investigated item sits in
   the middle, surrounded by the CVEs, weaknesses, malware, groups, techniques, products and
   related indicators that the sources and the research agent reported.

Both are built from the saved investigation by plain rules, never by AI, so they're
predictable and testable. Nothing is stored: old investigations get a graph too.

Names from outside feeds ("AgentTesla", "APT29") are matched to ATT&CK entries only on
exact names and aliases, the same rule the research agent uses. A similar spelling is
not the same threat, so it's left as a plain name rather than linked to the wrong entry.
"""
import re

from pydantic import BaseModel, Field

from app.ai.prompt import build_evidence
from app.knowledge.repository import KnowledgeRepository
from app.knowledge.search import search
from app.models import Citation, Investigation, IndicatorType, SourceStatus
from app.scoring import COMBINED_SIGNALS, THREAT_SIGNALS

EXACT_SCORE = 190  # exact ID, name or alias tiers in knowledge search
MAX_RESOLVE = 20  # names looked up in the knowledge base per graph
MAX_PER_SOURCE_LIST = 6  # e.g. at most 6 malware families from one source
MAX_PRODUCTS = 4  # NVD can list dozens of product models; the rest are in the NVD source
MAX_PER_PROFILE_GROUP = 6
MAX_CONNECTION_NODES = 45
LABEL_CHARS = 140

ATTACK_ID_RE = re.compile(r"^((?:T\d{4}(?:\.\d{3})?|TA\d{4}|[GSCM]\d{4}))\b\s*(.*)$")
CWE_RE = re.compile(r"^(CWE-\d+)\b\s*(.*)$", re.IGNORECASE)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# "Magic Hound (G0059) → Log4j (S1234): sentence" -> the first name and ID
MENTION_RE = re.compile(r"^(.+?) \(((?:T\d{4}(?:\.\d{3})?|TA\d{4}|[GSCM]\d{4}))\)")
# "G0059 Magic Hound (group, matched by alias: ...)"
MATCH_RE = re.compile(r"^(\S+) (.+?) \((\w+)(?:,.*)?\)$")
NOT_NAMES = {"", "generic", "unknown", "malware", "trojan", "other", "none", "n/a", "unnamed malware"}
ATTACK_PREFIX_KIND = {"G": "group", "S": "malware", "C": "campaign", "T": "technique", "M": "mitigation"}


class GraphNode(BaseModel):
    id: str
    kind: str  # see the comments in decision_map() and connections()
    label: str
    detail: str | None = None  # a longer explanation, shown when the node is selected
    link: str | None = None
    column: str | None = None  # decision map only: sources, evidence, verdict, explanation
    status: str | None = None  # source status, statement type, or "failed" for a research step
    points: int | None = None  # a signal's points
    level: str | None = None  # verdict level, or a related indicator's level
    cite: str | None = None  # the citation id the AI report uses for this node (S0, S1, ...)
    seen_in: list[str] = Field(default_factory=list)  # connections: which sources or research steps reported it
    depth: int = 1  # connections: 0 the investigated item, 1 directly connected, 2 found through research


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: str  # reported, scores, profile, cites, connects
    label: str = ""


class Graph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)  # plain-language caveats shown under the graph


class InvestigationGraph(BaseModel):
    investigation_id: str | None
    decision: Graph
    connections: Graph


def _short(text: str, limit: int = LABEL_CHARS) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rsplit(" ", 1)[0] + "…"


# ---------------------------------------------------------------- 1. the decision map

STATUS_TEXT = {
    SourceStatus.OK: "Found data",
    SourceStatus.NOT_FOUND: "No record",
    SourceStatus.ERROR: "Couldn't be checked (error)",
    SourceStatus.TIMEOUT: "Couldn't be checked (no answer in time)",
    SourceStatus.RATE_LIMITED: "Couldn't be checked (usage limit)",
    SourceStatus.SKIPPED: "Not checked",
}
STATEMENT_KINDS = (("findings", "finding"), ("affected", "affected"), ("actions", "action"))


def _citations(investigation: Investigation) -> list[Citation]:
    """The citation ids the AI report used. A saved report's own list wins, so ids match its statements."""
    if investigation.report and investigation.report.citations:
        return investigation.report.citations
    return build_evidence(investigation)[1]


def decision_map(investigation: Investigation) -> Graph:
    graph = Graph()
    nodes: dict[str, GraphNode] = {}
    verdict = investigation.verdict
    profile = verdict.level == "PROFILE"

    def add(node: GraphNode) -> GraphNode:
        nodes.setdefault(node.id, node)
        return nodes[node.id]

    def edge(source: str, target: str, kind: str, label: str = "") -> None:
        if source in nodes and target in nodes and source != target:
            graph.edges.append(GraphEdge(source=source, target=target, kind=kind, label=label))

    citations = _citations(investigation)
    cite_by_source = {c.source: c.id for c in citations}

    # Column 1: every source that was asked, including the ones that couldn't answer (that's evidence too)
    for result in investigation.sources:
        add(GraphNode(id=f"src:{result.source}", kind="source", column="sources", label=result.source,
                      status=result.status.value, link=result.link, cite=cite_by_source.get(result.source),
                      detail=result.message or STATUS_TEXT.get(result.status)))

    # Column 3: the verdict
    if profile:
        verdict_label = "Weakness profile" if investigation.indicator.subtype == "weakness" else "Threat profile"
    elif verdict.level == "UNKNOWN":
        verdict_label = "Unknown: not enough evidence"
    else:
        verdict_label = f"{verdict.level}, {verdict.score}/100"
    add(GraphNode(id="verdict", kind="verdict", column="verdict", label=verdict_label, level=verdict.level,
                  cite="S0", detail=" ".join([verdict.headline, *verdict.rules_applied])))

    # Column 2: scoring signals, each linked to the source it came from and to the verdict
    for signal in investigation.signals:
        node = add(GraphNode(id=f"sig:{signal.id}", kind="signal", column="evidence", label=signal.label,
                             points=signal.points, detail=signal.evidence))
        if signal.source == "ThreatLens":
            if signal.id in COMBINED_SIGNALS:
                # Agreement and freshness are worked out from the other sources' signals
                for other in investigation.signals:
                    if other.id in THREAT_SIGNALS:
                        edge(f"sig:{other.id}", node.id, "reported", "combined")
            else:
                add(GraphNode(id="src:ThreatLens", kind="source", column="sources", label="ThreatLens rules",
                              status="ok", detail="ThreatLens's own lists and rules, such as known legitimate services."))
                edge("src:ThreatLens", node.id, "reported")
        else:
            add(GraphNode(id=f"src:{signal.source}", kind="source", column="sources", label=signal.source,
                          status="ok", cite=cite_by_source.get(signal.source)))
            edge(f"src:{signal.source}", node.id, "reported")
        edge(node.id, "verdict", "scores", f"{signal.points:+d}")

    if profile:
        for result in investigation.sources:
            if result.status == SourceStatus.OK:
                edge(f"src:{result.source}", "verdict", "profile", "profile from")

    # Column 2 too: research steps. They never point at the verdict, because research never changes the score.
    research = investigation.research
    for step in (research.steps if research else []):
        add(GraphNode(id=f"res:{step.id}", kind="research", column="evidence", label=f"{step.id}: {step.title}",
                      status="ok" if step.ok else "failed", link=step.link,
                      cite=cite_by_source.get(f"Research {step.id}: {step.title}"),
                      detail=f"Why: {step.why} Found: {step.summary}"))
    by_cite = {n.cite: n.id for n in nodes.values() if n.cite and n.kind in ("source", "research")}
    by_cite["S0"] = "verdict"

    # Column 4: what the AI wrote, each statement linked to the sources it cites
    report = investigation.report
    if report and report.status == "ready":
        for field, kind in STATEMENT_KINDS:
            for index, item in enumerate(getattr(report, field)):
                status = f"action-{item.priority}" if kind == "action" else kind
                node = add(GraphNode(id=f"stmt:{kind}:{index}", kind="statement", column="explanation",
                                     label=_short(item.text), detail=item.text, status=status))
                for cid in item.sources:
                    if cid in by_cite:
                        edge(by_cite[cid], node.id, "cites", cid)
    else:
        graph.notes.append("There's no AI summary for this investigation, so the map ends at the verdict.")

    if research and research.steps:
        graph.notes.append("Research steps never point at the verdict: research adds context but never changes the score.")
    if not profile and investigation.signals:
        total = sum(s.points for s in investigation.signals)
        if total > 100 and verdict.score == 100:
            graph.notes.append(f"The signals add up to {total}; scores stop at 100.")
        elif total < 0 and verdict.score == 0:
            graph.notes.append(f"The signals add up to {total}; scores never go below 0.")
        elif total != verdict.score:
            graph.notes.append(f"The signals add up to {total}; the score is {verdict.score} because of a rule: "
                               + " ".join(verdict.rules_applied))
    graph.nodes = list(nodes.values())
    return graph


# ---------------------------------------------------------------- 2. the connections graph

class _Connections:
    """Collects connected things, merging repeats: the same malware reported by two sources is one node."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple[str, str], GraphEdge] = {}
        self.names: list[tuple[str, str, str]] = []  # (node key, name, kind) to match to the knowledge base
        self.notes: list[str] = []

    def node(self, key: str, kind: str, label: str, seen_in: str, depth: int = 1, **extra) -> GraphNode:
        if key not in self.nodes:
            self.nodes[key] = GraphNode(id=key, kind=kind, label=_short(label, 90), depth=depth, **extra)
        node = self.nodes[key]
        node.depth = min(node.depth, depth)
        if seen_in and seen_in not in node.seen_in:
            node.seen_in.append(seen_in)
        for name, value in extra.items():
            if value and not getattr(node, name):
                setattr(node, name, value)
        return node

    def edge(self, source: str, target: str, label: str) -> None:
        if source != target and (source, target) not in self.edges and (target, source) not in self.edges:
            self.edges[(source, target)] = GraphEdge(source=source, target=target, kind="connects", label=label)

    def named(self, name, kind: str, seen_in: str, label: str, parent: str = "subject", depth: int = 1) -> None:
        """A plain name from a feed, such as a malware family. Matched to ATT&CK later, if it exactly matches."""
        text = " ".join(str(name or "").split())
        if text.lower() in NOT_NAMES or len(text) > 80:
            return
        key = f"{kind}:{text.lower()}"
        self.node(key, kind, text, seen_in, depth)
        self.edge(parent, key, label)
        self.names.append((key, text, kind))

    def entry(self, external_id: str, name: str, kind: str, seen_in: str, label: str, parent: str = "subject",
              depth: int = 1, link: str | None = None) -> str:
        """An entry with a known ID: an ATT&CK ID, CWE or CVE."""
        key = f"id:{external_id.upper()}"
        self.node(key, kind, _label(name, external_id, kind), seen_in, depth, link=link)
        self.edge(parent, key, label)
        return key


def _label(name: str, external_id: str, kind: str) -> str:
    """'Volt Typhoon (G1017)'. MITRE names some campaigns only by ID, so those read 'Campaign C0017', not 'C0017 (C0017)'."""
    name = " ".join(str(name or "").split())
    if not name:
        return external_id
    if name.upper() == external_id.upper():
        return f"{kind.capitalize()} {external_id}" if kind in ("campaign", "group", "malware", "tool") else external_id
    return f"{name} ({external_id})"


def _entry_from_text(text: str) -> tuple[str | None, str]:
    """'G0059 Magic Hound' -> ('G0059', 'Magic Hound'); 'CWE-502 Deserialization…' -> ('CWE-502', ...)."""
    text = " ".join(str(text or "").split())
    for pattern in (ATTACK_ID_RE, CWE_RE):
        match = pattern.match(text)
        if match:
            return match.group(1).upper(), match.group(2)
    return None, text


def _kind_for(external_id: str, fallback: str) -> str:
    if external_id.startswith("CWE-"):
        return "weakness"
    if external_id.startswith("CVE-"):
        return "cve"
    if external_id.startswith("TA"):
        return "tactic"
    return ATTACK_PREFIX_KIND.get(external_id[0], fallback)


def _from_sources(investigation: Investigation, c: _Connections) -> None:
    for result in investigation.sources:
        if result.status != SourceStatus.OK:
            continue
        facts, where = result.facts, result.source
        if where == "NVD":
            for weakness in facts.get("weaknesses") or []:
                external_id, name = _entry_from_text(weakness)
                if external_id:
                    c.entry(external_id, name, "weakness", where, "has the weakness",
                            link=f"https://cwe.mitre.org/data/definitions/{external_id.split('-')[1]}.html")
            products = facts.get("affected_products") or []
            for product in products[:MAX_PRODUCTS]:
                c.node(f"product:{product.lower()}", "product", product, where)
                c.edge("subject", f"product:{product.lower()}", "affects")
            if len(products) > MAX_PRODUCTS:
                more = len(products) - MAX_PRODUCTS
                c.notes.append(f"NVD lists {more} more affected product{'s' if more != 1 else ''}, not drawn here "
                               "to keep the picture readable. They're in the NVD source on this page.")
        elif where == "CISA KEV" and facts.get("product"):
            product = f"{facts.get('vendor') or ''} {facts['product']}".strip()
            c.node(f"product:{product.lower()}", "product", product, where)
            c.edge("subject", f"product:{product.lower()}", "exploited in")
        elif where == "AlienVault OTX":
            for family in (facts.get("malware_families") or [])[:MAX_PER_SOURCE_LIST]:
                c.named(family, "malware", where, "reported with")
            for adversary in (facts.get("adversaries") or [])[:MAX_PER_SOURCE_LIST]:
                c.named(adversary, "group", where, "reported with")
            for technique in (facts.get("attack_techniques") or [])[:MAX_PER_SOURCE_LIST]:
                match = TECHNIQUE_RE.search(str(technique))
                if match:
                    c.entry(match.group(0), "", "technique", where, "reported with")
        elif where == "ThreatFox":
            for family in (facts.get("malware_families") or [])[:MAX_PER_SOURCE_LIST]:
                c.named(family, "malware", where, "linked to")
        elif where == "MalwareBazaar":
            c.named(facts.get("malware_family"), "malware", where, "a sample of")
        elif where == "VirusTotal":
            for family in (facts.get("family_names") or [])[:MAX_PER_SOURCE_LIST]:
                c.named(family, "malware", where, "detected as")


def _from_profile(investigation: Investigation, c: _Connections) -> None:
    profile = investigation.threat.profile
    for group in profile.related:
        if group.label == "Techniques used":
            continue  # often 50+; the profile page lists them by tactic
        for item in group.items[:MAX_PER_PROFILE_GROUP]:
            if item.external_id:
                c.entry(item.external_id, item.name, item.kind, "MITRE knowledge base", group.label.lower(), link=item.url)
            else:
                c.node(f"{item.kind}:{item.name.lower()}", item.kind, item.name, "MITRE knowledge base", link=item.url)
                c.edge("subject", f"{item.kind}:{item.name.lower()}", group.label.lower())
    if profile.techniques:
        count = len(profile.techniques)
        c.notes.append(f"Its {count} technique{'s' if count != 1 else ''} {'aren' if count != 1 else 'isn'}'t drawn here; "
                       "see the techniques by tactic on this page.")


def _from_research(investigation: Investigation, c: _Connections) -> None:
    research = investigation.research
    subject_value = investigation.indicator.value.lower()
    for step in (research.steps if research else []):
        if not step.ok:
            continue
        data, seen = step.data, f"Research {step.id}"
        if step.tool == "search_attack":
            match = MATCH_RE.match(str((data.get("matches") or [""])[0]))
            if match:
                external_id, name, kind = match.groups()
                c.entry(external_id, name, kind, seen, "found by research", link=step.link)
        elif step.tool == "attack_profile" and data.get("id"):
            parent = c.entry(data["id"], data.get("name", ""), data.get("kind", "entry"), seen,
                             "found by research", link=step.link)
            for key, values in data.items():
                if not isinstance(values, list) or key in ("aliases", "top_tactics", "top_defenses"):
                    continue
                for value in values[:5]:
                    external_id, name = _entry_from_text(value)
                    if external_id:
                        c.entry(external_id, name, _kind_for(external_id, "entry"), seen,
                                key.replace("_", " "), parent=parent, depth=2)
        elif step.tool == "attack_mentions":
            term = str(data.get("term", ""))
            if term.lower() == subject_value:
                parent = "subject"
            elif CVE_RE.match(term):
                parent = c.entry(term, "", "cve", seen, "found by research")
            else:
                parent = f"term:{term.lower()}"
                c.node(parent, "term", term, seen)
                c.edge("subject", parent, "found by research")
            for mention in (data.get("mentions") or [])[:MAX_PER_SOURCE_LIST]:
                match = MENTION_RE.match(str(mention))
                if match:
                    name, external_id = match.groups()
                    c.entry(external_id, name, _kind_for(external_id, "entry"), seen,
                            "its ATT&CK record mentions it", parent=parent, depth=1 if parent == "subject" else 2)
        elif step.tool == "investigate_indicator" and data.get("indicator"):
            key = f"ind:{str(data['indicator']).lower()}"
            c.node(key, data.get("type", "indicator"), str(data["indicator"]), seen, level=data.get("level"),
                   detail=data.get("headline"))
            c.edge("subject", key, "related indicator")


async def _resolve(c: _Connections, store) -> None:
    """Match plain names (and bare IDs) to knowledge base entries, merging nodes that are the same thing."""
    if not hasattr(store, "connection"):
        return
    repository = KnowledgeRepository(store)
    # Bare IDs get their names and links, e.g. T1059 -> "Command and Scripting Interpreter (T1059)"
    ids = [key[3:] for key in c.nodes if key.startswith("id:") and not key[3:].startswith("CVE-")]
    try:
        known = await repository.summaries(ids)
    except Exception:
        known = {}
    for key in list(c.nodes):
        summary = known.get(key[3:]) if key.startswith("id:") else None
        if summary:
            node = c.nodes[key]
            node.label = _short(_label(summary.name, summary.external_id, summary.kind), 90)
            node.kind = summary.kind
            node.link = node.link or summary.url

    # Names: exact name or alias only, so "Mirai" never becomes MirageFox
    for key, name, kind in c.names[:MAX_RESOLVE]:
        if key not in c.nodes:
            continue
        kinds = ["malware", "tool"] if kind == "malware" else [kind]
        try:
            results = await search(store, name, kinds=kinds, limit=1)
        except Exception:
            continue
        if not results or results[0].score < EXACT_SCORE or not results[0].external_id:
            continue
        top = results[0]
        target = f"id:{top.external_id.upper()}"
        old = c.nodes.pop(key)
        merged = c.node(target, top.kind, _label(top.name, top.external_id, top.kind), "", old.depth, link=top.url)
        for where in old.seen_in:
            if where not in merged.seen_in:
                merged.seen_in.append(where)
        if top.name.lower() != name.lower():
            merged.detail = merged.detail or f"Reported as \"{name}\", an alias of {top.name}."
        # Point the old node's edges at the merged one
        for (source, dest), edge in list(c.edges.items()):
            if key in (source, dest):
                del c.edges[(source, dest)]
                c.edge(target if source == key else source, target if dest == key else dest, edge.label)


async def connections(investigation: Investigation, store) -> Graph:
    c = _Connections()
    indicator = investigation.indicator
    profile = investigation.threat.profile if investigation.threat and investigation.threat.profile else None
    if profile:
        entity = profile.entity
        c.node("subject", entity.kind, f"{entity.name} ({entity.external_id})", "", depth=0, link=entity.url,
               level=investigation.verdict.level)
    else:
        c.node("subject", indicator.type.value, indicator.value, "", depth=0, level=investigation.verdict.level,
               detail=investigation.verdict.headline)

    if profile:
        _from_profile(investigation, c)
    elif indicator.type != IndicatorType.THREAT:
        _from_sources(investigation, c)
    _from_research(investigation, c)
    # The subject itself can show up again (research about a profile's own ID): fold it in
    if profile and profile.entity.external_id:
        own = f"id:{profile.entity.external_id.upper()}"
        if own in c.nodes:
            del c.nodes[own]
            for (source, dest), edge in list(c.edges.items()):
                if own in (source, dest):
                    del c.edges[(source, dest)]
                    other = dest if source == own else source
                    c.edge("subject", other, edge.label)
    await _resolve(c, store)

    nodes = sorted(c.nodes.values(), key=lambda n: (n.depth, n.kind, n.label.lower()))
    if len(nodes) > MAX_CONNECTION_NODES:
        c.notes.append(f"Showing {MAX_CONNECTION_NODES} of {len(nodes)} connections, the closest ones first.")
        nodes = nodes[:MAX_CONNECTION_NODES]
    kept = {n.id for n in nodes}
    edges = [e for e in c.edges.values() if e.source in kept and e.target in kept]
    if len(nodes) == 1:
        c.notes.append("The sources didn't report anything this is connected to.")
    return Graph(nodes=nodes, edges=edges, notes=c.notes)


async def build_graph(investigation: Investigation, store) -> InvestigationGraph:
    return InvestigationGraph(investigation_id=investigation.id, decision=decision_map(investigation),
                              connections=await connections(investigation, store))
