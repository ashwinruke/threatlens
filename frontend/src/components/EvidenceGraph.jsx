import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";

// Two pictures of one investigation, built by the backend from what was recorded (never by AI):
// "Why this verdict" traces every conclusion back to its evidence and sources,
// "Connections" shows what the investigated item is linked to.

const COLUMNS = [
  ["sources", "Sources"],
  ["evidence", "Evidence"],
  ["verdict", "Verdict"],
  ["explanation", "AI summary"],
];

const STATEMENT_TAGS = {
  finding: "Finding",
  affected: "Affected",
  "action-now": "Act now",
  "action-soon": "Act soon",
  "action-later": "Later",
};

const SOURCE_STATUS = { ok: "Found data", not_found: "No record" };

export const KIND_NAMES = {
  cve: "CVE",
  weakness: "Weakness (CWE)",
  product: "Product",
  malware: "Malware",
  tool: "Tool",
  group: "Threat group",
  campaign: "Campaign",
  technique: "Technique",
  tactic: "Tactic",
  mitigation: "Defense",
  term: "Search term",
  ip: "IP address",
  domain: "Domain",
  hash: "File hash",
  entry: "ATT&CK entry",
};

// Three color families, so colors stay tell-apart for everyone; the exact kind is always written out too
const FAMILIES = [
  ["threat", "Who attacks, and with what", ["group", "malware", "tool", "campaign"]],
  ["target", "What gets attacked", ["cve", "weakness", "product"]],
  ["method", "Methods and other indicators", []],
];
function family(kind) {
  return FAMILIES.find(([, , kinds]) => kinds.includes(kind))?.[0] || "method";
}

// Everything a node depends on (upstream) or feeds into (downstream), following the arrows
function reach(edges, start, upstream) {
  const found = new Set();
  const todo = [start];
  while (todo.length) {
    const current = todo.pop();
    for (const e of edges) {
      const [from, to] = upstream ? [e.target, e.source] : [e.source, e.target];
      if (from === current && !found.has(to)) {
        found.add(to);
        todo.push(to);
      }
    }
  }
  return found;
}

function useWidth(ref) {
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    if (!ref.current) return undefined;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, [ref]);
  return width;
}

function External({ href, children }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}

// ---------------------------------------------------------------- why this verdict

function MapNode({ node, state, onSelect, setRef }) {
  let tag = null;
  if (node.kind === "source") tag = node.cite || null;
  if (node.kind === "signal") tag = `${node.points > 0 ? "+" : ""}${node.points}`;
  if (node.kind === "research") tag = node.status === "failed" ? "Found nothing" : "Research";
  if (node.kind === "statement") tag = STATEMENT_TAGS[node.status] || node.status;
  const sub = node.kind === "source" ? SOURCE_STATUS[node.status] || "Couldn't be checked" : null;

  return (
    <button
      type="button"
      ref={setRef}
      className={`mapnode mapnode--${node.kind} mapnode--${node.status || "plain"} ${state}`}
      aria-pressed={state === "is-selected"}
      onClick={() => onSelect(node.id)}
    >
      {tag && <span className="mapnode__tag">{tag}</span>}
      <span className="mapnode__label">{node.label}</span>
      {sub && <span className="mapnode__sub">{sub}</span>}
    </button>
  );
}

function DecisionMap({ graph, level }) {
  const [selected, setSelected] = useState(null);
  const boxRef = useRef(null);
  const nodeRefs = useRef(new Map());
  const width = useWidth(boxRef);
  const [paths, setPaths] = useState([]);
  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);

  const up = useMemo(() => (selected ? reach(graph.edges, selected, true) : new Set()), [graph, selected]);
  const down = useMemo(() => (selected ? reach(graph.edges, selected, false) : new Set()), [graph, selected]);

  // Draw the arrows between the boxes, wherever the layout put them
  useLayoutEffect(() => {
    const box = boxRef.current?.getBoundingClientRect();
    if (!box) return;
    const drawn = [];
    for (const e of graph.edges) {
      const a = nodeRefs.current.get(e.source)?.getBoundingClientRect();
      const b = nodeRefs.current.get(e.target)?.getBoundingClientRect();
      if (!a || !b) continue;
      const y1 = a.top + a.height / 2 - box.top;
      const y2 = b.top + b.height / 2 - box.top;
      const sameColumn = byId.get(e.source)?.column === byId.get(e.target)?.column;
      let d;
      if (!sameColumn && b.left >= a.right - 1) {
        const x1 = a.right - box.left;
        const x2 = b.left - box.left;
        const mid = (x1 + x2) / 2;
        d = `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
      } else if (sameColumn) {
        // Within one column, e.g. signals combined into "sources agree": a loop on the right
        const x = a.right - box.left;
        d = `M${x},${y1} C${x + 22},${y1} ${x + 22},${y2} ${x},${y2}`;
      } else {
        continue; // columns stacked on a narrow screen: the highlighting shows the links instead
      }
      drawn.push({ key: `${e.source}>${e.target}`, d, source: e.source, target: e.target, loop: sameColumn });
    }
    setPaths(drawn);
  }, [graph, byId, width, selected]);

  const inUp = (id) => id === selected || up.has(id);
  const inDown = (id) => id === selected || down.has(id);
  const stateOf = (id) => {
    if (!selected) return "";
    if (id === selected) return "is-selected";
    return up.has(id) || down.has(id) ? "is-linked" : "is-dim";
  };

  const chosen = selected ? byId.get(selected) : null;
  const supports = chosen ? COLUMNS.flatMap(([col]) => graph.nodes.filter((n) => up.has(n.id) && n.column === col)) : [];
  const feeds = chosen ? graph.nodes.filter((n) => down.has(n.id)) : [];

  return (
    <div className={`lvl-${level}`}>
      <p className="muted graph__hint">
        Click any box to trace it: what supports it lights up to the left, what it supports to the right.
      </p>
      <div className="decision" ref={boxRef}>
        <svg className="decision__wires" aria-hidden="true">
          {paths.map((p) => {
            const on = selected && ((inUp(p.source) && inUp(p.target)) || (inDown(p.source) && inDown(p.target)));
            if (p.loop && !on) return null; // loops inside a column only appear when they're part of the selection
            return <path key={p.key} d={p.d} className={on ? "wire is-on" : selected ? "wire is-off" : "wire"} />;
          })}
        </svg>
        {COLUMNS.map(([column, title]) => {
          const items = graph.nodes.filter((n) => n.column === column);
          return (
            <div key={column} className={`decision__col decision__col--${column}`}>
              <h3>{title}</h3>
              {items.length === 0 && <p className="muted decision__empty">None</p>}
              {items.map((node) => (
                <MapNode key={node.id} node={node} state={stateOf(node.id)}
                  onSelect={(id) => setSelected(id === selected ? null : id)}
                  setRef={(el) => (el ? nodeRefs.current.set(node.id, el) : nodeRefs.current.delete(node.id))} />
              ))}
            </div>
          );
        })}
      </div>

      <div className="graph__detail" aria-live="polite">
        {chosen ? (
          <>
            <p className="graph__detail-title">{chosen.label}</p>
            {chosen.detail && chosen.detail !== chosen.label && <p>{chosen.detail}</p>}
            {chosen.link && <p><External href={chosen.link}>Open the source</External></p>}
            {supports.length > 0 ? (
              <>
                <h4>What supports this</h4>
                <ul className="chain">
                  {supports.map((n, i) => (
                    <li key={n.id}>
                      <span className="chain__col">
                        {i === 0 || supports[i - 1].column !== n.column ? COLUMNS.find(([c]) => c === n.column)?.[1] : ""}
                      </span>
                      <span>
                        {n.label}
                        {n.kind === "signal" && <span className="muted"> ({n.points > 0 ? "+" : ""}{n.points} points)</span>}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              chosen.column === "sources" && <p className="muted">A source is where the evidence starts.</p>
            )}
            {feeds.length > 0 && (
              <p className="muted">It supports {feeds.length} thing{feeds.length === 1 ? "" : "s"} to its right.</p>
            )}
            {chosen.kind === "research" && (
              <p className="muted">Research adds context for the AI summary but never changes the score.</p>
            )}
          </>
        ) : (
          <p className="muted">Nothing selected yet.</p>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- connections

// ---- Layout, in "world" units around (0, 0). Zooming scales the distances, never the text,
// so zooming in spreads the dots apart and gives their names room.
const RING_GAP = 34; // world units between neighbouring dots on a ring, at least
const MIN_ZOOM = 1;
const MAX_ZOOM = 4;
const MAX_HEIGHT = 720;

function circularMean(angles) {
  const x = angles.reduce((sum, a) => sum + Math.cos(a), 0);
  const y = angles.reduce((sum, a) => sum + Math.sin(a), 0);
  return Math.atan2(y, x);
}

function layout(graph) {
  const first = graph.nodes.filter((n) => n.depth === 1);
  const second = graph.nodes.filter((n) => n.depth === 2);
  const firstIds = new Set(first.map((n) => n.id));
  const familyOrder = FAMILIES.map(([f]) => f);
  first.sort((a, b) => familyOrder.indexOf(family(a.kind)) - familyOrder.indexOf(family(b.kind))
    || a.kind.localeCompare(b.kind) || a.label.localeCompare(b.label));

  // Rings big enough that neighbouring dots are at least RING_GAP apart
  const r1 = Math.max(150, (first.length * RING_GAP) / (Math.PI * 2));
  const r2 = Math.max(r1 + 130, (second.length * RING_GAP) / (Math.PI * 2));

  const pos = new Map([["subject", { x: 0, y: 0, angle: -Math.PI / 2 }]]);
  first.forEach((n, i) => {
    const angle = (i / first.length) * Math.PI * 2 - Math.PI / 2;
    pos.set(n.id, { x: r1 * Math.cos(angle), y: r1 * Math.sin(angle), angle });
  });

  // Outer ring: each dot wants to sit just outside the dot(s) it's linked to, but dots are
  // then spread out so none are closer than an even share of the ring allows.
  const wanted = second.map((n) => {
    const parents = graph.edges
      .filter((e) => (e.source === n.id && firstIds.has(e.target)) || (e.target === n.id && firstIds.has(e.source)))
      .map((e) => pos.get(e.source === n.id ? e.target : e.source).angle);
    return { n, angle: parents.length ? circularMean(parents) : -Math.PI / 2 };
  }).sort((a, b) => a.angle - b.angle || a.n.label.localeCompare(b.n.label));
  if (wanted.length) {
    const gap = Math.min((Math.PI * 2) / wanted.length, RING_GAP / r2 * 1.6);
    const placed = [wanted[0].angle];
    for (let i = 1; i < wanted.length; i += 1) placed.push(Math.max(wanted[i].angle, placed[i - 1] + gap));
    // Shift the whole run back so, on average, dots sit where they wanted to be
    const drift = placed.reduce((sum, a, i) => sum + (a - wanted[i].angle), 0) / placed.length;
    wanted.forEach(({ n }, i) => {
      const angle = placed[i] - drift;
      pos.set(n.id, { x: r2 * Math.cos(angle), y: r2 * Math.sin(angle), angle });
    });
  }
  const xs = [...pos.values()].map((p) => p.x);
  const ys = [...pos.values()].map((p) => p.y);
  return { pos, halfWidth: Math.max(1, ...xs.map(Math.abs)), top: Math.min(...ys), bottom: Math.max(...ys) };
}

function short(text, limit = 30) {
  return text.length <= limit ? text : `${text.slice(0, limit - 1)}…`;
}

const LABEL_FONT = 12.5;
const CHAR_WIDTH = 6.9; // average width of one character at LABEL_FONT, close enough to avoid overlaps

// Where each label goes, and which ones fit. Labels that would overlap another are hidden;
// they show again when you zoom in, hover a dot, or select it.
function placeLabels(graph, screen, selected, zoom, areaWidth, areaHeight) {
  const priority = (n) => (n.id === selected ? 0 : n.id === "subject" ? 1 : n.depth === 1 ? 2 : 3);
  const boxes = [{ left: areaWidth - 150, right: areaWidth, top: 0, bottom: 42 }]; // the zoom buttons
  const labels = new Map();
  let hidden = 0;
  for (const n of [...graph.nodes].sort((a, b) => priority(a) - priority(b))) {
    const p = screen.get(n.id);
    if (!p) continue;
    const isCenter = n.id === "subject";
    // Zoomed in, there is room for longer names before they need shortening
    const text = short(n.label, isCenter ? 40 : Math.min(60, Math.round(30 + 15 * (zoom - 1))));
    const width = text.length * CHAR_WIDTH;
    const cos = Math.cos(p.angle);
    const anchor = isCenter ? "middle" : cos > 0.35 ? "start" : cos < -0.35 ? "end" : "middle";
    const x = p.x + (anchor === "start" ? 13 : anchor === "end" ? -13 : 0);
    const y = p.y + (isCenter ? 34 : anchor === "middle" ? (Math.sin(p.angle) < 0 ? -14 : 22) : 4);
    const left = anchor === "start" ? x : anchor === "end" ? x - width : x - width / 2;
    const box = { left: left - 3, right: left + width + 3, top: y - LABEL_FONT, bottom: y + 4 };
    const outside = box.left < 0 || box.right > areaWidth || box.top < 0 || box.bottom > areaHeight;
    const clash = boxes.some((b) => box.left < b.right && box.right > b.left && box.top < b.bottom && box.bottom > b.top);
    if ((clash || outside) && priority(n) > 0) {
      hidden += 1;
      continue;
    }
    boxes.push(box);
    labels.set(n.id, { text, x, y, anchor });
  }
  return { labels, hidden };
}

function Connections({ graph }) {
  const boxRef = useRef(null);
  const svgRef = useRef(null);
  const width = useWidth(boxRef);
  const [selected, setSelected] = useState(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 }); // zoom level and how far it's been dragged
  const drag = useRef(null);
  const { pos, halfWidth, top, bottom } = useMemo(() => layout(graph), [graph]);
  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);

  // At zoom 1 the whole picture fits: as wide as the box allows, as tall as the dots need
  const narrow = width < 640;
  const room = narrow ? 16 : 190; // space beside the outermost dots for names
  const padding = narrow ? 70 : 90; // above and below, for names
  const span = Math.max(bottom - top, 1);
  const fit = Math.max(0.2, Math.min(1, (width / 2 - room) / halfWidth, (MAX_HEIGHT - padding) / span));
  const height = Math.round(span * fit + padding);
  const cx = width / 2;
  const cy = padding / 2 - top * fit;
  const scale = fit * view.k;
  const screen = useMemo(() => {
    const out = new Map();
    for (const [id, p] of pos) out.set(id, { x: cx + view.x + p.x * scale, y: cy + view.y + p.y * scale, angle: p.angle });
    return out;
  }, [pos, cx, cy, view, scale]);
  const { labels, hidden } = useMemo(() => placeLabels(graph, screen, selected, view.k, width, height), [graph, screen, selected, view.k, width, height]);

  const touching = selected ? graph.edges.filter((e) => e.source === selected || e.target === selected) : [];
  const neighbours = new Set(touching.flatMap((e) => [e.source, e.target]));
  const chosen = selected ? byId.get(selected) : null;
  const pick = (id) => setSelected(id === selected ? null : id);

  // Zoom around a point on screen, so whatever is under the pointer stays put
  function zoomTo(k, px = cx, py = cy) {
    setView((v) => {
      const next = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, k));
      if (next === MIN_ZOOM) return { k: MIN_ZOOM, x: 0, y: 0 };
      const ratio = next / v.k;
      return { k: next, x: px - cx - (px - cx - v.x) * ratio, y: py - cy - (py - cy - v.y) * ratio };
    });
  }

  // Ctrl/⌘ + scroll zooms. Plain scrolling still scrolls the page, so the graph never traps it.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return undefined;
    function onWheel(event) {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      const rect = svg.getBoundingClientRect();
      const factor = Math.exp(-event.deltaY * 0.0025);
      setView((v) => {
        const next = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, v.k * factor));
        if (next === MIN_ZOOM) return { k: MIN_ZOOM, x: 0, y: 0 };
        const px = event.clientX - rect.left;
        const py = event.clientY - rect.top;
        const ratio = next / v.k;
        return { k: next, x: px - cx - (px - cx - v.x) * ratio, y: py - cy - (py - cy - v.y) * ratio };
      });
    }
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, [cx, cy, width]);

  // Drag to move around once zoomed in
  function onPointerDown(event) {
    if (view.k === MIN_ZOOM) return;
    drag.current = { x: event.clientX, y: event.clientY, start: view, moved: false };
  }
  function onPointerMove(event) {
    const d = drag.current;
    if (!d) return;
    const dx = event.clientX - d.x;
    const dy = event.clientY - d.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) d.moved = true;
    if (d.moved) setView({ ...d.start, x: d.start.x + dx, y: d.start.y + dy });
  }
  function onPointerUp() {
    // Leave the flag for a moment so the click that ends a drag doesn't select a dot
    setTimeout(() => { drag.current = null; }, 0);
  }
  function onNodeClick(id) {
    if (drag.current?.moved) return;
    pick(id);
  }

  const groups = useMemo(() => {
    const byKind = new Map();
    for (const n of graph.nodes) {
      if (n.id === "subject") continue;
      byKind.set(n.kind, [...(byKind.get(n.kind) || []), n]);
    }
    return [...byKind.entries()];
  }, [graph]);
  const present = new Set(graph.nodes.filter((n) => n.id !== "subject").map((n) => family(n.kind)));
  const zoomed = view.k > MIN_ZOOM;

  return (
    <div>
      <p className="muted graph__hint">
        Everything the sources and the research agent linked to this, with the investigated item in the middle.
        Click a dot or a name below for details.
      </p>
      <div className="connections" ref={boxRef}>
        {width > 0 && graph.nodes.length > 1 && (
          <>
            <div className="zoom" role="group" aria-label="Zoom">
              <button type="button" className="zoom__button" onClick={() => zoomTo(view.k * 1.5)}
                disabled={view.k >= MAX_ZOOM} aria-label="Zoom in">+</button>
              <button type="button" className="zoom__button" onClick={() => zoomTo(view.k / 1.5)}
                disabled={!zoomed} aria-label="Zoom out">−</button>
              <button type="button" className="zoom__button zoom__button--text" onClick={() => setView({ k: 1, x: 0, y: 0 })}
                disabled={!zoomed}>Reset</button>
            </div>
            <svg ref={svgRef} width={width} height={height} role="img"
              className={`connections__svg ${zoomed ? "is-zoomed" : ""}`}
              aria-label={`Connections graph with ${graph.nodes.length - 1} connected items. The same items are listed below.`}
              onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerCancel={onPointerUp} onPointerLeave={onPointerUp}>
              {graph.edges.map((e) => {
                const a = screen.get(e.source);
                const b = screen.get(e.target);
                if (!a || !b) return null;
                const on = selected && (e.source === selected || e.target === selected);
                return (
                  <line key={`${e.source}>${e.target}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                    className={on ? "link is-on" : selected ? "link is-off" : "link"} />
                );
              })}
              {graph.nodes.map((n) => {
                const p = screen.get(n.id);
                if (!p) return null;
                const isCenter = n.id === "subject";
                const dim = selected && !neighbours.has(n.id) && n.id !== selected;
                return (
                  <g key={n.id} className={`gnode gnode--${isCenter ? "center" : family(n.kind)} ${dim ? "is-dim" : ""} ${n.id === selected ? "is-selected" : ""}`}
                    onClick={() => onNodeClick(n.id)}>
                    <title>{n.label}</title>
                    <circle cx={p.x} cy={p.y} r={isCenter ? 26 : 14} className="gnode__hit" />
                    <circle cx={p.x} cy={p.y} r={isCenter ? 14 : n.depth === 2 ? 6 : 8} className="gnode__dot" />
                  </g>
                );
              })}
              {/* Names go on top of every line and dot, so nothing is drawn over them */}
              {graph.nodes.map((n) => {
                const label = labels.get(n.id);
                if (!label) return null;
                const dim = selected && !neighbours.has(n.id) && n.id !== selected;
                return (
                  <text key={`name-${n.id}`} x={label.x} y={label.y} textAnchor={label.anchor}
                    className={`gnode__label ${n.id === "subject" ? "gnode__label--center" : ""} ${dim ? "is-dim" : ""}`}
                    onClick={() => onNodeClick(n.id)}>
                    {label.text}
                  </text>
                );
              })}
              {touching.map((e) => {
                const a = screen.get(e.source);
                const b = screen.get(e.target);
                if (!a || !b || !e.label) return null;
                return (
                  <text key={`label-${e.source}>${e.target}`} x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4}
                    className="link__label" textAnchor="middle">{e.label}</text>
                );
              })}
            </svg>
          </>
        )}
      </div>
      {width > 0 && graph.nodes.length > 1 && (
        <p className="muted graph__zoom-hint">
          {hidden > 0 ? `${hidden} name${hidden === 1 ? " is" : "s are"} hidden so nothing overlaps or gets cut off. ` : ""}
          Zoom in with the + button{narrow ? "" : " or Ctrl + scroll"}, then drag to move around. Hover or click a dot to see its name.
        </p>
      )}

      {present.size > 0 && (
        <ul className="legend" aria-label="Colors">
          {FAMILIES.filter(([f]) => present.has(f)).map(([f, text]) => (
            <li key={f}><span className={`legend__dot legend__dot--${f}`} aria-hidden="true" />{text}</li>
          ))}
        </ul>
      )}

      {chosen && (
        <div className="graph__detail" aria-live="polite">
          <p className="graph__detail-title">{chosen.label}</p>
          <p className="muted">{chosen.id === "subject" ? "The investigated item" : KIND_NAMES[chosen.kind] || chosen.kind}
            {chosen.level && chosen.id !== "subject" ? ` · ${chosen.level}` : ""}</p>
          {chosen.detail && <p>{chosen.detail}</p>}
          {chosen.seen_in.length > 0 && <p>Reported by: {chosen.seen_in.join(", ")}</p>}
          {touching.length > 0 && (
            <ul className="chain">
              {touching.map((e) => {
                const other = byId.get(e.source === selected ? e.target : e.source);
                return <li key={`${e.source}>${e.target}`}><span className="chain__col">{e.label}</span><span>{other?.label}</span></li>;
              })}
            </ul>
          )}
          {chosen.link && <p><External href={chosen.link}>Open the entry</External></p>}
        </div>
      )}

      {groups.length > 0 && (
        <div className="conn-list">
          {groups.map(([kind, items]) => (
            <div key={kind} className="conn-list__group">
              <h3>{KIND_NAMES[kind] || kind} <span className="muted">{items.length}</span></h3>
              <ul>
                {items.map((n) => (
                  <li key={n.id}>
                    <button type="button" className={`conn-item ${n.id === selected ? "is-selected" : ""}`}
                      aria-pressed={n.id === selected} onClick={() => pick(n.id)}>
                      <span className={`legend__dot legend__dot--${family(n.kind)}`} aria-hidden="true" />
                      <span>{n.label}</span>
                      {n.seen_in.length > 0 && <span className="muted conn-item__via">via {n.seen_in.join(", ")}</span>}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- the section

export default function EvidenceGraph({ id, level }) {
  const [graph, setGraph] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("decision");

  useEffect(() => {
    setGraph(null);
    setError(null);
    api.getGraph(id).then(setGraph).catch(setError);
  }, [id]);

  const current = graph?.[tab];
  return (
    <section className="graph-wrap" aria-labelledby="graph-title">
      <div className="graph__head">
        <h2 id="graph-title">How it fits together</h2>
        <div className="tabs" role="tablist" aria-label="Graph views">
          {[["decision", "Why this verdict"], ["connections", "Connections"]].map(([key, text]) => (
            <button key={key} type="button" role="tab" aria-selected={tab === key}
              className={`tab ${tab === key ? "is-active" : ""}`} onClick={() => setTab(key)}>
              {text}
            </button>
          ))}
        </div>
      </div>
      {error && <p className="notice is-error">The graph couldn't be loaded: {error.message}</p>}
      {!graph && !error && <p className="muted">Building the graph…</p>}
      {current && (
        <div role="tabpanel">
          {tab === "decision" ? <DecisionMap key={id} graph={current} level={level} /> : <Connections key={id} graph={current} />}
          {current.notes.map((note) => <p key={note} className="muted graph__note">{note}</p>)}
        </div>
      )}
    </section>
  );
}
