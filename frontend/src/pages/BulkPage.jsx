import { useEffect, useMemo, useState } from "react";
import Downloads from "../components/Downloads";
import { api } from "../lib/api";
import { typeName } from "../lib/format";
import { Link } from "../lib/router";

// Bulk lookup: paste a list or a whole alert, see what ThreatLens found in it, then investigate
// everything at once. Results fill in as each one finishes, and the finished table gets its own link.

const LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "PROFILE", "UNKNOWN"];
const LEVEL_TEXT = {
  CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", PROFILE: "Profile", UNKNOWN: "Unknown",
};
const EXAMPLE = `Paste a list, one per line:
CVE-2021-44228
45.95.147.236
evil-example[.]xyz
Volt Typhoon

…or a whole alert or report: ThreatLens picks the indicators out of the text.`;

function rank(row) {
  if (!row) return 99; // still running
  if (row.error) return 50;
  const i = LEVEL_ORDER.indexOf(row.level);
  return i === -1 ? 40 : i;
}

function seconds(ms) {
  return ms == null ? "" : `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}

// The results table, used while a bulk lookup runs and when a saved one is opened
export function BulkResults({ items, rows, running }) {
  const [order, setOrder] = useState("risk");
  const [only, setOnly] = useState(null); // a level to filter by, or null for all
  const all = items.map((item, index) => ({ item, index, row: rows[index] }));
  const counts = {};
  for (const { row } of all) {
    const key = !row ? "running" : row.error ? "error" : row.level;
    counts[key] = (counts[key] || 0) + 1;
  }
  const shown = all
    .filter(({ row }) => !only || (only === "error" ? row?.error : row?.level === only && !row?.error))
    .sort((a, b) => (order === "risk" ? rank(a.row) - rank(b.row) || (b.row?.score ?? 0) - (a.row?.score ?? 0) : 0)
      || a.index - b.index);
  const done = all.filter((x) => x.row).length;

  return (
    <section className="bulk-results" aria-labelledby="bulk-results-title">
      <div className="bulk-results__head">
        <h2 id="bulk-results-title">
          Results <span className="muted">{done} of {items.length}{running ? ", checking…" : ""}</span>
        </h2>
        <div className="tabs" role="group" aria-label="Order">
          {[["risk", "Highest risk first"], ["pasted", "As pasted"]].map(([key, text]) => (
            <button key={key} type="button" className={`tab ${order === key ? "is-active" : ""}`}
              aria-pressed={order === key} onClick={() => setOrder(key)}>{text}</button>
          ))}
        </div>
      </div>
      {running && (
        <div className="bulk-progress" aria-hidden="true">
          <span style={{ width: `${(done / Math.max(items.length, 1)) * 100}%` }} />
        </div>
      )}

      <ul className="bulk-counts" aria-label="Filter by risk">
        <li>
          <button type="button" className={`bulk-count ${!only ? "is-active" : ""}`} aria-pressed={!only}
            onClick={() => setOnly(null)}>All <b>{items.length}</b></button>
        </li>
        {[...LEVEL_ORDER, "error"].filter((l) => counts[l]).map((level) => (
          <li key={level}>
            <button type="button" className={`bulk-count lvl-${level} ${only === level ? "is-active" : ""}`}
              aria-pressed={only === level} onClick={() => setOnly(only === level ? null : level)}>
              <span className="bulk-count__dot" aria-hidden="true" />
              {level === "error" ? "Failed" : LEVEL_TEXT[level]} <b>{counts[level]}</b>
            </button>
          </li>
        ))}
      </ul>

      <ol className="bulk-table">
        {shown.map(({ item, index, row }) => (
          <li key={index} className={`bulk-row ${row ? `lvl-${row.error ? "UNKNOWN" : row.level}` : "is-running"}`}>
            <span className="bulk-row__risk">
              {!row && <span className="bulk-row__spinner" aria-label="Checking" />}
              {row?.error && <span className="bulk-pill bulk-pill--error">Failed</span>}
              {row && !row.error && (
                <span className="bulk-pill">
                  {LEVEL_TEXT[row.level] || row.level}{row.score != null && row.level !== "UNKNOWN" ? ` ${row.score}` : ""}
                </span>
              )}
            </span>
            <span className="bulk-row__what">
              <span className="bulk-row__value">{row?.value && row.value !== item.query ? row.value : item.query}</span>
              <span className="bulk-row__type">{typeName({ type: item.type, subtype: row?.subtype })}{row?.value && row.value !== item.query ? ` · you entered ${item.query}` : ""}</span>
            </span>
            <span className="bulk-row__why">
              {!row && <span className="muted">Checking the sources…</span>}
              {row?.error && <span>{row.error}</span>}
              {row && !row.error && (
                <>
                  <span>{row.headline}</span>
                  {row.top_signals.length > 0 && (
                    <span className="bulk-row__signals">{row.top_signals.join(" · ")}</span>
                  )}
                </>
              )}
            </span>
            <span className="bulk-row__meta">
              {row && !row.error && row.sources_total > 0 && (
                <span title="Sources that answered">{row.sources_ok}/{row.sources_total} sources</span>
              )}
              {row?.investigation_id && <Link to={`/i/${row.investigation_id}`}>Open report</Link>}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function PlanPreview({ plan }) {
  if (!plan) return null;
  return (
    <div className="bulk-preview" aria-live="polite">
      <p>
        <b>{plan.summary}</b>
        {plan.mode === "extract" && plan.items.length > 0 && (
          <span className="muted"> · picked out of the text (names are only read from a plain list)</span>
        )}
      </p>
      {plan.items.length > 0 && (
        <ul className="chips bulk-preview__chips">
          {plan.items.map((item) => (
            <li key={`${item.type}-${item.query}`} className="chip chip--plain" title={item.original}>{item.query}</li>
          ))}
        </ul>
      )}
      {(plan.repeats > 0 || plan.over_limit > 0) && (
        <p className="muted">
          {plan.repeats > 0 && `${plan.repeats} repeat${plan.repeats === 1 ? "" : "s"} removed. `}
          {plan.over_limit > 0 && `${plan.over_limit} more found, but a bulk lookup checks at most ${plan.items.length} at a time.`}
        </p>
      )}
      {plan.skipped.length > 0 && (
        <details className="bulk-preview__skipped">
          <summary>{plan.skipped.length} skipped</summary>
          <ul>
            {plan.skipped.map((s, i) => <li key={i}><code>{s.text}</code>: {s.reason}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}

export default function BulkPage() {
  const [text, setText] = useState("");
  const [preview, setPreview] = useState(null);
  const [run, setRun] = useState(null); // { items, rows, running, batchId }
  const [error, setError] = useState(null);

  // Show what would be investigated, shortly after typing stops (nothing is sent to any source)
  useEffect(() => {
    setError(null);
    if (!text.trim()) {
      setPreview(null);
      return undefined;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => {
      api.bulkParse(text, controller.signal).then(setPreview).catch((err) => {
        if (err.name !== "AbortError") setPreview(null);
      });
    }, 400);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [text]);

  async function start(event) {
    event.preventDefault();
    setError(null);
    setRun({ items: preview?.items || [], rows: {}, running: true, batchId: null });
    try {
      const batch = await api.bulkLive(text, {
        onPlan: (plan) => setRun((r) => ({ ...r, items: plan.items })),
        onRow: (row) => setRun((r) => ({ ...r, rows: { ...r.rows, [row.index]: row } })),
      });
      const rows = Object.fromEntries(batch.rows.map((row) => [row.index, row]));
      setRun((r) => ({ ...r, rows, running: false, batchId: batch.id }));
      // Give the finished results their own address, so they can be shared or reopened
      if (batch.id) window.history.replaceState({}, "", `/b/${batch.id}`);
    } catch (err) {
      setError(err.message);
      setRun((r) => (r && Object.keys(r.rows).length ? { ...r, running: false } : null));
    }
  }

  const count = preview?.items.length || 0;
  return (
    <main className="page page--wide">
      <h1 className="page-title">Bulk lookup</h1>
      <p className="page-lead">
        Check up to 20 indicators at once. Paste a list, a spreadsheet column, or a whole alert or threat report:
        ThreatLens finds the CVEs, IP addresses, domains, URLs, file hashes and CWE IDs in it, even when they're
        defanged, like <code>evil[.]com</code>.
      </p>
      <form className="bulk-form" onSubmit={start}>
        <label htmlFor="bulk-text" className="visually-hidden">Indicators or text to scan</label>
        <textarea id="bulk-text" value={text} onChange={(e) => setText(e.target.value)} placeholder={EXAMPLE}
          rows={9} maxLength={20000} spellCheck={false} disabled={run?.running} />
        <PlanPreview plan={preview} />
        <div className="bulk-form__actions">
          <button type="submit" disabled={!count || run?.running}>
            {run?.running ? "Investigating…" : count ? `Investigate ${count}` : "Investigate"}
          </button>
          <span className="muted bulk-form__note">
            To save the free AI quota, bulk lookups skip the AI summary and research agent. Open any report to run a
            full investigation.
          </span>
        </div>
      </form>
      {error && <p className="notice is-error">{error}</p>}
      {run && run.items.length > 0 && <BulkResults items={run.items} rows={run.rows} running={run.running} />}
      {run?.batchId && !run.running && (
        <p className="muted bulk-link">
          These results now have their own link: copy it from the address bar to share them.{" "}
          <Downloads path={`bulk/${encodeURIComponent(run.batchId)}`} label="Download all" />
        </p>
      )}
    </main>
  );
}

// A saved bulk lookup, opened from its link
export function BatchPage({ id }) {
  const [batch, setBatch] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    api.getBatch(id).then(setBatch).catch(setError);
  }, [id]);
  const items = useMemo(() => (batch ? batch.rows.map((r) => ({ query: r.query, type: r.type })) : []), [batch]);
  const rows = useMemo(() => (batch ? Object.fromEntries(batch.rows.map((r, i) => [i, { ...r, index: i }])) : {}), [batch]);

  if (error) {
    return (
      <main className="page">
        <h1 className="page-title">{error.status === 404 ? "Bulk lookup not found" : "Couldn't load this bulk lookup"}</h1>
        <p className="notice"><Link to="/bulk">Start a new bulk lookup</Link>.</p>
      </main>
    );
  }
  if (!batch) return <main className="page"><p className="muted">Loading…</p></main>;
  return (
    <main className="page page--wide">
      <h1 className="page-title">Bulk lookup</h1>
      <p className="page-lead">
        {batch.rows.length} indicators checked {new Date(batch.created_at).toLocaleString()}, in {seconds(batch.duration_ms)}.{" "}
        <Link to="/bulk">Start a new bulk lookup</Link>.{" "}
        <Downloads path={`bulk/${encodeURIComponent(id)}`} label="Download all" />
      </p>
      <BulkResults items={items} rows={rows} running={false} />
    </main>
  );
}
