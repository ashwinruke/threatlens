import { useEffect, useState } from "react";
import ProductPicker from "../components/ProductPicker";
import { api } from "../lib/api";
import { timeAgo } from "../lib/format";
import { Link, navigate } from "../lib/router";
import { CHANNELS, LEVELS, VERDICT_LABEL, VERDICTS, forget, keyFor, privateLink, remember } from "../lib/watchlists";

const FILTERS = [
  { value: "new", label: "Needs triage", test: (a) => a.status === "new" },
  { value: "confirmed", label: "Confirmed", test: (a) => a.status === "confirmed" },
  { value: "quiet", label: "Muted, resolved", test: (a) => ["false_alarm", "not_affected", "resolved"].includes(a.status) },
  { value: "all", label: "All", test: () => true },
];
const REASON = { new_cve: "New CVE", newly_exploited: "Now exploited", saved: "Saved from a report" };
const title = (level) => level.charAt(0) + level.slice(1).toLowerCase();

function AlertRow({ alert, onVerdict }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState(alert.note || "");
  const [busy, setBusy] = useState("");

  async function decide(status) {
    setBusy(status);
    await onVerdict(alert, status, note);
    setBusy("");
    setOpen(false);
  }

  return (
    <li className={`alert ${alert.status !== "new" ? "alert--decided" : ""}`}>
      <div className="alert__main">
        <div className="alert__head">
          <span className={`level-text lvl-${alert.level}`}>{title(alert.level)}{alert.score != null && ` ${alert.score}`}</span>
          {alert.investigation_id ? <Link to={`/i/${alert.investigation_id}`} className="alert__id">{alert.indicator}</Link>
            : <span className="alert__id">{alert.indicator}</span>}
          <span className={`alert__reason ${alert.reason === "newly_exploited" ? "is-hot" : ""}`}>
            {alert.escalated ? "Now exploited, after an earlier alert" : REASON[alert.reason]}
          </span>
        </div>
        {alert.title && <p className="alert__title">{alert.title}</p>}
        <p className="alert__meta">
          {alert.item_title && <>{alert.item_title}{alert.match === "name" && <span className="alert__warn"> · matched by name only, check it applies</span>} · </>}
          {alert.why && <>{alert.why} · </>}
          found {timeAgo(alert.found_at)}
        </p>
        {alert.status !== "new" && (
          <p className="alert__verdict">
            <b>{VERDICT_LABEL[alert.status]}</b>{alert.note && <>: {alert.note}</>}
          </p>
        )}
      </div>
      <div className="alert__actions">
        {!open ? (
          <button type="button" className="button-secondary" onClick={() => setOpen(true)}>
            {alert.status === "new" ? "Triage" : "Change"}
          </button>
        ) : (
          <div className="verdict-box">
            <textarea className="field" rows={2} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)}
                      placeholder="Note (optional): what you found, what you did" aria-label="Note" />
            <div className="verdict-box__buttons">
              {VERDICTS.map((v) => (
                <button key={v.value} type="button" className={`verdict-btn verdict-btn--${v.tone}`} disabled={!!busy}
                        onClick={() => decide(v.value)}>{busy === v.value ? "Saving…" : v.label}</button>
              ))}
              {alert.status !== "new" && (
                <button type="button" className="button-quiet" disabled={!!busy} onClick={() => decide("new")}>Back to triage</button>
              )}
              <button type="button" className="button-quiet" onClick={() => setOpen(false)}>Cancel</button>
            </div>
          </div>
        )}
      </div>
    </li>
  );
}

function Channels({ data, call }) {
  const [kind, setKind] = useState("discord");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const channels = data.watchlist.channels;
  const kinds = Object.entries(CHANNELS).filter(([k]) => k !== "email" || data.email_available);

  async function add(event) {
    event.preventDefault();
    setBusy(true);
    const ok = await call("/channels", { method: "POST", body: { kind, target } });
    setBusy(false);
    if (ok) setTarget("");
  }

  return (
    <section className="watch-section" aria-labelledby="channels-title">
      <h2 id="channels-title" className="watch-h2">Alert channels</h2>
      {channels.length === 0 && <p className="muted">No channels yet: new alerts only show on this page.</p>}
      <ul className="channel-list">
        {channels.map((c) => (
          <li key={c.id} className="channel">
            <div>
              <p className="channel__name">{CHANNELS[c.kind]?.label} <span className="muted channel__target">{c.target}</span></p>
              <p className={c.last_error ? "channel__status is-error" : "channel__status muted"}>
                {c.last_error ? `Last message failed: ${c.last_error}` : c.last_sent_at ? `Last message ${timeAgo(c.last_sent_at)}` : "Nothing sent yet"}
              </p>
            </div>
            <div className="channel__buttons">
              <button type="button" className="button-secondary" onClick={() => call(`/channels/${c.id}/test`, { method: "POST" })}>Send a test</button>
              <button type="button" className="button-quiet" onClick={() => call(`/channels/${c.id}`, { method: "DELETE" })}>Remove</button>
            </div>
          </li>
        ))}
      </ul>
      <form className="watch-row" onSubmit={add}>
        <select className="field watch-kind" value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Channel type">
          {kinds.map(([k, c]) => <option key={k} value={k}>{c.label}</option>)}
        </select>
        <input className="field" value={target} onChange={(e) => setTarget(e.target.value)} required
               placeholder={CHANNELS[kind].placeholder} aria-label={`${CHANNELS[kind].label} address`} />
        <button type="submit" className="button-secondary" disabled={busy}>{busy ? "Adding…" : "Add"}</button>
      </form>
      <p className="muted watch-hint">{CHANNELS[kind].help}</p>
    </section>
  );
}

export default function WatchlistPage({ id }) {
  const [key] = useState(() => keyFor(id));
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState("");
  const [filter, setFilter] = useState("new");
  const [checking, setChecking] = useState(false);
  const [copied, setCopied] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [isNew] = useState(() => new URLSearchParams(window.location.hash.slice(1)).has("new"));

  useEffect(() => {
    if (!key) return;
    api.watchlist(id, key)
      .then((view) => {
        setData(view);
        remember(id, key, view.watchlist.name);
        // Keep the key out of the address bar once it's saved (the private link button has it)
        window.history.replaceState({}, "", window.location.pathname);
        const pending = view.alerts.filter((a) => a.status === "new").length;
        if (!pending && view.alerts.length) setFilter("all");
      })
      .catch(setError);
  }, [id, key]);

  useEffect(() => {
    if (data) document.title = `${data.watchlist.name} · Watchlist · ThreatLens`;
  }, [data]);

  async function call(path, options = {}) {
    setNotice("");
    try {
      const view = await api.watchlist(id, key, path, options);
      setData((old) => ({ ...old, ...view }));
      return true;
    } catch (e) {
      setNotice(e.message);
      return false;
    }
  }

  async function onVerdict(alert, status, note) {
    try {
      const updated = await api.watchlist(id, key, `/alerts/${alert.id}/verdict`, { method: "POST", body: { status, note } });
      setData((old) => {
        const alerts = old.alerts.map((a) => (a.id === updated.id ? updated : a));
        return { ...old, alerts, stats: recount(alerts) };
      });
    } catch (e) {
      setNotice(e.message);
    }
  }

  async function checkNow() {
    setChecking(true);
    setNotice("");
    try {
      const view = await api.watchlist(id, key, "/check", { method: "POST", timeoutMs: 240_000 });
      setData(view);
      setNotice(view.check.text + (view.check.errors.length ? ` ${view.check.errors.join(" ")}` : ""));
      setFilter("new");
    } catch (e) {
      setNotice(e.message);
    }
    setChecking(false);
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(privateLink(id, key));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setNotice(privateLink(id, key));
    }
  }

  async function remove() {
    if (await call("", { method: "DELETE" })) {
      forget(id);
      navigate("/watchlists");
    }
  }

  if (!key || error) {
    return (
      <main className="page">
        <h1 className="page-title">Watchlist</h1>
        <p className="notice">
          {error && error.status !== 404 ? error.message
            : "This browser doesn't have this watchlist's private key. Open it with its private link, or ask whoever made it to share the link."}{" "}
          <Link to="/watchlists">All watchlists</Link>
        </p>
      </main>
    );
  }
  if (!data) return <main className="page"><p className="muted">Loading watchlist…</p></main>;

  const w = data.watchlist;
  const stats = data.stats;
  // Newest first; within a check, exploited ones first, then by score
  const shown = data.alerts.filter(FILTERS.find((f) => f.value === filter).test).sort((a, b) =>
    b.found_at.localeCompare(a.found_at) || (b.reason === "newly_exploited") - (a.reason === "newly_exploited") || (b.score ?? 0) - (a.score ?? 0));

  return (
    <main className="page page--wide watch">
      <p className="watch__crumb"><Link to="/watchlists">Watchlists</Link></p>
      <div className="watch-top">
        <div>
          <h1 className="page-title">{w.name}</h1>
          <p className="muted watch-top__meta">
            {w.items.length} product{w.items.length === 1 ? "" : "s"} · checked every morning
            {w.last_checked_at ? `, last ${timeAgo(w.last_checked_at)} (${w.last_check_summary})` : ", not checked yet"}
          </p>
        </div>
        <div className="watch-top__buttons">
          <button type="button" onClick={checkNow} disabled={checking || !w.items.length}>{checking ? "Checking NVD and CISA…" : "Check now"}</button>
          <button type="button" className="button-secondary" onClick={copyLink}>{copied ? "Copied" : "Copy private link"}</button>
        </div>
      </div>

      {isNew && (
        <p className="notice watch-saveit">
          <b>Save the private link.</b> It's the only way into this watchlist from another browser or for your team, and
          it can't be recovered. This browser remembers it. <button type="button" className="button-quiet" onClick={copyLink}>{copied ? "Copied" : "Copy it now"}</button>
        </p>
      )}
      {notice && <p className="notice" role="status">{notice}</p>}

      <section className="watch-stats" aria-label="Triage">
        <div><span className="watch-stats__n">{stats.new}</span><span>need triage</span></div>
        <div><span className="watch-stats__n">{stats.confirmed}</span><span>confirmed</span></div>
        <div><span className="watch-stats__n">{stats.false_alarm}</span><span>false alarms</span></div>
        <div><span className="watch-stats__n">{stats.not_affected}</span><span>not affected</span></div>
        <div title="Of the alerts you judged as confirmed or false alarm, the share that were real">
          <span className="watch-stats__n">{stats.precision_pct == null ? "–" : `${stats.precision_pct}%`}</span><span>alerts that were real</span>
        </div>
      </section>

      <section className="watch-section" aria-labelledby="alerts-title">
        <div className="watch-section__head">
          <h2 id="alerts-title" className="watch-h2">Alerts</h2>
          <div className="tabs" role="group" aria-label="Show">
            {FILTERS.map((f) => (
              <button key={f.value} type="button" className={`tab ${filter === f.value ? "is-active" : ""}`}
                      aria-pressed={filter === f.value} onClick={() => setFilter(f.value)}>{f.label}</button>
            ))}
          </div>
        </div>
        {shown.length === 0 ? (
          <p className="muted">
            {data.alerts.length === 0 ? (w.last_checked_at ? "Nothing serious found yet. That's good news." : "Press \"Check now\" for a first look, or wait for tomorrow morning's check.")
              : "Nothing here."}
          </p>
        ) : (
          <ul className="alerts">{shown.map((a) => <AlertRow key={a.id} alert={a} onVerdict={onVerdict} />)}</ul>
        )}
        <p className="muted watch-hint">
          "False alarm" and "Not affected" keep that CVE quiet for good. A CVE you were told about that CISA later confirms
          exploited alerts again, unless you muted it.
        </p>
      </section>

      <div className="watch-columns">
        <section className="watch-section" aria-labelledby="products-title">
          <h2 id="products-title" className="watch-h2">Products</h2>
          <ul className="chips watch-items">
            {w.items.map((i) => (
              <li key={i.id} className="chip" title={`${i.vendor}:${i.product}`}>
                {i.title}
                <button type="button" className="chip__remove" aria-label={`Stop watching ${i.title}`}
                        onClick={() => call(`/items/${i.id}`, { method: "DELETE" })}>×</button>
              </li>
            ))}
          </ul>
          <ProductPicker chosen={w.items} onPick={(p) => call("/items", { method: "POST", body: p })} />
          <label className="watch-label" htmlFor="wl-level">Alert me about</label>
          <select id="wl-level" className="field" value={w.min_level}
                  onChange={(e) => call("", { method: "PATCH", body: { min_level: e.target.value } })}>
            {LEVELS.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
          </select>
        </section>
        <Channels data={data} call={call} />
      </div>

      <section className="watch-section watch-danger">
        {confirmDelete ? (
          <p>
            Delete <b>{w.name}</b> and all its alerts and verdicts? This can't be undone.{" "}
            <button type="button" className="button-danger" onClick={remove}>Delete it</button>{" "}
            <button type="button" className="button-quiet" onClick={() => setConfirmDelete(false)}>Keep it</button>
          </p>
        ) : (
          <button type="button" className="button-quiet" onClick={() => setConfirmDelete(true)}>Delete this watchlist</button>
        )}
      </section>
    </main>
  );
}

function recount(alerts) {
  const count = (s) => alerts.filter((a) => a.status === s).length;
  const confirmed = count("confirmed");
  const falseAlarm = count("false_alarm");
  return {
    new: count("new"), confirmed, false_alarm: falseAlarm, not_affected: count("not_affected"), resolved: count("resolved"),
    total: alerts.length, precision_pct: confirmed + falseAlarm ? Math.round((100 * confirmed) / (confirmed + falseAlarm)) : null,
  };
}
