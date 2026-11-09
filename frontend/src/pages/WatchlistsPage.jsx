import { useState } from "react";
import ProductPicker from "../components/ProductPicker";
import { api } from "../lib/api";
import { Link, navigate } from "../lib/router";
import { CHANNELS, LEVELS, parseLink, remember, savedWatchlists } from "../lib/watchlists";

function CreateForm() {
  const [name, setName] = useState("");
  const [items, setItems] = useState([]);
  const [level, setLevel] = useState("HIGH");
  const [kind, setKind] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    if (!items.length) return setError("Add at least one product to watch.");
    setBusy(true);
    try {
      const body = { name: name.trim() || "My watchlist", min_level: level, items,
                     channels: kind && target.trim() ? [{ kind, target: target.trim() }] : [] };
      const created = await api.createWatchlist(body);
      remember(created.id, created.key, created.watchlist.name);
      navigate(`/watchlists/${created.id}#key=${encodeURIComponent(created.key)}&new=1`);
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  }

  return (
    <form className="watch-form panel" onSubmit={submit}>
      <h2 className="watch-h2">New watchlist</h2>
      <label className="watch-label" htmlFor="wl-name">Name</label>
      <input id="wl-name" className="field" value={name} onChange={(e) => setName(e.target.value)} maxLength={80}
             placeholder="Web servers, Office IT, Payment stack…" />

      <p className="watch-label">Products to watch</p>
      {items.length > 0 && (
        <ul className="chips watch-items">
          {items.map((i) => (
            <li key={`${i.vendor}:${i.product}`} className="chip">
              {i.title}
              <button type="button" className="chip__remove" aria-label={`Remove ${i.title}`}
                      onClick={() => setItems(items.filter((x) => x !== i))}>×</button>
            </li>
          ))}
        </ul>
      )}
      <ProductPicker chosen={items} onPick={(p) => setItems([...items, p])} disabled={items.length >= 25} />

      <label className="watch-label" htmlFor="wl-level">Alert me about</label>
      <select id="wl-level" className="field" value={level} onChange={(e) => setLevel(e.target.value)}>
        {LEVELS.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
      </select>
      <p className="muted watch-hint">
        Counted by ThreatLens's risk or NVD's CVSS severity, whichever is higher, because brand-new CVEs have no
        evidence of exploitation yet. Anything CISA confirms is being exploited always alerts.
      </p>

      <label className="watch-label" htmlFor="wl-kind">Send alerts to <span className="muted">(optional, add more later)</span></label>
      <div className="watch-row">
        <select id="wl-kind" className="field watch-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">Only show them here</option>
          {Object.entries(CHANNELS).filter(([k]) => k !== "email").map(([k, c]) => <option key={k} value={k}>{c.label}</option>)}
        </select>
        {kind && (
          <input className="field" value={target} onChange={(e) => setTarget(e.target.value)}
                 placeholder={CHANNELS[kind].placeholder} aria-label={`${CHANNELS[kind].label} address`} />
        )}
      </div>
      {kind && <p className="muted watch-hint">{CHANNELS[kind].help}</p>}

      {error && <p className="notice is-error">{error}</p>}
      <button type="submit" disabled={busy}>{busy ? "Creating…" : "Create watchlist"}</button>
    </form>
  );
}

export default function WatchlistsPage() {
  const [saved] = useState(savedWatchlists);
  const [link, setLink] = useState("");
  const [linkError, setLinkError] = useState("");

  function open(event) {
    event.preventDefault();
    const parsed = parseLink(link);
    if (!parsed) return setLinkError("That isn't a watchlist's private link.");
    navigate(`/watchlists/${parsed.id}#key=${encodeURIComponent(parsed.key)}`);
  }

  return (
    <main className="page page--wide watch">
      <h1 className="page-title">Watchlists</h1>
      <p className="watch__lead">
        List the software you run. Every morning ThreatLens checks NVD for new vulnerabilities in it, and CISA for older ones
        that have started being exploited. Anything serious is scored, explained and sent to you.
      </p>

      <div className="watch-layout">
        <section aria-labelledby="yours">
          <h2 id="yours" className="watch-h2">Your watchlists</h2>
          {saved.length === 0 ? (
            <p className="muted">None in this browser yet. Watchlists have no accounts: each one has a private link instead.</p>
          ) : (
            <ul className="watch-saved">
              {saved.map((w) => (
                <li key={w.id}><Link to={`/watchlists/${w.id}`}>{w.name || "Watchlist"}</Link></li>
              ))}
            </ul>
          )}
          <form className="watch-open" onSubmit={open}>
            <label className="watch-label" htmlFor="wl-link">Open a watchlist from its private link</label>
            <div className="watch-row">
              <input id="wl-link" className="field" value={link} onChange={(e) => { setLink(e.target.value); setLinkError(""); }}
                     placeholder="https://…/watchlists/…#key=…" />
              <button type="submit" className="button-secondary">Open</button>
            </div>
            {linkError && <p className="picker__note is-error">{linkError}</p>}
          </form>
        </section>
        <CreateForm />
      </div>
    </main>
  );
}
