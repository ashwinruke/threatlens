import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Link } from "../lib/router";
import { VERDICT_LABEL, VERDICTS, savedWatchlists } from "../lib/watchlists";

// An analyst's verdict on this report, saved to one of their watchlists
export default function VerdictPanel({ investigation }) {
  const [watchlists] = useState(savedWatchlists);
  const [chosen, setChosen] = useState(watchlists[0]?.id || "");
  const [current, setCurrent] = useState(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const indicator = investigation.indicator.value;

  // Show the verdict already recorded in the chosen watchlist, if any
  useEffect(() => {
    const w = watchlists.find((x) => x.id === chosen);
    if (!w) return;
    setCurrent(null);
    setMessage("");
    api.watchlist(w.id, w.key)
      .then((view) => {
        const found = view.alerts.find((a) => a.indicator === indicator);
        setCurrent(found || null);
        setNote(found?.note || "");
      })
      .catch(() => setCurrent(null));
  }, [chosen, indicator, watchlists]);

  async function decide(status) {
    const w = watchlists.find((x) => x.id === chosen);
    setBusy(status);
    try {
      const saved = await api.watchlist(w.id, w.key, "/cases", {
        method: "POST", body: { investigation_id: investigation.id, status, note },
      });
      setCurrent(saved);
      setMessage(`Saved to ${w.name}.`);
    } catch (e) {
      setMessage(e.message);
    }
    setBusy("");
  }

  return (
    <section className="panel verdict-panel" aria-labelledby="verdict-title">
      <h2 id="verdict-title" className="verdict-panel__title">Analyst verdict</h2>
      {watchlists.length === 0 ? (
        <p className="muted verdict-panel__text">
          Record whether this was a real threat. Verdicts are kept in a watchlist, your team's private space.{" "}
          <Link to="/watchlists">Create one</Link>
        </p>
      ) : (
        <>
          {watchlists.length > 1 && (
            <select className="field" value={chosen} onChange={(e) => setChosen(e.target.value)} aria-label="Watchlist">
              {watchlists.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
            </select>
          )}
          {current && current.status !== "new" && (
            <p className="verdict-panel__text">Current verdict: <b>{VERDICT_LABEL[current.status]}</b></p>
          )}
          <textarea className="field" rows={2} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)}
                    placeholder="What you found (optional)" aria-label="Note" />
          <div className="verdict-box__buttons">
            {VERDICTS.slice(0, 3).map((v) => (
              <button key={v.value} type="button" disabled={!!busy}
                      className={`verdict-btn verdict-btn--${v.tone} ${current?.status === v.value ? "is-current" : ""}`}
                      onClick={() => decide(v.value)}>{busy === v.value ? "Saving…" : v.label}</button>
            ))}
          </div>
          {message && <p className="muted verdict-panel__text" role="status">{message}</p>}
          {watchlists.length === 1 && !message && <p className="muted verdict-panel__text">Kept in {watchlists[0].name}.</p>}
        </>
      )}
    </section>
  );
}
