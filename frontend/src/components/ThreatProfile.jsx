import { useState } from "react";
import { api } from "../lib/api";
import { THREAT_KIND_NAMES } from "../lib/format";
import { navigate } from "../lib/router";

// Labels from the backend that this page shows in its own way (techniques are grouped by tactic)
const SHOWN_ELSEWHERE = new Set(["Techniques used"]);

function External({ href, children }) {
  if (!href) return <span>{children}</span>;
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}

// Matches to choose from: when a name was ambiguous, or "not the one you meant?" after a match.
// Picking one starts a new investigation by its ATT&CK ID, which is always an exact match.
export function Candidates({ lookup, compact = false }) {
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  if (!lookup.candidates.length) return null;

  async function open(candidate) {
    setBusy(candidate.external_id);
    setError(null);
    try {
      const result = await api.investigate(candidate.external_id);
      navigate(`/i/${result.id}`);
    } catch (err) {
      setError(err.message);
      setBusy(null);
    }
  }

  return (
    <section className={compact ? "panel" : "candidates"} aria-labelledby="candidates-title">
      <h2 id="candidates-title">{compact ? "Not the one you meant?" : "Did you mean"}</h2>
      <ul className="candidate-list">
        {lookup.candidates.map((c) => (
          <li key={c.external_id}>
            <button type="button" className="candidate" disabled={busy !== null} onClick={() => open(c)}>
              <span className="candidate__head">
                <span className="candidate__name">{c.name}</span>
                <span className="candidate__id">{c.external_id}</span>
              </span>
              <span className="candidate__meta">
                {THREAT_KIND_NAMES[c.kind] || c.kind} · {c.matched_on}
                {busy === c.external_id && " · opening…"}
              </span>
              {!compact && c.snippet && <span className="candidate__snippet">{c.snippet}</span>}
            </button>
          </li>
        ))}
      </ul>
      {error && <p className="notice is-error">{error}</p>}
    </section>
  );
}

// The side column: who this is, and where its techniques concentrate.
export function ProfileSide({ lookup }) {
  const { entity, tactics } = lookup.profile;
  const most = tactics.length ? tactics[0].count : 0;
  const details = entity.details || {};
  return (
    <>
      <section className="panel" aria-labelledby="glance-title">
        <h2 id="glance-title">At a glance</h2>
        {entity.aliases.length > 0 && (
          <div className="glance__block">
            <h3>Also known as</h3>
            <ul className="chips">
              {entity.aliases.map((a) => <li key={a} className="chip chip--plain">{a}</li>)}
            </ul>
          </div>
        )}
        {(details.first_seen || details.last_seen) && (
          <p className="glance__line">
            Active {details.first_seen ? new Date(details.first_seen).getFullYear() : "?"} to{" "}
            {details.last_seen ? new Date(details.last_seen).getFullYear() : "?"}
          </p>
        )}
        {details.platforms?.length > 0 && (
          <p className="glance__line">Platforms: {details.platforms.join(", ")}</p>
        )}
        {entity.kind === "technique" && details.tactics?.length > 0 && (
          <p className="glance__line">Tactic: {details.tactics.map((t) => t.name).join(", ")}</p>
        )}
        {tactics.length > 0 && (
          <div className="glance__block">
            <h3>Techniques by tactic</h3>
            <ul className="bars">
              {tactics.map((t) => (
                <li key={t.name} className="bar">
                  <span className="bar__label">{t.name}</span>
                  <span className="bar__track" aria-hidden="true">
                    <span className="bar__fill" style={{ width: `${(t.count / most) * 100}%` }} />
                  </span>
                  <span className="bar__count">{t.count}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        <p className="glance__source">
          Source: <External href={entity.url}>MITRE ATT&CK {entity.external_id}</External>
        </p>
      </section>
      <Candidates lookup={lookup} compact />
    </>
  );
}

// Below the summary: defenses, techniques, and everything connected to this threat.
export function ProfileDetails({ profile }) {
  const { techniques, tactics, mitigations, related } = profile;
  const byTactic = new Map(tactics.map((t) => [t.name, []]));
  for (const technique of techniques) {
    for (const tactic of technique.tactics.length ? technique.tactics : ["Other"]) {
      if (!byTactic.has(tactic)) byTactic.set(tactic, []);
      byTactic.get(tactic).push(technique);
    }
  }
  const most = mitigations.length ? mitigations[0].covers : 0;
  const groups = related.filter((g) => !SHOWN_ELSEWHERE.has(g.label));

  return (
    <div className="profile">
      {mitigations.length > 0 && (
        <section className="profile__section" aria-labelledby="defenses-title">
          <h2 id="defenses-title">Defenses that cover the most of its techniques</h2>
          <p className="muted">
            Ranked by how many of its {techniques.length} documented techniques each ATT&CK mitigation helps against.
            A good place to start checking your own controls.
          </p>
          <ol className="defenses">
            {mitigations.map((m) => (
              <li key={m.external_id} className="defense">
                <span className="defense__name">
                  <External href={m.url}>{m.name}</External> <span className="muted">{m.external_id}</span>
                </span>
                <span className="bar__track" aria-hidden="true">
                  <span className="bar__fill" style={{ width: `${(m.covers / most) * 100}%` }} />
                </span>
                <span className="defense__count">
                  {m.covers} of {techniques.length}
                </span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {techniques.length > 0 && (
        <section className="profile__section" aria-labelledby="techniques-title">
          <h2 id="techniques-title">Techniques, by tactic</h2>
          <div className="tactic-list">
            {[...byTactic.entries()].map(([tactic, items]) => (
              <details key={tactic} className="tactic">
                <summary>
                  <span>{tactic}</span>
                  <span className="muted">{items.length}</span>
                </summary>
                <ul className="technique-list">
                  {items.map((t) => (
                    <li key={t.external_id} className="technique">
                      <span className="technique__id">{t.external_id}</span>
                      <span><External href={t.url}>{t.name}</External></span>
                    </li>
                  ))}
                </ul>
              </details>
            ))}
          </div>
        </section>
      )}

      {groups.map((group) => (
        <section key={group.label} className="profile__section" aria-label={group.label}>
          <h2>
            {group.label} <span className="muted">{group.items.length}</span>
          </h2>
          <ul className="chips">
            {group.items.map((item) => (
              <li key={`${item.external_id}-${item.name}`} className="chip">
                <External href={item.url}>{item.name}</External>
                <span className="chip__id">{item.external_id}</span>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
