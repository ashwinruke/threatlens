import { useEffect, useState } from "react";
import { API_URL, api } from "../lib/api";

// The ATT&CK techniques an investigation touches, stage by stage, the way analysts read ATT&CK.
// Solid = reported for this item; dashed = known for a threat linked to it (context, not something seen).

function External({ href, children }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  );
}

const PER_STAGE = 8;

function plural(n, word, many = `${word}s`) {
  return `${n} ${n === 1 ? word : many}`;
}

function TechniqueDetail({ technique }) {
  return (
    <div className="amap__detail" aria-live="polite">
      <p className="graph__detail-title">
        {technique.name} <span className="muted">{technique.external_id}</span>
      </p>
      <p className="muted">
        {technique.strength === "reported" ? "Reported for this investigation" : "Known for a linked threat"}
      </p>
      <ul className="amap__evidence">
        {technique.evidence.map((e) => (
          <li key={e.text}>
            <span className={`amap__mark amap__mark--${e.strength}`} aria-hidden="true" />
            <span>{e.text}</span>
          </li>
        ))}
      </ul>
      {technique.url && <p><External href={technique.url}>Read about it on MITRE ATT&CK</External></p>}
    </div>
  );
}

export default function AttackMap({ id, showDefenses = true }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [only, setOnly] = useState("all"); // all or reported
  const [selected, setSelected] = useState(null); // "tactic|technique"
  const [showEmpty, setShowEmpty] = useState(false);
  const [expanded, setExpanded] = useState(new Set()); // stages showing all their techniques

  useEffect(() => {
    setData(null);
    setError(null);
    setSelected(null);
    setExpanded(new Set());
    api.getAttackMap(id).then(setData).catch(setError);
  }, [id]);

  if (error) {
    return (
      <section className="amap-wrap" aria-labelledby="amap-title">
        <h2 id="amap-title">ATT&CK map</h2>
        <p className="notice is-error">The ATT&CK map couldn't be loaded: {error.message}</p>
      </section>
    );
  }
  if (!data) return null;

  const hasBoth = data.reported_count > 0 && data.reported_count < data.technique_count;
  const visible = (t) => only === "all" || t.strength === "reported";
  const rows = data.tactics.map((tactic) => ({ ...tactic, shown: tactic.techniques.filter(visible) }));
  const filled = rows.filter((r) => r.shown.length > 0);
  const empty = rows.filter((r) => r.shown.length === 0 && r.id !== "other");
  const linkedCount = data.technique_count - data.reported_count;

  return (
    <section className="amap-wrap" aria-labelledby="amap-title">
      <div className="graph__head">
        <h2 id="amap-title">ATT&CK map</h2>
        {data.status === "ok" && (
          <a className="button-link" href={`${API_URL}/api/investigations/${encodeURIComponent(id)}/attack/layer`}
            download>
            Download for ATT&CK Navigator
          </a>
        )}
      </div>

      {data.status === "ok" ? (
        <>
          <p className="muted graph__hint">
            The attack techniques linked to this investigation, in the order an attack usually unfolds.{" "}
            {plural(data.technique_count, "technique")} across {plural(filled.length, "stage")}
            {data.reported_count > 0 && `: ${data.reported_count} reported`}
            {linkedCount > 0 && `${data.reported_count > 0 ? "," : ":"} ${linkedCount} from linked threats`}.
          </p>
          <div className="amap__controls">
            <ul className="legend" aria-label="Key">
              <li><span className="amap__mark amap__mark--reported" aria-hidden="true" />Reported for this investigation</li>
              <li><span className="amap__mark amap__mark--linked" aria-hidden="true" />Known for a linked threat (what to expect, not what was seen)</li>
            </ul>
            {hasBoth && (
              <div className="tabs" role="group" aria-label="Which techniques to show">
                {[["all", "All"], ["reported", "Reported only"]].map(([key, text]) => (
                  <button key={key} type="button" className={`tab ${only === key ? "is-active" : ""}`}
                    aria-pressed={only === key} onClick={() => setOnly(key)}>{text}</button>
                ))}
              </div>
            )}
          </div>

          <div className="amap">
            {(showEmpty ? rows.filter((r) => r.id !== "other" || r.shown.length) : filled).map((row) => {
              // Strongest first (reported, then used by the most linked threats); long stages fold after PER_STAGE
              const folded = !expanded.has(row.id) && row.shown.length > PER_STAGE + 2;
              const chips = folded ? row.shown.slice(0, PER_STAGE) : row.shown;
              const open = chips.find((t) => selected === `${row.id}|${t.external_id}`);
              return (
                <div key={row.id} className={`amap__row ${row.shown.length ? "" : "is-empty"}`}>
                  <div className="amap__stage">
                    <span className="amap__stage-name">{row.name}</span>
                    <span className="amap__stage-about">{row.about}</span>
                  </div>
                  <div className="amap__cell">
                    {row.shown.length === 0 && <span className="muted amap__none">Nothing found</span>}
                    <ul className="amap__chips">
                      {chips.map((t) => {
                        const key = `${row.id}|${t.external_id}`;
                        return (
                          <li key={t.external_id}>
                            <button type="button" aria-pressed={selected === key}
                              className={`amap__chip amap__chip--${t.strength} ${selected === key ? "is-selected" : ""}`}
                              onClick={() => setSelected(selected === key ? null : key)}>
                              <span className="amap__id">{t.external_id}</span>
                              <span>{t.name}</span>
                              {t.linked_threats.length > 1 && (
                                <span className="amap__count" title="Linked threats known to use it">
                                  ×{t.linked_threats.length}
                                </span>
                              )}
                            </button>
                          </li>
                        );
                      })}
                      {row.shown.length > PER_STAGE + 2 && (
                        <li>
                          <button type="button" className="amap__more"
                            onClick={() => setExpanded((old) => {
                              const next = new Set(old);
                              if (next.has(row.id)) next.delete(row.id); else next.add(row.id);
                              return next;
                            })}>
                            {folded ? `Show ${row.shown.length - PER_STAGE} more` : "Show fewer"}
                          </button>
                        </li>
                      )}
                    </ul>
                    {open && <TechniqueDetail technique={open} />}
                  </div>
                </div>
              );
            })}
          </div>
          {empty.length > 0 && (
            <button type="button" className="button-quiet amap__toggle" onClick={() => setShowEmpty(!showEmpty)}>
              {showEmpty ? "Hide stages with nothing found" : `Show the ${plural(empty.length, "stage")} with nothing found`}
            </button>
          )}

          {data.linked.length > 0 && only === "all" && (
            <p className="muted amap__linked">
              Linked threats included:{" "}
              {data.linked.map((l, i) => (
                <span key={l.external_id}>
                  {i > 0 && ", "}
                  {l.name} ({plural(l.techniques, "technique")}, via {l.found_by.join(" and ") || "this investigation"})
                </span>
              ))}
              .
            </p>
          )}

          {showDefenses && data.defenses.length > 0 && (
            <div className="amap__defenses">
              <h3>Defenses that cover the most of these techniques</h3>
              <ol className="defenses">
                {data.defenses.map((d) => (
                  <li key={d.external_id} className="defense">
                    <span className="defense__name">
                      {d.url ? <External href={d.url}>{d.name}</External> : d.name}{" "}
                      <span className="muted">{d.external_id}</span>
                    </span>
                    <span className="bar__track" aria-hidden="true">
                      <span className="bar__fill" style={{ width: `${(d.covers / data.defenses[0].covers) * 100}%` }} />
                    </span>
                    <span className="defense__count">{d.covers} of {data.technique_count}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </>
      ) : (
        <p className="muted graph__hint">
          {data.status === "unavailable" ? "The ATT&CK map isn't available right now." : "No attack techniques to map."}
        </p>
      )}
      {data.notes.map((note) => <p key={note} className="muted graph__note">{note}</p>)}
      {data.attack_version && data.status === "ok" && (
        <p className="muted graph__note">Based on MITRE ATT&CK version {data.attack_version}.</p>
      )}
    </section>
  );
}
