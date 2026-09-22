import { points } from "../lib/format";

// The score as an itemized ledger: every point is visible, with its source and evidence.
export default function ScoreLedger({ signals, verdict }) {
  const total = signals.reduce((sum, s) => sum + s.points, 0);
  const capped = total !== verdict.score && verdict.rules_applied.length === 0;

  return (
    <section className="panel" aria-labelledby="ledger-title">
      <h2 id="ledger-title">Score breakdown</h2>
      {signals.length === 0 ? (
        <p className="muted">No signals added or removed points.</p>
      ) : (
        <ol className="ledger">
          {signals.map((s) => (
            <li key={s.id} className="ledger__row">
              <div className="ledger__text">
                <p className="ledger__label">{s.label}</p>
                <p className="ledger__evidence">
                  {s.evidence} <span className="ledger__source">{s.source}</span>
                </p>
              </div>
              <span className={`ledger__points ${s.points < 0 ? "is-negative" : s.points === 0 ? "is-zero" : ""}`}>
                {points(s.points)}
              </span>
            </li>
          ))}
        </ol>
      )}
      <div className="ledger__total">
        <span>Score</span>
        <span>{verdict.score}</span>
      </div>
      {verdict.rules_applied.map((rule) => (
        <p key={rule} className="ledger__rule">{rule}</p>
      ))}
      {capped && <p className="ledger__rule">Points add up to {total}; the score is kept between 0 and 100.</p>}
    </section>
  );
}
