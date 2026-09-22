import Cites, { citationMap } from "./Citations";

const PRIORITY_TEXT = { now: "Do now", soon: "Do soon", later: "Later" };

function CitedList({ title, items, byId }) {
  if (!items.length) return null;
  return (
    <section className="report__block">
      <h3>{title}</h3>
      <ul className="cited">
        {items.map((item, i) => (
          <li key={i}>
            {item.text}
            <Cites ids={item.sources} byId={byId} />
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function AiSummary({ report }) {
  if (!report) return null;

  if (report.status !== "ready") {
    return (
      <section className="report report--unavailable" aria-labelledby="summary-title">
        <h2 id="summary-title">Summary</h2>
        <p>{report.message}</p>
        {report.attempts?.length > 0 && (
          <details>
            <summary>What happened</summary>
            <ul className="plain-list">
              {report.attempts.map((a) => <li key={a}>{a}</li>)}
            </ul>
          </details>
        )}
      </section>
    );
  }

  const byId = citationMap(report.citations);
  const order = { now: 0, soon: 1, later: 2 };
  const actions = [...report.actions].sort((a, b) => order[a.priority] - order[b.priority]);

  return (
    <section className="report" aria-labelledby="summary-title">
      <h2 id="summary-title">Summary</h2>
      <p className="report__summary">{report.summary}</p>

      <CitedList title="Key findings" items={report.findings} byId={byId} />
      <CitedList title="What's affected" items={report.affected} byId={byId} />

      {actions.length > 0 && (
        <section className="report__block">
          <h3>What to do</h3>
          <ul className="actions">
            {actions.map((a, i) => (
              <li key={i} className={`action action--${a.priority}`}>
                <span className="action__when">{PRIORITY_TEXT[a.priority]}</span>
                <span>
                  {a.text}
                  <Cites ids={a.sources} byId={byId} />
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {report.gaps.length > 0 && (
        <section className="report__block">
          <h3>What the evidence doesn't tell us</h3>
          <ul className="plain-list">
            {report.gaps.map((g, i) => <li key={i}>{g}</li>)}
          </ul>
        </section>
      )}

      <p className="report__byline">
        Written by {report.provider} ({report.model}){report.cached ? ", reused from an earlier identical investigation" : ""}.
        AI can make mistakes, so every statement links to the source it's based on.
        {report.removed_claims > 0 &&
          ` ${report.removed_claims} statement${report.removed_claims === 1 ? " was" : "s were"} removed because ${report.removed_claims === 1 ? "it" : "they"} didn't cite a source.`}
      </p>
    </section>
  );
}
