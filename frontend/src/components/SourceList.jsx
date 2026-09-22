import { humanize, SOURCE_STATUS_TEXT, seconds } from "../lib/format";

function Value({ name, value }) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    if (value.length && typeof value[0] === "object") {
      // e.g. NVD references: show them as links
      return (
        <ul className="plain-list">
          {value.map((item, i) =>
            item.url ? (
              <li key={i}>
                <a href={item.url} target="_blank" rel="noopener noreferrer nofollow">{item.url}</a>
                {item.tags?.length ? <span className="muted"> ({item.tags.join(", ")})</span> : null}
              </li>
            ) : (
              <li key={i}>{JSON.stringify(item)}</li>
            ),
          )}
        </ul>
      );
    }
    return value.join(", ");
  }
  if (value && typeof value === "object") {
    return Object.entries(value)
      .filter(([, v]) => v !== null && v !== "")
      .map(([k, v]) => `${humanize(k)}: ${v}`)
      .join("; ");
  }
  if (name === "probability" || name === "percentile") return `${(value * 100).toFixed(2)}%`;
  return String(value);
}

function Facts({ facts }) {
  const rows = Object.entries(facts).filter(
    ([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0) &&
      !(typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0),
  );
  if (!rows.length) return null;
  return (
    <dl className="facts">
      {rows.map(([k, v]) => (
        <div key={k} className="facts__row">
          <dt>{humanize(k)}</dt>
          <dd><Value name={k} value={v} /></dd>
        </div>
      ))}
    </dl>
  );
}

export default function SourceList({ sources }) {
  if (!sources.length) {
    return (
      <section className="panel" aria-labelledby="sources-title">
        <h2 id="sources-title">Sources</h2>
        <p className="muted">No outside sources were checked for this input.</p>
      </section>
    );
  }
  return (
    <section className="panel" aria-labelledby="sources-title">
      <h2 id="sources-title">Sources</h2>
      <ul className="sources">
        {sources.map((s) => (
          <li key={s.source} className={`source source--${s.status}`}>
            <details>
              <summary>
                <span className="source__dot" aria-hidden="true" />
                <span className="source__name">{s.source}</span>
                <span className="source__status">
                  {SOURCE_STATUS_TEXT[s.status]}
                  {s.cached ? ", saved copy" : s.duration_ms != null ? `, ${seconds(s.duration_ms)}` : ""}
                </span>
              </summary>
              <div className="source__body">
                {s.message && <p className="muted">{s.message}</p>}
                <Facts facts={s.facts} />
                {s.link && (
                  <a className="source__link" href={s.link} target="_blank" rel="noopener noreferrer nofollow">
                    Open in {s.source}
                  </a>
                )}
              </div>
            </details>
          </li>
        ))}
      </ul>
    </section>
  );
}
