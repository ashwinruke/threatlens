// Small numbered markers after each AI statement. Each opens the source it's based on.
// The links come from ThreatLens's own source data, never from the AI.
export function citationMap(citations) {
  const byId = new Map();
  citations.forEach((c, index) => byId.set(c.id, { ...c, number: index }));
  return byId;
}

export default function Cites({ ids, byId }) {
  return (
    <span className="cites">
      {ids.map((id) => {
        const c = byId.get(id);
        if (!c) return null;
        const label = c.number === 0 ? "TL" : c.number;
        const title = c.number === 0 ? "ThreatLens scoring signals" : `Source: ${c.source}`;
        return c.link ? (
          <a key={id} className="cite" href={c.link} target="_blank" rel="noopener noreferrer nofollow" title={title}>
            {label}
          </a>
        ) : (
          <span key={id} className="cite" title={title}>{label}</span>
        );
      })}
    </span>
  );
}
