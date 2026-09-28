import { Link } from "../lib/router";
import { typeName } from "../lib/format";

// Ready-made investigations. A first-time visitor can see a real report in one click,
// even while the free backend is still waking up.
export default function Examples({ items }) {
  if (!items.length) return null;
  return (
    <section className="examples" aria-labelledby="examples-title">
      <h2 id="examples-title">Try an example</h2>
      <ul className="example-list">
        {items.map((item) => (
          <li key={item.slot}>
            <Link to={`/i/${item.investigation_id}`} className={`example lvl-${item.level}`}>
              <span className="example__head">
                <span className="example__label">{item.label}</span>
                <span className="example__score">{item.level === "UNKNOWN" ? "?" : item.score}</span>
              </span>
              <span className="example__value">{item.indicator_value}</span>
              <span className="example__note">{item.note}</span>
              <span className="example__type">{typeName({ type: item.indicator_type })}</span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
