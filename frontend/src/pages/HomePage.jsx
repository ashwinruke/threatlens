import { useEffect, useState } from "react";
import Lens from "../components/Lens";
import SearchBox from "../components/SearchBox";
import { api } from "../lib/api";
import { TYPE_NAMES, timeAgo } from "../lib/format";
import { Link } from "../lib/router";

export function InvestigationRows({ items }) {
  return (
    <ul className="rows">
      {items.map((item) => (
        <li key={item.id}>
          <Link to={`/i/${item.id}`} className="row">
            <span className={`level-text lvl-${item.level}`}>{item.level}</span>
            <span className="row__value">{item.indicator_value}</span>
            <span className="row__type">{TYPE_NAMES[item.indicator_type]}</span>
            <span className="row__when">{timeAgo(item.created_at)}</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

export default function HomePage() {
  const [recent, setRecent] = useState(null);

  useEffect(() => {
    api.listInvestigations(5).then(setRecent).catch(() => setRecent([]));
  }, []);

  return (
    <main className="page">
      <section className="hero">
        <Lens size={132} />
        <div className="hero__text">
          <h1>ThreatLens</h1>
          <p className="tagline">See the threat before it sees you.</p>
          <p className="intro">
            Enter a CVE, IP address, domain, or file hash. ThreatLens checks trusted intelligence sources,
            scores the risk with a formula you can inspect, and explains what to do.
          </p>
        </div>
      </section>

      <SearchBox autoFocus />

      {recent && recent.length > 0 && (
        <section className="recent" aria-labelledby="recent-title">
          <div className="recent__head">
            <h2 id="recent-title">Recent investigations</h2>
            <Link to="/history">See all</Link>
          </div>
          <InvestigationRows items={recent} />
        </section>
      )}
    </main>
  );
}
