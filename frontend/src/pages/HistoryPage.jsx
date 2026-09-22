import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Link } from "../lib/router";
import { InvestigationRows } from "./HomePage";

export default function HistoryPage() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.listInvestigations(50).then(setItems).catch((err) => setError(err.message));
  }, []);

  return (
    <main className="page">
      <h1 className="page-title">History</h1>
      {error && <p className="notice is-error">{error}</p>}
      {!items && !error && <p className="muted">Loading investigations…</p>}
      {items && items.length === 0 && (
        <p className="notice">
          No investigations yet. <Link to="/">Start one</Link> with a CVE, IP address, domain, or file hash.
        </p>
      )}
      {items && items.length > 0 && <InvestigationRows items={items} />}
    </main>
  );
}
