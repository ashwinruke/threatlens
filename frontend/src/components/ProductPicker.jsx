import { useEffect, useState } from "react";
import { api } from "../lib/api";

// Search NVD's product dictionary and pick a product, so "nginx" means the real nginx
export default function ProductPicker({ onPick, chosen = [], disabled = false }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [state, setState] = useState("idle"); // idle | searching | done | error
  const [error, setError] = useState("");

  useEffect(() => {
    const q = query.trim();
    if (q.length < 2) {
      setResults([]);
      setState("idle");
      return;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setState("searching");
      api.products(q, controller.signal)
        .then((found) => {
          setResults(found);
          setState("done");
        })
        .catch((e) => {
          if (controller.signal.aborted) return;
          setError(e.message);
          setState("error");
        });
    }, 450);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query]);

  const isChosen = (p) => chosen.some((c) => c.part === p.part && c.vendor === p.vendor && c.product === p.product);

  return (
    <div className="picker">
      <input
        type="search" value={query} onChange={(e) => setQuery(e.target.value)} disabled={disabled}
        placeholder="Search a product: nginx, log4j, windows server, fortios…" aria-label="Search for a product"
        className="field"
      />
      {state === "searching" && <p className="muted picker__note">Searching NVD's product list…</p>}
      {state === "error" && <p className="picker__note is-error">{error}</p>}
      {state === "done" && results.length === 0 && (
        <p className="muted picker__note">No products by that name. Try the vendor's spelling, like "exchange server".</p>
      )}
      {results.length > 0 && (
        <ul className="picker__results">
          {results.map((p) => (
            <li key={`${p.part}:${p.vendor}:${p.product}`}>
              <button type="button" className="picker__result" disabled={disabled || isChosen(p)}
                      onClick={() => onPick({ part: p.part, vendor: p.vendor, product: p.product, title: p.title })}>
                <span className="picker__title">{p.title}</span>
                <span className="picker__meta">
                  {p.vendor}:{p.product} · {p.kind} · {p.versions} version{p.versions === 1 ? "" : "s"}
                </span>
                <span className="picker__add">{isChosen(p) ? "Added" : "Add"}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
