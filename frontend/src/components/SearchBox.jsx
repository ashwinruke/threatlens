import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { typeName } from "../lib/format";
import { navigate } from "../lib/router";

const EXAMPLE = "CVE-2021-44228, 45.95.147.236, example.com, or a file hash";

export default function SearchBox({ autoFocus = false }) {
  const [query, setQuery] = useState("");
  const [hint, setHint] = useState(null); // { kind: "ok" | "error", text }
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);

  // Tell the user what ThreatLens thinks they typed, shortly after they stop typing
  useEffect(() => {
    setError(null);
    const text = query.trim();
    if (!text) {
      setHint(null);
      return;
    }
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const indicator = await api.detect(text, controller.signal);
        const parts = [typeName(indicator)];
        if (indicator.value.toLowerCase() !== text.toLowerCase()) parts.push(`will investigate ${indicator.value}`);
        if (indicator.refanged) parts.push("defanging removed");
        setHint({ kind: "ok", text: parts.join(", ") });
      } catch (err) {
        if (err.name === "AbortError") return;
        setHint(err.status === 422 ? { kind: "error", text: err.message } : null);
      }
    }, 350);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query]);

  useEffect(() => {
    if (!running) return;
    const started = Date.now();
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, [running]);

  async function submit(event) {
    event.preventDefault();
    const text = query.trim();
    if (!text || running) return;
    setRunning(true);
    setElapsed(0);
    setError(null);
    try {
      const result = await api.investigate(text);
      navigate(`/i/${result.id}`);
    } catch (err) {
      setError(err.message);
      setRunning(false);
      inputRef.current?.focus();
    }
  }

  let status = null;
  if (running) {
    status =
      elapsed < 25
        ? "Checking intelligence sources and writing the summary. This usually takes 5 to 20 seconds."
        : "Still working. If the server was asleep, the first investigation can take up to a minute.";
  }

  return (
    <form className="search" onSubmit={submit} role="search">
      <label htmlFor="query" className="visually-hidden">Indicator to investigate</label>
      <div className="search__row">
        <input
          id="query"
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={EXAMPLE}
          autoComplete="off"
          spellCheck="false"
          maxLength={500}
          autoFocus={autoFocus}
          disabled={running}
          aria-describedby="query-help"
          aria-invalid={hint?.kind === "error" || !!error}
        />
        <button type="submit" disabled={running || !query.trim() || hint?.kind === "error"}>
          {running ? `Investigating ${elapsed}s` : "Investigate"}
        </button>
      </div>
      <p id="query-help" className={`search__help ${error || hint?.kind === "error" ? "is-error" : ""}`} aria-live="polite">
        {error || status || hint?.text || "Defanged input like hxxps://evil[.]com works too."}
      </p>
    </form>
  );
}
