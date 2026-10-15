import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import LiveRun from "./LiveRun";
import { typeName } from "../lib/format";
import { navigate } from "../lib/router";

const EXAMPLE = "CVE-2021-44228, an IP, a domain, a file hash, or a threat like Volt Typhoon";

export default function SearchBox({ autoFocus = false }) {
  const [query, setQuery] = useState("");
  const [hint, setHint] = useState(null); // { kind: "ok" | "error", text }
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState(null);
  const [steps, setSteps] = useState([]);
  const [liveStatus, setLiveStatus] = useState(null);
  const [submitted, setSubmitted] = useState("");
  const [finished, setFinished] = useState(false);
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
        if (indicator.type === "threat") {
          setHint({ kind: "ok", text: /^CWE-\d+$/.test(indicator.value)
            ? "Software weakness: ThreatLens will look it up in MITRE CWE"
            : "Threat name or weakness: ThreatLens will look it up in MITRE ATT&CK and CWE" });
          return;
        }
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
    setSteps([]);
    setLiveStatus(null);
    setFinished(false);
    setSubmitted(text);
    try {
      const result = await api.investigateLive(text, {
        onStep: (step) => setSteps((previous) => [...previous, step]),
        onStatus: setLiveStatus,
      });
      setFinished(true);
      // A short pause so the last steps can be seen before the report replaces them
      setTimeout(() => navigate(`/i/${result.id}`), 600);
    } catch (err) {
      setError(err.message);
      setRunning(false);
      inputRef.current?.focus();
    }
  }

  return (
    <>
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
          {error || (running ? "" : hint?.text || "Defanged input like hxxps://evil[.]com works too.")}
        </p>
      </form>
      {running && (
        <LiveRun query={submitted} steps={steps} status={liveStatus} elapsed={elapsed} finished={finished} />
      )}
    </>
  );
}
