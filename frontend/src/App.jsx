import { useCallback, useEffect, useRef, useState } from "react";

// Where the backend lives. Set VITE_API_URL on Vercel; falls back to local dev.
const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/+$/, "");

// Free hosting sleeps when idle, so the first request can take close to a minute.
const REQUEST_TIMEOUT_MS = 75_000;
const SLOW_HINT_AFTER_MS = 5_000;

async function callEndpoint(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const started = performance.now();
  try {
    const response = await fetch(`${API_URL}${path}`, { signal: controller.signal });
    const data = await response.json().catch(() => ({}));
    const ms = Math.round(performance.now() - started);
    return { ok: response.ok && data.status === "ok", data, ms };
  } catch (error) {
    const reason =
      error.name === "AbortError"
        ? "No answer after 75 seconds."
        : "Could not reach the server. Check the API address and CORS settings.";
    return { ok: false, data: { detail: reason }, ms: null };
  } finally {
    clearTimeout(timer);
  }
}

const INITIAL = { state: "waiting", data: null, ms: null };

export default function App() {
  const [api, setApi] = useState(INITIAL);
  const [db, setDb] = useState(INITIAL);
  const [slow, setSlow] = useState(false);
  const running = useRef(false);

  const runChecks = useCallback(async () => {
    if (running.current) return;
    running.current = true;
    setApi({ ...INITIAL, state: "checking" });
    setDb(INITIAL);
    setSlow(false);
    const slowTimer = setTimeout(() => setSlow(true), SLOW_HINT_AFTER_MS);

    const apiResult = await callEndpoint("/health");
    setApi({ state: apiResult.ok ? "ok" : "down", data: apiResult.data, ms: apiResult.ms });

    if (apiResult.ok) {
      setDb({ ...INITIAL, state: "checking" });
      const dbResult = await callEndpoint("/health/db");
      setDb({ state: dbResult.ok ? "ok" : "down", data: dbResult.data, ms: dbResult.ms });
    } else {
      setDb({ state: "skipped", data: null, ms: null });
    }

    clearTimeout(slowTimer);
    setSlow(false);
    running.current = false;
  }, []);

  useEffect(() => {
    runChecks();
  }, [runChecks]);

  const busy = api.state === "checking" || db.state === "checking";
  const overall = busy
    ? "checking"
    : api.state === "ok" && db.state === "ok"
      ? "ok"
      : "down";

  const summary = {
    checking: "Checking the system…",
    ok: "All systems are working.",
    down: "Something needs attention.",
  }[overall];

  return (
    <main className="page">
      <section className="hero">
        <div className={`lens lens--${overall}`} aria-hidden="true">
          <span className="lens__ring lens__ring--outer" />
          <span className="lens__ring lens__ring--inner" />
          <span className="lens__core" />
        </div>
        <div className="hero__text">
          <h1>ThreatLens</h1>
          <p className="tagline">See the threat before it sees you.</p>
          <p className="intro">
            Enter a CVE, IP address, domain, or file hash, and ThreatLens will investigate it,
            score the risk, and show every decision it made along the way.
          </p>
        </div>
      </section>

      <section className="status" aria-live="polite">
        <div className="status__head">
          <h2>{summary}</h2>
          <button type="button" onClick={runChecks} disabled={busy}>
            {busy ? "Checking" : "Check again"}
          </button>
        </div>

        {slow && busy && (
          <p className="hint">
            The server sleeps when nobody is using it and can take up to a minute to wake up.
          </p>
        )}

        <ul className="checks">
          <CheckRow
            name="API server"
            about="Receives investigations and runs them."
            result={api}
            okText={(d) => `Running version ${d.version}`}
          />
          <CheckRow
            name="Database"
            about="Stores investigations and threat knowledge."
            result={db}
            okText={(d) => (d.pgvector ? `Connected, vector search ${d.pgvector} ready` : "Connected, vector search not enabled yet")}
          />
        </ul>

        <p className="endpoint">
          API address <code>{API_URL}</code>
        </p>
      </section>

      <footer className="footer">
        Investigations arrive on Day 2. This page confirms the foundation is live.
      </footer>
    </main>
  );
}

function CheckRow({ name, about, result, okText }) {
  const { state, data, ms } = result;
  let text;
  if (state === "waiting") text = "Waiting";
  else if (state === "checking") text = "Checking";
  else if (state === "skipped") text = "Skipped until the API server responds";
  else if (state === "ok") text = okText(data);
  else if (data?.status === "not_configured") text = "Not set up yet: add DATABASE_URL";
  else text = data?.detail ? `Not working: ${data.detail}` : "Not working";

  return (
    <li className={`check check--${state}`}>
      <span className="check__dot" aria-hidden="true" />
      <div className="check__body">
        <p className="check__name">{name}</p>
        <p className="check__about">{about}</p>
      </div>
      <div className="check__result">
        <p>{text}</p>
        {ms !== null && <p className="check__ms">{ms} ms</p>}
      </div>
    </li>
  );
}
