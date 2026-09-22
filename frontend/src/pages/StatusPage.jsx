import { useCallback, useEffect, useState } from "react";
import { api, API_URL } from "../lib/api";
import { seconds } from "../lib/format";

async function timed(call) {
  const started = performance.now();
  try {
    const data = await call();
    return { state: data.status === "ok" ? "ok" : "down", data, ms: Math.round(performance.now() - started) };
  } catch (error) {
    return { state: "down", data: { detail: error.message }, ms: null };
  }
}

function Row({ name, about, result, okText }) {
  const text =
    result.state === "checking" ? "Checking"
      : result.state === "waiting" ? "Waiting"
        : result.state === "ok" ? okText(result.data)
          : `Not working: ${result.data?.detail || "no answer"}`;
  return (
    <li className={`check check--${result.state}`}>
      <span className="check__dot" aria-hidden="true" />
      <div>
        <p className="check__name">{name}</p>
        <p className="muted">{about}</p>
      </div>
      <p className="check__result">
        {text}
        {result.ms != null && <span className="muted"> {seconds(result.ms)}</span>}
      </p>
    </li>
  );
}

export default function StatusPage() {
  const [apiState, setApi] = useState({ state: "waiting" });
  const [db, setDb] = useState({ state: "waiting" });

  const run = useCallback(async () => {
    setApi({ state: "checking" });
    setDb({ state: "waiting" });
    const a = await timed(api.health);
    setApi(a);
    if (a.state === "ok") {
      setDb({ state: "checking" });
      setDb(await timed(api.healthDb));
    }
  }, []);

  useEffect(() => {
    run();
  }, [run]);

  const busy = apiState.state === "checking" || db.state === "checking";
  return (
    <main className="page">
      <h1 className="page-title">System status</h1>
      <p className="muted">
        The server sleeps when nobody is using it and can take up to a minute to wake up.
      </p>
      <ul className="checks">
        <Row name="API server" about="Receives investigations and runs them." result={apiState}
          okText={(d) => `Running version ${d.version}`} />
        <Row name="Database" about="Stores investigations and saved source answers." result={db}
          okText={(d) => `Connected${d.pgvector ? `, vector search ${d.pgvector}` : ""}`} />
      </ul>
      <p className="muted">API address <code>{API_URL}</code></p>
      <button type="button" onClick={run} disabled={busy}>{busy ? "Checking" : "Check again"}</button>
    </main>
  );
}
