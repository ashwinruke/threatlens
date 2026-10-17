import { useEffect, useState } from "react";
import { api, API_URL } from "../lib/api";
import { checkServer, useServerStatus } from "../lib/serverStatus";

// What each state of the API server means, in plain words
function apiText(server) {
  switch (server.state) {
    case "online":
      return { text: `Running version ${server.version}`, tone: "ok" };
    case "waking":
      return { text: "Waking up. The free server sleeps when nobody uses it and takes up to a minute to start. Retrying every few seconds.", tone: "checking" };
    case "blocked":
      return { text: "The server is answering, but the browser blocked its reply to this website.", tone: "down" };
    case "offline":
      return { text: `Not answering: ${server.detail || "no reply"} Retrying every 30 seconds.`, tone: "down" };
    default:
      return { text: "Checking", tone: "checking" };
  }
}

function Row({ name, about, tone, text }) {
  return (
    <li className={`check check--${tone}`}>
      <span className="check__dot" aria-hidden="true" />
      <div>
        <p className="check__name">{name}</p>
        <p className="muted">{about}</p>
      </div>
      <p className="check__result">{text}</p>
    </li>
  );
}

export default function StatusPage() {
  const server = useServerStatus();
  const [db, setDb] = useState({ tone: "waiting", text: "Waiting for the API server" });
  const [checking, setChecking] = useState(false);

  // The database is checked through the API, so only once the API answers
  useEffect(() => {
    if (server.state !== "online") {
      setDb({ tone: "waiting", text: "Waiting for the API server" });
      return;
    }
    let alive = true;
    setDb({ tone: "checking", text: "Checking" });
    api.healthDb()
      .then((data) => alive && setDb(data.status === "ok"
        ? { tone: "ok", text: "Connected" }
        : { tone: "down", text: `Not working: ${data.detail || data.status}` }))
      .catch((error) => alive && setDb({ tone: "down", text: `Not working: ${error.message}` }));
    return () => {
      alive = false;
    };
  }, [server.state, server.checkedAt]);

  async function again() {
    setChecking(true);
    await checkServer();
    setChecking(false);
  }

  const api_ = apiText(server);
  return (
    <main className="page">
      <h1 className="page-title">System status</h1>
      <p className="muted">
        The server sleeps when nobody is using it and can take up to a minute to wake up. This page keeps checking by itself.
      </p>
      <ul className="checks">
        <Row name="API server" about="Receives investigations and runs them." tone={api_.tone} text={api_.text} />
        <Row name="Database" about="Stores investigations and saved source answers." tone={db.tone} text={db.text} />
      </ul>

      {server.state === "blocked" && (
        <div className="notice is-error status-fix">
          <p>
            <b>How to fix it.</b> The server only lets listed websites read its answers. This website's address is{" "}
            <code>{window.location.origin}</code>. On Render, open the ThreatLens service, go to <b>Environment</b>, and add
            it to <code>CORS_ORIGINS</code> (separate addresses with commas). The server restarts with the new setting.
          </p>
          <p className="muted">
            If you just deployed, wait a minute first: while the server restarts, its replies are blocked the same way.
          </p>
        </div>
      )}

      <p className="muted">API address <code>{API_URL}</code></p>
      <p className="muted">This website <code>{window.location.origin}</code></p>
      <button type="button" onClick={again} disabled={checking}>{checking ? "Checking" : "Check again"}</button>
    </main>
  );
}
