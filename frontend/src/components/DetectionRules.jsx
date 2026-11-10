import { useState } from "react";
import { API_URL, api } from "../lib/api";

function External({ href, children }) {
  return <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>;
}

// Draft detection rules for a report or a bulk lookup. path is "investigations/<id>" or "bulk/<id>".
// Loaded only when opened: building and checking the rules takes the server a moment.
const TABS = [
  { id: "sigma", label: "Sigma", about: "The common rule format SIEMs import or convert." },
  { id: "splunk", label: "Splunk", about: "Ready-to-run searches, converted from the Sigma rules." },
  { id: "elastic", label: "Elastic", about: "Lucene queries for Elastic / Kibana, converted from the Sigma rules." },
  { id: "yara", label: "YARA", about: "Matches the exact file, for file scanners and EDR tools." },
];

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button type="button" className="button-secondary rules__copy" onClick={async () => {
      try {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      } catch {
        // clipboard blocked: the text is selectable
      }
    }}>{copied ? "Copied" : "Copy"}</button>
  );
}

export default function DetectionRules({ path, title = "Detection rules" }) {
  const [state, setState] = useState("closed"); // closed | loading | ready | error
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [tab, setTab] = useState("sigma");

  function open() {
    setState("loading");
    api.rules(path)
      .then((d) => {
        setData(d);
        setState("ready");
      })
      .catch((e) => {
        setError(e.message);
        setState("error");
      });
  }

  const tabs = data ? TABS.filter((t) => (t.id === "yara" ? data.yara : data.sigma)) : [];
  const text = !data ? "" : tab === "sigma" ? data.sigma : tab === "yara" ? data.yara
    : data.rules.map((r) => `# ${r.title}\n${r[tab]}`).join("\n\n");
  const base = `${API_URL}/api/${path}/export`;

  return (
    <section className="amap-wrap rules" aria-labelledby="rules-title">
      <div className="graph__head">
        <h2 id="rules-title">{title}</h2>
        {state === "closed" && <button type="button" className="button-secondary" onClick={open}>Write the rules</button>}
      </div>
      <p className="muted graph__hint">
        Draft rules to spot this in your own logs and files: Sigma for SIEMs (with Splunk and Elastic versions) and YARA for
        file hashes. Built from the evidence by fixed templates, not by AI, and checked with the official Sigma library.
        Review before deploying.
      </p>

      {state === "loading" && <p className="muted">Writing and checking the rules…</p>}
      {state === "error" && <p className="notice is-error">{error}</p>}
      {state === "ready" && (
        <>
          {data.notes.length > 0 && (
            <ul className="rules__notes">{data.notes.map((n) => <li key={n} className="muted">{n}</li>)}</ul>
          )}
          {data.links.length > 0 && (
            <ul className="rules__links">
              {data.links.map((l) => <li key={l.url}><External href={l.url}>{l.label}</External></li>)}
            </ul>
          )}
          {tabs.length > 0 && (
            <>
              <div className="rules__bar">
                <div className="tabs" role="tablist" aria-label="Rule format">
                  {tabs.map((t) => (
                    <button key={t.id} type="button" role="tab" aria-selected={tab === t.id}
                            className={`tab ${tab === t.id ? "is-active" : ""}`} onClick={() => setTab(t.id)}>{t.label}</button>
                  ))}
                </div>
                <span className="rules__actions">
                  <CopyButton text={text} />
                  {(tab === "sigma" || tab === "yara") && (
                    <a className="button-link" href={`${base}/${tab}`} download>Download {tab === "sigma" ? ".yml" : ".yar"}</a>
                  )}
                </span>
              </div>
              <p className="muted rules__about">{TABS.find((t) => t.id === tab)?.about}</p>
              <pre className="rules__code" tabIndex={0}><code>{text}</code></pre>
            </>
          )}
        </>
      )}
    </section>
  );
}
