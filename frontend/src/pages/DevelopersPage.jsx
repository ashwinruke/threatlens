import { useState } from "react";
import { API_URL, api } from "../lib/api";

const ENDPOINTS = [
  ["POST", "/v1/lookup", "Investigate one indicator: verdict, score, evidence, sources. Add \"ai_summary\": true for the cited AI summary.", "1"],
  ["POST", "/v1/lookup/batch", "Up to 20 indicators at once, results in the order sent.", "1 each"],
  ["GET", "/v1/investigations/{id}", "A saved investigation, by its id.", "0"],
  ["GET", "/v1/investigations/{id}/rules", "Draft Sigma and YARA rules, with Splunk and Elastic searches.", "0"],
  ["GET", "/v1/investigations/{id}/stix", "The investigation as a STIX 2.1 bundle.", "0"],
  ["GET", "/v1/usage", "This key's allowance today.", "0"],
  ["DELETE", "/v1/key", "Revoke this key for good, for example if it leaked.", "0"],
];

const ERRORS = [
  ["401", "No key, a wrong key, or a revoked one."],
  ["422", "The input isn't one indicator ThreatLens understands, or a batch has more than 20."],
  ["429", "The key's daily allowance or per-minute limit is used up. The Retry-After header says when to try again."],
  ["503", "ThreatLens has reached its daily limit for everyone. Try again tomorrow."],
];

const EXAMPLE = `{
  "id": "3f2a9c1e-…",
  "indicator": { "type": "cve", "value": "CVE-2021-44228", "subtype": null },
  "verdict": {
    "level": "CRITICAL", "score": 95, "confidence": "high",
    "headline": "CVE-2021-44228 is CRITICAL risk: CVSS 10.0, actively exploited (CISA KEV)."
  },
  "signals": [
    { "label": "CVSS 3.1 severity 10.0 (CRITICAL)", "points": 40, "source": "NVD", "evidence": "…" },
    { "label": "Exploited in real attacks (CISA KEV)", "points": 30, "source": "CISA KEV", "evidence": "…" }
  ],
  "sources": [ { "name": "NVD", "status": "ok", "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "message": null } ],
  "ai_summary": null,
  "threat": null,
  "report_url": "https://threatlens-xi.vercel.app/i/3f2a9c1e-…",
  "links": { "self": "/v1/investigations/3f2a9c1e-…", "rules": "…/rules", "stix": "…/stix" },
  "created_at": "2026-11-10T09:30:00+00:00"
}`;

function examples(key) {
  const k = key || "tl_your_key_here";
  return {
    curl: `curl -X POST ${API_URL}/v1/lookup \\
  -H "Authorization: Bearer ${k}" \\
  -H "Content-Type: application/json" \\
  -d '{"indicator": "CVE-2021-44228"}'`,
    python: `import requests

API = "${API_URL}"
KEY = "${k}"

# The free server can take up to a minute to wake up, so allow a long timeout
response = requests.post(f"{API}/v1/lookup", json={"indicator": "CVE-2021-44228"},
                         headers={"Authorization": f"Bearer {KEY}"}, timeout=120)
response.raise_for_status()
result = response.json()
print(result["verdict"]["level"], result["verdict"]["score"], result["report_url"])

# Rules for your SIEM
rules = requests.get(f"{API}{result['links']['rules']}", headers={"Authorization": f"Bearer {KEY}"}, timeout=60).json()
print(rules["sigma"] or rules["notes"])`,
    powershell: `$headers = @{ Authorization = "Bearer ${k}" }
$body = @{ indicator = "CVE-2021-44228" } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri "${API_URL}/v1/lookup" \`
  -Headers $headers -ContentType "application/json" -Body $body -TimeoutSec 120
"$($result.verdict.level) $($result.verdict.score) $($result.report_url)"`,
  };
}

function Copy({ text }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="button-secondary rules__copy" onClick={async () => {
      try {
        await navigator.clipboard.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1800);
      } catch {
        // clipboard blocked: the text is selectable
      }
    }}>{done ? "Copied" : "Copy"}</button>
  );
}

function KeyForm({ onKey }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [made, setMade] = useState(null);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const key = await api.createApiKey(name.trim() || "My integration");
      setMade(key);
      onKey(key.key);
    } catch (e) {
      setError(e.message);
    }
    setBusy(false);
  }

  if (made) {
    return (
      <div className="panel dev-key">
        <p><b>Your API key.</b> Copy it now: it won't be shown again, and only a scrambled version is stored.</p>
        <div className="dev-key__row">
          <code className="dev-key__value">{made.key}</code>
          <Copy text={made.key} />
        </div>
        <p className="muted">
          {made.daily_limit} indicators a day, {made.per_minute_limit} requests a minute. Keep it out of public code;
          if it leaks, revoke it with <code>DELETE /v1/key</code> and make another.
        </p>
      </div>
    );
  }
  return (
    <form className="panel dev-key" onSubmit={submit}>
      <label className="watch-label" htmlFor="key-name">What's it for?</label>
      <div className="watch-row">
        <input id="key-name" className="field" value={name} maxLength={60} onChange={(e) => setName(e.target.value)}
               placeholder="SOC alert enrichment, a Python script, a SOAR playbook…" />
        <button type="submit" disabled={busy}>{busy ? "Making…" : "Get a free key"}</button>
      </div>
      {error && <p className="picker__note is-error">{error}</p>}
    </form>
  );
}

export default function DevelopersPage() {
  const [key, setKey] = useState("");
  const [lang, setLang] = useState("curl");
  const code = examples(key)[lang];

  return (
    <main className="page page--wide dev">
      <h1 className="page-title">ThreatLens API</h1>
      <p className="watch__lead">
        Let your security tools ask ThreatLens directly: send an IP, domain, hash, CVE or threat name from an alert pipeline,
        a script or a SOAR playbook, and get the verdict, the evidence behind it and detection rules back as JSON. Free.
      </p>

      <h2 className="eval__h2">1. Get a key</h2>
      <KeyForm onKey={setKey} />

      <h2 className="eval__h2">2. Make a request</h2>
      <div className="rules__bar">
        <div className="tabs" role="tablist" aria-label="Language">
          {[["curl", "curl"], ["python", "Python"], ["powershell", "PowerShell"]].map(([id, label]) => (
            <button key={id} type="button" role="tab" aria-selected={lang === id} className={`tab ${lang === id ? "is-active" : ""}`}
                    onClick={() => setLang(id)}>{label}</button>
          ))}
        </div>
        <Copy text={code} />
      </div>
      <pre className="rules__code dev-code"><code>{code}</code></pre>
      <p className="muted rules__about">
        The first request after a quiet spell can take up to a minute while the free server wakes, so use a long timeout.
      </p>

      <h2 className="eval__h2">3. Read the answer</h2>
      <p className="muted eval__note">
        The verdict comes from ThreatLens's published scoring formula, never from AI. Fields may be added within v1, but
        never renamed or removed.
      </p>
      <pre className="rules__code dev-code"><code>{EXAMPLE}</code></pre>

      <h2 className="eval__h2">Endpoints</h2>
      <div className="eval-table-wrap">
        <table className="eval-table dev-table">
          <thead><tr><th scope="col">Endpoint</th><th scope="col">What it does</th><th scope="col">Units</th></tr></thead>
          <tbody>
            {ENDPOINTS.map(([method, path, about, units]) => (
              <tr key={method + path}>
                <th scope="row"><code>{method} {path}</code></th>
                <td className="muted">{about}</td>
                <td>{units}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted eval__note">
        Send the key as <code>Authorization: Bearer tl_…</code> (or <code>X-API-Key</code>). Every response to a lookup
        carries <code>X-RateLimit-Remaining</code>. Try every endpoint in the browser with the{" "}
        <a href={`${API_URL}/docs`} target="_blank" rel="noopener noreferrer">interactive API docs</a>.
      </p>

      <h2 className="eval__h2">Limits</h2>
      <ul className="eval-method dev-list">
        <li><b>200 indicators a day per key</b> (resets at midnight UTC), <b>30 requests a minute</b>.</li>
        <li>The API shares ThreatLens's daily limits with the website, so the free tiers it runs on stay healthy.</li>
        <li>AI summaries are optional and also count toward the site's daily AI limit; when it's reached, lookups still work without them.</li>
        <li>Lookups made through the API are saved unlisted: their report links work, but they never appear in the public History.</li>
      </ul>

      <h2 className="eval__h2">Errors</h2>
      <div className="eval-table-wrap">
        <table className="eval-table dev-table">
          <tbody>
            {ERRORS.map(([code, about]) => <tr key={code}><th scope="row"><code>{code}</code></th><td className="muted">{about}</td></tr>)}
          </tbody>
        </table>
      </div>
      <p className="muted eval__note">Every error is JSON with a plain-language <code>detail</code>.</p>
    </main>
  );
}
