import { useEffect, useState } from "react";
import AiSummary from "../components/AiSummary";
import Lens from "../components/Lens";
import ScoreLedger from "../components/ScoreLedger";
import SourceList from "../components/SourceList";
import Timeline from "../components/Timeline";
import { api } from "../lib/api";
import { seconds, timeAgo, typeName } from "../lib/format";
import { Link } from "../lib/router";

const LEVEL_TEXT = {
  CRITICAL: "Critical risk",
  HIGH: "High risk",
  MEDIUM: "Medium risk",
  LOW: "Low risk",
  UNKNOWN: "Unknown risk",
};

function CopyLink() {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard not available; the address bar still has the link */
    }
  }
  return (
    <button type="button" className="button-quiet" onClick={copy}>
      {copied ? "Link copied" : "Copy link"}
    </button>
  );
}

export default function ReportPage({ id }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setData(null);
    setError(null);
    api.getInvestigation(id).then(setData).catch(setError);
  }, [id]);

  if (error) {
    return (
      <main className="page">
        <h1 className="page-title">{error.status === 404 ? "Investigation not found" : "Couldn't load this investigation"}</h1>
        <p className="notice">
          {error.status === 404 ? "This link doesn't match any saved investigation." : error.message}{" "}
          <Link to="/">Start a new investigation</Link>.
        </p>
      </main>
    );
  }
  if (!data) {
    return (
      <main className="page">
        <p className="muted">Loading investigation…</p>
      </main>
    );
  }

  const { indicator, verdict } = data;
  document.title = `${indicator.value}: ${LEVEL_TEXT[verdict.level]} | ThreatLens`;

  return (
    <main className="page page--wide">
      <section className={`verdict lvl-${verdict.level}`}>
        <Lens score={verdict.score} level={verdict.level} size={176}
          label={`Risk score ${verdict.score} out of 100, ${verdict.level}`} />
        <div className="verdict__text">
          <p className="verdict__type">{typeName(indicator)}</p>
          <h1 className="verdict__value">{indicator.value}</h1>
          {indicator.notes.length > 0 && (
            <p className="verdict__note">You entered <code>{indicator.original}</code>. {indicator.notes.join(" ")}</p>
          )}
          <p className="verdict__level">
            <span className="level-pill">{LEVEL_TEXT[verdict.level]}</span>
            <span className="verdict__confidence">{verdict.confidence} confidence</span>
          </p>
          <p className="verdict__headline">{verdict.headline}</p>
          <p className="verdict__meta">
            Investigated {timeAgo(data.created_at)}, took {seconds(data.duration_ms)}. <CopyLink />
          </p>
        </div>
      </section>

      <div className="report-grid">
        <div className="report-grid__main">
          <AiSummary report={data.report} />
        </div>
        <aside className="report-grid__side">
          <ScoreLedger signals={data.signals} verdict={verdict} />
          <SourceList sources={data.sources} />
        </aside>
      </div>

      <Timeline steps={data.trace} />
    </main>
  );
}
