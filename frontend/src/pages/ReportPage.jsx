import { useEffect, useState } from "react";
import AiSummary from "../components/AiSummary";
import AttackMap from "../components/AttackMap";
import EvidenceGraph from "../components/EvidenceGraph";
import Research from "../components/Research";
import Lens from "../components/Lens";
import ScoreLedger from "../components/ScoreLedger";
import SourceList from "../components/SourceList";
import { Candidates, ProfileDetails, ProfileSide } from "../components/ThreatProfile";
import Timeline from "../components/Timeline";
import { api } from "../lib/api";
import { knowledgeBase, seconds, timeAgo, typeName } from "../lib/format";
import { Link } from "../lib/router";

const LEVEL_TEXT = {
  CRITICAL: "Critical risk",
  HIGH: "High risk",
  MEDIUM: "Medium risk",
  LOW: "Low risk",
  UNKNOWN: "Unknown risk",
  PROFILE: "Threat profile",
};

// A threat name that didn't resolve to one ATT&CK or CWE entry: no risk was assessed, so say what happened instead
const UNMATCHED_TEXT = { ambiguous: "Several matches", not_found: "No match", unavailable: "Not available" };

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

  const { indicator, verdict, threat } = data;
  const profile = threat?.status === "matched" ? threat.profile : null;
  const unmatched = threat && !profile;
  document.title = `${indicator.value}: ${unmatched ? UNMATCHED_TEXT[threat.status] || "No match" : LEVEL_TEXT[verdict.level]} | ThreatLens`;
  const lensLabel = profile
    ? `Threat profile for ${profile.entity.name}, ${knowledgeBase(profile.entity.kind)} ${profile.entity.external_id}`
    : `Risk score ${verdict.score} out of 100, ${verdict.level}`;

  return (
    <main className="page page--wide">
      <section className={`verdict lvl-${verdict.level}`}>
        <Lens score={verdict.score} level={verdict.level} size={176} label={lensLabel}
          badge={profile?.entity.external_id} base={profile ? knowledgeBase(profile.entity.kind) : undefined} />
        <div className="verdict__text">
          <p className="verdict__type">{typeName(indicator)}</p>
          <h1 className="verdict__value">{indicator.value}</h1>
          {indicator.notes.length > 0 && (
            <p className="verdict__note">You entered <code>{indicator.original}</code>. {indicator.notes.join(" ")}</p>
          )}
          <p className="verdict__level">
            <span className="level-pill">
              {unmatched ? UNMATCHED_TEXT[threat.status] || "No match"
                : profile?.entity.kind === "weakness" ? "Weakness profile" : LEVEL_TEXT[verdict.level]}
            </span>
            {!unmatched && (
              <span className="verdict__confidence">
                {profile ? `matched by ${threat.matched_on}` : `${verdict.confidence} confidence`}
              </span>
            )}
          </p>
          <p className="verdict__headline">{verdict.headline}</p>
          {verdict.rules_applied.length > 0 && profile && (
            <p className="verdict__note">{verdict.rules_applied.join(" ")}</p>
          )}
          <p className="verdict__meta">
            Investigated {timeAgo(data.created_at)}, took {seconds(data.duration_ms)}. <CopyLink />
          </p>
        </div>
      </section>

      {unmatched ? (
        <div className="report-single">
          <Candidates lookup={threat} />
          {threat.candidates.length === 0 && (
            <p className="notice">
              Try another spelling, an alias from a report (like "Cozy Bear"), an ATT&CK ID (like G1017), or a CWE ID (like CWE-79).
            </p>
          )}
        </div>
      ) : (
        <div className="report-grid">
          <div className="report-grid__main">
            <AiSummary report={data.report} />
            <Research run={data.research} />
          </div>
          <aside className="report-grid__side">
            {profile ? (
              <ProfileSide lookup={threat} />
            ) : (
              <>
                <ScoreLedger signals={data.signals} verdict={verdict} />
                <SourceList sources={data.sources} />
              </>
            )}
          </aside>
        </div>
      )}

      {profile && <ProfileDetails profile={profile} showTechniques={false} />}

      {!unmatched && <AttackMap id={data.id} showDefenses={!profile} />}

      {!unmatched && <EvidenceGraph id={data.id} level={verdict.level} />}

      <Timeline steps={data.trace} />
    </main>
  );
}
