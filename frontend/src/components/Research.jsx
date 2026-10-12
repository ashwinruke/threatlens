import { seconds } from "../lib/format";

const TOOL_LABELS = {
  search_attack: "Searched ATT&CK",
  attack_profile: "ATT&CK entry",
  attack_mentions: "ATT&CK mentions",
  investigate_indicator: "Related indicator",
};

// What the research agent chose to look up, why, and what it found.
// Hidden when it didn't run; the decision trail below still says why.
export default function Research({ run }) {
  if (!run || run.steps.length === 0) return null;
  const cost = run.cached
    ? "Reused the research saved for this same evidence."
    : `${run.ai_calls} AI decision${run.ai_calls === 1 ? "" : "s"} by ${run.provider} (${run.model})` +
      (run.duration_ms != null ? `, ${seconds(run.duration_ms)}` : "") + ".";

  return (
    <section className="research" aria-labelledby="research-title">
      <h2 id="research-title">What the agent looked into</h2>
      <p className="muted research__intro">
        After scoring, an AI agent chose what to look up next, using read-only tools and a small budget. Its findings
        are cited in the summary. They never change the score.
      </p>

      {run.leads.length > 0 && (
        <details className="research__leads">
          <summary>Started from {run.leads.length} lead{run.leads.length === 1 ? "" : "s"} in the evidence</summary>
          <ul className="plain-list">
            {run.leads.map((lead) => <li key={lead}>{lead}</li>)}
          </ul>
        </details>
      )}

      <ol className="research__steps">
        {run.steps.map((step) => (
          <li key={step.id} className={`rstep ${step.ok ? "" : "rstep--empty"}`}>
            <span className="rstep__id">{step.id}</span>
            <div className="rstep__body">
              <p className="rstep__title">
                <span className="rstep__tool">{TOOL_LABELS[step.tool] || step.tool}</span>
                <code>{step.input}</code>
              </p>
              <p className="rstep__why">{step.why}</p>
              <p className="rstep__found">
                {step.summary}
                {step.link && (
                  <>
                    {" "}
                    <a href={step.link} target="_blank" rel="noopener noreferrer nofollow">Verify</a>
                  </>
                )}
              </p>
            </div>
          </li>
        ))}
      </ol>

      <p className="research__end">
        <span>{run.status === "done" ? "Finished" : "Stopped"}: {run.reason}</span>
        <span className="muted">{cost}</span>
      </p>
    </section>
  );
}
