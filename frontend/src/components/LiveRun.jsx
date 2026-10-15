import { seconds, STEP_KIND_TEXT } from "../lib/format";

const PROBLEMS = new Set(["error", "timeout", "rate_limited"]);
// Steps whose reason is worth reading while it happens: the verdict, and the agent's choices
const SHOW_REASON = new Set(["verdict", "research"]);

// The investigation as it happens: each decision-trail step appears when it's recorded,
// and the status line says what ThreatLens is waiting for right now.
export default function LiveRun({ query, steps, status, elapsed, finished }) {
  const waking = steps.length === 0 && elapsed >= 4;
  const line = finished
    ? "Done. Opening the report…"
    : waking
      ? "Waking up the server. After a quiet period, the first investigation can take up to a minute."
      : status || "Starting…";

  return (
    <section className="live" aria-label={`Investigating ${query}`}>
      <p className="live__head">
        <span className={`live__pulse ${finished ? "is-done" : ""}`} aria-hidden="true" />
        <span>
          Investigating <code>{query}</code>
        </span>
        <span className="live__elapsed">{elapsed}s</span>
      </p>
      {steps.length > 0 && (
        <ol className="live__steps">
          {steps.map((step) => (
            <li key={step.step} className={`live__step ${PROBLEMS.has(step.status) ? "is-problem" : ""}`}>
              <span className="live__kind">{STEP_KIND_TEXT[step.kind] || step.kind}</span>
              <span className="live__title">
                {step.title}
                {step.duration_ms != null && <span className="live__time">{seconds(step.duration_ms)}</span>}
                {(SHOW_REASON.has(step.kind) || PROBLEMS.has(step.status)) && step.reason && (
                  <span className="live__reason">{step.reason}</span>
                )}
              </span>
            </li>
          ))}
        </ol>
      )}
      <p className="live__status" aria-live="polite">{line}</p>
    </section>
  );
}
