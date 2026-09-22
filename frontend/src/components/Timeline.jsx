import { seconds, STEP_KIND_TEXT } from "../lib/format";

const PROBLEMS = new Set(["error", "timeout", "rate_limited"]);

// Every step ThreatLens took, in order, with the reason for each decision.
export default function Timeline({ steps }) {
  return (
    <section className="timeline-wrap" aria-labelledby="timeline-title">
      <h2 id="timeline-title">How ThreatLens decided</h2>
      <ol className="timeline">
        {steps.map((step) => (
          <li key={step.step} className={`step step--${step.kind} ${PROBLEMS.has(step.status) ? "step--problem" : ""}`}>
            <span className="step__number" aria-hidden="true">{step.step}</span>
            <div className="step__body">
              <p className="step__title">
                <span className="step__kind">{STEP_KIND_TEXT[step.kind] || step.kind}</span>
                {step.title}
                {step.duration_ms != null && <span className="step__time">{seconds(step.duration_ms)}</span>}
              </p>
              {step.reason && <p className="step__reason">{step.reason}</p>}
              {step.detail?.signals?.length > 0 && (
                <p className="step__reason">
                  {step.detail.signals.length} signal{step.detail.signals.length === 1 ? "" : "s"} used. See the score breakdown.
                </p>
              )}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
