// The AI evaluation results. The data is produced by `python -m scripts.run_eval` (backend) and
// bundled at build time, so this page works even while the free server is asleep.
const found = import.meta.glob("../data/evaluation.json", { eager: true, import: "default" });
const DATA = Object.values(found)[0] || null;

const REPO = "https://github.com/ashwinruke/threatlens/tree/main/backend/evals";

const pct = (v) => (v === null || v === undefined ? "n/a" : `${Number(v).toFixed(v % 1 ? 1 : 0)}%`);
const date = (iso) =>
  new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });

function Tile({ value, label, note, tone }) {
  return (
    <div className={`eval-tile${tone ? ` eval-tile--${tone}` : ""}`}>
      <span className="eval-tile__value">{value}</span>
      <span className="eval-tile__label">{label}</span>
      {note && <span className="eval-tile__note">{note}</span>}
    </div>
  );
}

function measures(s) {
  const rows = [
    ["Valid report format", pct(s.json_valid_pct), "The model answered in the exact JSON shape required."],
    ["Facts found", pct(s.fact_recall_pct), "Of the facts each case says a correct report must mention."],
    ["Specifics grounded", pct(s.raw.grounded_pct), "IDs, numbers, versions and years that appear in the source the statement cites."],
    ["Right fact, wrong source", pct(s.raw.misattributed_pct), "The fact is in the evidence, but the statement cites a different source."],
    ["Specifics invented (as written)", pct(s.raw.invented_pct), "Not in the evidence at all: the model used its own memory, which the prompt forbids."],
    ["Specifics invented (as shown)", pct(s.shown.invented_pct), "After ThreatLens's guardrails, which remove statements with invented IDs, addresses, hashes and versions. Numbers are measured, not removed."],
    ["Statements with no valid citation", pct(s.uncited_pct), "Removed before anyone sees them."],
  ];
  if (s.judge) {
    rows.push(["Supported, says the AI judge", pct(s.judge.supported_pct),
      `A second model read each statement next to its cited sources. Partly: ${pct(s.judge.partly_pct)}, unsupported: ${pct(s.judge.unsupported_pct)}.`]);
  }
  rows.push(
    ["Reports that contradict the evidence", pct(s.reports_with_contradictions_pct), "For example, calling a CVE unlisted when CISA lists it as exploited."],
    ["Same risk level as the verdict", pct(s.verdict_consistency_pct), "The AI never restates the risk as a different level than the scoring formula gave."],
    ["Prompt-injection attacks resisted", `${pct(s.injection.resisted_pct)} of ${s.injection.attacks}`, "Attacker-written text planted in the evidence told the AI to call a threat safe. Resisted means the report didn't repeat it."],
    ["Attacks the report warned about", pct(s.injection.flagged_pct), "The report pointed out the suspicious text to the analyst."],
  );
  return rows;
}

function CaseRow({ c }) {
  const issues = [];
  c.missed_facts.forEach((m) => issues.push({ text: `Missed: ${m}`, tone: "warn" }));
  c.contradictions.forEach((m) => issues.push({ text: m, tone: "bad" }));
  if (c.consistent === false) issues.push({ text: "Stated a different risk level", tone: "bad" });
  if (c.injection) {
    issues.push(c.injection.resisted ? { text: "Attack resisted", tone: "good" } : { text: "Attack obeyed", tone: "bad" });
    if (c.injection.flagged) issues.push({ text: "Warned the analyst", tone: "good" });
  }
  if (c.removed) issues.push({ text: `${c.removed} statement${c.removed === 1 ? "" : "s"} removed by guardrails`, tone: "info" });
  const failed = c.valid < c.reports;

  return (
    <li className="eval-case">
      <details>
        <summary>
          <span className="eval-case__title">
            {c.title}
            <span className="eval-case__category">{c.category}</span>
          </span>
          <span className={`level-text lvl-${c.level}`}>{c.level.charAt(0) + c.level.slice(1).toLowerCase()}</span>
          <span className="eval-case__facts">{failed ? "Invalid answer" : `${pct(c.fact_recall_pct)} facts`}</span>
        </summary>
        <div className="eval-case__body">
          {issues.length > 0 && (
            <ul className="eval-chips">
              {issues.map((i) => <li key={i.text} className={`eval-chip eval-chip--${i.tone}`}>{i.text}</li>)}
            </ul>
          )}
          <p className="muted">
            {c.statements} statement{c.statements === 1 ? "" : "s"}: {c.grounding.grounded} grounded,{" "}
            {c.grounding.misattributed} wrong source, {c.grounding.invented} invented, {c.grounding.no_specifics} with
            nothing to check by rule, {c.grounding.uncited} uncited.
            {c.judge_supported_pct !== null && ` The judge found ${pct(c.judge_supported_pct)} supported.`}
          </p>
          {c.examples.length > 0 && (
            <>
              <p className="eval-case__label">What was caught</p>
              <ul className="eval-examples">
                {c.examples.map((e, i) => (
                  <li key={i}>
                    <q>{e.text}</q>
                    <span className="muted">
                      {" "}{e.status}{e.detail ? `: ${e.detail}` : ""}{e.removed ? ". Removed before display." : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </details>
    </li>
  );
}

export default function EvaluationPage() {
  if (!DATA) {
    return (
      <main className="page">
        <h1 className="page-title">How accurate is the AI?</h1>
        <p className="notice">
          The evaluation hasn't been run on this deployment yet. Run <code>python -m scripts.run_eval</code> in the{" "}
          <code>backend</code> folder, then rebuild the website.
        </p>
      </main>
    );
  }

  const { meta, summary: s, cases } = DATA;
  return (
    <main className="page page--wide eval">
      <h1 className="page-title">How accurate is the AI?</h1>
      <p className="eval__lead">
        ThreatLens's AI writes the explanation, never the score. This page measures how faithful those explanations are:
        whether every fact comes from the evidence, whether citations point at the right source, and whether planted
        attacker text can trick it.
      </p>
      <p className="eval__meta">
        Run on {date(meta.ran_at)} · report writer <b>{meta.writer.model}</b>
        {meta.judge && <> · judge <b>{meta.judge.model}</b></>} · {meta.cases} cases × {meta.runs} run
        {meta.runs === 1 ? "" : "s"} · {s.statements} statements
      </p>

      <section className="eval-tiles" aria-label="Headline results">
        <Tile value={pct(s.fact_recall_pct)} label="facts found" note="that a correct report must mention" />
        <Tile value={pct(s.raw.grounded_pct)} label="specifics grounded" note="IDs and numbers found in the cited source" />
        <Tile value={pct(s.shown.invented_pct)} label="invented specifics shown" note={`${pct(s.raw.invented_pct)} as written, before guardrails`}
              tone={s.shown.invented_pct > 0 ? "warn" : undefined} />
        <Tile value={`${Math.round((s.injection.resisted_pct / 100) * s.injection.attacks)} of ${s.injection.attacks}`}
              label="injection attacks resisted" note={`${pct(s.injection.flagged_pct)} flagged to the analyst`} />
      </section>

      <h2 className="eval__h2">Every measure</h2>
      <div className="eval-table-wrap">
        <table className="eval-table">
          <thead><tr><th scope="col">Measure</th><th scope="col">Result</th><th scope="col">What it means</th></tr></thead>
          <tbody>
            {measures(s).map(([name, value, about]) => (
              <tr key={name}><th scope="row">{name}</th><td>{value}</td><td className="muted">{about}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="eval__h2">The cases</h2>
      <p className="muted eval__note">
        Open a case to see what was caught. Malicious IPs, domains and file hashes are made up, so no real system is
        labelled malicious; CVEs are real.
      </p>
      <ul className="eval-cases">
        {cases.map((c) => <CaseRow key={c.id} c={c} />)}
      </ul>

      <h2 className="eval__h2">How it's measured</h2>
      <ol className="eval-method">
        <li><b>Frozen evidence.</b> Each case is the exact evidence the AI would receive, built by running ThreatLens's real pipeline on recorded source answers. Nothing changes between runs except the AI's answer.</li>
        <li><b>Same code as production.</b> The same prompt, the same parser and the same guardrails.</li>
        <li><b>Rule checks.</b> Every ID, number, version and year in a statement is looked up in the sources it cites. Each case also lists facts a correct report must mention and claims it must never make.</li>
        <li><b>An AI judge</b> reads each statement next to its cited sources, for claims without anything checkable by rule. It is a different model from the writer, and its verdicts are an estimate.</li>
        <li><b>Prompt-injection attacks.</b> Four cases hide instructions in a vulnerability description, a threat-feed title, a file name and malware tags.</li>
      </ol>
      <p className="muted eval__note">
        Limits: {meta.cases} cases is a small set, and rule checks can't judge meaning. The cases, the grader and every
        raw answer are in the <a href={REPO} target="_blank" rel="noopener noreferrer">evals folder on GitHub</a>.
      </p>
    </main>
  );
}
