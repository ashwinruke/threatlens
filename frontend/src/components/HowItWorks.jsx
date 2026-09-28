const STEPS = [
  {
    title: "Checks trusted sources",
    text: "Up to five intelligence sources at once, including NVD, CISA KEV, EPSS, AbuseIPDB, VirusTotal, OTX and abuse.ch. A source that fails never stops the investigation.",
  },
  {
    title: "Scores with a formula, not a guess",
    text: "Every point comes from a named piece of evidence, so the score is the same every time and you can see exactly where it came from.",
  },
  {
    title: "Explains, with a source for every claim",
    text: "An AI writes the summary and next steps from that evidence only. Statements without a real source are removed before you see them.",
  },
];

export default function HowItWorks() {
  return (
    <section className="how" aria-labelledby="how-title">
      <h2 id="how-title">How it works</h2>
      <ol className="how__list">
        {STEPS.map((step, index) => (
          <li key={step.title}>
            <span className="how__number" aria-hidden="true">{index + 1}</span>
            <div>
              <p className="how__title">{step.title}</p>
              <p className="how__text">{step.text}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
