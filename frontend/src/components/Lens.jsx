// The ThreatLens lens. On the home page it's the brand mark; on a report it becomes
// the risk gauge: the arc fills with the score and the core takes the risk level's color.
export default function Lens({ score = null, level = null, size = 168, label }) {
  const radius = 44;
  const circumference = 2 * Math.PI * radius;
  const known = score !== null && level && level !== "UNKNOWN";
  const filled = known ? (Math.max(0, Math.min(100, score)) / 100) * circumference : 0;

  return (
    <div
      className={`lens ${level ? `lvl-${level}` : "lens--idle"}`}
      style={{ width: size, height: size }}
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : "true"}
    >
      <svg viewBox="0 0 100 100" className="lens__svg">
        <circle className="lens__track" cx="50" cy="50" r={radius} />
        {level === "UNKNOWN" && <circle className="lens__unknown" cx="50" cy="50" r={radius} />}
        {!level && (
          <circle className="lens__glint" cx="50" cy="50" r={radius}
            strokeDasharray={`${circumference * 0.28} ${circumference}`} />
        )}
        {known && filled > 0 && (
          <circle className="lens__arc" cx="50" cy="50" r={radius}
            strokeDasharray={`${filled} ${circumference}`}
            style={{ "--full": circumference, "--filled": filled }} />
        )}
        <circle className="lens__inner" cx="50" cy="50" r="32" />
        <circle className="lens__core" cx="50" cy="50" r={level ? 24 : 15} />
      </svg>
      {level && (
        <div className="lens__score">
          <span className="lens__number">{level === "UNKNOWN" ? "?" : score}</span>
          {level !== "UNKNOWN" && <span className="lens__outof">of 100</span>}
        </div>
      )}
    </div>
  );
}
