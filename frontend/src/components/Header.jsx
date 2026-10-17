import { Link, usePath } from "../lib/router";
import { useServerStatus } from "../lib/serverStatus";
import Lens from "./Lens";
import ThemeSwitch from "./ThemeSwitch";

const SERVER_TEXT = {
  checking: ["Connecting", "Checking the ThreatLens server"],
  waking: ["Waking up", "The free server sleeps when idle and takes up to a minute to start"],
  online: ["Online", "The ThreatLens server is running"],
  offline: ["Offline", "The ThreatLens server isn't answering. Retrying automatically"],
  blocked: ["Offline", "The server answered, but the browser blocked the reply. See System status"],
};

function ServerStatus() {
  const { state } = useServerStatus();
  const [text, title] = SERVER_TEXT[state] || SERVER_TEXT.checking;
  return (
    <Link to="/status" className={`server server--${state}`} title={title} aria-live="polite">
      <span className="server__dot" aria-hidden="true" />
      {text}
    </Link>
  );
}

export default function Header() {
  const path = usePath();
  const current = (to) => {
    if (to === "/") return path === "/" || path.startsWith("/i/");
    if (to === "/bulk") return path.startsWith("/bulk") || path.startsWith("/b/");
    return path.startsWith(to);
  };
  return (
    <header className="topbar">
      <Link to="/" className="brand" aria-label="ThreatLens home">
        <Lens size={28} />
        <span>ThreatLens</span>
      </Link>
      <nav className="topnav" aria-label="Main">
        <Link to="/" aria-current={current("/") ? "page" : undefined}>Investigate</Link>
        <Link to="/bulk" aria-current={current("/bulk") ? "page" : undefined}>Bulk</Link>
        <Link to="/history" aria-current={current("/history") ? "page" : undefined}>History</Link>
      </nav>
      <ServerStatus />
      <ThemeSwitch />
    </header>
  );
}
