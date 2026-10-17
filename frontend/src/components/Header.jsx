import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Link, usePath } from "../lib/router";
import Lens from "./Lens";
import ThemeSwitch from "./ThemeSwitch";

function ServerStatus() {
  const [state, setState] = useState("checking");
  useEffect(() => {
    let alive = true;
    api.health()
      .then(() => alive && setState("online"))
      .catch(() => alive && setState("offline"));
    return () => {
      alive = false;
    };
  }, []);
  const text = { checking: "Connecting", online: "Online", offline: "Offline" }[state];
  return (
    <Link to="/status" className={`server server--${state}`} title="System status">
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
