// A tiny router: enough for four pages without adding a library.
// vercel.json sends every path to index.html, so links like /i/<id> work when shared.
import { useEffect, useState } from "react";

export function navigate(to) {
  if (to === window.location.pathname) return;
  window.history.pushState({}, "", to);
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo(0, 0);
}

export function usePath() {
  const [path, setPath] = useState(window.location.pathname);
  useEffect(() => {
    const update = () => setPath(window.location.pathname);
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  return path;
}

export function Link({ to, children, ...props }) {
  function onClick(event) {
    // Let the browser handle new-tab clicks (Ctrl/Cmd/middle click)
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    navigate(to);
  }
  return (
    <a href={to} onClick={onClick} {...props}>
      {children}
    </a>
  );
}
