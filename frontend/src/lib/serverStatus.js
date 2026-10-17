// Is the ThreatLens server reachable? One shared checker, so the header dot and the status page agree.
//
// Why this is more than one request: the backend runs on a free plan that sleeps when idle and takes
// up to a minute to wake, and while it restarts the hosting returns errors the browser can't read.
// A single failed check would show "Offline" until the page is reloaded, even after the server is fine.
// So the checker:
//   - shows "waking" (not "offline") for the first two minutes of failures, retrying every 5 seconds
//   - keeps retrying after that, every 30 seconds, and immediately when the tab gets focus again
//   - tells "no answer at all" apart from "the server answered but the browser blocked the reply"
//     (the website's address is missing from the server's CORS settings), so the fix is obvious
import { useEffect, useState } from "react";
import { API_URL, api } from "./api";

const WAKE_WINDOW_MS = 120_000; // how long failures count as "still waking up"
const BLOCKED_WINDOW_MS = 30_000; // a restarting server's error pages are also unreadable, briefly
const RETRY_WAKING_MS = 5_000;
const RETRY_DOWN_MS = 30_000;
const RECHECK_ONLINE_MS = 300_000;
const SLOW_ANSWER_MS = 4_000; // a check taking longer than this means the server is starting up

let status = { state: "checking", version: null, detail: null, checkedAt: 0 };
let failingSince = null;
let inflight = null;
let timer = null;
let listening = false;
const listeners = new Set();

function update(next) {
  status = { ...status, ...next };
  listeners.forEach((listener) => listener(status));
}

// A request the browser is allowed to send without reading the reply. If this succeeds where the
// normal request failed, the server is up but the browser refused to show its answer to this website.
async function answersAtAll() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    await fetch(`${API_URL}/health`, { mode: "no-cors", cache: "no-store", signal: controller.signal });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

function schedule() {
  clearTimeout(timer);
  const delay = status.state === "online" ? RECHECK_ONLINE_MS : status.state === "waking" ? RETRY_WAKING_MS : RETRY_DOWN_MS;
  timer = setTimeout(() => {
    if (document.hidden) schedule(); // no checks while nobody is looking; focus triggers one
    else checkServer();
  }, delay);
}

export function checkServer() {
  if (inflight) return inflight;
  // A slow answer is a sleeping server waking up, not a failure: say so while waiting
  const slow = setTimeout(() => {
    if (status.state !== "online") update({ state: "waking", detail: "The server is starting up. This can take up to a minute." });
  }, SLOW_ANSWER_MS);

  inflight = (async () => {
    try {
      const data = await api.health();
      failingSince = null;
      update({ state: "online", version: data.version, detail: null, checkedAt: Date.now() });
    } catch (error) {
      failingSince ??= Date.now();
      const failingFor = Date.now() - failingSince;
      const blocked = error.kind === "network" && (await answersAtAll());
      const stillWaking = failingFor < (blocked ? BLOCKED_WINDOW_MS : WAKE_WINDOW_MS);
      if (stillWaking) {
        update({ state: "waking", detail: "The server is starting up. This can take up to a minute.", checkedAt: Date.now() });
      } else if (blocked) {
        update({ state: "blocked", detail: error.message, checkedAt: Date.now() });
      } else {
        update({ state: "offline", detail: error.message, checkedAt: Date.now() });
      }
    } finally {
      clearTimeout(slow);
      inflight = null;
      schedule();
    }
    return status;
  })();
  return inflight;
}

function startListening() {
  if (listening) return;
  listening = true;
  const recheckSoon = () => {
    if (!document.hidden && status.state !== "online") checkServer();
  };
  window.addEventListener("focus", recheckSoon);
  window.addEventListener("online", () => checkServer());
  document.addEventListener("visibilitychange", recheckSoon);
}

export function useServerStatus() {
  const [current, setCurrent] = useState(status);
  useEffect(() => {
    listeners.add(setCurrent);
    startListening();
    if (!status.checkedAt && !inflight) checkServer();
    setCurrent(status);
    return () => listeners.delete(setCurrent);
  }, []);
  return current;
}
