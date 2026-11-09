// Watchlists this browser can open. There are no accounts: each watchlist has a private key,
// kept here and in its private link (after the #, so it never reaches a server log).
const STORE = "threatlens-watchlists";

export const LEVELS = [
  { value: "CRITICAL", label: "Critical only" },
  { value: "HIGH", label: "High and critical" },
  { value: "MEDIUM", label: "Medium and above" },
];

export const VERDICTS = [
  { value: "confirmed", label: "Confirmed threat", short: "Confirmed", tone: "bad" },
  { value: "false_alarm", label: "False alarm", short: "False alarm", tone: "muted" },
  { value: "not_affected", label: "Not affected", short: "Not affected", tone: "muted" },
  { value: "resolved", label: "Resolved", short: "Resolved", tone: "good" },
];
export const VERDICT_LABEL = Object.fromEntries(VERDICTS.map((v) => [v.value, v.label]));
VERDICT_LABEL.new = "Needs triage";

export const CHANNELS = {
  discord: { label: "Discord", placeholder: "https://discord.com/api/webhooks/…",
    help: "In Discord: channel settings → Integrations → Webhooks → New Webhook → Copy Webhook URL." },
  slack: { label: "Slack", placeholder: "https://hooks.slack.com/services/…",
    help: "In Slack: create an app with Incoming Webhooks turned on, add it to a channel, and copy the webhook URL." },
  teams: { label: "Microsoft Teams", placeholder: "https://…webhook.office.com/… or …logic.azure.com/…",
    help: "In Teams: the channel's ••• menu → Workflows → \"Post to a channel when a webhook request is received\" → copy the URL." },
  ntfy: { label: "Phone push (ntfy)", placeholder: "https://ntfy.sh/a-long-random-topic-name",
    help: "Install the free ntfy app, subscribe to a topic name nobody could guess, and paste https://ntfy.sh/<that topic>." },
  email: { label: "Email", placeholder: "you@example.com",
    help: "Sent through the server's email service." },
};

function read() {
  try {
    const list = JSON.parse(localStorage.getItem(STORE) || "[]");
    return Array.isArray(list) ? list.filter((w) => w && w.id && w.key) : [];
  } catch {
    return [];
  }
}

function write(list) {
  try {
    localStorage.setItem(STORE, JSON.stringify(list));
  } catch {
    // storage blocked: the private link still works
  }
}

export function savedWatchlists() {
  return read();
}

export function remember(id, key, name) {
  const list = read().filter((w) => w.id !== id);
  list.unshift({ id, key, name });
  write(list);
}

export function forget(id) {
  write(read().filter((w) => w.id !== id));
}

// The key from this page's link (#key=…), else the one saved in this browser
export function keyFor(id) {
  const fromLink = new URLSearchParams(window.location.hash.slice(1)).get("key");
  return fromLink || read().find((w) => w.id === id)?.key || null;
}

export function privateLink(id, key) {
  return `${window.location.origin}/watchlists/${id}#key=${encodeURIComponent(key)}`;
}

// "https://…/watchlists/<id>#key=<key>" → { id, key }
export function parseLink(text) {
  const match = String(text).trim().match(/\/watchlists\/([0-9a-f-]{36})#key=([\w%-]+)/i);
  return match ? { id: match[1], key: decodeURIComponent(match[2]) } : null;
}
