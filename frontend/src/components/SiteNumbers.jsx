import { useEffect, useState } from "react";
import { api } from "../lib/api";

const VISITOR_KEY = "threatlens-visitor";
const COUNTED_KEY = "threatlens-counted";

function randomId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// A random ID this browser keeps, so returning visitors are counted once. It says nothing about the person.
function visitorId() {
  try {
    let id = localStorage.getItem(VISITOR_KEY);
    if (!id) {
      id = randomId();
      localStorage.setItem(VISITOR_KEY, id);
    }
    return id;
  } catch {
    return randomId(); // storage blocked: counted for this visit only
  }
}

// Counted once per browser tab session; after that the numbers are only read
function alreadyCounted() {
  try {
    if (sessionStorage.getItem(COUNTED_KEY)) return true;
    sessionStorage.setItem(COUNTED_KEY, "1");
  } catch {
    // no session storage: counting again is harmless, the server ignores repeats
  }
  return false;
}

const full = new Intl.NumberFormat("en-US");
const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });
const short = (n) => (n >= 10_000 ? compact.format(n) : full.format(n));
const plural = (n, one, many) => `${n === 1 ? one : many}`;

// Small numbers in the top bar: visitors and investigations so far (the rest in the tooltip).
// Shown on every page, and the first page a browser opens is what counts it as a visitor.
export default function SiteNumbers() {
  const [numbers, setNumbers] = useState(null);

  useEffect(() => {
    let alive = true;
    const load = alreadyCounted() ? api.numbers() : api.countVisitor(visitorId());
    load.then((data) => alive && setNumbers(data)).catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  if (!numbers) return null;

  const { visitors, investigations, bulk_lookups: bulk, knowledge_entries: entries } = numbers;
  const title = [
    `${full.format(visitors)} ${plural(visitors, "visitor", "visitors")}`,
    `${full.format(investigations)} ${plural(investigations, "investigation", "investigations")} run`,
    bulk > 0 && `${full.format(bulk)} ${plural(bulk, "bulk lookup", "bulk lookups")}`,
    entries > 0 && `${full.format(entries)} ATT&CK and CWE entries in the knowledge base`,
  ].filter(Boolean).join("\n");

  return (
    <p className="sitenums" title={title} aria-label={title.replaceAll("\n", ", ")}>
      <span><b>{short(visitors)}</b> {plural(visitors, "visitor", "visitors")}</span>
      <span aria-hidden="true" className="sitenums__sep">·</span>
      <span><b>{short(investigations)}</b> {plural(investigations, "investigation", "investigations")}</span>
    </p>
  );
}
