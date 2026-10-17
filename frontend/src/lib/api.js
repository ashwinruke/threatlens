// Every call to the ThreatLens backend goes through here.
export const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/+$/, "");

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

function messageFrom(data, status) {
  const detail = data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return "That input is empty or too long.";
  return `The server returned an error (HTTP ${status}).`;
}

async function request(path, { method = "GET", body, timeoutMs = 20_000, signal } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  signal?.addEventListener("abort", () => controller.abort());
  try {
    const response = await fetch(`${API_URL}${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const data = await response.json().catch(() => null);
    if (!response.ok) throw new ApiError(messageFrom(data, response.status), response.status);
    return data;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.name === "AbortError") {
      if (signal?.aborted) throw error;
      throw new ApiError("The server took too long to answer. Try again in a moment.", 0);
    }
    throw new ApiError("Can't reach the ThreatLens server. Check your connection and try again.", 0);
  } finally {
    clearTimeout(timer);
  }
}

// How long a live investigation may stay silent. The server sends a keep-alive every 15 seconds,
// so a minute and a half of nothing means the connection is gone.
const STREAM_STALL_MS = 90_000;

// Server-Sent Events arrive as blocks separated by a blank line:
//   event: step
//   data: {...}
// Lines starting with ":" are keep-alive comments.
function parseBlock(block) {
  let event = "message";
  const data = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  return data.length ? { event, data: JSON.parse(data.join("\n")) } : null;
}

// Reads a Server-Sent Events response, calling onEvent(event, data) for each message, until "done"
// (whose data it returns) or "error" (which it throws). Returns null if the server can't stream.
async function streamEvents(path, body, onEvent, droppedMessage) {
  const controller = new AbortController();
  let stall = setTimeout(() => controller.abort(), STREAM_STALL_MS);
  const keepWaiting = () => {
    clearTimeout(stall);
    stall = setTimeout(() => controller.abort(), STREAM_STALL_MS);
  };

  let response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch {
    clearTimeout(stall);
    throw new ApiError("Can't reach the ThreatLens server. Check your connection and try again.", 0);
  }
  if (response.status === 404 || response.status === 405 || !response.body) {
    clearTimeout(stall);
    return null; // an older server without streaming: the caller falls back to a normal request
  }
  if (!response.ok) {
    clearTimeout(stall);
    const data = await response.json().catch(() => null);
    throw new ApiError(messageFrom(data, response.status), response.status);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      keepWaiting();
      buffer += decoder.decode(value, { stream: true });
      const blocks = buffer.split(/\r?\n\r?\n/);
      buffer = blocks.pop();
      for (const block of blocks) {
        const message = parseBlock(block);
        if (!message) continue;
        if (message.event === "done") return message.data;
        if (message.event === "error") throw new ApiError(message.data.detail, 500);
        onEvent(message.event, message.data);
      }
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(droppedMessage, 0);
  } finally {
    clearTimeout(stall);
    reader.releaseLock?.();
  }
  throw new ApiError(droppedMessage, 0);
}

function streamInvestigation(query, { onStep, onStatus }) {
  return streamEvents("/api/investigations/stream", { query }, (event, data) => {
    if (event === "step") onStep?.(data);
    else if (event === "status") onStatus?.(data.text);
  }, "The connection dropped. The investigation may still finish: check History in a minute.");
}

// Investigations already loaded in this browser tab, so opening a report right after
// creating it (or going back to it) doesn't fetch it again.
const loaded = new Map();

export const api = {
  health: () => request("/health", { timeoutMs: 75_000 }),
  healthDb: () => request("/health/db", { timeoutMs: 75_000 }),
  detect: (query, signal) => request("/api/detect", { method: "POST", body: { query }, signal, timeoutMs: 75_000 }),
  async investigate(query) {
    const result = await request("/api/investigations", { method: "POST", body: { query }, timeoutMs: 150_000 });
    if (result.id) loaded.set(result.id, result);
    return result;
  },
  // The same investigation, but each step is reported as it happens: onStep(step), onStatus(text).
  // Falls back to a normal request if the server can't stream.
  async investigateLive(query, handlers = {}) {
    const result = (await streamInvestigation(query, handlers)) ?? (await api.investigate(query));
    if (result.id) loaded.set(result.id, result);
    return result;
  },
  async getInvestigation(id) {
    if (loaded.has(id)) return loaded.get(id);
    const result = await request(`/api/investigations/${encodeURIComponent(id)}`, { timeoutMs: 75_000 });
    loaded.set(id, result);
    return result;
  },
  getAttackMap: (id) => request(`/api/investigations/${encodeURIComponent(id)}/attack`, { timeoutMs: 75_000 }),
  getGraph: (id) => request(`/api/investigations/${encodeURIComponent(id)}/graph`, { timeoutMs: 75_000 }),
  // Bulk lookup: what would be investigated (no sources contacted), then the live run, then saved results
  bulkParse: (text, signal) => request("/api/bulk/parse", { method: "POST", body: { text }, signal, timeoutMs: 30_000 }),
  async bulkLive(text, { onPlan, onRow } = {}) {
    const batch = await streamEvents("/api/bulk/stream", { text }, (event, data) => {
      if (event === "plan") onPlan?.(data);
      else if (event === "row") onRow?.(data);
    }, "The connection dropped. The bulk lookup may still finish: its results appear in History.");
    if (!batch) throw new ApiError("This server doesn't support bulk lookups yet.", 404);
    return batch;
  },
  getBatch: (id) => request(`/api/bulk/${encodeURIComponent(id)}`, { timeoutMs: 75_000 }),
  examples: () => request("/api/examples", { timeoutMs: 75_000 }),
  listInvestigations: (limit = 20) => request(`/api/investigations?limit=${limit}`, { timeoutMs: 75_000 }),
};
