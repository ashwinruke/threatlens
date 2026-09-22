// Every call to the ThreatLens backend goes through here.
export const API_URL = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/+$/, "");

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
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
    if (!response.ok) {
      const detail = data?.detail;
      const message =
        typeof detail === "string"
          ? detail
          : Array.isArray(detail)
            ? "Enter between 1 and 500 characters."
            : `The server returned an error (HTTP ${response.status}).`;
      throw new ApiError(message, response.status);
    }
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
  async getInvestigation(id) {
    if (loaded.has(id)) return loaded.get(id);
    const result = await request(`/api/investigations/${encodeURIComponent(id)}`, { timeoutMs: 75_000 });
    loaded.set(id, result);
    return result;
  },
  listInvestigations: (limit = 20) => request(`/api/investigations?limit=${limit}`, { timeoutMs: 75_000 }),
};
