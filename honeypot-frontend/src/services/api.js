
const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

// --------------------------------------------------
// GET request helper
// --------------------------------------------------

async function request(endpoint, signal) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
    signal,
  });

  if (!response.ok) {
    let message = `API request failed (${response.status})`;

    try {
      const body = await response.json();
      message = body.detail || message;
    } catch {
      // Keep the fallback message if the response isn't JSON.
    }

    throw new Error(message);
  }

  return response.json();
}

// --------------------------------------------------
// POST request helper
// --------------------------------------------------

async function postRequest(endpoint, signal) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
    },
    signal,
  });

  if (!response.ok) {
    let message = `API request failed (${response.status})`;

    try {
      const body = await response.json();
      message = body.detail || message;
    } catch {
      // Keep the fallback error message if the response isn't JSON.
    }

    throw new Error(message);
  }

  return response.json();
}

// --------------------------------------------------
// API methods
// --------------------------------------------------

export const api = {
  // Connection events
  getEvents({ limit = 100, offset = 0, sourceId, signal } = {}) {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });

    if (sourceId?.trim()) {
      params.set("source_id", sourceId.trim());
    }

    return request(`/events?${params}`, signal);
  },

  // Detection alerts
  getAlerts({
    limit = 100,
    offset = 0,
    severity,
    sourceId,
    signal,
  } = {}) {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });

    if (severity && severity !== "ALL") {
      params.set("severity", severity);
    }

    if (sourceId?.trim()) {
      params.set("source_id", sourceId.trim());
    }

    return request(`/alerts?${params}`, signal);
  },

  getAlert(id, signal) {
    return request(`/alerts/${encodeURIComponent(id)}`, signal);
  },

  // Deception action history
  getDeceptionActions({
    limit = 100,
    offset = 0,
    alertId,
    signal,
  } = {}) {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });

    if (alertId !== undefined && alertId !== null) {
      params.set("alert_id", String(alertId));
    }

    return request(`/deception-actions?${params}`, signal);
  },

  // Trigger a simulated deception action for an alert
  triggerDeception(alertId, signal) {
    const id = Number(alertId);

    if (!Number.isInteger(id) || id < 1) {
      throw new Error("A valid alert ID is required.");
    }

    return postRequest(
      `/alerts/${encodeURIComponent(id)}/deception`,
      signal
    );
  },

  // Health checks
  getHealth(signal) {
    return request("/health", signal);
  },

  getDatabaseHealth(signal) {
    return request("/db-health", signal);
  },
};
