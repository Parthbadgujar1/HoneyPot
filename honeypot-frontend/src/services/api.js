
// "sensor" (default) reads live decoy data through the backend's /sensor
// bridge. Set VITE_DATA_SOURCE=postgres to use the original database routes.
const DATA_SOURCE = import.meta.env.VITE_DATA_SOURCE || "sensor";
const DATA_PREFIX = DATA_SOURCE === "postgres" ? "" : "/sensor";
export const SOURCE_LABEL = DATA_SOURCE === "postgres" ? "PostgreSQL" : "Sensor";

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
// POST request helper with a JSON body
// --------------------------------------------------

async function postJsonRequest(endpoint, body, signal) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    signal,
  });

  if (!response.ok) {
    let message = `API request failed (${response.status})`;
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch {
      // Keep the fallback error message if the response isn't JSON.
    }
    throw new Error(message);
  }

  return response.json();
}

// --------------------------------------------------
// DELETE request helper
// --------------------------------------------------

async function deleteRequest(endpoint, signal) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method: "DELETE",
    headers: { Accept: "application/json" },
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

    return request(`${DATA_PREFIX}/events?${params}`, signal);
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

    return request(`${DATA_PREFIX}/alerts?${params}`, signal);
  },

  getAlert(id, signal) {
    return request(`${DATA_PREFIX}/alerts/${encodeURIComponent(id)}`, signal);
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

    return request(`${DATA_PREFIX}/deception-actions?${params}`, signal);
  },

  // Trigger a simulated deception action for an alert
  triggerDeception(alertId, signal) {
    const id = Number(alertId);

    if (!Number.isInteger(id) || id < 1) {
      throw new Error("A valid alert ID is required.");
    }

    return postRequest(
      `${DATA_PREFIX}/alerts/${encodeURIComponent(id)}/deception`,
      signal
    );
  },

  // Firewall blocks (sensor only; the sensor applies its own safety checks)
  getBlocks(signal) {
    return request(`${DATA_PREFIX}/blocks`, signal);
  },

  blockSource(ip, reason, ttlMinutes, signal) {
    const body = { ip, reason };
    if (ttlMinutes !== undefined && ttlMinutes !== null) {
      body.ttl_minutes = ttlMinutes;
    }
    return postJsonRequest(`${DATA_PREFIX}/blocks`, body, signal);
  },

  unblockSource(ip, signal) {
    return deleteRequest(`${DATA_PREFIX}/blocks/${encodeURIComponent(ip)}`, signal);
  },

  blockAlertSource(alertId, signal) {
    return postRequest(`${DATA_PREFIX}/alerts/${encodeURIComponent(alertId)}/block`, signal);
  },

  // Health checks
  getHealth(signal) {
    return request("/health", signal);
  },

  getDatabaseHealth(signal) {
    return request(DATA_SOURCE === "postgres" ? "/db-health" : "/sensor/health", signal);
  },
};
