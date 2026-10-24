
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  Database,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  Eye,
  Server,
} from "lucide-react";

import { api } from "./services/api";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import StatCard from "./components/StatCard";
import ActivityChart from "./components/ActivityChart";
import SeverityChart from "./components/SeverityChart";
import EventsTable from "./components/EventsTable";
import AlertsTable from "./components/AlertsTable";
import AlertDetails from "./components/AlertDetails";


const REFRESH_INTERVAL = 15000;

function buildActivityData(events) {
  const buckets = new Map();

  for (const event of events) {
    const date = new Date(event.timestamp);
    if (Number.isNaN(date.getTime())) continue;

    date.setSeconds(0, 0);
    const key = date.getTime();
    buckets.set(key, (buckets.get(key) || 0) + 1);
  }

  return [...buckets.entries()]
    .sort(([a], [b]) => a - b)
    .slice(-20)
    .map(([timestamp, count]) => ({
      time: new Date(timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      count,
    }));
}

function downloadCsv(filename, rows) {
  if (!rows.length) return;

  const columns = Object.keys(rows[0]);

  const escapeCsv = (value) => {
    const text =
      value == null
        ? ""
        : typeof value === "object"
          ? JSON.stringify(value)
          : String(value);

    return `"${text.replaceAll('"', '""')}"`;
  };

  const csv = [
    columns.map(escapeCsv).join(","),
    ...rows.map((row) =>
      columns.map((column) => escapeCsv(row[column])).join(",")
    ),
  ].join("\r\n");

  const url = URL.createObjectURL(
    new Blob(["\uFEFF", csv], {
      type: "text/csv;charset=utf-8;",
    })
  );

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function formatDate(value) {
  if (!value) return "Unknown time";

  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString();
}

function DeceptionHistory({ actions, loading, error }) {
  return (
    <section className="panel recent-panel">
      <div className="panel-heading">
        <div>
          <h2>Adaptive Deception Actions</h2>
          <p>
            Saved simulated decoy decisions from the backend.
          </p>
        </div>

        <span className="status-dot online" />
      </div>

      {loading && actions.length === 0 ? (
        <div className="loading-panel">
          <RefreshCw className="spin" size={20} />
          Loading deception history...
        </div>
      ) : error ? (
        <div className="error-banner" role="alert">
          <AlertTriangle size={18} />
          <div>
            <strong>Could not load deception history</strong>
            <p>{error}</p>
          </div>
        </div>
      ) : actions.length === 0 ? (
        <div className="loading-panel">
          <Eye size={22} />
          <p>No deception actions have been recorded yet.</p>
          <span>
            Generate an alert and trigger its simulated deception
            endpoint to see an action here.
          </span>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
            gap: "16px",
          }}
        >
          {actions.map((action) => (
            <article
              key={action.id}
              style={{
                border: "1px solid var(--border-color, #dfe3e8)",
                borderRadius: "12px",
                padding: "16px",
                minWidth: 0,
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: "10px",
                  marginBottom: "12px",
                }}
              >
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <Server size={19} />
                  <strong>{action.selected_decoy || "Unknown decoy"}</strong>
                </div>

                <span
                  style={{
                    fontSize: "11px",
                    borderRadius: "999px",
                    padding: "4px 8px",
                    background: "#e7f5ec",
                    color: "#17663a",
                    fontWeight: 600,
                    whiteSpace: "nowrap",
                  }}
                >
                  SIMULATED
                </span>
              </div>

              <div style={{ display: "grid", gap: "10px" }}>
                <div>
                  <small>Action ID</small>
                  <div>#{action.id}</div>
                </div>

                <div>
                  <small>Associated alert</small>
                  <div>
                    #{action.alert_id} · {action.source_id}
                  </div>
                </div>

                <div>
                  <small>Response type</small>
                  <div>{action.response_type || "Not specified"}</div>
                </div>

                <div>
                  <small>Decision reasoning</small>
                  <div>
                    {action.decision_reason || "No reason recorded."}
                  </div>
                </div>

                <div>
                  <small>Recorded at</small>
                  <div>{formatDate(action.created_at)}</div>
                </div>

                <details>
                  <summary style={{ cursor: "pointer", fontWeight: 600 }}>
                    View simulated response
                  </summary>

                  <pre
                    style={{
                      marginTop: "10px",
                      padding: "12px",
                      borderRadius: "8px",
                      overflowX: "auto",
                      whiteSpace: "pre-wrap",
                      overflowWrap: "anywhere",
                      fontSize: "12px",
                      background: "var(--code-background, #f4f6f8)",
                    }}
                  >
                    {JSON.stringify(action.simulated_response, null, 2)}
                  </pre>
                </details>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

export default function App() {
  const [page, setPage] = useState("overview");
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [deceptionActions, setDeceptionActions] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [deceptionError, setDeceptionError] = useState("");
  const [connectionStatus, setConnectionStatus] = useState("checking");
  const [databaseStatus, setDatabaseStatus] = useState("checking");
  const [lastUpdated, setLastUpdated] = useState("");

  const refreshData = useCallback(async ({ initial = false } = {}) => {
    if (initial) setLoading(true);
    else setRefreshing(true);

    try {
      // Core dashboard data: events and alerts.
      const [eventResult, alertResult] = await Promise.all([
        api.getEvents({ limit: 100, offset: 0 }),
        api.getAlerts({ limit: 100, offset: 0 }),
      ]);

      setEvents(
        Array.isArray(eventResult.events) ? eventResult.events : []
      );
      setAlerts(
        Array.isArray(alertResult.alerts) ? alertResult.alerts : []
      );

      setConnectionStatus("online");
      setError("");
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      setConnectionStatus("offline");
      setError(err.message || "Could not load data from the backend.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }

    // Deception history is independent of the core dashboard.
    // A history endpoint failure should not hide events or alerts.
    try {
      const result = await api.getDeceptionActions({
        limit: 100,
        offset: 0,
      });

      setDeceptionActions(
        Array.isArray(result.actions) ? result.actions : []
      );
      setDeceptionError("");
    } catch (err) {
      setDeceptionError(
        err.message || "Could not load deception history."
      );
    }

    try {
      await api.getDatabaseHealth();
      setDatabaseStatus("online");
    } catch {
      setDatabaseStatus("offline");
    }
  }, []);

  useEffect(() => {
    refreshData({ initial: true });

    const interval = setInterval(() => {
      if (document.visibilityState === "visible") {
        refreshData();
      }
    }, REFRESH_INTERVAL);

    const onVisible = () => {
      if (document.visibilityState === "visible") {
        refreshData();
      }
    };

    document.addEventListener("visibilitychange", onVisible);

    return () => {
      clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [refreshData]);

  const filteredEvents = useMemo(() => {
    const term = search.trim().toLowerCase();

    return events.filter((event) => {
      if (!term) return true;

      return [
        event.id,
        event.source_id,
        event.destination_port,
        event.success ? "success" : "failed",
        event.timestamp,
      ].some((value) =>
        String(value ?? "").toLowerCase().includes(term)
      );
    });
  }, [events, search]);

  const filteredAlerts = useMemo(() => {
    const term = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      const severityMatches =
        severityFilter === "ALL" || alert.severity === severityFilter;

      const textMatches =
        !term ||
        [
          alert.id,
          alert.source_id,
          alert.severity,
          alert.score,
          alert.status,
          ...(Array.isArray(alert.reasons) ? alert.reasons : []),
        ].some((value) =>
          String(value ?? "").toLowerCase().includes(term)
        );

      return severityMatches && textMatches;
    });
  }, [alerts, search, severityFilter]);

  const uniqueSources = useMemo(
    () => new Set(events.map((event) => event.source_id)).size,
    [events]
  );

  const highAlerts = alerts.filter(
    (alert) => alert.severity === "HIGH"
  ).length;

  const activityData = useMemo(
    () => buildActivityData(events),
    [events]
  );

  const openAlert = async (alert) => {
    setSelectedAlert(alert);

    try {
      const detail = await api.getAlert(alert.id);
      setSelectedAlert(detail);
    } catch {
      // Keep the alert summary if the detail request fails.
    }
  };

  const exportCurrentData = () => {
    if (page === "events") {
      downloadCsv("honeypot-events.csv", filteredEvents);
    } else {
      downloadCsv("honeypot-alerts.csv", filteredAlerts);
    }
  };

  return (
    <div className="app-shell">
      <Sidebar
        page={page}
        setPage={(nextPage) => {
          setPage(nextPage);
          setSearch("");
        }}
        alertCount={alerts.length}
      />

      <main className="main-content">
        <Topbar
          page={page}
          onRefresh={() => refreshData()}
          refreshing={refreshing}
          lastUpdated={lastUpdated}
          search={search}
          setSearch={setSearch}
          connectionStatus={connectionStatus}
        />

        <div className="page-content">
          {error && (
            <div className="error-banner" role="alert">
              <AlertTriangle size={18} />
              <div>
                <strong>Unable to refresh dashboard data</strong>
                <p>{error}</p>
                <span>
                  Showing the most recently loaded data, if available.
                </span>
              </div>
              <button
                className="button-secondary"
                onClick={() => refreshData()}
              >
                <RefreshCw size={15} /> Retry
              </button>
            </div>
          )}

          <div className="environment-banner">
            <div className="environment-icon">
              <ShieldCheck size={18} />
            </div>
            <div>
              <strong>Honeypot monitoring environment</strong>
              <span>
                Detection history is sourced from your FastAPI backend.
              </span>
            </div>
            <div className="environment-status">
              <span className={`status-dot ${connectionStatus}`} />
              {connectionStatus === "online"
                ? "Connected"
                : connectionStatus === "offline"
                  ? "Disconnected"
                  : "Connecting"}
            </div>
          </div>

          {page === "overview" && (
            <>
              <div className="section-title-row">
                <div>
                  <h2>Security Overview</h2>
                  <p>
                    Summary of the most recently retrieved records.
                  </p>
                </div>
                <button
                  className="button-secondary"
                  onClick={() => refreshData()}
                  disabled={refreshing}
                >
                  <RefreshCw
                    size={15}
                    className={refreshing ? "spin" : ""}
                  />
                  Refresh data
                </button>
              </div>

              {loading &&
              events.length === 0 &&
              alerts.length === 0 ? (
                <div className="loading-panel">
                  <RefreshCw className="spin" size={22} />
                  Loading monitoring data...
                </div>
              ) : (
                <>
                  <div className="stats-grid">
                    <StatCard
                      label="Events Retrieved"
                      value={events.length.toLocaleString()}
                      description="Latest 100 event records"
                      icon={Activity}
                      tone="blue"
                    />
                    <StatCard
                      label="Alerts Retrieved"
                      value={alerts.length.toLocaleString()}
                      description="Latest 100 alert records"
                      icon={ShieldAlert}
                      tone="purple"
                    />
                    <StatCard
                      label="High Severity"
                      value={highAlerts.toLocaleString()}
                      description="Among retrieved alerts"
                      icon={AlertTriangle}
                      tone="red"
                    />
                    <StatCard
                      label="Deception Actions"
                      value={deceptionActions.length.toLocaleString()}
                      description="Latest 100 saved actions"
                      icon={Eye}
                      tone="green"
                    />
                  </div>

                  <div className="charts-grid">
                    <ActivityChart data={activityData} />
                    <SeverityChart alerts={alerts} />
                  </div>

                  <section className="panel recent-panel">
                    <div className="panel-heading">
                      <div>
                        <h2>Recent Threat Alerts</h2>
                        <p>
                          Latest alerts returned by the backend.
                        </p>
                      </div>
                      <button
                        className="text-button"
                        onClick={() => {
                          setPage("alerts");
                          setSearch("");
                        }}
                      >
                        View all alerts →
                      </button>
                    </div>
                    <AlertsTable
                      alerts={alerts.slice(0, 5)}
                      onSelect={openAlert}
                    />
                  </section>

                  <DeceptionHistory
                    actions={deceptionActions}
                    loading={refreshing || loading}
                    error={deceptionError}
                  />
                </>
              )}
            </>
          )}

          {page === "events" && (
            <section className="panel data-panel">
              <div className="panel-heading table-panel-heading">
                <div>
                  <h2>Connection Events</h2>
                  <p>
                    {filteredEvents.length} displayed from up to 100
                    retrieved records.
                  </p>
                </div>
                <button
                  className="button-secondary"
                  onClick={exportCurrentData}
                  disabled={filteredEvents.length === 0}
                >
                  <ArrowDownToLine size={16} /> Export CSV
                </button>
              </div>
              <EventsTable events={filteredEvents} />
            </section>
          )}

          {page === "alerts" && (
            <section className="panel data-panel">
              <div className="panel-heading table-panel-heading">
                <div>
                  <h2>Threat Alerts</h2>
                  <p>
                    {filteredAlerts.length} displayed from up to 100
                    retrieved records.
                  </p>
                </div>
                <div className="table-actions">
                  <select
                    className="filter-select"
                    value={severityFilter}
                    onChange={(event) =>
                      setSeverityFilter(event.target.value)
                    }
                    aria-label="Filter by severity"
                  >
                    <option value="ALL">All severities</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                  <button
                    className="button-secondary"
                    onClick={exportCurrentData}
                    disabled={filteredAlerts.length === 0}
                  >
                    <ArrowDownToLine size={16} /> Export CSV
                  </button>
                </div>
              </div>
              <AlertsTable
                alerts={filteredAlerts}
                onSelect={openAlert}
              />
            </section>
          )}

          <footer className="app-footer">
            <div>
              <Database size={14} /> PostgreSQL:{" "}
              <strong>
                {databaseStatus === "online"
                  ? "Connected"
                  : databaseStatus === "offline"
                    ? "Unavailable"
                    : "Checking"}
              </strong>
            </div>
            <span>
              Auto-refresh every 15 seconds · API records are limited
              to the latest 100 per endpoint
            </span>
          </footer>
        </div>
      </main>

      <AlertDetails
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onDeceptionTriggered={async () => {
          const result = await api.getDeceptionActions({
            limit: 100,
            offset: 0,
          });
        
          setDeceptionActions(
            Array.isArray(result.actions) ? result.actions : []
          );
        }}
      />

    </div>
  );
}
