
import { Bell, RefreshCw, Search } from "lucide-react";

export default function Topbar({
  page,
  onRefresh,
  refreshing,
  lastUpdated,
  search,
  setSearch,
  connectionStatus,
}) {
  const titles = {
    overview: ["Security Overview", "Monitor your honeypot activity and detections."],
    events: ["Connection Events", "Inspect connection attempts seen by the decoys."],
    alerts: ["Threat Alerts", "Investigate reconnaissance detections and their evidence."],
  };

  const [title, subtitle] = titles[page] || titles.overview;

  return (
    <header className="topbar">
      <div className="topbar-heading">
        <div className="breadcrumb">HONEY POT <span>/</span> MONITORING</div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>

      <div className="topbar-actions">
        <label className="search-box">
          <Search size={17} />
          <input
            aria-label="Search current table"
            placeholder="Search current table..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          {search && (
            <button
              className="icon-button clear-search"
              onClick={() => setSearch("")}
              aria-label="Clear search"
            >
              ×
            </button>
          )}
        </label>

        <button
          className="icon-button refresh-button"
          onClick={onRefresh}
          disabled={refreshing}
          title="Refresh data"
          aria-label="Refresh data"
        >
          <RefreshCw size={18} className={refreshing ? "spin" : ""} />
        </button>

        <div className="connection-indicator" title="Backend connectivity">
          <span className={`status-dot ${connectionStatus}`} />
          <span>{connectionStatus === "online" ? "API Connected" :
            connectionStatus === "offline" ? "API Offline" : "Checking API"}</span>
        </div>

        <div className="topbar-bell" title="Threat alerts">
          <Bell size={19} />
        </div>
      </div>

      <div className="topbar-meta">
        <span>Last updated: {lastUpdated || "Not yet refreshed"}</span>
      </div>
    </header>
  );
}
