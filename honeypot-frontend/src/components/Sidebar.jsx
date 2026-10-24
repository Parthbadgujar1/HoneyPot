
import {
  Activity,
  BellRing,
  ChartNoAxesCombined,
  LayoutDashboard,
  Network,
  Shield,
  ShieldCheck,
} from "lucide-react";

const navigation = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "events", label: "Connection Events", icon: Network },
  { id: "alerts", label: "Threat Alerts", icon: BellRing },
];

export default function Sidebar({ page, setPage, alertCount = 0 }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <ShieldCheck size={25} />
        </div>
        <div>
          <div className="brand-name">HONEY<span>POT</span></div>
          <div className="brand-caption">AI SECURITY PLATFORM</div>
        </div>
      </div>

      <div className="nav-label">MONITORING</div>

      <nav className="nav-list">
        {navigation.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            className={`nav-item ${page === id ? "active" : ""}`}
            onClick={() => setPage(id)}
          >
            <Icon size={19} />
            <span>{label}</span>
            {id === "alerts" && alertCount > 0 && (
              <span className="nav-count">
                {alertCount > 99 ? "99+" : alertCount}
              </span>
            )}
          </button>
        ))}
      </nav>

      <div className="sidebar-spacer" />

      <div className="sidebar-status">
        <div className="status-icon">
          <Shield size={18} />
        </div>
        <div>
          <strong>Deception Lab</strong>
          <p>Local monitoring mode</p>
        </div>
      </div>

      <div className="sidebar-footer">
        <Activity size={14} />
        <span>AI-ADAPTIVE HONEYPOT</span>
      </div>
    </aside>
  );
}
