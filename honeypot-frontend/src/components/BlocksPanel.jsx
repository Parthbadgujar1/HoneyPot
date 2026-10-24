import { useState } from "react";
import { Ban, Unlock, ShieldCheck, AlertTriangle, Info } from "lucide-react";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

const FIREWALL_TONE = {
  enforce: { icon: ShieldCheck, label: "Applied", color: "var(--green, #2e7d32)" },
  dry_run: { icon: Info, label: "Dry run", color: "var(--amber, #b26a00)" },
  not_elevated: { icon: AlertTriangle, label: "Not applied", color: "var(--red, #c62828)" },
  disabled: { icon: Info, label: "Disabled", color: "var(--muted, #657085)" },
};

export function FirewallBanner({ firewall }) {
  if (!firewall) return null;
  const tone = FIREWALL_TONE[firewall.state] || FIREWALL_TONE.disabled;
  const Icon = tone.icon;
  return (
    <div role="status" className="muted-text" style={{ display: "flex", gap: 8, alignItems: "center", color: tone.color }}>
      <Icon size={16} />
      <span><strong>{tone.label}:</strong> {firewall.message}</span>
    </div>
  );
}

export default function BlocksPanel({ blocks, onUnblock }) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  async function handleUnblock(ip) {
    setBusy(ip);
    setError("");
    const result = await onUnblock(ip);
    if (!result.ok) setError(result.message);
    setBusy("");
  }

  return (
    <section className="panel recent-panel">
      <div className="panel-heading">
        <div>
          <h2>Firewall blocks</h2>
          <p>Sources the sensor is blocking right now.</p>
        </div>
      </div>

      <FirewallBanner firewall={blocks.firewall} />

      {error && (
        <div className="error-banner" role="alert" style={{ marginTop: 12 }}>
          <AlertTriangle size={18} />
          <div><strong>Unblock failed</strong><p>{error}</p></div>
        </div>
      )}

      {blocks.active.length === 0 ? (
        <div className="loading-panel" style={{ marginTop: 12 }}>
          <Ban size={22} />
          <p>No active blocks.</p>
          <span>Blocks appear here when a high-severity alert is blocked.</span>
        </div>
      ) : (
        <div className="table-scroll" style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th>Reason</th>
                <th>Blocked at</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {blocks.active.map((block) => (
                <tr key={block.id}>
                  <td><span className="source-name">{block.ip}</span></td>
                  <td>
                    {block.status === "DRY_RUN" ? "Dry run (not applied)" : block.status}
                    {block.error && <div className="muted-text">{block.error}</div>}
                  </td>
                  <td>{block.reason}</td>
                  <td>{formatDate(block.created)}</td>
                  <td>{block.expires ? formatDate(block.expires) : "Permanent"}</td>
                  <td>
                    <button
                      className="button-secondary"
                      onClick={() => handleUnblock(block.ip)}
                      disabled={busy === block.ip}
                      aria-label={`Unblock ${block.ip}`}
                    >
                      <Unlock size={15} />
                      {busy === block.ip ? "Unblocking..." : "Unblock"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
