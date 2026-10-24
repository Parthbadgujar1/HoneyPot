
import { ChevronRight, Eye } from "lucide-react";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export default function AlertsTable({ alerts, onSelect }) {
  if (alerts.length === 0) {
    return <div className="empty-state table-empty">No alerts match your filters.</div>;
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Alert</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Score</th>
            <th>Evidence</th>
            <th>Created</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id}>
              <td className="muted-cell">#{alert.id}</td>
              <td><span className="source-name">{alert.source_id}</span></td>
              <td>
                <span className={`severity-badge ${String(alert.severity).toLowerCase()}`}>
                  <span className="severity-dot" />
                  {alert.severity}
                </span>
              </td>
              <td>
                <div className="score-cell">
                  <strong>{alert.score}/100</strong>
                  <div className="score-track">
                    <span
                      className={`score-fill ${String(alert.severity).toLowerCase()}`}
                      style={{ width: `${Math.max(0, Math.min(100, alert.score || 0))}%` }}
                    />
                  </div>
                </div>
              </td>
              <td>{Array.isArray(alert.reasons) ? alert.reasons.length : 0} reasons</td>
              <td>{formatDate(alert.created_at)}</td>
              <td>
                <button
                  className="details-button"
                  onClick={() => onSelect(alert)}
                  aria-label={`View alert ${alert.id}`}
                >
                  <Eye size={15} />
                  View
                  <ChevronRight size={14} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
