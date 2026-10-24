
import { useState } from "react";
import {
  X,
  ShieldAlert,
  ShieldCheck,
  Eye,
  AlertTriangle,
  LoaderCircle,
} from "lucide-react";
import { api } from "../services/api";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export default function AlertDetails({ alert, onClose, onDeceptionTriggered }) {
  const [confirming, setConfirming] = useState(false);
  const [triggering, setTriggering] = useState(false);
  const [deceptionResult, setDeceptionResult] = useState(null);
  const [deceptionError, setDeceptionError] = useState("");

  async function handleTriggerDeception() {
    if (!alert?.id || triggering) return;

    setTriggering(true);
    setDeceptionError("");
    setDeceptionResult(null);

    try {
      const result = await api.triggerDeception(alert.id);
      setDeceptionResult(result);
      setConfirming(false);

      if (onDeceptionTriggered) {
        await onDeceptionTriggered(result);
      }
    } catch (error) {
      setDeceptionError(
        error.message || "Could not trigger the simulated deception action."
      );
    } finally {
      setTriggering(false);
    }
  }

  if (!alert) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="alert-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="alert-modal-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-heading">
          <div className="modal-title-icon">
            <ShieldAlert size={23} />
          </div>

          <div className="modal-title-text">
            <h2 id="alert-modal-title">Alert #{alert.id}</h2>
            <p>Detection evidence and event summary</p>
          </div>

          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Close alert details"
            disabled={triggering}
          >
            <X size={19} />
          </button>
        </div>

        <div className="modal-summary">
          <div>
            <span>Severity</span>
            <strong
              className={`severity-text ${String(alert.severity).toLowerCase()}`}
            >
              {alert.severity}
            </strong>
          </div>

          <div>
            <span>Detection score</span>
            <strong>{alert.score}/100</strong>
          </div>

          <div>
            <span>Attempts (10 min)</span>
            <strong>{alert.attempts_10m}</strong>
          </div>
        </div>

        <div className="detail-section">
          <h3>Source</h3>
          <p className="detail-value">{alert.source_id}</p>
        </div>

        <div className="detail-section">
          <h3>Activity metrics</h3>

          <div className="metric-list">
            <div>
              <span>Unique ports in 60 seconds</span>
              <strong>{alert.unique_ports_60s}</strong>
            </div>

            <div>
              <span>Unique ports in 10 minutes</span>
              <strong>{alert.unique_ports_10m}</strong>
            </div>

            <div>
              <span>Failure ratio</span>
              <strong>
                {Number.isFinite(Number(alert.failure_ratio_10m))
                  ? `${(Number(alert.failure_ratio_10m) * 100).toFixed(1)}%`
                  : "—"}
              </strong>
            </div>

            <div>
              <span>Status</span>
              <strong>{alert.status}</strong>
            </div>

            <div>
              <span>Window ended</span>
              <strong>{formatDate(alert.window_end)}</strong>
            </div>

            <div>
              <span>Alert created</span>
              <strong>{formatDate(alert.created_at)}</strong>
            </div>
          </div>
        </div>

        <div className="detail-section">
          <h3>Detection reasons</h3>

          {Array.isArray(alert.reasons) && alert.reasons.length > 0 ? (
            <ul className="reason-list">
              {alert.reasons.map((reason, index) => (
                <li key={`${index}-${String(reason)}`}>
                  {String(reason).replaceAll("_", " ")}
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted-text">
              No reason details were recorded for this alert.
            </p>
          )}
        </div>

        {/* Interactive simulated deception workflow */}
        <div className="detail-section deception-section">
          <h3>
            <Eye size={17} style={{ verticalAlign: "middle", marginRight: 6 }} />
            Adaptive Deception
          </h3>

          <p className="muted-text">
            Select a predefined simulated decoy response for this alert.
            This does not start a real network service.
          </p>

          {!confirming && !deceptionResult && (
            <button
              type="button"
              className="button-secondary"
              onClick={() => setConfirming(true)}
              disabled={triggering}
            >
              <ShieldCheck size={16} />
              Trigger Deception
            </button>
          )}

          {confirming && !deceptionResult && (
            <div
              style={{
                border: "1px solid var(--border-color, #dfe3e8)",
                borderRadius: 10,
                padding: 14,
                display: "grid",
                gap: 12,
              }}
            >
              <strong>Confirm simulated deception?</strong>

              <p className="muted-text">
                The backend will select a decoy based on this alert and
                save the simulated action in the database.
              </p>

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="button-secondary"
                  onClick={() => setConfirming(false)}
                  disabled={triggering}
                >
                  Cancel
                </button>

                <button
                  type="button"
                  className="button-primary"
                  onClick={handleTriggerDeception}
                  disabled={triggering}
                >
                  {triggering ? (
                    <>
                      <LoaderCircle
                        size={16}
                        className="spin"
                      />
                      Processing...
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={16} />
                      Confirm and Trigger
                    </>
                  )}
                </button>
              </div>
            </div>
          )}

          {deceptionError && (
            <div className="error-banner" role="alert">
              <AlertTriangle size={18} />
              <div>
                <strong>Deception action failed</strong>
                <p>{deceptionError}</p>
              </div>
            </div>
          )}

          {deceptionResult && (
            <div
              role="status"
              style={{
                border: "1px solid #a9d8b8",
                background: "var(--success-background, #f0faf3)",
                borderRadius: 10,
                padding: 14,
                display: "grid",
                gap: 10,
                overflowWrap: "anywhere",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <ShieldCheck size={20} />
                <strong>Simulated deception action saved</strong>
              </div>

              <div className="metric-list">
                <div>
                  <span>Action ID</span>
                  <strong>#{deceptionResult.action_id}</strong>
                </div>

                <div>
                  <span>Selected decoy</span>
                  <strong>{deceptionResult.selected_decoy}</strong>
                </div>

                <div>
                  <span>Response type</span>
                  <strong>{deceptionResult.response_type}</strong>
                </div>
              </div>

              <div>
                <strong>Decision reasoning</strong>
                <p>
                  {deceptionResult.decision_reason}
                </p>
              </div>

              <div>
                <strong>Simulated response</strong>
                <pre
                  style={{
                    marginTop: 8,
                    padding: 12,
                    borderRadius: 8,
                    overflowX: "auto",
                    whiteSpace: "pre-wrap",
                    overflowWrap: "anywhere",
                    fontSize: 12,
                    background: "var(--code-background, #f4f6f8)",
                  }}
                >
                  {JSON.stringify(
                    deceptionResult.simulated_response,
                    null,
                    2
                  )}
                </pre>
              </div>

              <button
                type="button"
                className="button-secondary"
                onClick={() => {
                  setDeceptionResult(null);
                  setDeceptionError("");
                  setConfirming(false);
                }}
              >
                Trigger another action
              </button>
            </div>
          )}
        </div>

        <div className="modal-footer">
          This is rule-based detection evidence, not a verified attacker
          identity or a probability of compromise.
        </div>
      </section>
    </div>
  );
}
