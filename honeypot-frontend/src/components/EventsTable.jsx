
import { CheckCircle2, CircleX } from "lucide-react";

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export default function EventsTable({ events }) {
  if (events.length === 0) {
    return <div className="empty-state table-empty">No connection events match your search.</div>;
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Source</th>
            <th>Destination Port</th>
            <th>Result</th>
            <th>Event Time</th>
            <th>Received At</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td className="muted-cell">#{event.id}</td>
              <td><span className="source-name">{event.source_id}</span></td>
              <td><span className="port-chip">{event.destination_port}</span></td>
              <td>
                <span className={`result-badge ${event.success ? "success" : "failure"}`}>
                  {event.success
                    ? <CheckCircle2 size={13} />
                    : <CircleX size={13} />}
                  {event.success ? "Success" : "Failed"}
                </span>
              </td>
              <td>{formatDate(event.timestamp)}</td>
              <td>{formatDate(event.received_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
