
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

const COLORS = {
  HIGH: "#fb647c",
  MEDIUM: "#f4b860",
  LOW: "#55c9a7",
};

export default function SeverityChart({ alerts }) {
  const data = ["HIGH", "MEDIUM", "LOW"].map((severity) => ({
    name: severity,
    value: alerts.filter((alert) => alert.severity === severity).length,
  }));

  const total = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <section className="panel severity-panel">
      <div className="panel-heading">
        <div>
          <h2>Alert Severity</h2>
          <p>Distribution of returned alerts</p>
        </div>
      </div>

      {total === 0 ? (
        <div className="empty-state severity-empty">
          <p>No alerts available</p>
          <span>Alert distribution will appear when detections are stored.</span>
        </div>
      ) : (
        <>
          <div className="donut-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.filter((item) => item.value > 0)}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={65}
                  outerRadius={92}
                  paddingAngle={4}
                  stroke="none"
                >
                  {data.filter((item) => item.value > 0).map((item) => (
                    <Cell key={item.name} fill={COLORS[item.name]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#111c2c",
                    border: "1px solid #2b3b51",
                    borderRadius: 10,
                    color: "#f0f5fc",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="donut-center">
              <strong>{total}</strong>
              <span>Alerts</span>
            </div>
          </div>

          <div className="severity-legend">
            {data.map((item) => (
              <div className="severity-legend-row" key={item.name}>
                <span className="severity-name">
                  <span className="legend-dot" style={{ background: COLORS[item.name] }} />
                  {item.name}
                </span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
