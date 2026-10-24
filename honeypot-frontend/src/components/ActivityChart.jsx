
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

export default function ActivityChart({ data }) {
  return (
    <section className="panel chart-panel">
      <div className="panel-heading">
        <div>
          <h2>Connection Activity</h2>
          <p>Events grouped by recorded time</p>
        </div>
        <span className="chart-legend">
          <span className="legend-dot blue-dot" /> Connections
        </span>
      </div>

      <div className="chart-area">
        {data.length === 0 ? (
          <div className="empty-state">
            <p>No connection activity recorded yet.</p>
            <span>Submit events through the detection API to populate this chart.</span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 12, right: 12, left: -18, bottom: 4 }}>
              <CartesianGrid stroke="#243144" strokeDasharray="3 5" vertical={false} />
              <XAxis
                dataKey="time"
                tick={{ fill: "#8493a8", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                minTickGap={18}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: "#8493a8", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#111c2c",
                  border: "1px solid #2b3b51",
                  borderRadius: 10,
                  color: "#f0f5fc",
                }}
              />
              <Line
                type="monotone"
                dataKey="count"
                name="Connections"
                stroke="#59a9ff"
                strokeWidth={2.5}
                dot={{ r: 3, fill: "#59a9ff" }}
                activeDot={{ r: 5 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}
