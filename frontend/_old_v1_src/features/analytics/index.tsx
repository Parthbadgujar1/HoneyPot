import { Card, Empty, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const PIE_COLORS = ['#22d3ee', '#f59e0b', '#a78bfa', '#f43f5e', '#34d399', '#fb7185', '#64748b']

export default function AnalyticsPage() {
  const { data: classifications, loading: l1 } = useFetch<{ class: string; count: number }[]>(
    () => api.get('/analytics/classification-distribution'),
  )
  const { data: riskDist, loading: l2 } = useFetch<{ severity: string; count: number }[]>(
    () => api.get('/analytics/risk-distribution'),
  )
  const { data: services, loading: l3 } = useFetch<{ service: string; count: number }[]>(
    () => api.get('/analytics/service-usage'),
  )
  const { data: transitions, loading: l4 } = useFetch<{ from: string; to: string; count: number }[]>(
    () => api.get('/analytics/behaviour-transitions'),
  )
  const { data: durations, loading: l5 } = useFetch<{ bucket: string; count: number }[]>(
    () => api.get('/analytics/session-durations'),
  )
  const { data: adaptive, loading: l6 } = useFetch<{ policy_id: string; status: string; count: number }[]>(
    () => api.get('/analytics/adaptive-actions'),
  )

  if (l1 || l2 || l3 || l4 || l5 || l6) return <Spinner />

  const riskData = (riskDist || []).map((r) => ({
    name: r.severity,
    value: r.count,
  }))

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-soc-text">Analytics</h1>

      <div className="grid grid-cols-2 gap-4">
        <Card title="Behaviour classifications">
          {classifications?.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={classifications}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="class" tick={{ fill: '#9ca3af', fontSize: 9 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1f2937' }}
                  itemStyle={{ color: '#22d3ee' }}
                />
                <Bar dataKey="count" fill="#22d3ee" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <Empty />
          )}
        </Card>

        <Card title="Risk severity distribution">
          {riskData.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={riskData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={50}
                  outerRadius={80}
                >
                  {riskData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1f2937' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <Empty />
          )}
        </Card>

        <Card title="Service usage">
          {services?.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={services}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="service" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1f2937' }}
                />
                <Bar dataKey="count" fill="#a78bfa" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <Empty />
          )}
        </Card>

        <Card title="Session durations">
          {durations?.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={durations}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="bucket" tick={{ fill: '#9ca3af', fontSize: 9 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1f2937' }}
                />
                <Bar dataKey="count" fill="#34d399" />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <Empty />
          )}
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card title="Behaviour transitions (top)">
          {transitions?.length ? (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-soc-border text-soc-muted">
                <tr>
                  <th className="px-2 py-2">From</th>
                  <th className="px-2 py-2">To</th>
                  <th className="px-2 py-2">Transitions</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {transitions.slice(0, 12).map((t, i) => (
                  <tr key={i} className="border-b border-soc-border/40">
                    <td className="px-2 py-1.5 text-amber-300">{t.from}</td>
                    <td className="px-2 py-1.5 text-cyan-300">{t.to}</td>
                    <td className="px-2 py-1.5 text-slate-300">{t.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty />
          )}
        </Card>

        <Card title="Adaptive deception actions">
          {adaptive?.length ? (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-soc-border text-soc-muted">
                <tr>
                  <th className="px-2 py-2">Policy</th>
                  <th className="px-2 py-2">Status</th>
                  <th className="px-2 py-2">Count</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {adaptive.map((t, i) => (
                  <tr key={i} className="border-b border-soc-border/40">
                    <td className="px-2 py-1.5 text-fuchsia-300">{t.policy_id}</td>
                    <td className="px-2 py-1.5 text-slate-300">{t.status}</td>
                    <td className="px-2 py-1.5 text-slate-300">{t.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty />
          )}
        </Card>
      </div>
    </div>
  )
}
