import { Link } from 'react-router-dom'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Card, Empty, Spinner, StatCard } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { useLiveEvents } from '../../hooks/useLiveEvents'
import { api } from '../../services/api'
import type { DashboardSummary, LiveEvent } from '../../types'
import { eventTypeColor, fmtTime } from '../../utils/format'

export default function DashboardPage() {
  const { data: summary, loading } = useFetch<DashboardSummary>(() =>
    api.get('/dashboard/summary'),
  )
  const { data: ever } = useFetch<{ bucket: string; count: number }[]>(() =>
    api.get('/analytics/events-over-time?bucket=hour'),
  )
  const { data: system } = useFetch<any>(() => api.get('/system/status'))
  const { connected, recent } = useLiveEvents()

  if (loading || !summary) return <Spinner />

  const chart = (ever || []).map((p) => ({
    label: new Date(p.bucket).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    }),
    events: p.count,
  }))

  const lastTen = recent.slice(0, 10) as LiveEvent[]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-soc-text">Security Operations Overview</h1>
          <p className="text-sm text-soc-muted">
            Live telemetry from the adaptive deception honeypot
          </p>
        </div>
        <span
          className={`inline-flex items-center gap-2 rounded border px-3 py-1 text-xs ${
            connected
              ? 'border-emerald-500/40 text-emerald-400'
              : 'border-rose-500/40 text-rose-400'
          }`}
        >
          <span
            className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-rose-500'}`}
          />
          {connected ? 'Realtime connected' : 'Realtime off'}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 lg:grid-cols-7">
        <StatCard label="Sessions" value={summary.total_sessions} />
        <StatCard label="Active" value={summary.active_sessions} accent="text-sky-400" />
        <StatCard
          label="High risk"
          value={summary.high_risk_sessions}
          accent="text-rose-400"
        />
        <StatCard label="Anomalies" value={summary.anomalies} accent="text-amber-400" />
        <StatCard label="Events" value={summary.total_events} />
        <StatCard label="Predictions" value={summary.predictions} accent="text-cyan-400" />
        <StatCard
          label="Adaptive"
          value={summary.adaptive_actions}
          accent="text-fuchsia-400"
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Card title="Events over time (hourly)" className="col-span-2">
          {chart.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={chart}>
                <defs>
                  <linearGradient id="ev" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="label" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{
                    background: '#0f172a',
                    border: '1px solid #1f2937',
                    fontSize: 12,
                  }}
                  itemStyle={{ color: '#22d3ee' }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  stroke="#22d3ee"
                  fill="url(#ev)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <Empty message="No hourly events yet. Trigger a simulation in Honeypot." />
          )}
        </Card>

        <Card title="Model status">
          {(system?.models && (
            <div className="space-y-3 text-sm">
              {Object.entries(system.models).map(([k, v]: any) => (
                <div key={k} className="flex items-center justify-between">
                  <span className="capitalize text-soc-muted">{k}</span>
                  {v?.status === 'not_trained' ? (
                    <span className="text-amber-400">
                      <Link className="underline" to="/models">
                        not trained
                      </Link>
                    </span>
                  ) : (
                    <span className="text-emerald-400">
                      {v.version} · {v.name}
                    </span>
                  )}
                </div>
              ))}
              <Link
                to="/models"
                className="mt-2 block text-center text-xs text-soc-accent hover:underline"
              >
                Go to Model Registry →
              </Link>
            </div>
          )) || <Empty />}
        </Card>
      </div>

      <Card
        title="Live events"
        actions={
          <Link to="/live" className="text-xs text-soc-accent hover:underline">
            Full feed →
          </Link>
        }
      >
        {lastTen.length ? (
          <div className="max-h-80 space-y-1 overflow-y-auto font-mono text-xs">
            {lastTen.map((e, i) => (
              <div
                key={i}
                className="flex items-center gap-2 rounded px-2 py-1 hover:bg-soc-panel"
              >
                <span className="w-28 shrink-0 text-soc-muted">
                  {fmtTime(e.timestamp).split(', ')[1] || fmtTime(e.timestamp)}
                </span>
                <span className="w-32 shrink-0 text-slate-300">{e.source || '—'}</span>
                <span
                  className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] ${eventTypeColor(e.event_type)}`}
                >
                  {e.event_type}
                </span>
                <span className="truncate text-slate-300">{e.action || '—'}</span>
              </div>
            ))}
          </div>
        ) : (
          <Empty message="No live events. Trigger a simulation to see telemetry stream in." />
        )}
      </Card>
    </div>
  )
}
