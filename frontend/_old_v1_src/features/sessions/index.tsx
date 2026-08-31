import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Card, Empty, SeverityBadge, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import type { Paged, SessionSummary } from '../../types'
import { fmtDur, fmtTime, severityColor } from '../../utils/format'

const PAGE_SIZE = 50

export default function SessionsPage() {
  const [page, setPage] = useState(1)
  const [riskMin, setRiskMin] = useState('')

  const { data, loading } = useFetch<Paged<SessionSummary>>(
    () =>
      api.get(
        `/sessions?page=${page}&page_size=${PAGE_SIZE}${
          riskMin ? `&risk_min=${riskMin}` : ''
        }`,
      ),
    [page, riskMin],
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-soc-text">Sessions</h1>
        <input
          value={riskMin}
          onChange={(e) => {
            setRiskMin(e.target.value)
            setPage(1)
          }}
          placeholder="Min risk score (0-100)…"
          className="w-52 rounded border border-soc-border bg-soc-panel px-3 py-1.5 text-sm text-soc-text outline-none focus:border-soc-accent"
        />
      </div>

      {loading ? (
        <Spinner />
      ) : (
        <Card className="overflow-hidden">
          {data?.items.length ? (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-soc-border text-soc-muted">
                <tr>
                  <th className="px-3 py-2">Session</th>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Service</th>
                  <th className="px-3 py-2">Started</th>
                  <th className="px-3 py-2">Duration</th>
                  <th className="px-3 py-2">Events</th>
                  <th className="px-3 py-2">Risk</th>
                  <th className="px-3 py-2">Severity</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {data.items.map((s) => (
                  <tr
                    key={s.id}
                    className="border-b border-soc-border/50 hover:bg-soc-panel"
                  >
                    <td className="px-3 py-2">
                      <Link
                        to={`/sessions/${s.id}`}
                        className="text-soc-accent hover:underline"
                      >
                        {s.session_ref}
                      </Link>
                    </td>
                    <td className="px-3 py-2 text-slate-300">{s.source || '—'}</td>
                    <td className="px-3 py-2 text-slate-300">{s.service || '—'}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                      {fmtTime(s.start_time)}
                    </td>
                    <td className="px-3 py-2 text-slate-400">
                      {fmtDur(s.duration_seconds)}
                    </td>
                    <td className="px-3 py-2 text-slate-300">{s.event_count}</td>
                    <td className={`px-3 py-2 ${severityColor(s.severity)}`}>
                      {s.risk_score != null ? s.risk_score.toFixed(1) : '—'}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge sev={s.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty message="No sessions. Ingest telemetry via Honeypot simulation." />
          )}
        </Card>
      )}

      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-soc-muted">
          <span>{data.total} total · page {page}</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
              className="rounded border border-soc-border px-3 py-1 disabled:opacity-40"
            >
              Prev
            </button>
            <button
              disabled={page * PAGE_SIZE >= data.total}
              onClick={() => setPage((p) => p + 1)}
              className="rounded border border-soc-border px-3 py-1 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
