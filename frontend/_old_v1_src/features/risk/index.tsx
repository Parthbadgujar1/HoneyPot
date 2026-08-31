import { Card, Empty, SeverityBadge, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'

interface RiskRow {
  session_id: string
  session_ref?: string | null
  score?: number | null
  severity?: string | null
  contributions?: any
  policy_version?: string | null
}

export default function RiskPage() {
  const { data, loading } = useFetch<{ total: number; items: RiskRow[] }>(() =>
    api.get('/risk'),
  )

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-soc-text">Risk Assessment</h1>

      {loading ? (
        <Spinner />
      ) : (
        <Card className="overflow-hidden">
          {data?.items.length ? (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-soc-border text-soc-muted">
                <tr>
                  <th className="px-3 py-2">Session</th>
                  <th className="px-3 py-2">Score</th>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Contributions</th>
                  <th className="px-3 py-2">Policy</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {data.items.map((r) => (
                  <tr key={r.session_id} className="border-b border-soc-border/50 hover:bg-soc-panel">
                    <td className="px-3 py-2 text-soc-accent">{r.session_ref || r.session_id}</td>
                    <td className="px-3 py-2 text-slate-300">
                      {r.score != null ? r.score.toFixed(1) : '—'}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge sev={r.severity} />
                    </td>
                    <td className="max-w-sm truncate px-3 py-2 text-slate-400">
                      {r.contributions
                        ? Object.entries(r.contributions)
                            .filter(([, c]: any) => c.score > 0)
                            .map(([k, c]: any) => `${k}:${c.score.toFixed(0)}`)
                            .join(' ')
                        : '—'}
                    </td>
                    <td className="px-3 py-2 text-slate-400">{r.policy_version || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty message="No risk assessments yet." />
          )}
        </Card>
      )}
    </div>
  )
}
