import { Card, Empty, SeverityBadge, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import { fmtTime } from '../../utils/format'

interface AnomalyRow {
  id: string
  session_id?: string
  session_ref?: string | null
  anomaly_score?: number | null
  label?: string | null
  reasons?: any
  contributing_features?: any
  model: string
  model_version?: string | null
  created_at?: string | null
}

export default function AnomaliesPage() {
  const { data, loading } = useFetch<{ total: number; items: AnomalyRow[] }>(() =>
    api.get('/anomalies?min_score=0'),
  )
  const { data: stats } = useFetch<{ anomalies: number; normal: number; distribution: any[] }>(
    () => api.get('/anomalies/stats'),
  )

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-soc-text">Anomaly Detection</h1>

      <div className="grid grid-cols-3 gap-4">
        <Card className="!p-4">
          <div className="text-xs uppercase text-soc-muted">Anomalies</div>
          <div className="mt-1 text-2xl font-semibold text-rose-400">{stats?.anomalies ?? 0}</div>
        </Card>
        <Card className="!p-4">
          <div className="text-xs uppercase text-soc-muted">Normal</div>
          <div className="mt-1 text-2xl font-semibold text-emerald-400">{stats?.normal ?? 0}</div>
        </Card>
        <Card className="!p-4">
          <div className="text-xs uppercase text-soc-muted">Detector</div>
          <div className="mt-1 text-sm text-soc-text">Isolation Forest</div>
        </Card>
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
                  <th className="px-3 py-2">Score</th>
                  <th className="px-3 py-2">Label</th>
                  <th className="px-3 py-2">Reasons</th>
                  <th className="px-3 py-2">Model</th>
                  <th className="px-3 py-2">Detected</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {data.items.map((a) => (
                  <tr key={a.id} className="border-b border-soc-border/50 hover:bg-soc-panel">
                    <td className="px-3 py-2 text-soc-accent">{a.session_ref || a.session_id}</td>
                    <td className={`px-3 py-2 ${a.label === 'anomaly' ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {a.anomaly_score?.toFixed(3)}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge
                        sev={a.label === 'anomaly' ? 'HIGH' : 'LOW'}
                      />
                      <span className="ml-1 text-slate-300">{a.label}</span>
                    </td>
                    <td className="max-w-xs truncate px-3 py-2 text-slate-400">
                      {Array.isArray(a.reasons) ? a.reasons.join(', ') : (a.reasons ? JSON.stringify(a.reasons) : '—')}
                    </td>
                    <td className="px-3 py-2 text-slate-300">{a.model}</td>
                    <td className="px-3 py-2 text-slate-400">{fmtTime(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty message="No anomalies recorded yet." />
          )}
        </Card>
      )}
    </div>
  )
}
