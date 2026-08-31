import { Card, Empty, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'

interface BehaviourRow {
  session_id: string
  session_ref?: string | null
  behaviour_class: string
  confidence?: number | null
  probabilities?: any
  model: string
  model_version?: string | null
}

const CLASS_COLORS: Record<string, string> = {
  reconnaissance: 'text-rose-400',
  credential_abuse: 'text-orange-400',
  discovery: 'text-amber-400',
  resource_access: 'text-yellow-300',
  suspicious_execution: 'text-fuchsia-400',
  data_collection: 'text-violet-400',
  other_unknown: 'text-slate-400',
}

export default function BehavioursPage() {
  const { data, loading } = useFetch<{
    total: number
    items: BehaviourRow[]
    distribution: { class: string; count: number }[]
  }>(() => api.get('/behaviours'))

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-soc-text">Behavioural Classification</h1>

      {data?.distribution?.length ? (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          {data.distribution.map((d) => (
            <Card key={d.class} className="!p-4">
              <div className={`text-sm ${CLASS_COLORS[d.class] || 'text-slate-300'}`}>
                {d.class}
              </div>
              <div className="mt-1 text-2xl font-semibold text-soc-text">{d.count}</div>
            </Card>
          ))}
        </div>
      ) : null}

      {loading ? (
        <Spinner />
      ) : (
        <Card className="overflow-hidden">
          {data?.items.length ? (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-soc-border text-soc-muted">
                <tr>
                  <th className="px-3 py-2">Session</th>
                  <th className="px-3 py-2">Class</th>
                  <th className="px-3 py-2">Confidence</th>
                  <th className="px-3 py-2">Model</th>
                  <th className="px-3 py-2">Version</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {data.items.map((b, i) => (
                  <tr key={i} className="border-b border-soc-border/50 hover:bg-soc-panel">
                    <td className="px-3 py-2 text-soc-accent">{b.session_ref || b.session_id}</td>
                    <td className={`px-3 py-2 ${CLASS_COLORS[b.behaviour_class] || 'text-slate-300'}`}>
                      {b.behaviour_class}
                    </td>
                    <td className="px-3 py-2 text-slate-300">
                      {b.confidence != null ? (b.confidence * 100).toFixed(0) + '%' : '—'}
                    </td>
                    <td className="px-3 py-2 text-slate-400">{b.model}</td>
                    <td className="px-3 py-2 text-slate-400">{b.model_version || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty message="No classifications yet. Run analysis on sessions or train a model." />
          )}
        </Card>
      )}
    </div>
  )
}
