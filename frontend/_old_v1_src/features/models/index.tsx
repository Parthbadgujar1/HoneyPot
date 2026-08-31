import { useState } from 'react'
import { Card, Empty, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import type { ModelInfo } from '../../types'
import { useAuth } from '../../hooks/useAuth'
import { fmtTime } from '../../utils/format'

export default function ModelsPage() {
  const { user } = useAuth()
  const canTrain = ['ADMIN', 'ANALYST', 'RESEARCHER'].includes(user?.role || '')
  const [training, setTraining] = useState(false)
  const [msg, setMsg] = useState('')
  const { data, loading, reload } = useFetch<{ items: ModelInfo[] }>(() =>
    api.get('/models'),
  )

  const train = async () => {
    setTraining(true)
    setMsg('')
    try {
      const res = await api.post<any>('/models/train')
      const r = res.results || {}
      setMsg(
        `Trained classifier ${r.classifier?.version} (${Object.entries(r.classifier?.metrics || {})[0]?.[1] ?? '?'} accuracy), anomaly ${r.anomaly?.version}, sequence ${r.sequence?.version}`,
      )
      reload()
    } catch (e: any) {
      setMsg('Error: ' + e?.message)
    } finally {
      setTraining(false)
    }
  }

  const activate = async (id: string) => {
    try {
      await api.post(`/models/${id}/activate`)
      reload()
    } catch (e: any) {
      setMsg('Activation error: ' + e?.message)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-soc-text">Model Registry</h1>
        {canTrain && (
          <button
            onClick={train}
            disabled={training}
            className="rounded bg-soc-accent px-4 py-2 text-sm font-semibold text-soc-bg hover:opacity-90 disabled:opacity-60"
          >
            {training ? 'Training…' : 'Train all models'}
          </button>
        )}
      </div>
      {msg && (
        <p className="rounded border border-soc-border bg-soc-panel px-3 py-2 text-sm text-soc-muted">
          {msg}
        </p>
      )}

      {loading ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          {data?.items.length ? (
            <Card className="overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-soc-border text-soc-muted">
                  <tr>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Name / Version</th>
                    <th className="px-3 py-2">Metrics</th>
                    <th className="px-3 py-2">Trained</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Action</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {data.items.map((m) => (
                    <tr key={m.id} className="border-b border-soc-border/50 hover:bg-soc-panel">
                      <td className="px-3 py-2">
                        <span className="rounded border border-soc-border px-1.5 py-0.5 text-soc-accent">
                          {m.model_type}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-slate-300">
                        {m.name} <span className="text-soc-muted">({m.version})</span>
                      </td>
                      <td className="max-w-xs truncate px-3 py-2 text-slate-400">
                        {m.metrics ? metricsSummary(m.metrics) : '—'}
                      </td>
                      <td className="px-3 py-2 text-slate-400">{fmtTime(m.trained_at)}</td>
                      <td className="px-3 py-2">
                        {m.is_active ? (
                          <span className="text-emerald-400">● active</span>
                        ) : (
                          <span className="text-slate-500">○</span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        {canTrain && !m.is_active && (
                          <button
                            onClick={() => activate(m.id)}
                            className="rounded border border-soc-border px-2 py-0.5 text-soc-muted hover:border-soc-accent hover:text-soc-accent"
                          >
                            Activate
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          ) : (
            <Empty message="No models trained yet. Click 'Train all models' to build the ML pipeline." />
          )}
        </div>
      )}
    </div>
  )
}

function metricsSummary(m: any): string {
  if (m.accuracy != null) return `accuracy ${(m.accuracy * 100).toFixed(0)}%`
  if (m.top1_accuracy != null)
    return `top1 ${(m.top1_accuracy * 100).toFixed(0)}% · mrr ${(m.mrr || 0).toFixed(2)}`
  return Object.entries(m)
    .slice(0, 2)
    .map(([k, v]) => `${k}:${typeof v === 'number' ? v.toFixed(2) : v}`)
    .join(', ')
}
