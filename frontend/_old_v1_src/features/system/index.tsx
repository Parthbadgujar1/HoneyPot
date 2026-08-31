import { Card, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'

export default function SystemPage() {
  const { data, loading } = useFetch<any>(() => api.get('/system/status'))

  if (loading || !data) return <Spinner />

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-soc-text">System Status</h1>

      <div className="grid grid-cols-3 gap-4">
        <Card title="Services">
          {(Object.entries(data.services || {}) as any[]).map(([k, v]) => (
            <div key={k} className="mb-2 flex items-center justify-between text-xs">
              <span className="text-soc-muted">{k}</span>
              {k === 'collector' ? (
                <span className={v?.running ? 'text-emerald-400' : 'text-rose-400'}>
                  {v.running ? 'running' : 'stopped'}
                </span>
              ) : (
                <span className="text-emerald-400">{String(v)}</span>
              )}
            </div>
          ))}
        </Card>

        <Card title="Active models">
          {(Object.entries(data.models || {}) as any[]).map(([k, v]) => (
            <div key={k} className="mb-2 flex items-center justify-between text-xs">
              <span className="capitalize text-soc-muted">{k}</span>
              {v?.status === 'not_trained' ? (
                <span className="text-amber-400">not trained</span>
              ) : (
                <span className="text-slate-300">
                  {v.name} <span className="text-soc-muted">({v.version})</span>
                </span>
              )}
            </div>
          ))}
        </Card>

        <Card title="Runtime configuration">
          {(Object.entries(data.config || {}) as any[]).map(([k, v]) => (
            <div key={k} className="mb-2 flex items-center justify-between text-xs">
              <span className="text-soc-muted">{k}</span>
              <span className="font-mono text-slate-300">{String(v)}</span>
            </div>
          ))}
        </Card>
      </div>

      <Card title="Platform">
        <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
          {Object.entries({
            'Platform': 'SentinelTrap · AICD-TIP',
            'Honeypot': 'Local simulated adapter',
            'Detection': 'ML + anomaly + risk',
            'Deception': 'Adaptive policies',
          }).map(([k, v]) => (
            <div key={k} className="rounded border border-soc-border p-2">
              <div className="text-soc-muted">{k}</div>
              <div className="font-mono text-slate-300">{v}</div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
