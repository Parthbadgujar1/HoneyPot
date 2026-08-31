import { Card, Empty, SeverityBadge, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import type { DeceptionAction, DeceptionEnvironment } from '../../types'
import { fmtTime } from '../../utils/format'

export default function DeceptionPage() {
  const { data: env, loading: l1 } = useFetch<DeceptionEnvironment>(() =>
    api.get('/deception/environment'),
  )
  const { data: actions, loading: l2 } = useFetch<{ items: DeceptionAction[] }>(() =>
    api.get('/deception/actions'),
  )

  if (l1 || l2) return <Spinner />

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-soc-text">Adaptive Deception</h1>

      <Card
        title={`Decoy environment · ${env?.active_count ?? 0} active`}
      >
        {env?.decoys.length ? (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {env.decoys.map((d) => (
              <div
                key={d.decoy}
                className={`rounded-lg border p-3 ${
                  d.active
                    ? 'border-emerald-500/50 bg-emerald-500/5'
                    : 'border-soc-border bg-soc-panel2'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm text-soc-text">{d.decoy}</span>
                  <span
                    className={`h-2.5 w-2.5 rounded-full ${
                      d.active ? 'bg-emerald-400' : 'bg-slate-600'
                    }`}
                  />
                </div>
                <div className="mt-1 text-xs text-soc-muted">target: {d.target}</div>
                <div className="mt-0.5 text-xs text-slate-400">{d.description}</div>
              </div>
            ))}
          </div>
        ) : (
          <Empty />
        )}
      </Card>

      <Card title="Deception action history">
        {actions?.items.length ? (
          <table className="w-full text-left text-xs">
            <thead className="border-b border-soc-border text-soc-muted">
              <tr>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Policy</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Session</th>
                <th className="px-3 py-2">Reason</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {actions.items.map((d) => (
                <tr key={d.id} className="border-b border-soc-border/50 hover:bg-soc-panel">
                  <td className="whitespace-nowrap px-3 py-2 text-slate-400">
                    {fmtTime(d.created_at)}
                  </td>
                  <td className="px-3 py-2 text-fuchsia-300">{d.policy_id}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge
                      sev={d.status === 'executed' ? 'HIGH' : d.status === 'rolled_back' ? 'LOW' : 'MEDIUM'}
                    />
                    <span className="ml-1 text-slate-300">{d.status}</span>
                  </td>
                  <td className="px-3 py-2 text-soc-accent">
                    {d.session_id ? d.session_id.slice(0, 8) : '—'}
                  </td>
                  <td className="max-w-sm truncate px-3 py-2 text-slate-400">{d.reason || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty message="No adaptive deception actions yet." />
        )}
      </Card>
    </div>
  )
}
