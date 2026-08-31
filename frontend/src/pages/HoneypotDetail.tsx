import { useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useDemo } from '../services/demoContext'
import { Card, ThreatBadge, StatusBadge, EmptyState, TimeAgo } from '../components/ui'
import { AdaptationTimeline } from '../components/domain'

export default function HoneypotDetail() {
  const { id } = useParams()
  const { getHoneypot, adaptations } = useDemo()
  const hp = useMemo(() => (id ? getHoneypot(id) : undefined), [id, getHoneypot])

  if (!hp) return <EmptyState message="Honeypot not found" />

  const history = adaptations.filter((a) => a.honeypot_id === hp.id || a.honeypot_name === hp.name)

  const config = [
    { k: 'Name', v: hp.name },
    { k: 'Type', v: hp.type },
    { k: 'Exposed service', v: hp.service },
    { k: 'Interaction level', v: hp.interaction_level },
    { k: 'AI adaptation', v: hp.ai_enabled ? 'Enabled' : 'Disabled' },
    { k: 'Status', v: hp.status },
  ]

  return (
    <div>
      <div className="mb-4">
        <Link to="/honeypots" className="text-xs text-cyan-400 hover:underline">← Back to Adaptive Honeypots</Link>
      </div>

      <div className="mb-4 rounded-lg border border-slate-800 bg-slate-900/60 p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="font-mono text-3xl font-bold text-slate-100">{hp.name}</div>
            <div className="text-sm text-slate-500">{hp.type} honeypot · service: {hp.service}</div>
          </div>
          <div className="flex gap-2">
            <StatusBadge label={hp.status} tone={hp.status === 'active' ? 'green' : 'red'} />
            <StatusBadge label={hp.ai_state} tone={hp.ai_state === 'ADAPTING' ? 'amber' : 'cyan'} />
          </div>
        </div>
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {config.map((c) => (
            <div key={c.k} className="rounded border border-slate-800 bg-slate-950/50 p-3">
              <div className="text-[10px] uppercase tracking-wide text-slate-500">{c.k}</div>
              <div className="mt-0.5 text-sm font-semibold text-slate-100">{c.v}</div>
            </div>
          ))}
        </div>
        {hp.current_threat !== 'None' && (
          <div className="mt-4 flex items-center gap-3">
            <span className="text-sm text-slate-400">Current Threat:</span>
            <span className="font-semibold text-slate-100">{hp.current_threat}</span>
            {hp.current_severity && <ThreatBadge sev={hp.current_severity} />}
            <span className="text-xs text-slate-500">adapted {hp.last_adaptation ? <TimeAgo iso={hp.last_adaptation} /> : '—'} ago</span>
          </div>
        )}
      </div>

      <Card title="Adaptation History">
        <AdaptationTimeline adaptations={history} />
      </Card>
    </div>
  )
}
