import { useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useDemo } from '../services/demoContext'
import { Card, ThreatBadge, RiskScore, TimeAgo, EmptyState, StatusBadge } from '../components/ui'
import { BehaviorTimeline } from '../components/domain'

export default function AttackerDetail() {
  const { id } = useParams()
  const { getAttacker, events, analyses } = useDemo()
  const attacker = useMemo(() => (id ? getAttacker(id) : undefined), [id, getAttacker])

  if (!attacker) return <EmptyState message="Attacker not found" />

  const evs = events.filter((e) => e.source_ip === attacker.source_ip)
  const analysis = analyses.find((a) => a.session_id && evs.some((e) => e.session_id === a.session_id))

  const ind = [
    { label: 'Attack frequency', value: attacker.attack_frequency },
    { label: 'Avg session duration', value: `${attacker.avg_session_duration_s || '—'}s` },
    { label: 'Unique commands', value: attacker.unique_commands },
    { label: 'Unique endpoints', value: attacker.unique_endpoints },
    { label: 'Repeated actions', value: attacker.repeated_actions },
    { label: 'Escalation', value: attacker.escalation ? 'Yes' : 'No' },
    { label: 'Persistence', value: attacker.persistence ? 'Yes' : 'No' },
  ]

  return (
    <div>
      <div className="mb-4">
        <Link to="/attacks" className="text-xs text-cyan-400 hover:underline">← Back to Attack Analysis</Link>
      </div>

      <div className="mb-4 rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div>
            <div className="text-xs uppercase tracking-wide text-slate-500">Attacker</div>
            <div className="font-mono text-2xl font-bold text-cyan-300">{attacker.source_ip}</div>
            <div className="text-xs text-slate-500">ID: {attacker.id}</div>
          </div>
          <RiskScore score={attacker.risk_score} size="lg" />
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-3">
            <Meta k="First seen" v={attacker.first_seen ? <TimeAgo iso={attacker.first_seen} /> : '—'} />
            <Meta k="Last seen" v={attacker.last_seen ? <TimeAgo iso={attacker.last_seen} /> : '—'} />
            <Meta k="Total sessions" v={String(attacker.total_sessions)} />
            <Meta k="Total events" v={String(attacker.total_events)} />
            <Meta k="Attack types" v={attacker.attack_types.join(', ') || '—'} />
            <Meta k="Targeted services" v={attacker.targeted_services.join(', ') || '—'} />
            <Meta k="Severity" v={attacker.severity ? <ThreatBadge sev={attacker.severity} /> : '—'} />
            <Meta k="AI confidence" v={attacker.confidence ? `${(attacker.confidence * 100).toFixed(0)}%` : '—'} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Behavioral Pattern">
          <BehaviorTimeline stages={attacker.behavior_stages} />
        </Card>
        <Card title="Behavioral Indicators" className="lg:col-span-2">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {ind.map((x) => (
              <div key={x.label} className="rounded border border-slate-800 bg-slate-950/50 p-3 text-center">
                <div className="text-lg font-bold text-slate-100">{x.value}</div>
                <div className="text-[10px] uppercase tracking-wide text-slate-500">{x.label}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {analysis && (
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Card title="AI Classification">
            <div className="text-lg font-semibold text-slate-100">{analysis.classification}</div>
            <div className="mt-1 text-xs text-slate-500">{analysis.behavior_pattern}</div>
            <div className="mt-3 flex items-center justify-between text-xs"><span className="text-slate-500">Confidence</span><span className="font-bold text-cyan-300">{(analysis.confidence * 100).toFixed(0)}%</span></div>
            <div className="mt-1 h-2 w-full overflow-hidden rounded bg-slate-800"><div className="h-full rounded bg-cyan-400" style={{ width: `${analysis.confidence * 100}%` }} /></div>
          </Card>
          <Card title="Recent Activity" className="lg:col-span-2">
            <div className="space-y-1.5 font-mono text-xs">
              {evs.slice(0, 12).map((e) => (
                <Link key={e.id} to={`/sessions/${e.session_id}`} className="flex items-center gap-3 rounded border border-slate-800/60 bg-slate-950/40 px-3 py-1.5 hover:border-slate-700">
                  <StatusBadge label={e.status} />
                  <span className="w-40 shrink-0 text-slate-300">{e.attack_type}</span>
                  <span className="text-slate-500">{e.target_honeypot}</span>
                  <span className="flex-1" />
                  <ThreatBadge sev={e.severity} />
                  <span className="text-slate-500"><TimeAgo iso={e.timestamp} /></span>
                </Link>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

function Meta({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div>
      <div className="text-slate-500">{k}</div>
      <div className="text-slate-200">{v}</div>
    </div>
  )
}
