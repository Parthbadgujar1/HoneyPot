import { Link } from 'react-router-dom'
import type { AttackEvent, Attacker, DemoSession, Honeypot, ThreatIndicator } from '../types'
import { SEVERITY_HEX, StatusBadge, ThreatBadge, TimeAgo, fmtTime } from './ui'

export function AttackCard({ ev }: { ev: AttackEvent }) {
  return (
    <Link to={`/sessions/${ev.session_id}`} className="block rounded-lg border border-slate-800 bg-slate-900/60 p-3 transition hover:border-slate-700">
      <div className="flex items-center justify-between">
        <span className="text-sm font-semibold text-slate-200">{ev.attack_type}</span>
        <ThreatBadge sev={ev.severity} />
      </div>
      <div className="mt-2 space-y-0.5 text-xs text-slate-400">
        <div>Source: <span className="font-mono text-slate-300">{ev.source_ip}</span></div>
        <div>Target: <span className="text-slate-300">{ev.target_honeypot}</span></div>
        {ev.attempts != null && <div>{ev.attempts} attempts</div>}
        {ev.requests != null && <div>{ev.requests} requests · {ev.unique_paths} paths</div>}
        {ev.filename && <div className="truncate font-mono text-amber-200/80">{ev.filename}</div>}
        <div className="flex items-center justify-between pt-1">
          <span className="text-cyan-300">AI conf {(ev.confidence * 100).toFixed(0)}%</span>
          <TimeAgo iso={ev.timestamp} />
        </div>
      </div>
    </Link>
  )
}

export function LiveEventFeed({ events, limit = 60 }: { events: AttackEvent[]; limit?: number }) {
  const rows = events.slice(0, limit)
  return (
    <div className="space-y-1 font-mono text-xs">
      {rows.length === 0 && <div className="py-6 text-center text-slate-500">No events yet</div>}
      {rows.map((e) => (
        <div key={e.id} className="flex items-center gap-3 rounded border border-slate-800/60 bg-slate-900/40 px-3 py-2">
          <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY_HEX[e.severity] }} />
          <span className="w-14 shrink-0 text-slate-500">{new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
          <span className="w-36 shrink-0 font-medium" style={{ color: SEVERITY_HEX[e.severity] }}>{e.attack_type}</span>
          <span className="w-32 shrink-0 text-slate-300">{e.source_ip}</span>
          <span className="w-20 shrink-0 text-slate-500">{e.target_honeypot}</span>
          <span className="flex-1 truncate text-slate-400">
            {e.attempts ? `${e.attempts} attempts` : e.requests ? `${e.requests} req · ${e.unique_paths} paths` : e.filename}
          </span>
          <span className="text-cyan-300/80">{Math.round(e.confidence * 100)}%</span>
        </div>
      ))}
    </div>
  )
}

export function HoneypotCard({ hp }: { hp: Honeypot }) {
  const tone = hp.status === 'offline' ? 'red' : hp.ai_state === 'ADAPTING' ? 'amber' : 'green'
  return (
    <Link to={`/honeypots/${hp.id}`} className="block rounded-lg border border-slate-800 bg-slate-900/60 p-4 hover:border-slate-700">
      <div className="flex items-center justify-between">
        <div className="font-mono text-lg font-bold text-slate-100">{hp.name}</div>
        <StatusBadge label={hp.status} tone={tone} />
      </div>
      <div className="mt-0.5 text-xs text-slate-500">{hp.type} · {hp.service}</div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <Meta k="Interaction" v={hp.interaction_level} />
        <Meta k="AI" v={hp.ai_state} />
        <Meta k="Sessions" v={String(hp.sessions)} />
        <Meta k="Threat" v={hp.current_threat === 'None' ? '—' : hp.current_threat} />
      </div>
      {hp.current_threat !== 'None' && (
        <div className="mt-2 flex items-center justify-between text-xs">
          <ThreatBadge sev={hp.current_severity || 'medium'} />
          <span className="text-slate-500">adapt {hp.last_adaptation ? <TimeAgo iso={hp.last_adaptation} /> : '—'}</span>
        </div>
      )}
    </Link>
  )
}

function Meta({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <div className="text-slate-500">{k}</div>
      <div className="font-medium text-slate-300">{v}</div>
    </div>
  )
}

export function AttackerTable({ attackers }: { attackers: Attacker[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="text-slate-500">
          <tr className="border-b border-slate-800">
            <th className="px-3 py-2">Source IP</th>
            <th className="px-3 py-2">Attack</th>
            <th className="px-3 py-2 text-right">Events</th>
            <th className="px-3 py-2 text-right">Sessions</th>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2 text-right">Risk</th>
            <th className="px-3 py-2">Last Seen</th>
          </tr>
        </thead>
        <tbody className="font-mono">
          {attackers.slice(0, 20).map((a) => (
            <tr key={a.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
              <td className="px-3 py-2">
                <Link to={`/attacks/${a.id}`} className="text-cyan-300 hover:underline">{a.source_ip}</Link>
              </td>
              <td className="px-3 py-2 text-slate-300">{a.attack_types.join(', ') || '—'}</td>
              <td className="px-3 py-2 text-right text-slate-300">{a.total_events}</td>
              <td className="px-3 py-2 text-right text-slate-300">{a.total_sessions}</td>
              <td className="px-3 py-2"><ThreatBadge sev={a.severity} /></td>
              <td className="px-3 py-2 text-right font-semibold" style={{ color: a.risk_score >= 51 ? '#fb923c' : a.risk_score >= 26 ? '#f59e0b' : '#34d399' }}>{a.risk_score}</td>
              <td className="px-3 py-2 text-slate-400"><TimeAgo iso={a.last_seen} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function ThreatIntelTable({ indicators }: { indicators: ThreatIndicator[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="text-slate-500">
          <tr className="border-b border-slate-800">
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2">Indicator</th>
            <th className="px-3 py-2">Detail</th>
            <th className="px-3 py-2 text-right">Events</th>
            <th className="px-3 py-2">Attacks</th>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2">First / Last</th>
          </tr>
        </thead>
        <tbody className="font-mono">
          {indicators.slice(0, 20).map((i) => (
            <tr key={i.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
              <td className="px-3 py-2">
                <span className="rounded border border-slate-700 px-1.5 py-0.5 text-[10px] text-slate-300">{i.type}</span>
              </td>
              <td className="max-w-[180px] truncate px-3 py-2 text-slate-200">{i.label}</td>
              <td className="px-3 py-2 text-slate-400">{i.detail || '—'}</td>
              <td className="px-3 py-2 text-right text-slate-300">{i.events}</td>
              <td className="px-3 py-2 text-slate-300">{i.attacks.join(', ')}</td>
              <td className="px-3 py-2"><ThreatBadge sev={i.severity} /></td>
              <td className="px-3 py-2 text-slate-400">
                <TimeAgo iso={i.first_seen} /> / <TimeAgo iso={i.last_seen} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function AdaptationTimeline({ adaptations, limit = 50 }: { adaptations: any[]; limit?: number }) {
  return (
    <div className="space-y-2">
      {adaptations.slice(0, limit).length === 0 && <div className="py-6 text-center text-slate-500">No adaptations yet</div>}
      {adaptations.slice(0, limit).map((a) => (
        <div key={a.id} className="rounded border border-slate-800 bg-slate-900/40 p-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-cyan-300">{a.decision}</span>
            <span className="text-slate-500">{fmtTime(a.timestamp)}</span>
          </div>
          <div className="mt-1 text-xs text-slate-400">Trigger: {a.trigger}</div>
          <div className="mt-1 flex items-center gap-3 text-xs">
            <span className="text-slate-500">{a.honeypot_name}</span>
            <span className="text-amber-300/90">→ {a.configuration_changed}</span>
            <span className="text-emerald-300/80">→ {a.result}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

export function BehaviorTimeline({ stages }: { stages: string[] }) {
  return (
    <div className="space-y-0">
      {stages.map((s, i) => (
        <div key={i} className="relative flex items-center gap-3 pb-1">
          {i < stages.length - 1 && <span className="absolute left-1.5 top-4 h-full w-px bg-slate-800" />}
          <span className="z-10 h-3 w-3 shrink-0 rounded-full border border-cyan-400 bg-slate-900" />
          <span className="text-sm text-slate-200">{s}</span>
        </div>
      ))}
    </div>
  )
}

export function SessionViewer({ session }: { session: DemoSession }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-3 rounded border border-slate-800 bg-slate-900/40 p-4">
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span className="font-mono text-lg font-bold text-slate-100">{session.id}</span>
          <span className="text-slate-400">Attacker:</span> <span className="font-mono text-cyan-300">{session.attacker_ip}</span>
          <span className="text-slate-400">Target:</span> <span className="text-slate-300">{session.target_honeypot}</span>
          <ThreatBadge sev={session.severity} />
          <span className="text-cyan-300">AI conf {(session.confidence * 100).toFixed(0)}%</span>
          <StatusBadge label={session.status} tone={session.status === 'quarantined' ? 'red' : 'cyan'} />
        </div>
      </div>
      <div className="rounded border border-slate-800 bg-slate-900/40 p-4 lg:col-span-2">
        <div className="mb-2 text-xs font-semibold text-slate-400">Session Timeline</div>
        <div className="space-y-2">
          {session.timeline.map((t, i) => (
            <div key={i} className="flex items-center gap-3 text-xs font-mono">
              <span className="w-20 shrink-0 text-slate-500">{new Date(t.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
              <span className={`h-2 w-2 shrink-0 rounded-full ${dotFor(t.kind)}`} />
              <span className="text-slate-300">{t.label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="rounded border border-slate-800 bg-slate-900/40 p-4">
        <div className="mb-2 text-xs font-semibold text-slate-400">Observed Commands (read-only)</div>
        {session.commands?.length ? (
          <div className="space-y-1 font-mono text-xs text-slate-300">
            {session.commands.map((c, i) => (
              <div key={i} className="rounded bg-slate-950 px-2 py-1">$ {c}</div>
            ))}
          </div>
        ) : (
          <div className="text-xs text-slate-500">No commands recorded.</div>
        )}
        <div className="mt-3 text-xs text-slate-600">Commands are displayed for analysis only — never executed.</div>
      </div>
    </div>
  )
}

function dotFor(kind: string) {
  switch (kind) {
    case 'connect': return 'bg-sky-400'
    case 'auth': return 'bg-amber-400'
    case 'fail': return 'bg-rose-500'
    case 'req': return 'bg-slate-500'
    case 'warn': return 'bg-orange-400'
    case 'ai': return 'bg-cyan-400'
    case 'capture': return 'bg-emerald-400'
    default: return 'bg-slate-500'
  }
}
