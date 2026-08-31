import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls } from '../components/DemoControls'
import { KpiCard, Card, ThreatBadge } from '../components/ui'
import { AttackTimeline, AttackDistributionChart, SeverityChart } from '../components/charts'
import { buildTimeline, attackDistribution, severityDistribution, topAttackers } from '../utils/analytics'
import { TimeAgo } from '../components/ui'

export default function Dashboard() {
  const { summary, events, attackers } = useDemo()
  const timeline = buildTimeline(events)
  const dist = attackDistribution(events)
  const sevDist = severityDistribution(events)
  const top = topAttackers(events).slice(0, 6)

  const kpis = [
    { label: 'Active Attacks', value: summary.active_attacks, accent: 'text-rose-400' },
    { label: 'Total Events', value: summary.total_events },
    { label: 'Unique Attackers', value: summary.unique_attackers },
    { label: 'High/Critical Threats', value: summary.high_critical_threats, accent: 'text-orange-400' },
    { label: 'Active Honeypots', value: summary.active_honeypots, accent: 'text-emerald-400' },
    { label: 'AI Adaptations', value: summary.ai_adaptations, accent: 'text-cyan-400' },
    { label: 'Sessions Captured', value: summary.sessions_captured },
    { label: 'Detection Accuracy', value: `${(summary.detection_accuracy * 100).toFixed(1)}%`, accent: 'text-cyan-300' },
  ]

  return (
    <div>
      <PageHeader title="Security Overview" subtitle="AI-Based Adaptive Honeypot · SOC Dashboard" actions={<DemoControls />} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-4">
        {kpis.map((k) => (
          <KpiCard key={k.label} label={k.label} value={k.value} accent={k.accent} />
        ))}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title="Attack Timeline (last 20 min)">
            <AttackTimeline data={timeline} />
          </Card>
        </div>
        <Card title="Attack Distribution">
          <AttackDistributionChart data={dist} />
          <div className="mt-2 flex justify-center gap-4 text-xs text-slate-400">
            {dist.map((d, i) => (
              <span key={i} className="flex items-center gap-1">
                <span className="h-2 w-2 rounded-full" style={{ background: ['#22d3ee', '#a78bfa', '#f43f5e'][i % 3] }} />
                {d.name} ({d.value})
              </span>
            ))}
          </div>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Threat Severity">
          <SeverityChart data={sevDist} />
        </Card>
        <Card title="Top Attacker Sources" className="lg:col-span-2">
          <table className="w-full text-left text-xs">
            <thead className="text-slate-500">
              <tr className="border-b border-slate-800">
                <th className="px-2 py-2">Source IP</th>
                <th className="px-2 py-2">Attack</th>
                <th className="px-2 py-2 text-right">Events</th>
                <th className="px-2 py-2">Severity</th>
                <th className="px-2 py-2">Last Seen</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {top.map((t) => {
                const a = attackers.find((x) => x.source_ip === t.ip)
                const ev = events.find((e) => e.source_ip === t.ip)
                return (
                  <tr key={t.ip} className="border-b border-slate-800/50">
                    <td className="px-2 py-2 text-cyan-300">{t.ip}</td>
                    <td className="px-2 py-2">{ev?.attack_type ?? '—'}</td>
                    <td className="px-2 py-2 text-right">{t.count}</td>
                    <td className="px-2 py-2">{a ? <ThreatBadge sev={a.severity} /> : '—'}</td>
                    <td className="px-2 py-2 text-slate-400">{ev ? <TimeAgo iso={ev.timestamp} /> : '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  )
}
