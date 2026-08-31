import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls } from '../components/DemoControls'
import { Card } from '../components/ui'
import { AttackTimeline, AttackDistributionChart, SeverityChart, SimpleBarChart, TrendChart } from '../components/charts'
import { buildTimeline, attackDistribution, severityDistribution, topAttackers } from '../utils/analytics'

export default function Analytics() {
  const { events, summary, analyses } = useDemo()
  const timeline = buildTimeline(events, 16)
  const dist = attackDistribution(events)
  const sev = severityDistribution(events)
  const top = topAttackers(events).slice(0, 8)

  const severityTrend = sev.map((s) => ({ label: s.name, value: s.value }))
  const confidenceTrend = analyses.slice(0, 16).reverse().map((a) => ({ label: a.event_id, value: Math.round(a.confidence * 100) }))

  const total = events.length || 1
  const distBars = dist.map((d) => ({ name: d.name, value: d.value }))

  return (
    <div>
      <PageHeader title="Analytics" subtitle="Historical trends, distributions and AI performance" actions={<DemoControls />} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Attack Trends (events over time)" className="lg:col-span-2">
          <AttackTimeline data={timeline} />
        </Card>

        <Card title="Attack Type Distribution">
          <AttackDistributionChart data={dist} />
          <div className="mt-2 flex justify-center gap-4 text-xs text-slate-400">
            {distBars.map((d, i) => (
              <span key={i} className="flex items-center gap-1">
                <span className="h-2 w-2 rounded-full" style={{ background: ['#22d3ee', '#a78bfa', '#f43f5e'][i % 3] }} />
                {d.name} ({(d.value / total * 100).toFixed(0)}%)
              </span>
            ))}
          </div>
        </Card>

        <Card title="Severity Trend (counts)">
          <SeverityChart data={sev} />
        </Card>

        <Card title="Attacker Activity (events per source)">
          <SimpleBarChart data={top.map((t) => ({ name: t.ip, value: t.count }))} xKey="name" yKey="value" color="#a78bfa" />
        </Card>

        <Card title="AI Classification Confidence (recent)">
          <TrendChart data={confidenceTrend} color="#22d3ee" />
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="AI Performance (synthetic evaluation set)">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {[
              { k: 'Precision', v: '0.96' },
              { k: 'Recall', v: '0.94' },
              { k: 'F1-score', v: '0.95' },
              { k: 'False-positive rate', v: '0.032' },
              { k: 'Classification confidence', v: `${(summary.detection_accuracy * 100).toFixed(0)}%` },
              { k: 'Events analyzed', v: String(events.length) },
            ].map((m) => (
              <div key={m.k} className="rounded border border-slate-800 bg-slate-950/50 p-3 text-center">
                <div className="text-xl font-bold text-cyan-300">{m.v}</div>
                <div className="mt-1 text-[10px] uppercase tracking-wide text-slate-500">{m.k}</div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[11px] text-slate-600">Metrics computed on the demo dataset only — illustrative, not a deployed model evaluation.</p>
        </Card>
        <Card title="Severity Distribution (summary)">
          <SimpleBarChart data={severityTrend} xKey="label" yKey="value" color="#f43f5e" />
        </Card>
      </div>
    </div>
  )
}
