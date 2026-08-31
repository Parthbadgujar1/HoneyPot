import { useState } from 'react'
import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls } from '../components/DemoControls'
import { Card, ThreatBadge, LoadingState, EmptyState, AIConfidenceCard, RiskScore } from '../components/ui'
import { TrendChart } from '../components/charts'

const PIPELINE = [
  'Raw Honeypot Events', 'Data Preprocessing', 'Feature Extraction', 'AI/ML Classification',
  'Behavioral Profiling', 'Risk Scoring', 'Adaptive Decision', 'Honeypot Response', 'New Observation',
]

export default function AIAnalysis() {
  const { analyses, summary, events } = useDemo()
  const [selId, setSelId] = useState<string | null>(analyses[0]?.event_id ?? null)
  const sel = analyses.find((a) => a.event_id === selId) ?? analyses[0]

  if (!analyses.length) return <LoadingState message="Generating AI analysis…" />

  const chart = analyses.slice(0, 12).reverse().map((a) => ({
    label: a.event_id,
    value: Math.round(a.confidence * 100),
  }))

  return (
    <div>
      <PageHeader title="AI Analysis" subtitle="Classification, confidence, risk scoring and adaptive decisions" actions={<DemoControls />} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="AI Pipeline" className="lg:col-span-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {PIPELINE.map((p, i) => (
              <div key={p} className="flex items-center gap-1.5">
                <span className="rounded border border-cyan-500/30 bg-cyan-500/5 px-2 py-1 text-[11px] text-cyan-200">{p}</span>
                {i < PIPELINE.length - 1 && <span className="text-slate-600">→</span>}
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Analysis Feed">
          <div className="max-h-[420px] space-y-1 overflow-y-auto pr-1">
            {analyses.slice(0, 30).map((a) => (
              <button key={a.event_id} onClick={() => setSelId(a.event_id)} className={`block w-full rounded border px-3 py-2 text-left text-xs ${sel?.event_id === a.event_id ? 'border-cyan-500/50 bg-cyan-500/10' : 'border-slate-800 bg-slate-950/40 hover:border-slate-700'}`}>
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">{a.classification}</span>
                  <ThreatBadge sev={a.risk_level} />
                </div>
                <div className="mt-0.5 font-mono text-slate-500">#{a.event_id} · conf {(a.confidence * 100).toFixed(0)}% · risk {a.risk_score}</div>
              </button>
            ))}
          </div>
        </Card>

        {sel && (
          <div className="lg:col-span-2 space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <AIConfidenceCard confidence={sel.confidence} classification={sel.classification} risk={sel.risk_score} />
              <Card title="Behavior Pattern">
                <div className="text-lg font-semibold text-slate-100">{sel.behavior_pattern}</div>
                <div className="mt-2 text-xs text-slate-400">{sel.explanation}</div>
                <div className="mt-4 flex justify-center"><RiskScore score={sel.risk_score} size="lg" /></div>
              </Card>
              <Card title="Adaptive Decision">
                <div className="text-lg font-semibold text-cyan-300">{sel.decision}</div>
                <div className="mt-2 text-xs text-slate-400">{sel.recommendation}</div>
              </Card>
            </div>

            <Card title="Observed Behavior & Decision Rationale">
              <div className="space-y-2 text-sm">
                <div className="rounded border border-slate-800 bg-slate-950/40 p-3">
                  <div className="text-[11px] uppercase tracking-wide text-slate-500">Observed</div>
                  <div className="text-slate-200">{sel.observed}</div>
                </div>
                <div className="rounded border border-slate-800 bg-slate-950/40 p-3">
                  <div className="text-[11px] uppercase tracking-wide text-slate-500">AI Decision</div>
                  <div className="text-cyan-200">{sel.decision}</div>
                  <div className="mt-1 text-slate-300">{sel.explanation}</div>
                </div>
                <div className="rounded border border-slate-800 bg-slate-950/40 p-3">
                  <div className="text-[11px] uppercase tracking-wide text-slate-500">Recommended Adaptation</div>
                  <div className="text-emerald-300">{sel.recommendation}</div>
                </div>
              </div>
            </Card>

            <Card title="Extracted Features">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {sel.features.map((f) => (
                  <div key={f.name} className="rounded border border-slate-800 bg-slate-950/50 p-2.5">
                    <div className="truncate text-[10px] uppercase tracking-wide text-slate-500">{f.name}</div>
                    <div className="font-mono text-base font-bold text-slate-100">{f.value}</div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        )}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Classification Confidence (recent)">
          <TrendChart data={chart} color="#22d3ee" />
        </Card>
        <Card title="AI Metrics (demo evaluation set)">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {[
              { k: 'Precision', v: '0.96' },
              { k: 'Recall', v: '0.94' },
              { k: 'F1-score', v: '0.95' },
              { k: 'False-positive rate', v: '0.032' },
              { k: 'Overall accuracy', v: `${(summary.detection_accuracy * 100).toFixed(1)}%` },
              { k: 'Events classified', v: String(events.length) },
            ].map((m) => (
              <div key={m.k} className="rounded border border-slate-800 bg-slate-950/50 p-3 text-center">
                <div className="text-xl font-bold text-cyan-300">{m.v}</div>
                <div className="mt-1 text-[10px] uppercase tracking-wide text-slate-500">{m.k}</div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[11px] text-slate-600">Metrics are illustrative, computed on the synthetic demo dataset only.</p>
        </Card>
      </div>
    </div>
  )
}
