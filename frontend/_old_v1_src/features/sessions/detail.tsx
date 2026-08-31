import { useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Badge,
  Card,
  Empty,
  SeverityBadge,
  Spinner,
} from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import type { GraphData, SessionDetail, TimelineEntry } from '../../types'
import { fmtDur, fmtTime, severityColor } from '../../utils/format'
import { AttackGraph } from '../graph/AttackGraph'

interface AnalysisResponse {
  status: string
  analysis: any
}

export default function SessionDetailPage() {
  const { id } = useParams()
  const { data, loading, reload } = useFetch<SessionDetail>(
    () => api.get(`/sessions/${id}`),
    [id],
  )
  const [analysing, setAnalysing] = useState(false)
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null)
  const [notes, setNotes] = useState('')

  const { data: graph, reload: reloadGraph } = useFetch<GraphData>(
    () => api.get(`/sessions/${id}/graph`),
    [id],
  )
  const { data: timeline } = useFetch<TimelineEntry[]>(
    () => api.get(`/sessions/${id}/timeline`),
    [id],
  )

  const runAnalysis = async () => {
    if (!id) return
    setAnalysing(true)
    setNotes('')
    try {
      const res = await api.post<AnalysisResponse>(`/sessions/${id}/analyse`)
      setAnalysis(res)
      setNotes('Analysis complete')
      reload()
      reloadGraph()
    } catch (e: any) {
      setNotes(e?.message || 'Analysis failed')
    } finally {
      setAnalysing(false)
    }
  }

  if (loading || !data) return <Spinner />

  // Prefer freshly computed analysis, fall back to persisted artifacts.
  const a = analysis?.analysis || {
    classification: data.classification,
    anomaly: data.anomaly,
    prediction: data.prediction,
    features: data.features,
    risk: data.risk_score
      ? { score: data.risk_score, severity: data.severity }
      : null,
    deception_actions: data.deception_actions,
  }

  const risk = a.risk

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-soc-text">
            Session <span className="text-soc-accent">{data.session_ref}</span>
          </h1>
          <div className="mt-1 flex flex-wrap items-center gap-3 text-sm text-soc-muted">
            <span>{data.source || '—'}</span>
            <span>·</span>
            <span>{data.service || '—'}</span>
            <span>·</span>
            <span>{fmtTime(data.start_time)}</span>
            <span>·</span>
            <span>{fmtDur(data.duration_seconds)}</span>
            <span>·</span>
            <span>{data.event_count} events</span>
            {data.is_active && <Badge className="border-sky-500/40 text-sky-400">active</Badge>}
          </div>
        </div>
        <button
          onClick={runAnalysis}
          disabled={analysing}
          className="rounded bg-soc-accent px-4 py-2 text-sm font-semibold text-soc-bg hover:opacity-90 disabled:opacity-60"
        >
          {analysing ? 'Analysing…' : 'Run analysis'}
        </button>
      </div>
      {notes && <p className="text-sm text-soc-muted">{notes}</p>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Info
          label="Behaviour classification"
          value={
            data?.risk_score != null
              ? undefined
              : (() => {
                  const c = a.classification
                  if (!c || c.status === 'model_not_trained')
                    return <span className="font-normal text-soc-muted">not analysed</span>
                  return (
                    <span>
                      {c.behaviour_class}
                      {c.confidence && (
                        <span className="ml-2 text-xs text-soc-muted">
                          {(c.confidence * 100).toFixed(0)}%
                        </span>
                      )}
                    </span>
                  )
                })()
          }
        />
        <Info
          label="Risk"
          value={
            risk ? (
              <>
                <span className={severityColor(risk.severity)}>
                  {risk.score != null ? risk.score.toFixed(1) : '—'}
                </span>
                <span className="ml-2">
                  <SeverityBadge sev={risk.severity} />
                </span>
              </>
            ) : (
              <span className="font-normal text-soc-muted">not assessed</span>
            )
          }
        />
        <Info
          label="Anomaly"
          value={
            a.anomaly && a.anomaly.status !== 'model_not_trained' ? (
              <span
                className={
                  a.anomaly?.label === 'anomaly' ? 'font-semibold text-rose-400' : 'text-emerald-400'
                }
              >
                {a.anomaly?.label?.toUpperCase() || '—'}{' '}
                {a.anomaly?.anomaly_score != null && (
                  <span className="text-xs text-soc-muted">
                    ({a.anomaly.anomaly_score.toFixed(3)})
                  </span>
                )}
              </span>
            ) : (
              <span className="font-normal text-soc-muted">—</span>
            )
          }
        />
        <Info
          label="Predicted next"
          value={
            a.prediction && a.prediction.status !== 'model_not_trained' && a.prediction.top1 ? (
              <span>
                <span className="font-semibold text-amber-300">{a.prediction.top1}</span>
                <span className="ml-2 text-xs text-soc-muted">
                  {(a.prediction.top1_probability * 100).toFixed(0)}%
                </span>
              </span>
            ) : (
              <span className="font-normal text-soc-muted">—</span>
            )
          }
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Card title="Behaviour features" className="col-span-1">
          {a.features ? (
            <div className="max-h-80 space-y-1 overflow-y-auto text-xs">
              {Object.entries(a.features).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between border-b border-soc-border/40 py-1">
                  <span className="text-soc-muted">{k}</span>
                  <span className="font-mono text-slate-300">
                    {typeof v === 'number' ? v.toFixed(2) : String(v)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <Empty message="No features yet." />
          )}
        </Card>

        <Card title="Risk contributions" className="col-span-2">
          {risk?.contributions ? (
            <div className="space-y-3">
              {Object.entries(risk.contributions).map(([k, c]: any) => {
                const pct = (c.score / 100) * 100
                return (
                  <div key={k}>
                    <div className="mb-1 flex justify-between text-xs">
                      <span className="text-soc-muted">{k}</span>
                      <span className="font-mono text-slate-300">
                        signal {c.signal.toFixed(2)} · {c.score.toFixed(1)} pts
                      </span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded bg-soc-border">
                      <div
                        className="h-full rounded bg-soc-accent"
                        style={{ width: `${Math.min(100, pct)}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <Empty message="Run analysis to compute risk contributions." />
          )}
        </Card>
      </div>

      <Card title="Attack graph">
        {graph && graph.nodes.length ? (
          <AttackGraph graph={graph} />
        ) : (
          <Empty message="Graph available after analysis." />
        )}
      </Card>

      <div className="grid grid-cols-2 gap-4">
        <Card
          title="Timeline"
          actions={
            timeline && (
              <span className="text-xs text-soc-muted">{timeline.length} entries</span>
            )
          }
        >
          {timeline && timeline.length ? (
            <div className="max-h-96 space-y-1 overflow-y-auto">
              {timeline.map((t, i) => (
                <div
                  key={i}
                  className="flex gap-3 border-b border-soc-border/40 py-1.5 text-xs"
                >
                  <span className="w-24 shrink-0 font-mono text-soc-muted">
                    {fmtTime(t.timestamp).split(', ')[1] || fmtTime(t.timestamp)}
                  </span>
                  <span className="w-28 shrink-0 text-sky-300">{t.event_type}</span>
                  <span className="w-20 shrink-0 text-cyan-300">{t.action || ''}</span>
                  <span className="flex-1 text-slate-300">{t.description}</span>
                </div>
              ))}
            </div>
          ) : (
            <Empty message="Timeline available after analysis." />
          )}
        </Card>

        <div className="space-y-4">
          <Card title="Prediction">
            {a.prediction && a.prediction.status !== 'model_not_trained' ? (
              <div className="space-y-2">
                {a.prediction.top_predictions?.map((p: any) => (
                  <div key={p.stage}>
                    <div className="mb-1 flex justify-between text-xs">
                      <span className="text-slate-300">{p.stage}</span>
                      <span className="font-mono text-soc-muted">
                        {(p.probability * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded bg-soc-border">
                      <div
                        className="h-full rounded bg-amber-400/70"
                        style={{ width: `${(p.probability * 100).toFixed(1)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <Empty message="Prediction available after analysis." />
            )}
          </Card>

          <Card title="Deception actions">
            {data.deception_actions?.length ? (
              <div className="space-y-2 text-xs">
                {data.deception_actions.map((d) => (
                  <div
                    key={d.id}
                    className="rounded border border-soc-border/50 p-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-fuchsia-300">{d.policy_id}</span>
                      <Badge
                        className={`${
                          d.status === 'executed'
                            ? 'border-emerald-500/40 text-emerald-400'
                            : 'border-slate-500/40 text-slate-400'
                        }`}
                      >
                        {d.status}
                      </Badge>
                    </div>
                    {d.reason && (
                      <p className="mt-1 text-soc-muted">{d.reason}</p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <Empty message="No deception actions for this session." />
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}

function Info({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-panel px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-soc-muted">{label}</div>
      <div className="mt-1 text-sm font-semibold text-soc-text">{value}</div>
    </div>
  )
}
