import { useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useDemo } from '../services/demoContext'
import { Card, ThreatBadge, StatusBadge, EmptyState, AIConfidenceCard } from '../components/ui'
import { SessionViewer } from '../components/domain'

export default function SessionDetail() {
  const { id } = useParams()
  const { getSession, getEvent, getAnalysis } = useDemo()
  const session = useMemo(() => (id ? getSession(id) : undefined), [id, getSession])

  if (!session) return <EmptyState message="Session not found" />

  const event = getEvent(session.id)
  const analysis = event ? getAnalysis(event.id) : undefined

  return (
    <div>
      <div className="mb-4">
        <Link to="/sessions" className="text-xs text-cyan-400 hover:underline">← Back to Sessions</Link>
      </div>
      <SessionViewer session={session} />
      {analysis && (
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <AIConfidenceCard confidence={analysis.confidence} classification={analysis.classification} risk={analysis.risk_score} />
          <Card title="AI Decision">
            <div className="text-lg font-semibold text-cyan-300">{analysis.decision}</div>
            <div className="mt-1 text-xs text-slate-400">{analysis.observed}</div>
            <div className="mt-2 text-xs text-emerald-300">{analysis.recommendation}</div>
          </Card>
        </div>
      )}
      {event?.filename && (
        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="mb-2 text-xs font-semibold text-slate-400">Payload Metadata</div>
          <div className="grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
            <div><div className="text-slate-500">File name</div><div className="font-mono text-amber-200">{event.filename}</div></div>
            <div><div className="text-slate-500">Type</div><div className="text-slate-200">{event.file_type}</div></div>
            <div><div className="text-slate-500">Size</div><div className="text-slate-200">{(event.file_size! / 1024).toFixed(0)} KB</div></div>
            <div><div className="text-slate-500">SHA-256</div><div className="truncate font-mono text-slate-300">{event.sha256}</div></div>
          </div>
          <div className="mt-3 flex items-center gap-2"><StatusBadge label={event.status} tone="red" /><span className="text-xs text-slate-500">File quarantined — never executed.</span></div>
        </div>
      )}
    </div>
  )
}
