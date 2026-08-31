import { Link } from 'react-router-dom'
import { Card, Empty } from '../../components/ui'
import { useLiveEvents } from '../../hooks/useLiveEvents'
import { eventTypeColor, fmtTime } from '../../utils/format'

export default function LiveEventsPage() {
  const { connected, recent } = useLiveEvents()

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-soc-text">Live Telemetry</h1>
        <span
          className={`inline-flex items-center gap-2 rounded border px-3 py-1 text-xs ${
            connected
              ? 'border-emerald-500/40 text-emerald-400'
              : 'border-rose-500/40 text-rose-400'
          }`}
        >
          <span
            className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-rose-500'}`}
          />
          {connected ? 'Streaming' : 'Disconnected'}
        </span>
      </div>

      <Card
        title={`Real-time feed · ${recent.length} events buffered`}
        actions={
          <Link to="/sessions" className="text-xs text-soc-accent hover:underline">
            Investigate sessions →
          </Link>
        }
      >
        {recent.length ? (
          <div className="space-y-1 font-mono text-xs">
            {recent.map((e, i) => (
              <div
                key={i}
                className="flex items-center gap-3 rounded border border-soc-border/40 px-3 py-2 hover:bg-soc-panel"
              >
                <span className="w-32 shrink-0 text-soc-muted">{fmtTime(e.timestamp)}</span>
                <span className="w-24 shrink-0 text-slate-300">{e.source || '—'}</span>
                <span className="w-20 shrink-0 text-slate-400">{e.service || '—'}</span>
                <span
                  className={`w-44 shrink-0 rounded px-1.5 py-0.5 text-[10px] ${eventTypeColor(e.event_type)}`}
                >
                  {e.event_type}
                </span>
                <span className="min-w-0 flex-1 truncate text-slate-200">{e.action || '—'}</span>
                <span className="truncate text-violet-300">{e.target || ''}</span>
              </div>
            ))}
          </div>
        ) : (
          <Empty message="Streaming is active — trigger a honeypot simulation to see events arrive instantly." />
        )}
      </Card>
    </div>
  )
}
