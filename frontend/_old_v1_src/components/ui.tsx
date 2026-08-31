import type { ReactNode } from 'react'

export function Card({
  title,
  children,
  actions,
  className = '',
}: {
  title?: ReactNode
  children: ReactNode
  actions?: ReactNode
  className?: string
}) {
  return (
    <div className={`rounded-lg border border-soc-border bg-soc-panel ${className}`}>
      {(title || actions) && (
        <div className="flex items-center justify-between border-b border-soc-border px-4 py-3">
          <h3 className="text-sm font-semibold text-soc-text">{title}</h3>
          {actions}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}

export function StatCard({
  label,
  value,
  accent = 'text-soc-text',
}: {
  label: string
  value: ReactNode
  accent?: string
}) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-panel px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-soc-muted">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${accent}`}>{value}</div>
    </div>
  )
}

export function Badge({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium ${className}`}
    >
      {children}
    </span>
  )
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-soc-muted">
      <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-soc-border border-t-soc-accent" />
      {label}
    </div>
  )
}

export function Empty({ message = 'No data' }: { message?: string }) {
  return <div className="py-6 text-center text-sm text-soc-muted">{message}</div>
}

export function SeverityBadge({ sev }: { sev?: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: 'bg-rose-500/15 text-rose-400 border-rose-500/40',
    HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
    MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
    LOW: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  }
  return (
    <Badge className={map[sev || ''] || 'bg-slate-500/15 text-slate-400 border-slate-500/40'}>
      {sev || '—'}
    </Badge>
  )
}
