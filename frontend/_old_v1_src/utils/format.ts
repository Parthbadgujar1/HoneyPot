export function fmtTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

export function fmtDur(seconds?: number | null): string {
  if (seconds == null) return '—'
  if (seconds < 60) return `${seconds.toFixed(0)}s`
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  return `${m}m ${s}s`
}

export function severityColor(sev?: string | null): string {
  switch (sev) {
    case 'CRITICAL':
      return 'text-rose-500'
    case 'HIGH':
      return 'text-orange-400'
    case 'MEDIUM':
      return 'text-amber-400'
    case 'LOW':
      return 'text-emerald-400'
    default:
      return 'text-slate-400'
  }
}

export function severityBg(sev?: string | null): string {
  switch (sev) {
    case 'CRITICAL':
      return 'bg-rose-500/15 text-rose-400 border-rose-500/30'
    case 'HIGH':
      return 'bg-orange-500/15 text-orange-400 border-orange-500/30'
    case 'MEDIUM':
      return 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    case 'LOW':
      return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
    default:
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30'
  }
}

export function eventTypeColor(t?: string | null): string {
  if (!t) return 'bg-slate-500/20 text-slate-300'
  if (t.includes('authentication_failure')) return 'bg-rose-500/15 text-rose-400'
  if (t.includes('authentication_success')) return 'bg-emerald-500/15 text-emerald-400'
  if (t.includes('authentication')) return 'bg-amber-500/15 text-amber-400'
  if (t.includes('command')) return 'bg-cyan-500/15 text-cyan-400'
  if (t.includes('file')) return 'bg-violet-500/15 text-violet-400'
  if (t.includes('connection')) return 'bg-sky-500/15 text-sky-400'
  if (t.includes('deception')) return 'bg-fuchsia-500/15 text-fuchsia-400'
  return 'bg-slate-500/20 text-slate-300'
}
