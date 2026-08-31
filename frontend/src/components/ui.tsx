import type { ReactNode } from 'react'
import type { Severity } from '../types'

// ---------- severity helpers ----------
export const SEVERITY_STYLES: Record<Severity, { txt: string; bg: string; border: string; dot: string }> = {
  low: { txt: 'text-emerald-300', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', dot: 'bg-emerald-400' },
  medium: { txt: 'text-amber-300', bg: 'bg-amber-500/10', border: 'border-amber-500/30', dot: 'bg-amber-400' },
  high: { txt: 'text-orange-300', bg: 'bg-orange-500/10', border: 'border-orange-500/30', dot: 'bg-orange-400' },
  critical: { txt: 'text-rose-300', bg: 'bg-rose-500/10', border: 'border-rose-500/40', dot: 'bg-rose-500' },
}
export const SEVERITY_HEX: Record<Severity, string> = {
  low: '#34d399', medium: '#f59e0b', high: '#fb923c', critical: '#f43f5e',
}

export function threatTextColor(sev?: Severity) {
  return sev ? SEVERITY_STYLES[sev].txt : 'text-slate-300'
}

// ---------- primitives ----------
export function Card({ title, actions, children, className = '' }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-slate-800 bg-slate-900/60 ${className}`}>
      {(title || actions) && (
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-2.5">
          <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
          {actions}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}

export function KpiCard({ label, value, sub, accent = 'text-slate-100', icon }: { label: string; value: ReactNode; sub?: ReactNode; accent?: string; icon?: ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-center justify-between">
        <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
        {icon && <div className="text-slate-600">{icon}</div>}
      </div>
      <div className={`mt-1 text-3xl font-bold ${accent}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-slate-500">{sub}</div>}
    </div>
  )
}

export function ThreatBadge({ sev }: { sev: Severity }) {
  const s = SEVERITY_STYLES[sev]
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] font-medium uppercase ${s.bg} ${s.border} ${s.txt}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {sev}
    </span>
  )
}

export function StatusBadge({ label, tone = 'slate' }: { label: string; tone?: 'slate' | 'green' | 'amber' | 'red' | 'cyan' }) {
  const map = {
    slate: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    green: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
    amber: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
    red: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
    cyan: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
  }
  return <span className={`inline-flex rounded border px-2 py-0.5 text-[11px] ${map[tone]}`}>{label}</span>
}

export function RiskScore({ score, size = 'md' }: { score: number; size?: 'sm' | 'md' | 'lg' }) {
  const cls = score >= 76 ? 'text-rose-400' : score >= 51 ? 'text-orange-400' : score >= 26 ? 'text-amber-400' : 'text-emerald-400'
  const dim = size === 'lg' ? 'w-20 h-20 text-xl' : size === 'sm' ? 'w-12 h-12 text-sm' : 'w-16 h-16 text-lg'
  const stroke = score >= 76 ? '#f43f5e' : score >= 51 ? '#fb923c' : score >= 26 ? '#f59e0b' : '#34d399'
  const r = size === 'lg' ? 34 : size === 'sm' ? 20 : 27
  const c = 2 * Math.PI * r
  const off = c - (Math.min(100, score) / 100) * c
  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size === 'lg' ? 80 : size === 'md' ? 64 : 48} height={size === 'lg' ? 80 : size === 'md' ? 64 : 48} className="-rotate-90">
        <circle cx={size === 'lg' ? 40 : size === 'md' ? 32 : 24} cy={size === 'lg' ? 40 : size === 'md' ? 32 : 24} r={r} fill="none" stroke="#1e293b" strokeWidth="6" />
        <circle cx={size === 'lg' ? 40 : size === 'md' ? 32 : 24} cy={size === 'lg' ? 40 : size === 'md' ? 32 : 24} r={r} fill="none" stroke={stroke} strokeWidth="6" strokeLinecap="round" strokeDasharray={c} strokeDashoffset={off} />
      </svg>
      <span className={`absolute font-bold ${dim} ${cls}`}>{Math.round(score)}</span>
    </div>
  )
}

export function AIConfidenceCard({ confidence, classification, risk }: { confidence: number; classification: string; risk: number }) {
  const pct = Math.round(confidence * 100)
  const col = pct >= 95 ? 'text-emerald-300' : pct >= 90 ? 'text-cyan-300' : 'text-amber-300'
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">AI Classification</div>
      <div className="mt-1 text-lg font-semibold text-slate-100">{classification}</div>
      <div className="mt-3 flex items-center justify-between text-xs">
        <span className="text-slate-500">Confidence</span>
        <span className={`font-bold ${col}`}>{pct}%</span>
      </div>
      <div className="mt-1 h-2 w-full overflow-hidden rounded bg-slate-800">
        <div className="h-full rounded bg-cyan-400" style={{ width: `${pct}%` }} />
      </div>
      <div className="mt-3 flex items-center justify-between text-xs">
        <span className="text-slate-500">Risk Score</span>
        <span className={`font-bold ${risk >= 51 ? 'text-orange-400' : 'text-amber-300'}`}>{risk}/100</span>
      </div>
    </div>
  )
}

// ---------- states ----------
export function LoadingState({ message = 'Loading…' }: { message?: string }) {
  return (
    <div className="flex items-center gap-2 py-10 text-sm text-slate-500">
      <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />
      {message}
    </div>
  )
}

export function EmptyState({ message = 'No data available' }: { message?: string }) {
  return <div className="py-10 text-center text-sm text-slate-500">{message}</div>
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-300">
      {message}
    </div>
  )
}

// ---------- filters & search ----------
export function FilterBar({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-3">{children}</div>
}

export function Select({ value, onChange, options, label }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; label?: string }) {
  return (
    <label className="flex items-center gap-2 text-xs text-slate-400">
      {label && <span>{label}</span>}
      <select value={value} onChange={(e) => onChange(e.target.value)} className="rounded border border-slate-800 bg-slate-900 px-2 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan-500">
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  )
}

export function SearchBar({ value, onChange, placeholder = 'Search…' }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-56 rounded border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-500"
    />
  )
}

export function DateRangePicker({ from, to, onChange }: { from: string; to: string; onChange: (from: string, to: string) => void }) {
  return (
    <div className="flex items-center gap-1 text-xs text-slate-400">
      <label className="flex items-center gap-1">
        <span>From</span>
        <input type="datetime-local" value={from} onChange={(e) => onChange(e.target.value, to)} className="rounded border border-slate-800 bg-slate-900 px-2 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan-500" />
      </label>
      <label className="flex items-center gap-1">
        <span>To</span>
        <input type="datetime-local" value={to} onChange={(e) => onChange(from, e.target.value)} className="rounded border border-slate-800 bg-slate-900 px-2 py-1.5 text-xs text-slate-300 outline-none focus:border-cyan-500" />
      </label>
    </div>
  )
}

export function Pagination({ page, total, pageSize, onChange }: { page: number; total: number; pageSize: number; onChange: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
      <span>
        {total} item{total === 1 ? '' : 's'} · page {page}/{pages}
      </span>
      <div className="flex gap-2">
        <button disabled={page <= 1} onClick={() => onChange(page - 1)} className="rounded border border-slate-800 px-2 py-1 disabled:opacity-40 hover:text-slate-200">Prev</button>
        <button disabled={page >= pages} onClick={() => onChange(page + 1)} className="rounded border border-slate-800 px-2 py-1 disabled:opacity-40 hover:text-slate-200">Next</button>
      </div>
    </div>
  )
}

export function TimeAgo({ iso }: { iso: string }) {
  if (!iso) return <span>—</span>
  const diff = Math.max(0, Date.now() - new Date(iso).getTime())
  const m = Math.floor(diff / 60000)
  if (m < 1) return <span>just now</span>
  if (m < 60) return <span>{m} min ago</span>
  const h = Math.floor(m / 60)
  return <span>{h} hr ago</span>
}

export function fmtTime(iso: string) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString()
}
