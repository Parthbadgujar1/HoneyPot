import { useMemo, useState } from 'react'
import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls, LiveActivityBadge } from '../components/DemoControls'
import { Card, FilterBar, Select, SearchBar, DateRangePicker, EmptyState, KpiCard } from '../components/ui'
import { AttackCard, LiveEventFeed } from '../components/domain'
import { ATTACK_TYPES } from '../types'

const PAGE_SIZE = 12

export default function LiveMonitor() {
  const { events, running } = useDemo()
  const [type, setType] = useState('all')
  const [sev, setSev] = useState('all')
  const [hp, setHp] = useState('all')
  const [status, setStatus] = useState('all')
  const [query, setQuery] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [minConf, setMinConf] = useState(0)
  const [page, setPage] = useState(1)

  const filtered = useMemo(() => {
    const fromT = from ? new Date(from).getTime() : -Infinity
    const toT = to ? new Date(to).getTime() : Infinity
    return events.filter((e) => {
      if (type !== 'all' && e.attack_type !== type) return false
      if (sev !== 'all' && e.severity !== sev) return false
      if (hp !== 'all' && e.target_honeypot !== hp) return false
      if (status !== 'all' && e.status !== status) return false
      if (query && !e.source_ip.includes(query) && !e.id.toLowerCase().includes(query.toLowerCase())) return false
      if (e.confidence < minConf) return false
      const t = new Date(e.timestamp).getTime()
      if (t < fromT || t > toT) return false
      return true
    })
  }, [events, type, sev, hp, status, query, from, to, minConf])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const lastEvent = events[0]
  const activeCounter = events.filter((e) => e.status !== 'quarantined' && e.status !== 'blocked').length

  const indicators = [
    { label: 'Active Events', value: activeCounter, accent: running ? 'text-emerald-400' : '' },
    { label: 'Connection/Session', value: events.filter((e) => e.status === 'captured' || e.status === 'observed').length },
    { label: 'Streaming Events', value: events.length },
    { label: 'Last Event', value: lastEvent ? new Date(lastEvent.timestamp).toLocaleTimeString() : '—', accent: 'text-cyan-300' },
  ]

  return (
    <div>
      <PageHeader title="Live Attack Monitor" subtitle="Real-time event stream with filters" actions={<DemoControls />} />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        {indicators.map((k) => (
          <KpiCard key={k.label} label={k.label} value={k.value} accent={k.accent} />
        ))}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <LiveActivityBadge />
        <FilterBar>
          <Select value={type} onChange={setType} options={[{ value: 'all', label: 'All Attack Types' }].concat(ATTACK_TYPES.map((t) => ({ value: t, label: t })))} label="Type" />
          <Select value={sev} onChange={setSev} options={[{ value: 'all', label: 'All Severity' }].concat(['low', 'medium', 'high', 'critical'].map((s) => ({ value: s, label: s })))} label="Severity" />
          <Select value={hp} onChange={setHp} options={[{ value: 'all', label: 'All Honeypots' }].concat(['SSH-01', 'WEB-01', 'FILE-01'].map((h) => ({ value: h, label: h })))} label="Honeypot" />
          <Select value={status} onChange={setStatus} options={[{ value: 'all', label: 'All Status' }].concat(['blocked', 'observed', 'quarantined', 'captured'].map((s) => ({ value: s, label: s })))} label="Status" />
          <SearchBar value={query} onChange={setQuery} placeholder="Filter by source IP / event id…" />
        </FilterBar>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-4">
        <DateRangePicker from={from} to={to} onChange={(f, t) => { setFrom(f); setTo(t) }} />
        <label className="flex items-center gap-2 text-xs text-slate-400">
          <span>Min confidence {(minConf * 100).toFixed(0)}%</span>
          <input type="range" min={0} max={100} value={minConf * 100} onChange={(e) => setMinConf(Number(e.target.value) / 100)} className="accent-cyan-500" />
        </label>
        <span className="text-xs text-slate-500">{filtered.length} matching</span>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <Card title={`Live Event Stream (${filtered.length})`} className="lg:col-span-3">
          {filtered.length === 0 ? <EmptyState message="No events match the active filters" /> : <LiveEventFeed events={filtered} limit={40} />}
        </Card>
        <Card title="Attack Cards" className="lg:col-span-2">
          {pageItems.length === 0 ? (
            <EmptyState message="No events match the active filters" />
          ) : (
            <>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {pageItems.map((e) => <AttackCard key={e.id} ev={e} />)}
              </div>
              <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
                <span>page {page}/{totalPages}</span>
                <div className="flex gap-2">
                  <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-slate-800 px-2 py-1 disabled:opacity-40 hover:text-slate-200">Prev</button>
                  <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="rounded border border-slate-800 px-2 py-1 disabled:opacity-40 hover:text-slate-200">Next</button>
                </div>
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  )
}
