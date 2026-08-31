import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls } from '../components/DemoControls'
import { Card, SearchBar, Select, FilterBar, EmptyState, RiskScore } from '../components/ui'
import { AttackerTable } from '../components/domain'
import type { AttackType } from '../types'

export default function AttackAnalysis() {
  const { attackers } = useDemo()
  const [cat, setCat] = useState<'all' | AttackType>('all')
  const [sev, setSev] = useState('all')
  const [query, setQuery] = useState('')

  const filtered = attackers.filter((a) => {
    if (cat !== 'all' && !a.attack_types.includes(cat)) return false
    if (sev !== 'all' && a.severity !== sev) return false
    if (query && !a.source_ip.includes(query)) return false
    return true
  })

  const tabs = [
    { v: 'all' as const, label: 'All Attackers' },
    { v: 'SSH Brute Force' as const, label: 'SSH Brute Force' },
    { v: 'Web Scanner' as const, label: 'Web Scanner' },
    { v: 'Payload Delivery' as const, label: 'Payload Delivery' },
  ]

  return (
    <div>
      <PageHeader title="Attack Analysis" subtitle="Attacker profiles, behavior patterns and risk scoring" actions={<DemoControls />} />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {tabs.map((t) => (
          <button key={t.v} onClick={() => setCat(t.v)} className={`rounded-full border px-3 py-1.5 text-xs font-medium ${cat === t.v ? 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300' : 'border-slate-800 text-slate-400 hover:text-slate-200'}`}>
            {t.label}
          </button>
        ))}
      </div>

      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <SearchBar value={query} onChange={setQuery} placeholder="Filter by source IP…" />
          <Select value={sev} onChange={setSev} options={[{ value: 'all', label: 'All Severity' }].concat(['low', 'medium', 'high', 'critical'].map((s) => ({ value: s, label: s })))} label="Severity" />
        </div>
        {filtered.length === 0 ? (
          <EmptyState message="No attackers match the current filters" />
        ) : (
          <AttackerTable attackers={filtered} />
        )}
      </Card>

      {attackers.length > 0 && (
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
          {attackers.slice(0, 6).map((a) => (
            <Link key={a.id} to={`/attacks/${a.source_ip}`} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-center hover:border-slate-700">
              <div className="mb-1 flex justify-center"><RiskScore score={a.risk_score} size="sm" /></div>
              <div className="truncate font-mono text-xs text-cyan-300">{a.source_ip}</div>
              <div className="text-[10px] text-slate-500">{a.attack_types.join(', ')}</div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
