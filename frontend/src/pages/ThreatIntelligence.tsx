import { useState } from 'react'
import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls } from '../components/DemoControls'
import { Card, EmptyState, Select, FilterBar, StatusBadge } from '../components/ui'
import { ThreatIntelTable } from '../components/domain'

export default function ThreatIntelligence() {
  const { indicators } = useDemo()
  const [type, setType] = useState('all')

  const filtered = type === 'all' ? indicators : indicators.filter((i) => i.type === type)

  const summary = {
    ips: indicators.filter((i) => i.type === 'ip').length,
    hashes: indicators.filter((i) => i.type === 'hash').length,
    behaviors: indicators.filter((i) => i.type === 'behavior').length,
  }

  return (
    <div>
      <PageHeader title="Threat Intelligence" subtitle="Raw honeypot events converted into actionable indicators" actions={<DemoControls />} />

      <div className="mb-4 grid grid-cols-3 gap-3">
        {[
          { k: 'IP Indicators', v: summary.ips, color: 'text-cyan-300' },
          { k: 'Hash Indicators', v: summary.hashes, color: 'text-amber-300' },
          { k: 'Behavioral Indicators', v: summary.behaviors, color: 'text-violet-300' },
        ].map((s) => (
          <div key={s.k} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
            <div className={`text-3xl font-bold ${s.color}`}>{s.v}</div>
            <div className="text-xs uppercase tracking-wide text-slate-500">{s.k}</div>
          </div>
        ))}
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-4">
        <FilterBar>
          <Select value={type} onChange={setType} options={[
            { value: 'all', label: 'All Indicators' },
            { value: 'ip', label: 'IP Indicators' },
            { value: 'hash', label: 'Hash Indicators' },
            { value: 'behavior', label: 'Behavioral Indicators' },
          ]} label="Type" />
        </FilterBar>
        <div className="flex gap-1.5">
          <StatusBadge label="Derived from synthetic demo telemetry" tone="cyan" />
        </div>
      </div>

      <Card>
        {filtered.length === 0 ? <EmptyState message="No indicators of this type yet — generate payload events to create hashes" /> : <ThreatIntelTable indicators={filtered} />}
      </Card>
    </div>
  )
}
