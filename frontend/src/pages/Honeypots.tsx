import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls } from '../components/DemoControls'
import { Card, ThreatBadge, StatusBadge, TimeAgo, Select, EmptyState, FilterBar } from '../components/ui'
import { HoneypotCard, AdaptationTimeline } from '../components/domain'

export default function Honeypots() {
  const { honeypots, adaptations } = useDemo()
  const [status, setStatus] = useState('all')

  const filtered = useMemo(
    () => (status === 'all' ? honeypots : honeypots.filter((h) => h.status === status)),
    [honeypots, status]
  )

  return (
    <div>
      <PageHeader title="Adaptive Honeypots" subtitle="Deployed honeypots, AI adaptation state and history" actions={<DemoControls />} />

      <div className="mb-4">
        <FilterBar>
          <Select value={status} onChange={setStatus} options={[{ value: 'all', label: 'All Status' }].concat(['active', 'paused', 'offline'].map((s) => ({ value: s, label: s })))} label="Status" />
        </FilterBar>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {filtered.length === 0 ? <EmptyState message="No honeypots match filter" /> : filtered.map((hp) => <HoneypotCard key={hp.id} hp={hp} />)}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title="Adaptation History" actions={<Link to="/analytics" className="text-xs text-cyan-400 hover:underline">Analytics →</Link>}>
            <AdaptationTimeline adaptations={adaptations} />
          </Card>
        </div>
        <Card title="Management Summary">
          <div className="space-y-2 text-xs">
            {honeypots.map((hp) => (
              <Link key={hp.id} to={`/honeypots/${hp.id}`} className="flex items-center justify-between rounded border border-slate-800 bg-slate-950/40 px-3 py-2 hover:border-slate-700">
                <div>
                  <div className="font-mono font-bold text-slate-100">{hp.name}</div>
                  <div className="text-slate-500">{hp.type} · {hp.service}</div>
                </div>
                <div className="text-right">
                  <div className="flex justify-end gap-1"><StatusBadge label={hp.status} tone={hp.status === 'active' ? 'green' : 'red'} /><StatusBadge label={hp.ai_state} tone={hp.ai_state === 'ADAPTING' ? 'amber' : 'cyan'} /></div>
                  {hp.current_threat !== 'None' && <div className="mt-1"><ThreatBadge sev={hp.current_severity || 'medium'} /></div>}
                  <div className="mt-1 text-[10px] text-slate-600">{hp.last_adaptation ? <TimeAgo iso={hp.last_adaptation} /> : 'no adaptation'}</div>
                </div>
              </Link>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}
