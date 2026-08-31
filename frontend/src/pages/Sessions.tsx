import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useDemo } from '../services/demoContext'
import { PageHeader, DemoControls } from '../components/DemoControls'
import { Card, ThreatBadge, StatusBadge, TimeAgo, Select, SearchBar, FilterBar, EmptyState, Pagination } from '../components/ui'

const PAGE_SIZE = 12

export default function Sessions() {
  const { sessions } = useDemo()
  const [query, setQuery] = useState('')
  const [type, setType] = useState('all')
  const [page, setPage] = useState(1)

  const filtered = sessions.filter((s) => {
    if (type !== 'all' && s.attack_type !== type) return false
    if (query && !s.id.toLowerCase().includes(query.toLowerCase()) && !s.attacker_ip.includes(query)) return false
    return true
  })

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  return (
    <div>
      <PageHeader title="Sessions" subtitle="Captured attack sessions and timelines" actions={<DemoControls />} />

      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <SearchBar value={query} onChange={setQuery} placeholder="Search session id / attacker ip…" />
          <Select value={type} onChange={setType} options={[{ value: 'all', label: 'All Attack Types' }].concat(['SSH Brute Force', 'Web Scanner', 'Payload Delivery'].map((t) => ({ value: t, label: t })))} label="Type" />
        </div>
        {filtered.length === 0 ? (
          <EmptyState message="No sessions match the current filters" />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-500">
                  <tr className="border-b border-slate-800">
                    <th className="px-3 py-2">Session</th>
                    <th className="px-3 py-2">Attacker</th>
                    <th className="px-3 py-2">Target</th>
                    <th className="px-3 py-2">Attack</th>
                    <th className="px-3 py-2">Severity</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2 text-right">Events</th>
                    <th className="px-3 py-2">Start</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {pageItems.map((s) => (
                    <tr key={s.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                      <td className="px-3 py-2 text-cyan-300"><Link to={`/sessions/${s.id}`} className="hover:underline">{s.id}</Link></td>
                      <td className="px-3 py-2">{s.attacker_ip}</td>
                      <td className="px-3 py-2 text-slate-400">{s.target_honeypot}</td>
                      <td className="px-3 py-2 text-slate-300">{s.attack_type}</td>
                      <td className="px-3 py-2"><ThreatBadge sev={s.severity} /></td>
                      <td className="px-3 py-2"><StatusBadge label={s.status} tone={s.status === 'quarantined' ? 'red' : 'cyan'} /></td>
                      <td className="px-3 py-2 text-right">{s.event_count}</td>
                      <td className="px-3 py-2 text-slate-500"><TimeAgo iso={s.start_time} /> · <span className="text-cyan-300/70">{(s.confidence * 100).toFixed(0)}%</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} total={filtered.length} pageSize={PAGE_SIZE} onChange={setPage} />
          </>
        )}
      </Card>
    </div>
  )
}
