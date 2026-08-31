import { useState } from 'react'
import { Card, Empty, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import type { AuditEntry } from '../../types'
import { fmtTime } from '../../utils/format'

const PAGE_SIZE = 100

export default function AuditPage() {
  const [page, setPage] = useState(1)
  const [action, setAction] = useState('')
  const { data, loading } = useFetch<{ total: number; items: AuditEntry[] }>(
    () =>
      api.get(
        `/audit?page=${page}&page_size=${PAGE_SIZE}${action ? `&action=${action}` : ''}`,
      ),
    [page, action],
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-soc-text">Audit Log</h1>
        <input
          value={action}
          onChange={(e) => {
            setAction(e.target.value)
            setPage(1)
          }}
          placeholder="Filter by action…"
          className="w-60 rounded border border-soc-border bg-soc-panel px-3 py-1.5 text-sm text-soc-text outline-none focus:border-soc-accent"
        />
      </div>

      {loading ? (
        <Spinner />
      ) : (
        <Card className="overflow-hidden">
          {data?.items.length ? (
            <table className="w-full text-left text-xs">
              <thead className="border-b border-soc-border text-soc-muted">
                <tr>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">Action</th>
                  <th className="px-3 py-2">Resource</th>
                  <th className="px-3 py-2">IP</th>
                  <th className="px-3 py-2">Details</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {data.items.map((a) => (
                  <tr key={a.id} className="border-b border-soc-border/50 hover:bg-soc-panel">
                    <td className="whitespace-nowrap px-3 py-2 text-slate-400">{fmtTime(a.created_at)}</td>
                    <td className="px-3 py-2 text-slate-300">
                      {a.user_id ? a.user_id.slice(0, 8) : '—'}
                    </td>
                    <td className="px-3 py-2 text-cyan-300">{a.action}</td>
                    <td className="px-3 py-2 text-soc-muted">
                      {a.resource_type}/{a.resource_id || ''}
                    </td>
                    <td className="px-3 py-2 text-slate-400">{a.ip_address || '—'}</td>
                    <td className="max-w-md truncate px-3 py-2 text-slate-500">
                      {a.details ? JSON.stringify(a.details) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty message="No audit entries." />
          )}
        </Card>
      )}

      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-soc-muted">
          <span>{data.total} total · page {page}</span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
              className="rounded border border-soc-border px-3 py-1 disabled:opacity-40"
            >
              Prev
            </button>
            <button
              disabled={page * PAGE_SIZE >= data.total}
              onClick={() => setPage((p) => p + 1)}
              className="rounded border border-soc-border px-3 py-1 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
