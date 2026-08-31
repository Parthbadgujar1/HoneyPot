import { useEffect, useState } from 'react'
import { Card, Empty, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import type { HoneypotEvent, Paged } from '../../types'
import { eventTypeColor, fmtTime } from '../../utils/format'

const PAGE_SIZE = 50

export default function EventsPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  const [sessionId, setSessionId] = useState('')

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 400)
    return () => clearTimeout(t)
  }, [search])

  const build = () => {
    let q = `/events?page=${page}&page_size=${PAGE_SIZE}`
    if (debounced) q += `&search=${encodeURIComponent(debounced)}`
    if (sessionId) q += `&session_id=${encodeURIComponent(sessionId)}`
    return q
  }

  const { data, loading, reload } = useFetch<Paged<HoneypotEvent>>(
    () => api.get(build()),
    [page, debounced, sessionId],
  )

  useEffect(() => {
    if (page !== 1) setPage(1)
  }, [debounced, sessionId])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-soc-text">Event Log</h1>
        <button
          onClick={reload}
          className="rounded border border-soc-border px-3 py-1 text-xs text-soc-muted hover:text-soc-accent"
        >
          Refresh
        </button>
      </div>

      <div className="flex flex-wrap gap-3">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search action / command…"
          className="w-72 rounded border border-soc-border bg-soc-panel px-3 py-1.5 text-sm text-soc-text outline-none focus:border-soc-accent"
        />
        <input
          value={sessionId}
          onChange={(e) => setSessionId(e.target.value)}
          placeholder="Filter by session ID…"
          className="w-64 rounded border border-soc-border bg-soc-panel px-3 py-1.5 text-sm text-soc-text outline-none focus:border-soc-accent"
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
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Service</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Action</th>
                  <th className="px-3 py-2">Target</th>
                  <th className="px-3 py-2">Command</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {data.items.map((e) => (
                  <tr key={e.id} className="border-b border-soc-border/50 hover:bg-soc-panel">
                    <td className="whitespace-nowrap px-3 py-1.5 text-slate-400">
                      {fmtTime(e.timestamp)}
                    </td>
                    <td className="px-3 py-1.5 text-slate-300">{e.source || '—'}</td>
                    <td className="px-3 py-1.5 text-slate-300">{e.service || '—'}</td>
                    <td className="px-3 py-1.5">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] ${eventTypeColor(e.event_type)}`}
                      >
                        {e.event_type}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-cyan-300">{e.action || '—'}</td>
                    <td className="px-3 py-1.5 text-violet-300">{e.target || '—'}</td>
                    <td className="max-w-md truncate px-3 py-1.5 text-slate-300">
                      {e.command || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty message="No events match." />
          )}
        </Card>
      )}

      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center justify-between text-sm text-soc-muted">
          <span>
            {data.total} total · page {page}
          </span>
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
