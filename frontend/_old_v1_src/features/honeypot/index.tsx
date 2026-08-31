import { useState } from 'react'
import { Card, Empty, Spinner } from '../../components/ui'
import { useFetch } from '../../hooks/useFetch'
import { api } from '../../services/api'
import type { HoneypotStatus, ScenarioInfo } from '../../types'
import { useAuth } from '../../hooks/useAuth'

export default function HoneypotPage() {
  const { user } = useAuth()
  const canSimulate = ['ADMIN', 'ANALYST', 'RESEARCHER'].includes(user?.role || '')
  const { data: status, loading, reload } = useFetch<HoneypotStatus>(() =>
    api.get('/honeypot/status'),
  )
  const { data: scenarios, loading: l2 } = useFetch<ScenarioInfo[]>(() =>
    api.get('/honeypot/scenarios'),
  )
  const [selected, setSelected] = useState('multi_stage')
  const [n, setN] = useState(3)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const simulate = async () => {
    setBusy(true)
    setMsg('')
    try {
      const res = await api.simulate(selected, n)
      setMsg(`Emitted ${res.emitted} events across ${res.sessions} session(s) for '${res.scenario}'.`)
      reload()
    } catch (e: any) {
      setMsg('Error: ' + e?.message)
    } finally {
      setBusy(false)
    }
  }

  if (loading || l2) return <Spinner />

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-soc-text">Honeypot</h1>

      <div className="grid grid-cols-3 gap-4">
        <Card title="Adapter">
          <div className="space-y-1 text-xs">
            <Row k="Adapter" v={status?.adapter?.adapter} />
            <Row k="Service" v={status?.adapter?.service} />
            <Row k="Mode" v={status?.adapter?.mode} />
            <Row k="Online" v={status?.adapter?.online ? 'yes' : 'no'} accent="text-emerald-400" />
          </div>
        </Card>
        <Card title="Collector">
          <div className="space-y-1 text-xs">
            <Row k="Running" v={status?.collector?.running ? 'yes' : 'no'} accent="text-emerald-400" />
            <Row k="Collected events" v={status?.collector?.collected} />
            <Row k="Analysed sessions" v={status?.collector?.analysed} />
          </div>
        </Card>
        <Card title="Database">
          <div className="space-y-1 text-xs">
            <Row k="Online" v={status?.db?.online ? 'yes' : 'no'} accent="text-emerald-400" />
            <Row k="Driver" v={status?.db?.driver} />
          </div>
        </Card>
      </div>

      <Card title="Simulate attacker behaviour (safe, local)">
        {canSimulate ? (
          <>
            <div className="mb-3 flex flex-wrap gap-2">
              {(scenarios || []).map((s) => (
                <button
                  key={s.id}
                  onClick={() => setSelected(s.id)}
                  className={`rounded border px-3 py-1 text-xs ${
                    selected === s.id
                      ? 'border-soc-accent bg-soc-accent/10 text-soc-accent'
                      : 'border-soc-border text-soc-muted hover:text-soc-text'
                  }`}
                >
                  {s.id}
                </button>
              ))}
            </div>
            {selected && (
              <p className="mb-3 text-xs text-soc-muted">
                {(scenarios || []).find((s) => s.id === selected)?.description}
              </p>
            )}
            <div className="flex items-center gap-3">
              <label className="text-xs text-soc-muted">Sessions</label>
              <input
                type="number"
                min={1}
                max={20}
                value={n}
                onChange={(e) => setN(Number(e.target.value))}
                className="w-20 rounded border border-soc-border bg-soc-panel px-2 py-1 text-sm text-soc-text"
              />
              <button
                onClick={simulate}
                disabled={busy}
                className="rounded bg-soc-accent px-4 py-1.5 text-sm font-semibold text-soc-bg hover:opacity-90 disabled:opacity-60"
              >
                {busy ? 'Simulating…' : 'Simulate'}
              </button>
            </div>
          </>
        ) : (
          <Empty message="Viewer role cannot trigger simulations." />
        )}
        {msg && <p className="mt-3 text-sm text-soc-muted">{msg}</p>}
      </Card>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        {(scenarios || []).map((s) => (
          <div key={s.id} className="rounded-lg border border-soc-border bg-soc-panel p-3">
            <div className="font-mono text-sm text-soc-accent">{s.id}</div>
            <div className="text-xs font-semibold text-soc-text">{s.label}</div>
            <div className="mt-1 text-xs text-soc-muted">{s.description}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function Row({ k, v, accent = '' }: { k: string; v: any; accent?: string }) {
  return (
    <div className="flex justify-between border-b border-soc-border/40 py-1">
      <span className="text-soc-muted">{k}</span>
      <span className={`font-mono text-slate-300 ${accent}`}>{String(v)}</span>
    </div>
  )
}
