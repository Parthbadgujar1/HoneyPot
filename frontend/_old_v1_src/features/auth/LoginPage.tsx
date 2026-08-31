import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth'

const DEMO = [
  { u: 'admin', p: 'admin123', r: 'ADMIN' },
  { u: 'analyst', p: 'analyst123', r: 'ANALYST' },
  { u: 'viewer', p: 'viewer123', r: 'VIEWER' },
]

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin123')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(username, password)
      navigate('/')
    } catch (err: any) {
      setError(err?.message || 'Login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-soc-bg">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-3">
          <img src="/favicon.svg" alt="" className="h-10 w-10" />
          <div>
            <div className="text-xl font-bold text-soc-text">SentinelTrap</div>
            <div className="text-xs uppercase tracking-widest text-soc-accent">
              Adaptive AI Cyber Deception · Threat Intelligence Platform
            </div>
          </div>
        </div>
        <form
          onSubmit={submit}
          className="rounded-lg border border-soc-border bg-soc-panel p-6"
        >
          <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-soc-muted">
            Sign in
          </h2>
          {error && (
            <div className="mb-3 rounded border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-400">
              {error}
            </div>
          )}
          <label className="mb-1 block text-xs text-soc-muted">Username</label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="mb-3 w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-sm text-soc-text outline-none focus:border-soc-accent"
          />
          <label className="mb-1 block text-xs text-soc-muted">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mb-4 w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-sm text-soc-text outline-none focus:border-soc-accent"
          />
          <button
            disabled={busy}
            className="w-full rounded bg-soc-accent px-3 py-2 text-sm font-semibold text-soc-bg hover:opacity-90 disabled:opacity-60"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <div className="mt-4 rounded-lg border border-soc-border bg-soc-panel p-4 text-xs text-soc-muted">
          <div className="mb-1 font-semibold text-soc-text">Demo accounts</div>
          {DEMO.map((d) => (
            <button
              key={d.u}
              onClick={() => {
                setUsername(d.u)
                setPassword(d.p)
              }}
              className="mr-2 mb-1 inline-flex items-center gap-1 rounded border border-soc-border px-2 py-0.5 text-soc-muted hover:border-soc-accent hover:text-soc-accent"
            >
              {d.u}
              <span className="text-[10px] text-soc-accent">{d.r}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
