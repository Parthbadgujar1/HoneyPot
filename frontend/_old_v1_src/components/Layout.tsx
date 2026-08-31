import type { ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

const NAV = [
  { to: '/', label: 'Overview', icon: '◎' },
  { to: '/live', label: 'Live Events', icon: '▣' },
  { to: '/events', label: 'Event Log', icon: '≡' },
  { to: '/sessions', label: 'Sessions', icon: '◈' },
  { to: '/anomalies', label: 'Anomalies', icon: '⚠' },
  { to: '/behaviours', label: 'Behaviours', icon: '◉' },
  { to: '/risk', label: 'Risk', icon: '▲' },
  { to: '/analytics', label: 'Analytics', icon: '▤' },
  { to: '/deception', label: 'Deception', icon: '◗' },
  { to: '/models', label: 'Models', icon: '✚' },
  { to: '/honeypot', label: 'Honeypot', icon: '◈' },
  { to: '/audit', label: 'Audit', icon: '✎' },
  { to: '/system', label: 'System', icon: '⚙' },
]

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  return (
    <div className="flex h-full">
      <aside className="flex w-52 shrink-0 flex-col border-r border-soc-border bg-soc-panel2">
        <div className="flex items-center gap-2 border-b border-soc-border px-4 py-4">
          <img src="/favicon.svg" alt="" className="h-6 w-6" />
          <div>
            <div className="text-sm font-bold text-soc-text">SentinelTrap</div>
            <div className="text-[10px] uppercase tracking-widest text-soc-accent">
              SOC · AICD-TIP
            </div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded px-3 py-2 text-sm transition ${
                  isActive
                    ? 'bg-soc-accent/10 text-soc-accent'
                    : 'text-soc-muted hover:bg-soc-panel hover:text-soc-text'
                }`
              }
            >
              <span className="w-4 text-center">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-soc-border p-3">
          <div className="mb-2 truncate text-xs text-soc-muted">
            {user?.username} · <span className="text-soc-accent">{user?.role}</span>
          </div>
          <button
            onClick={() => {
              logout()
              navigate('/')
            }}
            className="w-full rounded border border-soc-border px-3 py-1.5 text-xs text-soc-muted hover:border-rose-500/40 hover:text-rose-400"
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto bg-soc-bg p-6">{children}</main>
    </div>
  )
}
