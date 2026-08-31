import { NavLink, Outlet } from 'react-router-dom'
import { useDemo } from '../services/demoContext'
import { LiveActivityBadge } from './DemoControls'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/live', label: 'Live Monitor' },
  { to: '/attacks', label: 'Attack Analysis' },
  { to: '/ai', label: 'AI Analysis' },
  { to: '/honeypots', label: 'Adaptive Honeypots' },
  { to: '/intel', label: 'Threat Intelligence' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/analytics', label: 'Analytics' },
]

export default function Layout() {
  const { summary, lastEvent, version } = useDemo()
  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-200">
      <aside className="w-60 shrink-0 border-r border-slate-800 bg-slate-950 flex-col lg:flex hidden">
        <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-4">
          <div className="flex h-9 w-9 items-center justify-center rounded bg-cyan-500/15 font-mono text-lg text-cyan-300">⌖</div>
          <div>
            <div className="text-sm font-bold text-slate-100">AI Adaptive Honeypot</div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500">SOC Dashboard</div>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 p-3">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) =>
                `block rounded px-3 py-2 text-sm ${isActive ? 'bg-cyan-500/10 text-cyan-300' : 'text-slate-400 hover:bg-slate-900 hover:text-slate-200'}`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 p-4 text-[11px] text-slate-500">
          <div className="flex items-center gap-2">
            <LiveActivityBadge />
            <span>{version} updates</span>
          </div>
          <div className="mt-1">Active honeypots: {summary.active_honeypots}</div>
          <div className="mt-1 truncate">Last: {lastEvent ? lastEvent.event : '—'}</div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-4 py-3 lg:hidden">
          <div className="text-sm font-bold text-slate-100">AI Adaptive Honeypot</div>
          <LiveActivityBadge />
        </header>
        <main className="flex-1 p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
