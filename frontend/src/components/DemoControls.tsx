import { useDemo } from '../services/demoContext'

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-bold text-slate-100">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-slate-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function LiveActivityBadge() {
  const { running } = useDemo()
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${running ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' : 'border-slate-700 bg-slate-800/50 text-slate-400'}`}>
      <span className={`h-2 w-2 rounded-full ${running ? 'animate-pulse bg-emerald-400' : 'bg-slate-500'}`} />
      {running ? 'LIVE' : 'PAUSED'}
    </span>
  )
}

function Btn({ onClick, children, tone = 'slate' }: { onClick: () => void; children: React.ReactNode; tone?: 'slate' | 'green' | 'red' | 'cyan' | 'amber' }) {
  const map = {
    slate: 'border-slate-700 text-slate-300 hover:bg-slate-800',
    green: 'border-emerald-500/50 text-emerald-300 hover:bg-emerald-500/10',
    red: 'border-rose-500/50 text-rose-300 hover:bg-rose-500/10',
    cyan: 'border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/10',
    amber: 'border-amber-500/50 text-amber-300 hover:bg-amber-500/10',
  }
  return (
    <button onClick={onClick} className={`rounded border px-3 py-1.5 text-xs font-medium transition ${map[tone]}`}>
      {children}
    </button>
  )
}

export function DemoControls() {
  const { running, controls } = useDemo()
  return (
    <div className="flex flex-wrap items-center gap-2">
      <LiveActivityBadge />
      {running ? (
        <Btn tone="amber" onClick={controls.pause}>Pause Simulation</Btn>
      ) : (
        <Btn tone="green" onClick={controls.start}>Start Simulation</Btn>
      )}
      <Btn tone="red" onClick={controls.reset}>Reset Data</Btn>
      <span className="mx-1 h-5 w-px bg-slate-800" />
      <Btn tone="cyan" onClick={controls.ssh}>Generate SSH Attack</Btn>
      <Btn tone="cyan" onClick={controls.web}>Generate Web Scan</Btn>
      <Btn tone="cyan" onClick={controls.payload}>Generate Payload Event</Btn>
    </div>
  )
}
