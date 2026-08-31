import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { Severity } from '../types'
import { SEVERITY_HEX } from './ui'

const PIE_COLORS = ['#22d3ee', '#a78bfa', '#f43f5e']
const TOOLTIP_STYLE = { background: '#0f172a', border: '1px solid #1e293b', fontSize: 12, color: '#e2e8f0' } as const

export function AttackTimeline({ data }: { data: { time: string; ssh: number; web: number; payload: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={230}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="gSsh" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.4} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient>
          <linearGradient id="gWeb" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#a78bfa" stopOpacity={0.4} /><stop offset="100%" stopColor="#a78bfa" stopOpacity={0} /></linearGradient>
          <linearGradient id="gPay" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f43f5e" stopOpacity={0.4} /><stop offset="100%" stopColor="#f43f5e" stopOpacity={0} /></linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 10 }} />
        <YAxis tick={{ fill: '#64748b', fontSize: 10 }} allowDecimals={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Area type="monotone" dataKey="ssh" stroke="#22d3ee" fill="url(#gSsh)" strokeWidth={2} name="SSH" />
        <Area type="monotone" dataKey="web" stroke="#a78bfa" fill="url(#gWeb)" strokeWidth={2} name="Web" />
        <Area type="monotone" dataKey="payload" stroke="#f43f5e" fill="url(#gPay)" strokeWidth={2} name="Payload" />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function AttackDistributionChart({ data }: { data: { name: string; value: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={230}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
          {data.map((_, i) => (
            <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip contentStyle={TOOLTIP_STYLE} />
      </PieChart>
    </ResponsiveContainer>
  )
}

export function SeverityChart({ data }: { data: { name: Severity; value: number }[] }) {
  const order = ['critical', 'high', 'medium', 'low'] as Severity[]
  const sorted = [...data].sort((a, b) => order.indexOf(a.name) - order.indexOf(b.name))
  return (
    <ResponsiveContainer width="100%" height={230}>
      <BarChart data={sorted}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
        <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 11 }} />
        <YAxis tick={{ fill: '#64748b', fontSize: 10 }} allowDecimals={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
          {sorted.map((d) => (
            <Cell key={d.name} fill={SEVERITY_HEX[d.name]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function SimpleBarChart({ data, xKey, yKey, color = '#22d3ee' }: { data: any[]; xKey: string; yKey: string; color?: string }) {
  return (
    <ResponsiveContainer width="100%" height={230}>
      <BarChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
        <XAxis dataKey={xKey} tick={{ fill: '#64748b', fontSize: 10 }} />
        <YAxis tick={{ fill: '#64748b', fontSize: 10 }} allowDecimals={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Bar dataKey={yKey} fill={color} radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TrendChart({ data, color = '#34d399' }: { data: { label: string; value: number }[]; color?: string }) {
  return (
    <ResponsiveContainer width="100%" height={230}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="gAvg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity={0.4} /><stop offset="100%" stopColor={color} stopOpacity={0} /></linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis dataKey="label" tick={{ fill: '#64748b', fontSize: 10 }} />
        <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Area type="monotone" dataKey="value" stroke={color} fill="url(#gAvg)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
