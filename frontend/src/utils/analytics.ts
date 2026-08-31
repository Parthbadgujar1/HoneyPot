import type { AttackEvent, AttackType } from '../types'

export function buildTimeline(events: AttackEvent[], buckets = 14): { time: string; ssh: number; web: number; payload: number }[] {
  const now = Date.now()
  const out: { time: string; ssh: number; web: number; payload: number }[] = []
  const span = 20 * 60 * 1000 // look back 20 min
  const step = span / buckets
  for (let i = buckets - 1; i >= 0; i--) {
    const start = now - (i + 1) * step
    const end = now - i * step
    out.push({
      time: new Date(end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      ssh: 0, web: 0, payload: 0,
    })
    for (const e of events) {
      const t = new Date(e.timestamp).getTime()
      if (t >= start && t < end) {
        if (e.attack_type === 'SSH Brute Force') out[out.length - 1].ssh++
        else if (e.attack_type === 'Web Scanner') out[out.length - 1].web++
        else out[out.length - 1].payload++
      }
    }
  }
  return out
}

export function attackDistribution(events: AttackEvent[]): { name: string; value: number }[] {
  const counts: Record<string, number> = { 'SSH Brute Force': 0, 'Web Scanner': 0, 'Payload Delivery': 0 }
  for (const e of events) counts[e.attack_type] = (counts[e.attack_type] ?? 0) + 1
  return (Object.keys(counts) as AttackType[]).map((name) => ({ name, value: counts[name] }))
}

export function severityDistribution(events: AttackEvent[]): { name: any; value: number }[] {
  const counts: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
  for (const e of events) counts[e.severity] = (counts[e.severity] ?? 0) + 1
  return (Object.keys(counts)).map((name) => ({ name, value: counts[name] }))
}

export function topAttackers(events: AttackEvent[]): { ip: string; count: number }[] {
  const m = new Map<string, number>()
  for (const e of events) m.set(e.source_ip, (m.get(e.source_ip) ?? 0) + 1)
  return Array.from(m.entries()).map(([ip, count]) => ({ ip, count })).sort((a, b) => b.count - a.count)
}
