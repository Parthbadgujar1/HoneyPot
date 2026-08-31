// React store wrapping the in-browser demo engine.
// Emits a version bump on every engine event so pages re-render reactively.

import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { demo, WsEvent } from '../data/demo'
import type {
  AIAnalysis,
  AttackEvent,
  Attacker,
  DashboardSummary,
  DemoSession,
  Honeypot,
  ThreatIndicator,
} from '../types'

interface DemoApi {
  version: number
  running: boolean
  events: AttackEvent[]
  attackers: Attacker[]
  honeypots: Honeypot[]
  adaptations: any[]
  analyses: AIAnalysis[]
  sessions: DemoSession[]
  indicators: ThreatIndicator[]
  summary: DashboardSummary
  lastEvent: WsEvent | null
  controls: {
    start: () => void
    pause: () => void
    reset: () => void
    ssh: () => void
    web: () => void
    payload: () => void
  }
  // REST-shaped accessors (§17)
  getEvent: (id: string) => AttackEvent | undefined
  getSession: (id: string) => DemoSession | undefined
  getAttacker: (id: string) => Attacker | undefined
  getHoneypot: (id: string) => Honeypot | undefined
  getAnalysis: (eventId: string) => AIAnalysis | undefined
}

const DemoContext = createContext<DemoApi>(null as unknown as DemoApi)

function snapshot() {
  return {
    events: demo.getEvents(),
    attackers: demo.getAttackers(),
    honeypots: demo.getHoneypots(),
    adaptations: demo.getAdaptations(),
    analyses: demo.getAnalyses(),
    sessions: demo.getSessions(),
    indicators: demo.getIndicators(),
    summary: demo.getSummary(),
  }
}

export function DemoProvider({ children }: { children: ReactNode }) {
  const [version, setVersion] = useState(0)
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null)
  const [running, setRunning] = useState(demo.running)

  useEffect(() => {
    let v = 0
    const unsub = demo.subscribe((e) => {
      v += 1
      setVersion(v)
      setLastEvent(e)
      setRunning(demo.running)
    })
    const iv = setInterval(() => {
      setVersion((x) => x + 1) // poll summary counters
    }, 1500)
    return () => {
      unsub()
      clearInterval(iv)
    }
  }, [])

  const value = useMemo<DemoApi>(() => {
    const s = snapshot()
    return {
      version,
      running,
      ...s,
      lastEvent,
      controls: {
        start: () => demo.start(),
        pause: () => demo.pause(),
        reset: () => demo.reset(),
        ssh: () => demo.generateSSH(),
        web: () => demo.generateWeb(),
        payload: () => demo.generatePayload(),
      },
      getEvent: (id) => demo.getEvents().find((e) => e.id === id),
      getSession: (id) => demo.getSessions().find((x) => x.id === id),
      getAttacker: (id) => demo.getAttackers().find((x) => x.id === id || x.source_ip === id),
      getHoneypot: (id) => demo.getHoneypots().find((x) => x.id === id || x.name === id),
      getAnalysis: (eventId) => demo.getAnalyses().find((a) => a.event_id === eventId),
    }
  }, [version, running, lastEvent])

  return <DemoContext.Provider value={value}>{children}</DemoContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useDemo(): DemoApi {
  return useContext(DemoContext)
}
