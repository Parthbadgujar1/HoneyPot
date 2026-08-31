// REST-shaped API layer (§17). Backed by the in-browser demo engine.
// Each function mirrors the documented endpoint. Swap implementations to a real
// backend later without changing the page code.

import { demo } from '../data/demo'
import type {
  AIAnalysis,
  AttackEvent,
  Attacker,
  DemoSession,
  Honeypot,
  ThreatIndicator,
} from '../types'

const delay = (ms = 80) => new Promise((r) => setTimeout(r, ms))

export const api = {
  // GET /api/dashboard/summary
  async dashboardSummary() {
    await delay(60)
    return demo.getSummary()
  },

  // GET /api/events
  async events() {
    await delay()
    return demo.getEvents()
  },

  // GET /api/events/{event_id}
  async event(id: string): Promise<AttackEvent | undefined> {
    await delay()
    return demo.getEvents().find((e) => e.id === id)
  },

  // GET /api/attackers/{attacker_id}
  async attacker(id: string): Promise<Attacker | undefined> {
    await delay()
    return demo.getAttackers().find((a) => a.id === id || a.source_ip === id)
  },

  // GET /api/honeypots
  async honeypots(): Promise<Honeypot[]> {
    await delay()
    return demo.getHoneypots()
  },

  // GET /api/honeypots/{honeypot_id}
  async honeypot(id: string): Promise<Honeypot | undefined> {
    await delay()
    return demo.getHoneypots().find((h) => h.id === id || h.name === id)
  },

  // GET /api/ai/analysis/{event_id}
  async analysis(eventId: string): Promise<AIAnalysis | undefined> {
    await delay()
    return demo.getAnalyses().find((a) => a.event_id === eventId)
  },

  // GET /api/adaptations
  async adaptations() {
    await delay()
    return demo.getAdaptations()
  },

  // GET /api/threat-intelligence
  async threatIntelligence(): Promise<ThreatIndicator[]> {
    await delay()
    return demo.getIndicators()
  },

  // GET /api/sessions
  async sessions(): Promise<DemoSession[]> {
    await delay()
    return demo.getSessions()
  },

  // GET /api/sessions/{session_id}
  async session(id: string): Promise<DemoSession | undefined> {
    await delay()
    return demo.getSessions().find((s) => s.id === id)
  },
}
