// Data models per spec §19

export type AttackType = 'SSH Brute Force' | 'Web Scanner' | 'Payload Delivery'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type EventStatus = 'blocked' | 'observed' | 'quarantined' | 'captured'
export type HoneypotType = 'SSH' | 'Web' | 'File'
export type HoneypotStatus = 'active' | 'paused' | 'offline'
export type InteractionLevel = 'LOW' | 'MEDIUM' | 'HIGH'
export type AIState = 'LEARNING' | 'ADAPTING' | 'STABLE'

export interface AttackEvent {
  id: string // EVT-xxx
  timestamp: string // ISO
  attack_type: AttackType
  source_ip: string
  target_honeypot: string
  target_service: string
  severity: Severity
  confidence: number
  status: EventStatus
  session_id: string
  // scenario-specific
  attempts?: number // SSH
  usernames?: string[] // SSH
  requests?: number // Web
  unique_paths?: number // Web
  method?: string // Web
  filename?: string // Payload
  file_type?: string // Payload
  file_size?: number // Payload
  sha256?: string // Payload
}

export interface Attacker {
  id: string // ATT-xx
  source_ip: string
  first_seen: string
  last_seen: string
  total_events: number
  total_sessions: number
  attack_types: AttackType[]
  targeted_services: string[]
  severity: Severity
  confidence: number
  risk_score: number // 0-100
  // behavioral pattern (compressed stage sequence)
  behavior_stages: string[]
  // behavioral indicators (§8)
  attack_frequency: number
  avg_session_duration_s: number
  unique_commands: number
  unique_endpoints: number
  repeated_actions: number
  escalation: boolean
  persistence: boolean
}

export interface Honeypot {
  id: string
  name: string
  type: HoneypotType
  service: string
  status: HoneypotStatus
  interaction_level: InteractionLevel
  ai_enabled: boolean
  ai_state: AIState
  sessions: number
  current_threat: AttackType | 'None'
  current_severity?: Severity
  last_adaptation: string | null
}

export interface AIAnalysis {
  event_id: string
  session_id: string
  classification: AttackType | 'Normal'
  confidence: number
  risk_score: number // 0-100
  risk_level: Severity
  behavior_pattern: string
  observed: string
  decision: string
  recommendation: string
  explanation: string
  features: { name: string; value: number }[]
}

export interface Adaptation {
  id: string // ADP-xxx
  timestamp: string
  honeypot_id: string
  honeypot_name: string
  trigger: string
  decision: string
  configuration_changed: string
  result: string
  event_id: string
}

export interface ThreatIndicator {
  type: 'ip' | 'hash' | 'behavior'
  id: string
  label: string
  first_seen: string
  last_seen: string
  events: number
  attacks: AttackType[]
  severity: Severity
  detail?: string
}

export interface DemoSession {
  id: string // A-10291
  attacker_ip: string
  target_honeypot: string
  attack_type: AttackType
  severity: Severity
  confidence: number
  status: EventStatus
  start_time: string
  end_time: string | null
  event_count: number
  timeline: { time: string; label: string; kind: string }[]
  commands?: string[]
}

// Dashboard summary (§17)
export interface DashboardSummary {
  active_attacks: number
  total_events: number
  unique_attackers: number
  high_critical_threats: number
  active_honeypots: number
  ai_adaptations: number
  sessions_captured: number
  detection_accuracy: number
}

export const ATTACK_TYPES: AttackType[] = [
  'SSH Brute Force',
  'Web Scanner',
  'Payload Delivery',
]

export const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical']
