export interface User {
  id: string
  username: string
  email?: string | null
  role: string
  is_active: boolean
  created_at?: string | null
}

export interface LoginResponse {
  access_token: string
  token_type: string
  user: User
}

export interface DashboardSummary {
  total_sessions: number
  active_sessions: number
  high_risk_sessions: number
  anomalies: number
  total_events: number
  predictions: number
  adaptive_actions: number
}

export interface HoneypotEvent {
  id: string
  event_ref?: string | null
  session_id?: string | null
  timestamp: string
  source?: string | null
  destination?: string | null
  service?: string | null
  event_type: string
  action?: string | null
  target?: string | null
  result?: string | null
  username?: string | null
  command?: string | null
  metadata?: any
  is_anomaly?: boolean | null
  risk_score?: number | null
}

export interface Paged<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export interface SessionSummary {
  id: string
  session_ref: string
  source?: string | null
  service?: string | null
  start_time?: string | null
  end_time?: string | null
  duration_seconds?: number | null
  event_count: number
  is_active: boolean
  risk_score?: number | null
  severity?: string | null
}

export interface ClassificationObject {
  behaviour_class: string
  confidence?: number | null
  probabilities?: Record<string, number> | null
  model: string
  model_version?: string | null
  feature_version?: string | null
}

export interface AnomalyObject {
  anomaly_score?: number | null
  label?: string | null
  reasons?: any[] | null
  contributing_features?: { feature: string; value: number; deviation: number }[] | null
  model: string
  model_version?: string | null
}

export interface PredictionObject {
  top1?: string | null
  top1_probability: number
  top_predictions: { stage: string; probability: number }[]
  input_sequence: string[]
  model: string
  model_version?: string | null
}

export interface RiskObject {
  score: number
  severity: string
  policy_version: string
  weights: Record<string, number>
  contributions: Record<string, { weight: number; signal: number; score: number }>
}

export interface TimelineEntry {
  timestamp: string
  event_type: string
  action?: string | null
  target?: string | null
  service?: string | null
  result?: string | null
  stage?: string
  description?: string
  event_id?: string
  sensitive?: boolean
}

export interface GraphNode {
  data: { id: string; label: string; node_type: string }
}
export interface GraphEdge {
  data: {
    id: string
    source: string
    target: string
    edge_type: string
    label?: string
  }
}
export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  stats: { node_count: number; edge_count: number }
}

export interface ClassificationExplanation {
  model: string
  model_version?: string
  class: string
  feature_version?: string
  contributions: { feature: string; importance: number }[]
  reasons: string[]
  summary: string
  method: string
}

export interface RiskExplanation {
  severity: string
  score?: number | null
  contributing_signals: string[]
  policy_version?: string | null
  summary: string
}

export interface SessionDetail extends SessionSummary {
  classification?: ClassificationObject | null
  anomaly?: AnomalyObject | null
  prediction?: PredictionObject | null
  features?: Record<string, number> | null
  deception_actions?: DeceptionAction[]
}

export interface DeceptionAction {
  id: string
  session_id?: string
  policy_id?: string
  action?: string
  reason?: string | null
  status: string
  result?: any
  rollback_status?: string | null
  created_at?: string | null
}

export interface Decoy {
  name: string
  target: string
  description: string
  decoy: string
  active: boolean
}
export interface DeceptionEnvironment {
  decoys: Decoy[]
  active_count: number
}

export interface ModelInfo {
  id: string
  model_type: string
  name: string
  version: string
  metrics?: any
  trained_at?: string | null
  is_active: boolean
  dataset_version?: string | null
  artifact_path?: string | null
}

export interface ScenarioInfo {
  id: string
  label: string
  description: string
}

export interface HoneypotStatus {
  adapter: Record<string, any>
  collector: { adapter: string; running: boolean; collected: number; analysed: number }
  db: Record<string, any>
  scenarios: string[]
  environment: Record<string, any>
}

export interface AuditEntry {
  id: string
  user_id?: string | null
  action: string
  resource_type?: string | null
  resource_id?: string | null
  ip_address?: string | null
  details?: any
  created_at?: string | null
}

export interface LiveEvent {
  event_id: string
  timestamp?: string
  session?: string | null
  service?: string | null
  event_type: string
  action?: string | null
  target?: string | null
  result?: string | null
  source?: string | null
}

export interface WsMessage {
  kind: string
  data?: any
}
