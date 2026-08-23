/**
 * Types for the FastAPI payloads the SPA reads.
 *
 * Derived from the real responses, not invented. `tests/test_ui_contract.py`
 * remains the authority on this boundary: when a type here and that test
 * disagree, the test is right and this file is the bug.
 *
 * Deep structures a screen only passes through are typed loosely on purpose. A
 * confidently wrong type is worse than an honest `unknown`, because it silences
 * the checker exactly where the checker was the point.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'normal'

/** Evidence-calibrated claim status. Never collapse these into a boolean. */
export type ClaimStatusValue =
  | 'observed'
  | 'inferred'
  | 'predicted'
  | 'confirmed'
  | 'disputed'
  | 'retracted'

export type Role = 'viewer' | 'analyst' | 'responder' | 'admin'

/** A measured figure, or an explicit statement that it was not measured. */
export interface Measured {
  value: number | null
  unit?: string
  state?: 'measured' | 'not measured' | string
  why?: string
  note?: string
}

// ─── Incident ────────────────────────────────────────────────────────────────
export interface IncidentStep {
  timestamp?: string | number
  user?: string
  source_host?: string
  destination_host?: string
  technique_id?: string
  technique?: string
  tactic?: string
  anomaly_score?: number
  is_alert?: boolean
  protocol?: string
  status?: string
  [k: string]: unknown
}

export interface Incident {
  incident_id: string
  severity: Severity
  max_anomaly_score: number
  alert_count: number
  event_count: number
  technique_ids: string[]
  accounts_involved: string[]
  users_involved?: string[]
  attack_chain?: unknown[]
  steps: IncidentStep[]
  steps_shown?: number
  steps_total?: number
  is_campaign?: boolean
  account?: string | null
  pivot?: unknown
}

// ─── Graph ───────────────────────────────────────────────────────────────────
export interface GraphNode {
  id: string
  type?: string
  critical?: boolean
  [k: string]: unknown
}

export interface GraphEdge {
  source: string
  target: string
  [k: string]: unknown
}

export interface AttackGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  entry_host: string | null
  critical_assets_at_risk: string[]
  blast_radius_size: number
  recommended_isolation: string | null
  isolation_cuts: number
  choke_points: string[]
  attacker_pivots: string[]
  paths_to_critical: Record<string, string[]>
  n_nodes: number
  n_edges: number
  n_pivots: number
}

// ─── The analysis layer (src/shared/enrich.py) ───────────────────────────────
export interface Claim {
  technique_id: string
  technique?: string
  status: ClaimStatusValue
  confidence: number
  strength?: number
  actionable?: boolean
  missing_evidence?: string[]
  alternatives?: string[]
  [k: string]: unknown
}

export interface Assessment {
  anomaly?: Measured & { label?: string }
  likelihood?: Measured & { label?: string }
  impact?: Measured & { label?: string }
  confidence?: Measured & { label?: string }
  [k: string]: unknown
}

export interface CrossCheck {
  available: boolean
  authoritative: string
  verdict: string
  corroboration_strength?: number
  reason?: string
  severity?: {
    workflow: string
    agent_lane: string
    agreement: string
    distance: number
    basis_workflow: string
    basis_agent_lane: string
  }
  techniques?: {
    workflow: string[]
    agent_lane: string[]
    shared: string[]
    workflow_only: string[]
    agent_lane_only: string[]
    overlap: number
  }
  narrative?: string
  narrative_method?: string
  narrative_authoritative?: boolean
  partial_independence?: {
    shared_components: string[]
    cap: number
    note: string
  }
  agent_lane_degraded?: string[]
}

export interface ForecastStep {
  step: number
  technique_id?: string
  technique?: string
  tactic?: string
  probability?: number
  cumulative_probability: number
  confidence?: number
  [k: string]: unknown
}

export interface Forecast {
  steps: ForecastStep[]
  headline?: string
  reliable_horizon?: number
  method?: string
  [k: string]: unknown
}

export interface AnalysisLayer {
  claims: Claim[]
  assessment: Assessment
  attack_progression_likelihood?: Measured
  evidence_confidence?: Measured & {
    terms?: unknown[]
    formula?: string
    actionable_claims?: number
    total_claims?: number
    crosscheck?: unknown
    missing_evidence?: string[]
  }
  crown_jewel_exposure?: Measured
  progression_forecast?: Forecast
  crosscheck?: CrossCheck
  note?: string
}

// ─── Bundles ─────────────────────────────────────────────────────────────────
export interface AgentTrace {
  agent: string
  status: string
  confidence?: number
  ms?: number
  notes?: string[]
  evidence_refs?: string[]
  [k: string]: unknown
}

export interface AgentPipeline {
  enabled: boolean
  status: string
  error?: string
  agent_traces: AgentTrace[]
  ranked_chains?: unknown[]
  chain_explanations?: string[]
  predictions?: unknown[]
  notes?: string[]
  incident_narrative?: string
  point_b_method?: string
  severity?: string
}

export interface BundleMeta {
  scenario?: string
  pipeline?: string
  agent_pipeline?: AgentPipeline
  [k: string]: unknown
}

/** What /api/analyze and the cached overview both return. */
export interface AnalysisBundle {
  overview?: Record<string, unknown>
  incident: Incident
  graph: AttackGraph
  threat_intel?: Record<string, unknown>
  report?: Record<string, unknown>
  attackers?: unknown
  soar?: unknown
  analysis?: AnalysisLayer
  meta?: BundleMeta
  [k: string]: unknown
}

// ─── The seven-node investigation ────────────────────────────────────────────
export interface TraceNode {
  node: string
  status: 'ok' | 'skipped' | 'degraded' | 'failed' | string
  ms: number
  summary: string
  notes: string[]
  output: Record<string, unknown>
}

export interface InvestigationResult {
  ok: boolean
  trace: {
    nodes: TraceNode[]
    total_ms: number
    bounded_by: string
    degraded: string[]
  }
  understand: {
    source: string
    provenance: string
    n_events: number
    accounts_total: number
    hosts_total: number
    crown_jewels_designated: string[]
    columns_missing: string[]
    crown_jewels_not_in_log: string[]
    [k: string]: unknown
  }
  evidence: Record<string, unknown>
  signals: {
    overview: Record<string, unknown>
    incident: Incident
    graph: AttackGraph
    threat_intel: Record<string, unknown>
    report: Record<string, unknown>
    attackers: unknown
    soar: unknown
    [k: string]: unknown
  }
  impact: Record<string, unknown>
  action: Record<string, unknown>
  headline: Record<string, unknown>
  crosscheck?: CrossCheck
  casefile?: Record<string, unknown> | null
  meta: Record<string, unknown>
  llm: Record<string, unknown>
  principal: Record<string, unknown>
  audit: Record<string, unknown>
  error?: string
}

// ─── Scoreboard ──────────────────────────────────────────────────────────────
export interface ScoreCard {
  id: string
  group: string
  name: string
  definition: string
  dataset?: string
  sample?: string
  value: number | null
  unit?: string
  state: 'measured' | 'not measured' | string
  baseline?: { name: string; value: number | null }
  report?: string
  why?: string
  note?: string
}

export interface Scoreboard {
  cards: ScoreCard[]
  groups: string[]
  summary: Record<string, unknown>
  sources?: unknown
  refused_claims?: unknown[]
  note?: string
  generated_at?: string
}

// ─── Capabilities, health, LLM ───────────────────────────────────────────────
export interface Capability {
  name?: string
  state: string
  detail?: string
  [k: string]: unknown
}

export interface Capabilities {
  capabilities: Record<string, Capability> | Capability[]
  degraded: string[]
  keys_required: unknown
  usable_offline: boolean
  versions: Record<string, string>
  note?: string
}

export interface LlmStatus {
  requested: string
  enabled: boolean
  active_provider: string | null
  providers: Record<string, { key_present: boolean; model: string }>
  authoritative: false
  note: string
}

export interface Health {
  ok: boolean
  cache_built: boolean
  evidence_index: boolean
  llm: LlmStatus
  version: string
}

// ─── Digital twin ────────────────────────────────────────────────────────────
export interface TwinCandidate {
  host: string
  crown_jewels_saved: string[]
  blast_cut: number
  blast_cut_pct?: number
  sessions_disrupted?: number
  users_disrupted?: number
  [k: string]: unknown
}

export interface TwinChatSource {
  title: string
  source: string
  publisher: string
  excerpt: string
  url: string
  identifiers?: string[]
  why_relevant?: string
  injection_suspected?: boolean
}

export interface TwinChatReply {
  reply: string
  sources: TwinChatSource[]
  facts_used: Record<string, unknown>
  follow_ups: string[]
  method: string
  model?: string
  llm?: LlmStatus
  llm_error?: string
  intent?: string
  authoritative: false
  disclaimer: string
}

// ─── Prediction ──────────────────────────────────────────────────────────────
export interface Prediction {
  rank: number
  technique_id: string
  name: string
  probability?: number
  source?: string
}

export interface PredictNextResult {
  given: string[]
  predictions: Prediction[]
  source?: string
}

// ─── Scoring ─────────────────────────────────────────────────────────────────
export interface ScoreFeatures {
  is_fail: number
  new_dst_for_user: number
  new_src_for_user: number
  user_distinct_dst_sofar: number
  user_fail_rate_sofar: number
  dst_rarity: number
  is_ntlm: number
}

export interface ScoreResult {
  anomaly_score: number
  severity: Severity
  [k: string]: unknown
}

// ─── Audit ───────────────────────────────────────────────────────────────────
export interface AuditRecord {
  seq?: number
  hash: string
  prev_hash: string
  incident_id?: string
  action?: string
  actor?: string
  role?: string
  decision?: string
  timestamp?: string
  evidence?: unknown
  technique_ids?: string[]
  [k: string]: unknown
}

/** An error carrying the backend's own refusal text, which is the demo. */
export interface ApiError extends Error {
  status?: number
  path?: string
}
