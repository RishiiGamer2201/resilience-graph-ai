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
  /** In `critical_assets_at_risk`: a crown jewel the attacker can reach. */
  critical?: boolean
  /** In `attacker_pivots`: an attacker-controlled source host. */
  pivot?: boolean
  /** The single `entry_host`. */
  entry?: boolean
  [k: string]: unknown
}

/** An edge of the attack graph as the backend really sends it: `from`/`to`,
 *  not source/target (see tests/test_ui_contract.py, which reads edges[0].from).
 *  A force-graph view maps these to its own source/target at the boundary. */
export interface GraphEdge {
  from: string
  to: string
  technique?: string
  technique_name?: string
  tactic?: string
  score?: number
  event_count?: number
  users?: string[]
  user?: string
  first_seen?: number
  last_seen?: number
  explanation?: string
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
  /** One sentence saying what the two lanes agreed or disagreed about. */
  explanation?: string
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
  claims: InvestigationClaim[]
  assessment?: WorkflowAssessment | null
  attack_progression_likelihood?: ExplainedMetric | null
  evidence_confidence?: ExplainedMetric | null
  crown_jewel_exposure?: ExplainedMetric | null
  progression_forecast?: ProgressionForecast | null
  crosscheck?: CrossCheck | null
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

export interface OverviewMttd {
  ours_seconds: number
  value: string
  was: string
  traditional_days: number
  ours_minutes: number
  citation: string
  note: string
}

/** The actual GET /api/overview cache view. */
export interface OverviewView {
  mttd: OverviewMttd
  active_incident: {
    id: string
    severity: Severity
    account: string
    summary: string
  }
  blast_radius_contained: number
  alerts_correlated: { alerts: number; events: number }
  score_trend: number[]
  accounts_involved: number
  is_campaign: boolean
  scorecard: Array<Record<string, unknown>>
  agent_pipeline?: AgentPipeline
  analysis?: AnalysisLayer
}

/** What /api/analyze returns and the live-analysis store carries. */
export interface AnalysisBundle {
  overview?: OverviewView
  incident: Incident
  graph: AttackGraph
  threat_intel?: ThreatIntelView
  report?: IncidentReportData
  attackers?: AttackerRow[]
  soar?: unknown
  analysis?: AnalysisLayer
  /** The cached GET /api/overview carries the agent lane at the top level;
   *  POST /api/analyze carries it under meta. Both are real. */
  agent_pipeline?: AgentPipeline
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
  evidence: EvidenceBundle
  signals: {
    overview: OverviewView
    incident: Incident
    graph: AttackGraph
    threat_intel: ThreatIntelView
    report: IncidentReportData
    attackers: AttackerRow[]
    soar: unknown
    [k: string]: unknown
  }
  impact: ImpactOutput
  action: ActionOutput
  headline: {
    attack_progression_likelihood: ExplainedMetric | null
    evidence_confidence: ExplainedMetric | null
    assessment: WorkflowAssessment | null
    crown_jewel_exposure: ExplainedMetric | null
  }
  crosscheck?: CrossCheck | null
  casefile?: CaseFile | null
  meta: Record<string, unknown>
  /** Provenance for the narrative text. Stays on screen. */
  llm: { provider: string; used_for: string[]; note: string }
  generated_at?: string
  scenario?: string | null
  incident_id?: string
  principal: Record<string, unknown>
  audit: Record<string, unknown>
  error?: string
}

// ─── Scoreboard ──────────────────────────────────────────────────────────────
// Shapes follow src/shared/scoreboard.py exactly. Note `state` is the literal
// "not_measured" with an underscore there; anything that is not "measured" is
// treated as unmeasured by the screen, which is the safe direction.
export interface ScoreBaseline {
  name: string
  /** Null where the baseline itself has never been measured. */
  value: number | null
}

export interface ScoreCard {
  id: string
  group: string
  name: string
  definition: string
  dataset: string
  sample?: string
  state: 'measured' | 'not_measured' | string
  value: number | null
  unit?: string
  baseline?: ScoreBaseline | null
  /** value − baseline.value, where both exist. */
  delta?: number | null
  /** value ÷ baseline.value, where the baseline is non-zero. */
  lift?: number | null
  higher_is_better: boolean
  /** Repo-relative path to the evidence file behind the number. */
  report?: string | null
  report_exists?: boolean
  /** Why a card was not measured. Required whenever state is not "measured". */
  why?: string | null
  note?: string
  provenance?: string
}

export interface ScoreGroup {
  name: string
  cards: ScoreCard[]
}

export interface ScoreboardSummary {
  total: number
  measured: number
  not_measured: number
  /** Card ids whose evidence file is missing on disk. */
  missing_reports: string[]
}

export interface Scoreboard {
  generated_at: string
  groups: ScoreGroup[]
  cards: ScoreCard[]
  summary: ScoreboardSummary
  sources: { metrics_store: string; regenerate: string[] }
  /** Claim → the reason we decline to make it. */
  refused_claims: Record<string, string>
  note: string
}

// ─── Metrics (reports/metrics.json, served by /api/metrics) ──────────────────
// Every field is optional: the evaluation scripts write what they could run,
// and a screen must render "Not measured" for the rest rather than a zero.
export interface LanlMetrics {
  roc_auc?: number
  tpr_at_1pct_fpr?: number
  tpr_at_5pct_fpr?: number
  behavioral_only_roc?: number
  detector?: string
  iforest_roc_auc?: number
  iforest_tpr_at_1pct_fpr?: number
  note?: string
}

export interface CicidsMetrics {
  autoencoder_prauc?: number
  iforest_prauc?: number
  iforest_roc?: number
  rule_prauc?: number
  random_prauc?: number
  note?: string
}

export interface UnswMetrics {
  roc_auc?: number
  prauc?: number
  note?: string
}

export interface PredictorMetrics {
  most_frequent_top3?: number
  killchain_top3?: number
  lstm_top3?: number
  markov_top3?: number
  markov_interp_top3?: number
  /** Key of the method actually shipped, e.g. "markov_interp". */
  shipped?: string
  shipped_top3?: number
  note?: string
}

export interface EmbeddingMetrics {
  same_tactic_cos?: number
  random_cos?: number
}

export interface MetricsPayload {
  engine1?: {
    lanl?: LanlMetrics
    cicids?: CicidsMetrics
    unsw?: UnswMetrics
  }
  engine2?: {
    predictor?: PredictorMetrics
    embeddings?: EmbeddingMetrics
    manual_cert_in_top3?: number
  }
}

// ─── Methodology (/api/methodology) ──────────────────────────────────────────
export interface DatasetRow {
  name: string
  /** Free text: "2.3M flows", "11.2M auth · 702 red-team". Not a number. */
  rows: string
  feeds: string
}

export interface MethodologyPayload {
  datasets?: DatasetRow[]
  honesty_notes?: string[]
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
  /** The interpolated Markov transition probability the endpoint returns.
   *  POST /api/predict-next calls this field `score`. */
  score?: number
  probability?: number
  source?: string
}

export interface PredictNextResult {
  given: string[]
  predictions: Prediction[]
  /** Deterministic plain-English projection built by
   *  src/shared/predictor.generate_prediction_narrative. Template, not a model. */
  projection_narrative?: string
  /** `markov-interpolated-order2` | `markov-interpolated-order1` |
   *  `frequency-fallback`. The last one means no observed context matched. */
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
  at?: string
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

// ─── The seven-node investigation, in detail ─────────────────────────────────
// Everything below is read directly by Investigate.tsx / Analyze.tsx and the
// panels they compose. Shapes come from src/shared/workflow.py, claims.py,
// rollout.py, twin.py, vuln.py, casefile.py and api/finalist.py — not invented.

/** One shipped demo event log, from GET /api/scenarios. */
export interface Scenario {
  name: string
  label: string
  description: string
  /** null when the file could not be counted. Never render this as 0. */
  n_events: number | null
  critical_default: string[]
}

export interface ScenarioList {
  scenarios: Scenario[]
}

/** One line of a headline metric's arithmetic. The backend uses two shapes:
 *  weighted terms (`name`/`weight`/`value`) and per-asset terms
 *  (`asset`/`hops`/`score`). Both are shown as the backend sends them. */
export interface MetricTerm {
  name?: string
  asset?: string
  weight?: number
  value?: number
  score?: number
  hops?: number | null
  detail?: string
  why?: string
}

/** A 0-100 figure that carries its own arithmetic, or says it was not measured. */
export interface ExplainedMetric extends Measured {
  reason?: string
  formula?: string
  terms?: MetricTerm[]
  designated?: string[]
  actionable_claims?: number
  total_claims?: number
  missing_evidence?: string[]
}

/** One of the four axes. `value` is null when the axis was not measured. */
export interface AssessmentAxis {
  value: number | null
  band: string
  question: string
}

/** src/shared/claims.py Assessment.as_dict(). Four questions, never collapsed. */
export interface WorkflowAssessment {
  anomaly: AssessmentAxis
  likelihood: AssessmentAxis
  impact: AssessmentAxis
  confidence: AssessmentAxis
  missing_evidence: string[]
  summary: string
  note: string
}

/** One piece of support behind a claim, tagged with its independence group so
 *  duplicate signals cannot inflate confidence. */
export interface ClaimEvidence {
  id: string
  kind: string
  source: string
  independence_group: string
  strength: number
  reliability: number
  support: number
  detail: string
}

/** src/shared/claims.py Claim.as_dict(). Distinct from the `Claim` the enrich
 *  layer returns: this one is subject/predicate/object with an external_id. */
export interface InvestigationClaim {
  subject: string
  predicate: string
  object: string
  external_id: string
  status: ClaimStatusValue
  actionable: boolean
  confidence: number
  confidence_band: string
  independent_groups: number
  mapper: string
  evidence: ClaimEvidence[]
  contradicted_by: ClaimEvidence[]
  missing_evidence: string[]
  alternatives: string[]
  note: string
}

/** One retrieved chunk of an official document, with everything a reviewer
 *  needs to check it themselves. */
export interface EvidenceHit {
  chunk_id: string
  title: string
  url: string
  publisher: string
  authority: string
  section: string
  /** The source's own date. Empty when the source states none. */
  published?: string
  retrieved_at?: string
  excerpt: string
  match_reason?: string
  why_relevant?: string
  sha256?: string
}

export interface EvidenceBundle {
  citations: EvidenceHit[]
  hits?: EvidenceHit[]
  corpus: Record<string, number>
  index_built_at: string | null
  retrieval: string
  query: string
  technique_ids: string[]
  disclosure?: string | null
}

// ─── Case file: the verified public record ───────────────────────────────────
export interface CaseFileSource {
  id: string
  url: string
  chamber?: string
  question_no?: string
  answered_on?: string
  ministry?: string
  verified: boolean
  note?: string
}

export interface CaseFileFact {
  quote: string
  source_id: string
}

export interface CaseFileClaim {
  external_id: string
  object: string
  tactic?: string
  status: ClaimStatusValue
  confidence: number
  confidence_band: string
  note: string
}

export interface ControlWeakness {
  weakness: string
  note: string
}

export interface CaseFile {
  title: string
  provenance: string
  sources: CaseFileSource[]
  sources_verified: number
  established_facts: CaseFileFact[]
  claims: CaseFileClaim[]
  control_weaknesses: ControlWeakness[]
  not_established: string[]
  why_this_matters: string
  relationship_to_scenario: { note: string; [k: string]: unknown }
  summary: string
}

// ─── Impact: forecast, twin, vulnerabilities ─────────────────────────────────
export interface ForecastPrediction {
  technique_id: string
  name: string
  stage: string
  probability: number
  is_impact: boolean
}

export interface ProgressionStep {
  step: number
  horizon_confidence: number
  predictions: ForecastPrediction[]
  impact_mass: number
  model_source: string
}

export interface ProgressionPath {
  path: string[]
  predicted: string[]
  probability: number
  stages: string[]
  reaches_impact: boolean
}

/** Probability and horizon confidence are two separate series, on purpose.
 *  Multiplying them made the cumulative curve fall, which is nonsense. */
export interface ProgressionForecast {
  available: boolean
  reason?: string
  k_steps: number
  observed_chain?: string[]
  steps?: ProgressionStep[]
  infiltration_probability?: number[]
  horizon_confidence?: number[]
  peak_infiltration_probability?: number
  reliable_horizon?: number
  headline?: string
  most_likely_paths?: ProgressionPath[]
  beyond_horizon_note?: string
  honesty?: string
  method?: { model: string; search: string; decay: string; deterministic: boolean }
}

export interface ContainmentCandidate {
  host: string
  crown_jewels_protected: string[]
  blast_radius_reduction: number
  blast_radius_reduction_pct: number
  sessions_severed: number
  accounts_disrupted: number
  is_crown_jewel: boolean
  verdict: string
}

export interface TwinExposure {
  blast_radius: number
  crown_jewels_reachable: string[]
  paths_to_critical: Record<string, string[]>
  attacker_pivots: string[]
  choke_points: string[]
  n_nodes: number
  n_edges: number
}

export interface OperationalCost {
  action: string
  hosts_taken_offline: number
  sessions_severed: number
  accounts_disrupted: string[]
  adjacent_hosts_losing_a_link: string[]
  host_is_crown_jewel: boolean
}

export interface TwinSimulation {
  candidate: { isolate_host: string | null; cut_edge: string[] | null }
  before: TwinExposure
  after: TwinExposure
  delta: {
    blast_radius: number
    blast_radius_reduction_pct: number
    crown_jewels_protected: string[]
    crown_jewels_still_reachable: string[]
    hosts_no_longer_reachable: number
  }
  operational_cost: OperationalCost
  verdict: string
  method: string
  note?: string
}

/** `value: null` means the factor is unknown. It is excluded from the weighted
 *  average and lowers confidence; it is never scored as zero. */
export interface VulnFactor {
  value: number | null
  fact: string
}

export interface VulnFinding {
  cve: string
  host: string
  asset_name: string
  owner: string
  software: string
  title: string
  priority_score: number
  band: string
  confidence: number
  unknown_factors: string[]
  factors: Record<string, VulnFactor>
  citation: {
    chunk_id: string
    url: string
    publisher: string
    title: string
    published?: string
  }
  provenance: string
}

export interface VulnReport {
  findings: VulnFinding[]
  total_findings: number
  assets_considered: number
  assets_without_software_data?: string[]
  kev_catalog_size?: number
  config?: {
    version: string
    sha256: string
    weights: Record<string, number>
    bands: Record<string, number>
  }
  inventory_provenance: string
  inventory_note?: string
  evaluated_on?: string
  note?: string
  disclosure?: string
}

export interface ImpactOutput {
  crown_jewel_exposure: ExplainedMetric | null
  attack_progression_likelihood: ExplainedMetric | null
  evidence_confidence: ExplainedMetric | null
  assessment: WorkflowAssessment | null
  claims: InvestigationClaim[]
  crosscheck: CrossCheck | null
  blast_radius: number | null
  paths_to_critical: Record<string, string[]>
  containment_candidates: ContainmentCandidate[]
  counterfactual: TwinSimulation | null
  progression_forecast: ProgressionForecast | null
  vulnerabilities: VulnReport
}

// ─── Action: proposals, gates, requests for information ──────────────────────
/** Decided server-side by src/shared/rbac.py. Hiding a button is a courtesy;
 *  this is the mechanism. */
export interface ActionPolicy {
  gate: string
  requires_approval: boolean
  reasons: string[]
  [k: string]: unknown
}

export interface ActionProposal {
  id: string
  kind: string
  tactic: string
  action: string
  touches_crown_jewel: boolean
  blast_radius_affected: number
  hosts_taken_offline: number
  /** Always true. Nothing in this product contacts a real system. */
  simulated: boolean
  policy: ActionPolicy
}

export interface RfiQuestion {
  field: string
  ask: string
  why: string
}

export interface Rfi {
  to: string
  subject: string
  context: string
  questions: RfiQuestion[]
  generated_by: string
  note: string
}

export interface ActionOutput {
  proposals: ActionProposal[]
  mitre_mitigations: string[]
  gating_policy: string
  rfi: Rfi | null
  executed: number
  note: string
}

/** POST /api/actions/approve. A human decision, recorded, never executed. */
export interface ApprovalResult {
  decision: string
  record: AuditRecord & {
    seq: number
    hash: string
    at: string
    actor: string
    role: string
  }
}

// ─── Explainability ──────────────────────────────────────────────────────────
export interface ExplainStage {
  stage: string
  produced_by: string
  value: unknown
  explanation: string
}

export interface ExplainTraceResult {
  available: boolean
  reason?: string
  alerts_available: number
  step: {
    user?: string
    source_host?: string
    destination_host?: string
    anomaly_score?: number
    technique_id?: string
    [k: string]: unknown
  }
  stages: ExplainStage[]
  note: string
}

// ─── Audit chain ─────────────────────────────────────────────────────────────
export interface AuditChain {
  records: AuditRecord[]
  count: number
  head: string
  verified: boolean
  problem?: string
}

export interface AuditVerification {
  verified: boolean
  problem?: string
  records: number
  hash_algorithm: string
  claim: string
}

export interface AuditExport {
  records: AuditRecord[]
  [k: string]: unknown
}

// ─── SSE ─────────────────────────────────────────────────────────────────────
/** One `progress` frame from GET /api/agents/stream. */
export interface AgentProgress {
  stage_num: number
  total_stages: number
  agent: string
  name: string
  status: string
  ms: number
  confidence: number
  summary: string
}

/** One `step` frame from GET /api/analyze/stream — a real per-event score. */
export interface AnalyzeStreamStep {
  i: number
  total: number
  step: IncidentStep
}

// ─── The "who" table: GET /api/attackers ─────────────────────────────────────
/** One compromised account's own footprint, computed from its alerts only
 *  (src/shared/views.py::attackers_view). `first_seen`/`last_seen` are LANL
 *  integer timestamps in seconds, not ISO strings. */
export interface AttackerRow {
  user: string
  alerts: number
  hosts: string[]
  hosts_reached: number
  pivots: string[]
  techniques: string[]
  max_score: number
  first_seen: number
  last_seen: number
  critical_reached: string[]
  severity: Severity
}

export interface AttackerList {
  attackers: AttackerRow[]
}

// ─── Threat intel and attribution: GET /api/threat-intel ─────────────────────
export interface TechniqueMapping {
  technique_id: string
  name: string
  /** The technique's own ATT&CK description, not a generated one. */
  explanation: string
}

/** One ranked ATT&CK group profile.
 *
 *  This is weighted retrieval over public group profiles, NOT a trained actor
 *  classifier and NOT an identification. `score` is the weighted figure,
 *  `coverage` the observed-technique overlap fraction, `matched` the techniques
 *  that produced it and `justification` the printed arithmetic. A screen that
 *  renders `actor` without those three has misrepresented the result. */
export interface ActorMatch {
  actor: string
  score: number
  coverage: number
  matched: string[]
  justification: string
}

export interface ThreatIntelView {
  mapping: TechniqueMapping[]
  attribution: ActorMatch[]
  note?: string
}

// ─── External CTI: POST /api/threat-radar ────────────────────────────────────
/** A feed the backend tried. `ok: false` means skipped or unreachable and the
 *  reason is in `note` (commonly a missing free API key). Never omit these. */
export interface RadarSourceStatus {
  source: string
  ok: boolean
  items: number
  note?: string
}

/** Three separately-reported signals. A tactic-level match is a weaker hit than
 *  a technique-level one and is never presented as the same thing. */
export interface RadarRelevance {
  score: number
  matched_techniques: string[]
  matched_tactics: string[]
  matched_actors: string[]
}

/** One of YOUR graph edges that uses a technique an external report describes. */
export interface ExposureMove {
  from: string | null
  to: string | null
  score: number | null
  event_count: number
  technique: string | null
}

export interface RadarItem {
  source: string
  title: string
  published: string
  url: string
  text?: string
  tags?: string[]
  iocs?: string[]
  india?: boolean
  techniques: string[]
  relevance?: RadarRelevance
  /** technique id -> your movements using it. Strongest bridge. */
  your_exposure?: Record<string, ExposureMove[]>
  /** tactic -> your movements in that tactic. Broader, weaker, still real. */
  your_exposure_tactic?: Record<string, ExposureMove[]>
}

export interface ThreatRadarPayload {
  fetched_at: string
  items: RadarItem[]
  sources: RadarSourceStatus[]
  technique_names?: Record<string, string>
  india_count?: number
  relevant_count?: number
  note?: string
  /** `live` = the feeds answered just now. `cache` = the bundled snapshot,
   *  which must never be presented as live. Set by api/main.py on every
   *  response, including a refresh where no source responded. */
  meta?: { source?: 'live' | 'cache' | string; [k: string]: unknown }
}

// ─── Report (GET /api/report, src/shared/views.py::report_view) ──────────────
export interface ReportTechnique {
  technique_id: string
  name: string
}

/** A proposed response. `mode` carries the gate — nothing here executes. */
export interface ReportAction {
  tactic?: string
  action: string
  mode: string
}

export interface IncidentReportData {
  incident_id: string
  generated_at: string
  severity: Severity
  max_anomaly_score: number
  account: string | null
  pivot: string | null
  summary: string
  attack_chain: { tactic: string; count: number }[]
  techniques: ReportTechnique[]
  attack_path: string[]
  attributed_actor: { actor: string; justification: string }
  predicted_next: ReportTechnique[]
  response_actions: ReportAction[]
  mitigations: string[]
  mttd: {
    traditional_days: number | null
    ours_minutes: number | null
    ours_seconds: number | null
    value: string
    citation: string
    note: string
  }
  /** `lanl_roc_auc` is null when reports/metrics.json has no such card. */
  evidence: {
    lanl_roc_auc: number | null
    detector: string
    basis: string
    source: string
  }
}
