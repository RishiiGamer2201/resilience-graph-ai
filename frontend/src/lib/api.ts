/**
 * API client for the SOC Command Center backend (FastAPI).
 *
 * Ported from api.js with the request and response shapes untouched:
 * `tests/test_ui_contract.py` guards this boundary and a redesign is not a
 * re-spec.
 *
 * TWO FABRICATED FALLBACKS WERE REMOVED IN THE PORT, deliberately:
 *
 *   - `predictNext` returned a hardcoded list of five techniques when the
 *     backend was unreachable, flagged `live: false`. A flag on invented data
 *     is still invented data on screen, and "T1021 Remote Services" rendered
 *     identically whether the Markov model produced it or a constant did.
 *   - `scoreEvent` fell back to a hand-tuned arithmetic formula standing in for
 *     the trained autoencoder. Same problem: a plausible number with no model
 *     behind it.
 *
 * Both now surface the failure. A screen that cannot reach the backend says so;
 * it does not show a confident answer nobody computed.
 */
import type {
  AgentReasoning,
  AnalysisBundle,
  ApiError,
  ApprovalResult,
  AttackGraph,
  AuditChain,
  AuditExport,
  AuditVerification,
  Capabilities,
  CaseFile,
  ContainmentCandidate,
  ExplainTraceResult,
  Health,
  Incident,
  IncidentReportData,
  InvestigationResult,
  LlmStatus,
  MethodologyPayload,
  MetricsPayload,
  OverviewView,
  PredictNextResult,
  Role,
  Scoreboard,
  AttackerList,
  ThreatIntelView,
  ThreatRadarPayload,
  ScoreFeatures,
  ScoreResult,
  ScenarioList,
  TwinChatReply,
  TwinSimulation,
} from '@/types/api'
import { normalizeApiBase } from '@/lib/apiBase'

// Same-origin "/api" in production (FastAPI serves the built SPA). In dev the
// Vite proxy forwards /api to the local backend configured in vite.config.ts.
const BASE = normalizeApiBase(import.meta.env.VITE_API_BASE as string | undefined)

// API responses contain analyst-authored and source-derived prose. Normalize
// punctuation at this single boundary so an old cache or a new endpoint cannot
// reintroduce the UI punctuation rule that the static-source check enforces.
const normalizeUiString = (value: string): string => value.replace(/\s*\u2014\s*/g, ' - ')

function normalizeUiCopy<T>(value: T): T {
  if (typeof value === 'string') return normalizeUiString(value) as T
  if (Array.isArray(value)) return value.map(normalizeUiCopy) as T
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, normalizeUiCopy(nested)]),
    ) as T
  }
  return value
}

// ─── Session ─────────────────────────────────────────────────────────────────
// The role travels as a header and is enforced SERVER-SIDE on every mutating
// endpoint. Changing it here cannot grant permission; it only changes which
// refusal you get back. See src/shared/rbac.py.
export interface Session {
  role: Role
  actor: string
  token?: string
}

let session: Session = { role: 'analyst', actor: 'analyst@soc' }
export const setSession = (s: Partial<Session>): void => {
  session = { ...session, ...s }
}
export const getSession = (): Session => ({ ...session })

const authHeaders = (): Record<string, string> => {
  const token = session.token?.trim()
  return {
    'X-Role': session.role,
    'X-Actor': session.actor,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
}

// ─── Transport ───────────────────────────────────────────────────────────────
/** Surface the backend's own message (a 403 reason, a 422 detail) rather than a
 *  bare status code. The refusal text is the point of the RBAC demo. */
async function fail(path: string, r: Response): Promise<ApiError> {
  let detail = `${r.status}`
  try {
    const body = (await r.json()) as { detail?: unknown }
    if (typeof body.detail === 'string') {
      detail = normalizeUiString(body.detail)
    } else if (Array.isArray(body.detail)) {
      detail = body.detail
        .map((item) => {
          if (typeof item === 'string') return item
          if (typeof item === 'object' && item !== null) {
            const record = item as Record<string, unknown>
            const location = Array.isArray(record.loc) ? record.loc.join('.') : ''
            const message = typeof record.msg === 'string' ? record.msg : JSON.stringify(record)
            return location ? `${location}: ${message}` : message
          }
          return String(item)
        })
        .join('; ')
    } else if (body.detail != null) {
      detail = JSON.stringify(body.detail)
    }
  } catch {
    /* not json */
  }
  const e = new Error(detail) as ApiError
  e.status = r.status
  e.path = path
  return e
}

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`, { headers: authHeaders() })
  if (!r.ok) throw await fail(path, r)
  return normalizeUiCopy((await r.json()) as T)
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw await fail(path, r)
  return normalizeUiCopy((await r.json()) as T)
}

// ─── Cached endpoints ────────────────────────────────────────────────────────
export const getOverview = () => get<OverviewView>('/overview')
export const getIncident = () => get<Incident>('/incident')
export const getGraph = () => get<AttackGraph>('/graph')

/** `/overview` is a summary view, not a full analysis bundle. Compose the
 *  cached slices the redesigned command center actually renders. */
export async function getOverviewBundle(): Promise<AnalysisBundle> {
  const [overview, incident, graph] = await Promise.all([
    getOverview(),
    getIncident(),
    getGraph(),
  ])
  return {
    overview,
    incident,
    graph,
    analysis: overview.analysis,
    agent_pipeline: overview.agent_pipeline,
  }
}

/** Read a server-sent event stream through fetch so role/auth headers travel
 * with the request. Native EventSource cannot send those headers. */
export async function readEventStream(
  url: string,
  onEvent: (event: string, data: string) => void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(url, {
    headers: { Accept: 'text/event-stream', ...authHeaders() },
    signal,
  })
  if (!response.ok) throw await fail(url, response)
  if (!response.body) throw new Error('The server returned no event stream body.')

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (true) {
    const { value, done } = await reader.read()
    buffer += decoder.decode(value, { stream: !done })
    const frames = buffer.split(/\r?\n\r?\n/)
    buffer = frames.pop() ?? ''
    for (const frame of frames) {
      let event = 'message'
      const data: string[] = []
      for (const line of frame.split(/\r?\n/)) {
        if (line.startsWith('event:')) event = line.slice(6).trim()
        if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
      }
      if (data.length) onEvent(event, normalizeUiString(data.join('\n')))
    }
    if (done) break
  }
}
// The reasoning lane: an Investigator agent picks which of seven graph tools
// to call, then a Critic gets the same tools and is told to refute it. Several
// model round trips, so it is asked for rather than run on page load.
export const reasonWithAgents = (body: {
  scenario?: string
  critical_assets?: string[]
  incident_id?: string
}) => post<AgentReasoning>('/agents/reason', body)

export const getThreatIntel = () => get<ThreatIntelView>('/threat-intel')
export const getMetrics = () => get<MetricsPayload>('/metrics')
export const getMethodology = () => get<MethodologyPayload>('/methodology')
export const getReport = () => get<IncidentReportData>('/report')
export const getAttackers = () => get<AttackerList>('/attackers')
export const getHealth = () => get<Health>('/health')
export const getLlm = () => get<LlmStatus>('/llm')
export const getScoreboard = () => get<Scoreboard>('/scoreboard')
export const getCapabilities = () => get<Capabilities>('/capabilities')
export const getReadiness = () => get<Record<string, unknown>>('/readiness')
export const getScenarios = () => get<ScenarioList>('/scenarios')

// ─── Threat radar ────────────────────────────────────────────────────────────
// Scoring happens server-side, in one implementation. `refresh` re-fetches the
// free feeds live; the backend falls back to its cache if no source answers and
// reports which via meta.source.
export interface ThreatRadarRequest {
  technique_ids?: string[]
  actors?: string[]
  edges?: unknown[]
  refresh?: boolean
}
export function getThreatRadar(req: ThreatRadarRequest = {}) {
  const { technique_ids = [], actors = [], edges = [], refresh = false } = req
  return post<ThreatRadarPayload>('/threat-radar', {
    technique_ids,
    actors,
    edges,
    refresh,
  })
}

// ─── Live analysis ───────────────────────────────────────────────────────────
export interface AnalyzeRequest {
  scenario?: string
  events?: unknown[]
  critical_assets?: string[]
  incident_id?: string
  account?: string
}

/** Analyse a shipped scenario or raw rows into a full bundle. The backend runs
 *  the 10-agent lane inside this same call and exposes traces in
 *  meta.agent_pipeline, so the SPA keeps one response contract. */
export function analyze(req: AnalyzeRequest) {
  const { critical_assets = [], ...rest } = req
  return post<AnalysisBundle>('/analyze', { critical_assets, ...rest })
}

/** Analyse an uploaded CSV. Multipart, so it does not go through post(). */
export async function analyzeUpload(
  file: File,
  criticalAssets: string[] = [],
  incidentId = 'INC-UPLOAD-001',
): Promise<AnalysisBundle> {
  const fd = new FormData()
  fd.append('file', file)
  fd.append('critical_assets', criticalAssets.join(','))
  fd.append('incident_id', incidentId)
  const r = await fetch(`${BASE}/analyze/upload`, {
    method: 'POST',
    headers: authHeaders(),
    body: fd,
  })
  if (!r.ok) throw await fail('/analyze/upload', r)
  return (await r.json()) as AnalysisBundle
}

// EventSource takes a plain URL and cannot carry our role header, so these are
// read-only streams and the backend treats them as such.
const qs = (scenario: string, criticalAssets: string[]) =>
  `?scenario=${encodeURIComponent(scenario)}` +
  (criticalAssets.length
    ? `&critical_assets=${encodeURIComponent(criticalAssets.join(','))}`
    : '')

export const streamUrl = (scenario: string, criticalAssets: string[] = []) =>
  `${BASE}/analyze/stream${qs(scenario, criticalAssets)}`

export const agentStreamUrl = (scenario: string, criticalAssets: string[] = []) =>
  `${BASE}/agents/stream${qs(scenario, criticalAssets)}`

// ─── Live model endpoints ────────────────────────────────────────────────────
/** Score one event with the trained detector.
 *
 *  Throws when the backend is unreachable. It used to fall back to a hand-tuned
 *  formula that produced a plausible score with no model behind it; a caller
 *  that cannot reach the detector must say so, not guess. */
export const scoreEvent = (features: ScoreFeatures) =>
  post<ScoreResult>('/score-event', features)

/** Rank the attacker's likely next techniques.
 *
 *  Throws when the backend is unreachable. It used to return five hardcoded
 *  techniques flagged `live: false`, which rendered on screen identically to a
 *  real prediction. */
export const predictNext = (techniqueIds: string[], k = 5) =>
  post<PredictNextResult>('/predict-next', { technique_ids: techniqueIds, k })

// ─── Finalist surface ────────────────────────────────────────────────────────
/** The seven-node investigation: trace, signals, impact, action. */
export const investigate = (body: Record<string, unknown>) =>
  post<InvestigationResult>('/investigate', body)

/** The verified public record behind a scenario. A 404 means the scenario is
 *  purely synthetic, which is the honest answer and not an error to hide. */
export const getCasefile = (scenario: string) =>
  get<CaseFile>(`/casefile/${encodeURIComponent(scenario)}`)

export const searchEvidence = (body: Record<string, unknown>) =>
  post<Record<string, unknown>>('/evidence/search', body)
export const getEvidenceStats = () => get<Record<string, unknown>>('/evidence/stats')

export const getVulnerabilities = (body: Record<string, unknown>) =>
  post<Record<string, unknown>>('/vulnerabilities', body)
export const getVulnConfig = () => get<Record<string, unknown>>('/vulnerabilities/config')

// Digital twin: counterfactual containment on a clone of the incident graph.
export const twinSimulate = (body: Record<string, unknown>) =>
  post<TwinSimulation>('/twin/simulate', body)
export const twinCandidates = (body: Record<string, unknown>) =>
  post<{ candidates: ContainmentCandidate[] }>('/twin/candidates', body)
export const twinChat = (body: Record<string, unknown>) =>
  post<TwinChatReply>('/twin/chat', body)

/** Raw event to proposed action, every stage in between. */
export const explainStep = (body: Record<string, unknown>) =>
  post<ExplainTraceResult>('/explain', body)

/** A human decision on a simulated action. Nothing is ever executed.
 *
 *  RBAC is enforced server-side: a role without the permission gets a 403 whose
 *  `detail` is the refusal to show the operator. Do not pre-empt it client-side. */
export interface ApproveActionRequest {
  proposal_id: string
  decision: 'approve' | 'reject'
  reason: string
}
export const approveAction = (body: ApproveActionRequest) =>
  post<ApprovalResult>('/actions/approve', body)

// ─── Audit chain ─────────────────────────────────────────────────────────────
export const getAudit = (limit = 100) => get<AuditChain>(`/audit?limit=${limit}`)
export const verifyAudit = () => get<AuditVerification>('/audit/verify')
export const exportAudit = () => get<AuditExport>('/audit/export')
export const verifyAuditExport = (exp: AuditExport) =>
  post<AuditVerification>('/audit/verify-export', exp)
export const resetAudit = () => post<Record<string, unknown>>('/audit/reset', {})

/** Markdown export goes through fetch rather than a plain <a href>: the role
 *  header is what authorises it and a browser navigation would not send one. */
export async function exportAuditMarkdown(): Promise<string> {
  const r = await fetch(`${BASE}/audit/export.md`, { headers: authHeaders() })
  if (!r.ok) throw await fail('/audit/export.md', r)
  return r.text()
}
