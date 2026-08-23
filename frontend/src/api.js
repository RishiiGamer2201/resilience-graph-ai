// API client for the SOC Command Center backend (FastAPI).
// Cached GETs are reliable; the two LIVE POSTs fall back to a cached example
// result on any error, so the demo never breaks mid-pitch.

// Same-origin "/api" in production (FastAPI serves the SPA). In local dev the
// Vite proxy (vite.config.js) forwards /api → http://localhost:8000.
const BASE = import.meta.env.VITE_API_BASE || "/api";

// ---- session (who the backend thinks is calling) ----
// The role travels as a header and is enforced SERVER-SIDE on every mutating
// endpoint — changing it here cannot grant permission, it only changes which
// refusal you get. See src/shared/rbac.py.
let session = { role: "analyst", actor: "analyst@soc" };
export const setSession = (s) => { session = { ...session, ...s }; };
export const getSession = () => ({ ...session });

const authHeaders = () => ({ "X-Role": session.role, "X-Actor": session.actor });

// Surface the backend's own error message (403 reason, 422 validation detail)
// instead of a bare status code — the refusal text is the demo.
async function fail(path, r) {
  let detail = `${r.status}`;
  try { detail = (await r.json()).detail || detail; } catch { /* not json */ }
  const e = new Error(detail);
  e.status = r.status;
  e.path = path;
  return e;
}

async function get(path) {
  const r = await fetch(`${BASE}${path}`, { headers: authHeaders() });
  if (!r.ok) throw await fail(path, r);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw await fail(path, r);
  return r.json();
}

// ---- cached endpoints ----
export const getOverview = () => get("/overview");
export const getIncident = () => get("/incident");
export const getGraph = () => get("/graph");
export const getThreatIntel = () => get("/threat-intel");
export const getMetrics = () => get("/metrics");
export const getMethodology = () => get("/methodology");
export const getReport = () => get("/report");
export const getAttackers = () => get("/attackers");
export const getHealth = () => get("/health");

// ---- Threat Radar: external CTI, cross-referenced with the current incident ----
// Scoring happens server-side (one implementation). `refresh` re-fetches the free
// feeds live; the backend falls back to cache if no source responds, and reports
// which via meta.source.
export function getThreatRadar({ technique_ids = [], actors = [], edges = [], refresh = false } = {}) {
  return post("/threat-radar", { technique_ids, actors, edges, refresh });
}

// ---- LIVE pipeline: analyze a whole event log ----
export const getScenarios = () => get("/scenarios");

// Analyze a shipped scenario or raw event rows → full bundle (overview,
// incident, graph, threat_intel, report, meta). The backend now runs the
// 10-agent orchestrator inside this standard pipeline and exposes traces in
// meta.agent_pipeline, so the SPA keeps one stable response contract.
// `account` scopes a campaign log to one compromised account's own incident.
export async function analyze({ scenario, events, critical_assets = [], incident_id, account }) {
  const r = await fetch(`${BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ scenario, events, critical_assets, incident_id, account }),
  });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

// SSE URL for live 10-agent multi-agent pipeline stream
export const agentStreamUrl = (scenario, critical_assets = []) =>
  `${BASE}/agents/stream?scenario=${encodeURIComponent(scenario)}` +
  (critical_assets.length ? `&critical_assets=${encodeURIComponent(critical_assets.join(','))}` : '');

// SSE URL for the streaming replay (EventSource needs a plain URL; same-origin
// /api is proxied in dev and same-origin in prod).
export const streamUrl = (scenario, critical_assets = []) =>
  `${BASE}/analyze/stream?scenario=${encodeURIComponent(scenario)}` +
  (critical_assets.length ? `&critical_assets=${encodeURIComponent(critical_assets.join(','))}` : '');

// Analyze an uploaded CSV file (multipart).
export async function analyzeUpload(file, critical_assets = [], incident_id = "INC-UPLOAD-001") {
  const fd = new FormData();
  fd.append("file", file);
  fd.append("critical_assets", critical_assets.join(","));
  fd.append("incident_id", incident_id);
  const r = await fetch(`${BASE}/analyze/upload`, { method: "POST", headers: authHeaders(), body: fd });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

// ---- LIVE endpoint 1: score an event ----
//
// There is deliberately NO offline fallback here, and there used to be one.
//
// The old version computed a score from hand-tuned weights when the backend was
// unreachable -- `new_dst ? 28 : 0` plus `is_ntlm ? 28 : 0` and so on -- and
// returned it in the same shape as the model's output, flagged only by a small
// `cached` dot. Those weights were never fitted against anything. They were a
// plausible-looking number standing in for a trained autoencoder, and the whole
// product rests on the claim that every number on screen comes from a model or a
// citation. A demo that keeps working when its model is gone is not a feature.
//
// Failing loudly costs a blank panel during a backend blip. Not failing cost the
// credibility of every other number on the screen.
export async function scoreEvent(features) {
  return { ...(await post("/score-event", features)), live: true };
}

// ---- LIVE endpoint 2: predict next technique ----
//
// Same reasoning. This previously returned five hardcoded technique IDs as
// "predictions" when the Markov model could not be reached.
export async function predictNext(technique_ids, k = 5) {
  return { ...(await post("/predict-next", { technique_ids, k })), live: true };
}


// ---------------------------------------------------------------------------
// Finalist surface: workflow, evidence, vulnerabilities, twin, RBAC, audit
// ---------------------------------------------------------------------------

// Service state: what is live, bundled, degraded or unavailable right now.
export const getCapabilities = () => get("/capabilities");
export const getReadiness = () => get("/readiness");

// The seven-node investigation. Returns trace + signals + impact + action.
export const investigate = (body) => post("/investigate", body);

// The verified public record for the real incident a scenario is styled on.
// 404 means the scenario is purely synthetic, which is the honest answer.
export const getCasefile = (scenario) => get(`/casefile/${encodeURIComponent(scenario)}`);

// Cited evidence over the bundled MITRE/CISA/CERT-In corpus.
export const searchEvidence = (body) => post("/evidence/search", body);
export const getEvidenceStats = () => get("/evidence/stats");

// Vulnerability prioritisation for an incident's estate.
export const getVulnerabilities = (body) => post("/vulnerabilities", body);
export const getVulnConfig = () => get("/vulnerabilities/config");

// Digital twin: counterfactual containment on the incident graph.
export const twinSimulate = (body) => post("/twin/simulate", body);
export const twinCandidates = (body) => post("/twin/candidates", body);
export const twinChat = (body) => post("/twin/chat", body);

// Full raw-event -> action provenance chain for one alert.
export const explainStep = (body) => post("/explain", body);

// Human decision on a simulated action. Nothing is ever executed.
export const approveAction = (body) => post("/actions/approve", body);

// Tamper-evident audit chain.
export const getAudit = (limit = 100) => get(`/audit?limit=${limit}`);
export const verifyAudit = () => get("/audit/verify");
export const exportAudit = () => get("/audit/export");
export const verifyAuditExport = (exp) => post("/audit/verify-export", exp);
export const resetAudit = () => post("/audit/reset", {});
// Markdown export goes through fetch, not a plain <a href>: the role header is
// what authorises it and a browser navigation would not send one.
export async function exportAuditMarkdown() {
  const r = await fetch(`${BASE}/audit/export.md`, { headers: authHeaders() });
  if (!r.ok) throw await fail("/audit/export.md", r);
  return r.text();
}

// PS7 evaluation scoreboard, read from reports/metrics.json.
export const getScoreboard = () => get("/scoreboard");
