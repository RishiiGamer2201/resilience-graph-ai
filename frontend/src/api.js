// API client for the SOC Command Center backend (FastAPI).
// Cached GETs are reliable; the two LIVE POSTs fall back to a cached example
// result on any error, so the demo never breaks mid-pitch.

// Same-origin "/api" in production (FastAPI serves the SPA). In local dev the
// Vite proxy (vite.config.js) forwards /api → http://localhost:8000.
const BASE = import.meta.env.VITE_API_BASE || "/api";

async function get(path) {
  const r = await fetch(`${BASE}${path}`);
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}
async function post(path, body) {
  const r = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
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
// incident, graph, threat_intel, report, meta). Errors bubble up so the
// Analyze screen can show the backend's validation message.
// `account` scopes a campaign log to one compromised account's own incident.
export async function analyze({ scenario, events, critical_assets = [], incident_id, account }) {
  const r = await fetch(`${BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario, events, critical_assets, incident_id, account }),
  });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

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
  const r = await fetch(`${BASE}/analyze/upload`, { method: "POST", body: fd });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* ignore */ }
    throw new Error(msg);
  }
  return r.json();
}

// ---- LIVE endpoint 1: score an event (with cached fallback) ----
export async function scoreEvent(features) {
  try {
    return { ...(await post("/score-event", features)), live: true };
  } catch {
    // deterministic fallback so the widget still responds if backend is down
    const distinct = Number(features.user_distinct_dst_sofar || 0);
    const failRate = Number(features.user_fail_rate_sofar || 0);
    const rarity = Number(features.dst_rarity || 0);
    const distinctPressure =
      distinct <= 5 ? 8 : distinct >= 100 ? Math.min(15, (distinct - 100) / 20) : 0;
    const s =
      (features.new_dst_for_user ? 28 : 0) +
      (features.is_ntlm ? 28 : 0) +
      (features.is_fail ? 12 : 0) +
      (features.new_src_for_user ? 10 : 0) +
      Math.min(17, rarity * 1.4) +
      Math.min(20, failRate * 40) +
      distinctPressure;
    const score = Math.min(100, s);
    const severity =
      score >= 90 ? "critical" : score >= 70 ? "high" : score >= 45 ? "medium" : "low";
    return { anomaly_score: Math.round(score * 10) / 10, severity, live: false };
  }
}

// ---- LIVE endpoint 2: predict next technique (with cached fallback) ----
const FALLBACK_NEXT = [
  { rank: 1, technique_id: "T1021", name: "Remote Services" },
  { rank: 2, technique_id: "T1059.001", name: "PowerShell" },
  { rank: 3, technique_id: "T1078", name: "Valid Accounts" },
  { rank: 4, technique_id: "T1003", name: "OS Credential Dumping" },
  { rank: 5, technique_id: "T1486", name: "Data Encrypted for Impact" },
];
export async function predictNext(technique_ids, k = 5) {
  try {
    return { ...(await post("/predict-next", { technique_ids, k })), live: true };
  } catch {
    return { given: technique_ids, predictions: FALLBACK_NEXT.slice(0, k), live: false };
  }
}
