import base64
from pathlib import Path

W, H = 2560, 1440
OUT = Path(__file__).resolve().parents[1] / "reports"
BG = None

def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def text(x, y, s, size=24, weight=400, fill="#17324D", anchor="start", family="Arial"):
    return f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{esc(s)}</text>'

def multiline(x, y, lines, size=20, fill="#52677A", weight=400, gap=1.25, anchor="start"):
    spans = []
    for i, line in enumerate(lines):
        dy = 0 if i == 0 else size * gap
        spans.append(f'<tspan x="{x}" dy="{dy}">{esc(line)}</tspan>')
    return f'<text x="{x}" y="{y}" font-family="Arial" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">' + "".join(spans) + "</text>"

def rect(x, y, w, h, fill="#FFFFFF", stroke="#6DC8DC", sw=2, r=18):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'

def card(x, y, w, h, title, lines, color="#159DB7", fill="#FFFFFF", title_size=22, body_size=18):
    out = [rect(x, y, w, h, fill, color, 2.5, 16),
           f'<rect x="{x}" y="{y}" width="{w}" height="10" rx="5" fill="{color}" stroke="none"/>',
           text(x+20, y+42, title, title_size, 700, "#102A43")]
    out.append(multiline(x+20, y+72, lines, body_size, "#52677A", 400, 1.22))
    return "".join(out)

def label(x, y, w, title, subtitle, color):
    return "".join([
        f'<rect x="{x}" y="{y}" width="{w}" height="54" rx="27" fill="{color}"/>',
        text(x+22, y+35, title, 22, 700, "#FFFFFF"),
        text(x+w+18, y+35, subtitle, 19, 600, "#52677A")
    ])

def arrow(x1, y1, x2, y2, color="#2586C4", dash=False, width=4):
    d = ' stroke-dasharray="12 10"' if dash else ""
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{width}"{d} marker-end="url(#arrow)"/>'

bg = ""
if BG is not None and Path(BG).exists():
    bg64 = base64.b64encode(Path(BG).read_bytes()).decode("ascii")
    bg = (f'<image href="data:image/png;base64,{bg64}" x="0" y="0" width="2560" '
          'height="1440" opacity="0.42" preserveAspectRatio="xMidYMid slice"/>')
s = [f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
<defs>
  <marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto"><path d="M0,0 L12,6 L0,12 Z" fill="#2586C4"/></marker>
  <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="4" stdDeviation="5" flood-color="#0B4660" flood-opacity="0.10"/></filter>
</defs>
<rect width="2560" height="1440" fill="#FFFFFF"/>
{bg}
<rect x="18" y="18" width="2524" height="1404" rx="8" fill="none" stroke="#172A3A" stroke-width="4"/>
<rect x="22" y="22" width="2516" height="126" fill="#B9E1F3" opacity="0.96"/>
''']

s += [text(1280, 92, "TECHNICAL ARCHITECTURE", 54, 800, "#071827", "middle"),
      text(1280, 129, "Resilience Graph AI | Live analysis, explainable intelligence, one deployable system", 22, 600, "#28536B", "middle")]

# Legend
s += [f'<circle cx="2040" cy="91" r="9" fill="#2586C4"/>', text(2058, 98, "live request", 18, 600, "#38556A"),
      f'<circle cx="2210" cy="91" r="9" fill="#D88916"/>', text(2228, 98, "persisted state", 18, 600, "#38556A"),
      f'<line x1="2390" y1="91" x2="2430" y2="91" stroke="#66788A" stroke-width="4" stroke-dasharray="10 8"/>', text(2440, 98, "offline", 18, 600, "#38556A")]

# Major column shells
s += [rect(54, 182, 314, 1000, "#F4FBFE", "#45B8C8", 3, 24),
      rect(396, 182, 1618, 1000, "#F9FCFE", "#2586C4", 3, 24),
      rect(2042, 182, 464, 1000, "#F4FBFE", "#45B8C8", 3, 24)]
s += [text(211, 224, "INPUTS", 24, 800, "#147D94", "middle"),
      text(1205, 224, "SINGLE CONTAINER RUNTIME", 24, 800, "#155A86", "middle"),
      text(2274, 224, "SOC OUTCOMES", 24, 800, "#147D94", "middle")]

# Inputs
s += [card(78, 250, 266, 164, "Analyst and browser", ["HTTPS session", "scenario selection", "CSV upload", "live event scoring"], "#2586C4", "#FFFFFF"),
      card(78, 438, 266, 184, "Telemetry", ["LANL auth events", "CICIDS network flows", "UNSW network records", "12 field common schema"], "#0E9BBF", "#FFFFFF"),
      card(78, 646, 266, 180, "Threat intelligence", ["free CTI feeds", "India first relevance", "MITRE ATT&CK STIX", "CERT-In sequences"], "#7657D5", "#FFFFFF"),
      card(78, 850, 266, 274, "Trust boundary", ["schema validation", "column alias resolution", "50K row design cap", "critical asset input", "account scoped analysis", "honest live or sample label"], "#E0712F", "#FFFFFF")]

# Frontend layer
s += [label(422, 244, 154, "01", "EXPERIENCE PLANE", "#2586C4"),
      rect(422, 308, 1566, 176, "#EDF6FF", "#79B5EE", 2.5, 20),
      card(446, 330, 350, 130, "React 19 and Vite 8", ["react-router 7", "lazy split SPA"], "#2586C4", "#FFFFFF", 21, 18),
      card(818, 330, 360, 130, "AnalysisProvider", ["live bundle overrides sample", "useScreenData state flow"], "#2586C4", "#FFFFFF", 21, 18),
      card(1200, 330, 366, 130, "API client", ["same origin /api", "live to cached fallback"], "#2586C4", "#FFFFFF", 21, 18),
      card(1588, 330, 376, 130, "SOC visualization", ["Recharts and force graph", "LIVE or SAMPLE status"], "#2586C4", "#FFFFFF", 21, 18)]

# API layer
s += [label(422, 510, 154, "02", "FASTAPI SERVICE PLANE", "#0E9BBF"),
      rect(422, 574, 1566, 188, "#EDFBFE", "#53C4D9", 2.5, 20),
      card(446, 596, 350, 142, "Live POST", ["/analyze", "/analyze/upload", "/score-event", "/predict-next"], "#0E9BBF", "#FFFFFF", 21, 17),
      card(818, 596, 360, 142, "Streaming SSE", ["/analyze/stream", "paced event replay", "final analysis bundle"], "#0E9BBF", "#FFFFFF", 21, 17),
      card(1200, 596, 366, 142, "Cached and CTI GET", ["overview, incident, graph", "report, metrics, attackers", "threat-intel, methodology"], "#0E9BBF", "#FFFFFF", 21, 17),
      card(1588, 596, 376, 142, "Runtime serving", ["uvicorn on port 8000", "built SPA from FastAPI", "health check and same origin"], "#0E9BBF", "#FFFFFF", 21, 17)]

# Spine
s += [label(422, 788, 154, "03", "LIVE ANALYSIS SPINE | analyze_events()", "#20A657"),
      rect(422, 852, 1566, 190, "#F0FCF4", "#58C97E", 2.5, 20)]
stages = [
    ("1", "Normalize", "schema + aliases"), ("2", "Score", "0 to 100 anomaly"),
    ("3", "Correlate", "alerts to incident"), ("4", "ATT&CK", "verified technique IDs"),
    ("5", "Graph", "paths + blast radius"), ("6", "SOAR", "human gated actions"),
    ("7", "Infer", "attribute + predict"), ("8", "Views", "screen JSON + MTTD")]
sx = 444
for i, (n, title_, sub) in enumerate(stages):
    x0 = sx + i * 191
    s += [rect(x0, 882, 170, 132, "#FFFFFF", "#56BF78", 2, 14),
          f'<circle cx="{x0+28}" cy="912" r="19" fill="#20A657"/>', text(x0+28, 920, n, 18, 800, "#FFFFFF", "middle"),
          text(x0+55, 920, title_, 20, 700, "#123B25"), text(x0+85, 969, sub, 16, 500, "#557163", "middle")]
    if i < 7:
        s.append(arrow(x0+171, 948, x0+188, 948, "#20A657", False, 3))

# Intelligence row
s += [label(422, 1068, 154, "04", "INTELLIGENCE, GRAPH AND STATE", "#E0712F"),
      card(422, 1126, 370, 176, "Detection engine", ["Autoencoder, benign trained", "7 behavioral features", "LANL ROC AUC 0.992", "TPR 87.7 pct at 1 pct FPR"], "#E0712F", "#FFF8F3", 21, 17),
      card(812, 1126, 370, 176, "Prediction and attribution", ["MiniLM embeddings, precomputed", "Interpolated Markov next technique", "5.4x kill chain baseline", "transparent actor ranking"], "#E0712F", "#FFF8F3", 21, 17),
      card(1202, 1126, 370, 176, "Attack graph and CTI", ["NetworkX graph analytics", "all pivots and crown jewels", "external relevance bridge", "gated sector alerts"], "#7657D5", "#F8F4FF", 21, 17),
      card(1592, 1126, 396, 176, "Persisted runtime artifacts", ["autoencoder and Markov models", "ATT&CK lookups and embeddings", "scenario CSV and cache JSON", "canonical metrics.json"], "#D88916", "#FFFBEE", 21, 17)]

# Outputs
s += [card(2068, 250, 412, 184, "Command center", ["Analyze and Overview", "Attackers and Incident", "Graph and Threat Intel", "Radar, Metrics, Methodology"], "#2586C4", "#FFFFFF"),
      card(2068, 458, 412, 180, "Incident intelligence", ["one correlated campaign", "per account investigation", "ATT&CK mapped evidence", "ranked actor attribution"], "#20A657", "#FFFFFF"),
      card(2068, 662, 412, 180, "Graph decisions", ["attack path and pivots", "blast radius and exposure", "critical asset reachability", "next technique forecast"], "#7657D5", "#FFFFFF"),
      card(2068, 866, 412, 258, "Response and evidence", ["human gated SOAR actions", "audit ready incident report", "live CTI relevance", "computed MTTD", "drift proof metrics", "LIVE or SAMPLE provenance"], "#E0712F", "#FFFFFF")]

# Main request arrows
s += [arrow(344, 332, 446, 390), arrow(796, 468, 796, 594), arrow(796, 738, 796, 850),
      arrow(1988, 948, 2068, 950), arrow(344, 530, 446, 650), arrow(344, 730, 446, 666)]

# Footer architecture plane
s += [rect(54, 1322, 2452, 84, "#DDF3FB", "#1581AF", 3, 18),
      f'<rect x="76" y="1340" width="180" height="48" rx="24" fill="#137BA7"/>',
      text(166, 1372, "DEPLOYMENT", 20, 800, "#FFFFFF", "middle"),
      text(282, 1358, "Two stage Docker build | React bundle plus Python 3.10 runtime | Render blueprint | one URL", 20, 700, "#173B53"),
      text(282, 1386, "Slim serving dependencies | models loaded once | no Torch at runtime | health check /api/health", 18, 500, "#42647A"),
      text(2425, 1361, "OFFLINE BUILD", 18, 800, "#66788A", "end"),
      text(2425, 1387, "11 GB datasets -> training -> artifacts -> cache", 17, 500, "#66788A", "end")]

# Dashed boot and offline relationships
s += [arrow(1770, 1124, 1770, 1028, "#D88916", True, 3),
      arrow(2320, 1320, 1850, 1302, "#66788A", True, 3)]

s.append("</svg>")
svg = "".join(s)
(OUT / "technical_architecture_final.svg").write_text(svg, encoding="utf-8")
print(OUT / "technical_architecture_final.svg")
