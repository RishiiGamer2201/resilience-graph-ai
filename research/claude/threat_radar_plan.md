# Threat Radar — scoped OSINT/CTI feature (approved build)

> **Execution protocol** (user's standing workflow):
> 1. All work on branch **`threat-radar`** (from `main`).
> 2. Task completes → tick checkbox + append findings/gotchas/numbers under it.
> 3. Phase completes → commit + push on its own (`Threat Radar Phase N: <summary>`).
> 4. Update `memory.md` session log as phases land.

## Context

User wanted OSINT-driven real-time analysis (scrape Google/Facebook/Instagram/Twitter/news, track attacker, stop attack, alert orgs). Assessment (delivered + agreed): full vision blocked — social scraping violates ToS, person-level attribution is harmful, nothing can be "stopped" from OSINT, and real alerts to real orgs are out. **Approved scope:** an **External Threat Radar** built on legitimate free CTI feeds, mapped to ATT&CK, cross-referenced with the current incident, with simulated human-gated alerting. Fits PS7 (resilience = anticipation) and composes with the existing live pipeline.

**Sources (all free):**
- **CISA KEV** — plain JSON, no key: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **ThreatFox (abuse.ch)** — POST API `https://threatfox-api.abuse.ch/api/v1/` `{query:"get_iocs", days:7}`; auth key optional (`ABUSECH_AUTH_KEY` env) — degrade gracefully without it
- **AlienVault OTX** — needs free key (`OTX_API_KEY` env), `GET /api/v1/pulses/subscribed`; skip silently if no key
- **Security-news RSS** — The Hacker News + BleepingComputer feeds; parse with stdlib `xml.etree` (no feedparser dep)
- **NO social scraping. NO CERT-In scraping** (no clean feed; the RSS news covers Indian incidents anyway).

**Honesty rules carried over:** cached-by-default + live refresh with fallback badge; alerts simulated + human-gated; every screen number traces to fetched data or a labelled citation; no "we stop attacks" claims.

**Reuse:** `attack_lookups.pkl` (`technique_to_name`) for mapping; `useScreenData`/`useAnalysis` (`frontend/src/lib/analysis.jsx`) for data + incident cross-ref; `LiveBadge`, `Card`, chip styles; `views.py`-style single code path for cached & live; stdlib `urllib.request` for HTTP (zero new deps, deploy image untouched).

---

## Phase 0 — Branch
- [x] `git checkout -b threat-radar` from up-to-date `main`; push upstream. Tracks `origin/threat-radar`.

## Phase 1 — Backend: `src/shared/osint.py` + tests

- [x] **1.1 Fetchers** — `src/shared/osint.py`, stdlib-only (`urllib`+`xml.etree`), 15s timeouts, each source isolated (dead feed → `sources[].ok=false` + note, never breaks radar).
  - **Probed live first — findings:** CISA KEV ✓ no key (1644 CVEs). CISA advisories RSS ✓, The Hacker News ✓, BleepingComputer ✓ (no keys). **ThreatFox now returns 401 — abuse.ch requires a free account key** (`ABUSECH_AUTH_KEY`) → optional/skipped. OTX needs free `OTX_API_KEY` → optional/skipped. **Krebs RSS timed out → dropped. URLhaus dropped** (11 MB dump, too heavy). Net: **4 zero-key sources work out of the box** = 40 items; demo needs no signup.
- [x] **1.2 ATT&CK mapping** — explicit `T####` regex + technique-name match + 67 curated aliases, every ID validated against `attack_lookups`.
  - **Key finding — precision bug:** naive name matching produced obvious false positives (an AI news story → `T1588.007` *Obtain Capabilities: AI*; a disclosure advisory → `T1588.006` *Vulnerabilities*). Cause: reconnaissance/resource-development technique NAMES are generic English nouns. **Fix:** exclude those two tactics from name matching + require multi-word names ≥12 chars; explicit IDs + aliases carry the load. Precision over recall — a wrong technique on screen is worse than none.
  - **Alias validation caught a real error:** `T1574.002` (DLL Side-Loading) doesn't exist in our ATT&CK version — folded into `T1574.001` ("DLL"). Fixed.
  - Result: 40 items, ~11–14 mapped, all spot-checked correct (SonicWall appliance→T1190, trojanized apps→T1204.002, ransomware→T1486).
- [x] **1.3 Relevance scoring** — three separately-reported signals: exact technique overlap (0.6), **same ATT&CK tactic (0.2)**, attributed-actor name in text/tags (0.2).
  - **Key finding:** exact-technique matching alone yields **zero** hits — our incident is auth-based (`T1550.002`/`T1110` = lateral-movement/credential-access) while the feed is vuln/malware-based (initial-access/execution/impact). Verified NOT a bug (a synthetic pass-the-hash item scores 0.6). Tactic-level match added as the realistic, still-honest signal. **Zero relevant items is a legitimate outcome** — the UI must say so plainly rather than fake matches (drives the two-section design in Phase 3).
- [x] **1.4 Tests** — `tests/test_osint.py`, 11 passing, no network. Locks in both regressions (KEV date ordering; ransomware flag ≠ T1486), the recon-name false-positive rule, alias validity, invented-ID rejection, dead-feed resilience.
  - **KEV bug found + fixed:** catalog is **vendor-ordered, not date-ordered** — my `[::-1]` gave reverse-alphabetical (CVE-2019/2020 on screen). Now sorted by `dateAdded` desc → shows 2026-07-15/14.
  - **Mapping bug found + fixed:** `knownRansomwareCampaignUse=Known` was being appended as the word "ransomware" to the mapping text, making an *auth-bypass* CVE map to `T1486`. Campaign USE ≠ technique. Now a display tag only.
- [x] **Phase 1 complete → commit + push.**

## Phase 2 — Cache + API ✅

- [x] **2.1 `build_cache.py`** — fetches CTI at build time → `api/cache/threat_radar.json` (40 items, committed so the deploy has intel day-one). Offline builds skip it gracefully rather than failing.
- [x] **2.2 `api/main.py`** — `GET /api/threat-radar` (plain cached) + **`POST /api/threat-radar`** `{technique_ids, actors, refresh}` → radar with per-item relevance.
  - **Design change from plan:** scoring moved server-side instead of client-side JS. Client-side would have duplicated `relevance()` in JS *and* needed tactic lookups the frontend doesn't have. One implementation (Python), client just renders.
  - **Bug found + fixed:** `collect()` isolates each feed, so it *succeeds* with everything down → refresh returned `source:"live"` with **0 items** (empty radar labelled live, breaking the never-break-the-demo contract). Now a live result is only accepted if ≥1 source actually returned items; else cache.
- [x] **2.3 Verified** — online refresh → `live/40`; sockets patched off → `cache/40`. 17 tests green.
- [x] **Phase 2 complete → commit + push** (`af3ed80`).

## Phase 3 — Frontend: Threat Radar screen ✅

- [x] **3.1** `screens/ThreatRadar.jsx` + route `/threat-radar` + sidebar "Threat Radar" (Satellite icon) + Layout title. Feed-status card with per-source ●/○ chips, `LiveBadge`, **Refresh (live)** button.
- [x] **3.2** Item cards: source chip, date, title→external link, ATT&CK technique chips (matched ones highlighted red), tags, snippet.
- [x] **3.3** Incident cross-reference — pulls the current incident + attribution via `useScreenData` (so it follows a live analysis or the sample), POSTs context, renders "Same technique / Same tactic / Mentions actor" explanations. Sorted relevance-then-recency.
  - **Verified:** synthetic `T1190`/`T1486` incident → **7 relevant, correct matches**; the real auth-based incident → **0**. Screen renders an explicit honest empty state explaining *why* (auth-based incident vs vuln/malware-dominated feeds) instead of manufacturing a match.
- [x] **3.4** Simulated gated alert — "Queue sector alert (simulated)" → "queued · awaiting human approval"; card footer states nothing is dispatched to any real organisation.
- [x] **3.5** `npm run build` clean; lint shows only the pre-existing fast-refresh warnings.
- [x] **Phase 3 complete → commit + push.**

## Phase 4 — Docs + end-to-end verify ✅

- [x] Docs updated: `prd.md` (radar feature + explicit "no social scraping" non-goal with the reasoning), `architecture.md` (osint.py, radar flow diagram, endpoint), `rules.md` (new "External intel" rule block), `phases.md` (Phase 9), `memory.md` (session log + the empty-match and optional-key caveats).
- [x] **Verified:** 17/17 tests pass · `npm run build` clean · **real `docker build` succeeds** · container smoke: health 200, cached radar 40 items (`relevant=0`, honest), **live refresh from inside the container works** (`source=live`, 6 relevant for a T1190 incident — proves outbound CTI fetch works in the deploy image), SPA 200. `threat_radar.json` committed and not `.dockerignore`d.
- [x] **Phase 4 complete → commit + push.** Merge `threat-radar → main` on request.

---

## DONE — Threat Radar complete on branch `threat-radar`
Commits: P1 `9c460e8` · P2 `af3ed80` · P3 `e620453` · P4 (this).
**Zero new dependencies** (stdlib HTTP/XML) — deploy image unchanged. **Zero signups required** for the demo (4 no-key sources); OTX/ThreatFox optional via free keys.

## Files
New: `src/shared/osint.py`, `tests/test_osint.py`, `frontend/src/screens/ThreatRadar.jsx`, `api/cache/threat_radar.json` (generated).
Modified: `scripts/build_cache.py`, `api/main.py`, `frontend/src/{api.js, App.jsx, components/{Sidebar,Layout}.jsx}`, docs.

## Cut lines (if time pressure)
Drop OTX (key setup) → KEV+ThreatFox+RSS still demo fine. Drop the refresh endpoint → cached-only radar. Never drop: technique validation against lookups, simulated-alert labelling.
