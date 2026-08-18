# Cybersecurity Retrieval System — Master Source Index

> **Purpose:** Curated, categorized list of real, scrapable/ingestible cybersecurity sources for building a RAG (Retrieval-Augmented Generation) knowledge base. Covers MITRE ATT&CK v19.2 (Aug 2026), MITRE ATLAS v6.0, live CVE/KEV feeds, 2026 threat reports, malware databases, APT profiles, and India-specific intel.

---

## 1. MITRE ATT&CK (v19 / v19.2 — 2026)

### Key 2026 Changes
- **Defense Evasion retired** -> split into **Stealth (TA0005)** + **Defense Impairment (TA0112)**
- **ICS sub-techniques** introduced (now 12 tactics x 79 techniques x 18 sub-techniques)
- **Agile release Aug 2026**: ShinyHunters (G1057), TeamPCP (G1056), CI/CD supply chain malware
- **Mobile**: expanded Detection Strategies for Android/iOS
- **Enterprise totals**: 15 tactics x 222 techniques x 475 sub-techniques

### Official Data Sources (Machine-Readable)
| Resource | URL | Format |
|---|---|---|
| Enterprise ATT&CK STIX 2.1 | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json | JSON/STIX |
| Mobile ATT&CK STIX 2.1 | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json | JSON/STIX |
| ICS ATT&CK STIX 2.1 | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json | JSON/STIX |
| ATT&CK STIX Data (GitHub) | https://github.com/mitre-attack/attack-stix-data | Git repo |
| Legacy STIX 2.0 (mitre/cti) | https://github.com/mitre/cti | JSON/STIX |
| ATT&CK Data Model (TypeScript) | https://github.com/mitre-attack/attack-data-model | TS library |

### Human-Readable / Web Scraping URLs
| Resource | URL |
|---|---|
| ATT&CK Enterprise Matrix | https://attack.mitre.org/matrices/enterprise/ |
| ATT&CK ICS Matrix | https://attack.mitre.org/matrices/ics/ |
| ATT&CK Mobile Matrix | https://attack.mitre.org/matrices/mobile/ |
| All Techniques (Enterprise) | https://attack.mitre.org/techniques/enterprise/ |
| ATT&CK Groups | https://attack.mitre.org/groups/ |
| ATT&CK Software | https://attack.mitre.org/software/ |
| v19 Changelog (Apr 2026) | https://attack.mitre.org/resources/updates/updates-april-2026/ |
| v19.2 Agile Release (Aug 2026) | https://attack.mitre.org/resources/updates/updates-august-2026/ |
| ATT&CK Navigator (tool) | https://mitre-attack.github.io/attack-navigator/ |

### Notable New 2026 Groups & Software (v19.2 Agile)
- **ShinyHunters (G1057)** -- data extortion group
- **TeamPCP (G1056)** -- cloud credential theft
- **TeamPCP Cloud Stealer (S9041)**
- **Shai-Hulud (S9008)** / **Mini Shai-Hulud (S9043)** -- supply chain worm
- **CanisterWorm (S9042)** -- CI/CD pipeline worm
- **Kali365 (S9044)** -- phishing-as-a-service kit

---

## 2. MITRE ATLAS (v6.0.0 -- July 2026)

### Stats (v6.0)
- **16 tactics x 101 techniques x 77 sub-techniques x 68 case studies**
- Focus: adversarial threats against AI/ML systems including agentic AI

### Official Sources
| Resource | URL |
|---|---|
| ATLAS Main Site | https://atlas.mitre.org/ |
| ATLAS Matrix | https://atlas.mitre.org/matrices/ATLAS/ |
| ATLAS Techniques | https://atlas.mitre.org/techniques/ |
| ATLAS Case Studies | https://atlas.mitre.org/studies/ |
| ATLAS Data (GitHub) | https://github.com/mitre-atlas/atlas-data |
| ATLAS Navigator | https://mitre-atlas.github.io/atlas-navigator/ |

### Key 2026 Case Studies
| ID | Name | Type |
|---|---|---|
| AML.CS0042 | SesameOp -- Agentic AI Backdoor | Realized |
| -- | iProov Deepfake Bypass | Demonstrated |
| -- | Endpoint Protection ML Model Bypass | Realized |

### Crosswalks
| Mapping | URL |
|---|---|
| ATLAS to OWASP LLM Top 10 | https://atlas.mitre.org/resources/ |
| ATLAS to NIST AI RMF | https://atlas.mitre.org/resources/ |
| ATLAS to ATT&CK Enterprise | https://atlas.mitre.org/resources/ |

---

## 3. Vulnerability & Exploit Databases

### Primary APIs (All Free / Public)
| Source | Endpoint | Notes |
|---|---|---|
| **CISA KEV Catalog JSON** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | No auth; poll daily |
| **CISA KEV Web** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Human-readable |
| **NVD CVE API 2.0** | https://services.nvd.nist.gov/rest/json/cves/2.0 | Free API key boosts rate limit |
| **NVD Home** | https://nvd.nist.gov/ | Full database |
| **NVD API Key** | https://nvd.nist.gov/developers/request-an-api-key | Free; 5 req/30s to 50 req/30s |
| **Rapid7 VulnDB** | https://www.rapid7.com/db/ | Verified + remediation guidance |
| **VulnCheck** | https://vulncheck.com/ | Routinely targeted vulns |
| **Exploit-DB** | https://www.exploit-db.com/ | PoC exploits |

### Notable 2026 CVEs
| CVE | Description | Actor |
|---|---|---|
| CVE-2026-68820 | Windows AFD.sys privilege escalation zero-day | Lazarus Group |
| CVE-2026-59310 | VMware vCenter RCE | Widespread |
| CVE-2026-20349 | Cisco ASA/FTD VPN service disruption | Widespread |
| CVE-2020-1472 | ZeroLogon (still actively exploited) | Multiple |
| CVE-2021-44228 | Log4Shell (still actively exploited) | Multiple |
| CVE-2021-26855 | ProxyLogon | Multiple |
| CVE-2022-22965 | Spring4Shell | Multiple |

---

## 4. Malware & Threat Intelligence

### Malware Sample Databases
| Source | URL | Access |
|---|---|---|
| **MalwareBazaar** | https://bazaar.abuse.ch/ | Free community API |
| MalwareBazaar API | https://bazaar.abuse.ch/api/ | Free Auth-Key |
| **URLhaus** (abuse.ch) | https://urlhaus.abuse.ch/ | Free feed |
| **ThreatFox** (abuse.ch) | https://threatfox.abuse.ch/ | Free IOC feed |
| **SSL Blacklist** | https://sslbl.abuse.ch/ | Free feed |
| **VirusTotal** | https://www.virustotal.com/ | Free public API (rate limited) |
| VirusTotal API v3 | https://developers.virustotal.com/reference/overview | API docs |
| **ANY.RUN** | https://any.run/ | Interactive sandbox |
| ANY.RUN API | https://any.run/api-documentation/ | SDK available |
| **Cuckoo Sandbox** | https://cuckoosandbox.org/ | Open-source self-hosted |
| **Malpedia** | https://malpedia.caad.fkie.fraunhofer.de/ | Malware family encyclopedia |

### Active 2026 Malware Families
| Family | Type | Notes |
|---|---|---|
| **Medusa** | Ransomware | Critical infra, healthcare |
| **LockBit** | Ransomware (RaaS) | Still active via resilient model |
| **Qilin** | Ransomware | Ex-LockBit affiliates |
| **Akira** | Ransomware | Healthcare focus |
| **DragonForce** | Ransomware | Government targeting |
| **The Gentlemen** | Ransomware | Most active group H1 2026 |
| **Lumma** | Infostealer | Dominant in RaaS marketplace |
| **AsyncRAT** | RAT | Widely used in RaaS |
| **XWorm** | RAT/stealer | Commodity malware |
| **Umbral Stealer** | Infostealer | Social engineering + defense evasion |
| **Troy** | Backdoor | Lazarus Group (Aug 2026) |
| **FudModule** | Rootkit | Lazarus Group |
| **InvisibleFerret** | Backdoor | Lazarus developer targeting |
| **BeaverTail** | Loader | Lazarus "Operation Dream Job" |
| **FCCCall** | Malware | Lazarus CI/CD targeting |
| **JadePuffer** | AI-automated ransomware | First major AI agent ransomware (Jul 2026) |
| **Shai-Hulud** | Supply chain worm | CI/CD compromise (ATT&CK v19.2) |
| **CanisterWorm** | Supply chain worm | CI/CD compromise (ATT&CK v19.2) |
| **TeamPCP Cloud Stealer** | Cloud credential theft | ShinyHunters / TeamPCP |

### Threat Intel Feeds (STIX/TAXII & REST)
| Source | URL | Format |
|---|---|---|
| **CISA KEV JSON** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | JSON |
| **AlienVault OTX** | https://otx.alienvault.com/ | STIX/TAXII + REST |
| OTX API | https://otx.alienvault.com/api/ | REST |
| **MISP Project** | https://www.misp-project.org/ | STIX 2.1 / TAXII |
| **DShield (SANS ISC)** | https://dshield.org/feeds/intelfeed.txt | Plain text |
| **PhishTank** | https://phishtank.org/developer_info.php | JSON/CSV |
| **Feodo Tracker** | https://feodotracker.abuse.ch/feeds/ | IP blocklists |
| **CINS Army List** | http://cinsscore.com/list/ci-badguys.txt | Plain text |

---

## 5. APT Groups & Nation-State Actors (2026)

### Chinese APTs
| Group | Aliases | Targets | TTPs |
|---|---|---|---|
| **Salt Typhoon** | -- | Telecom, government | LotL, edge devices |
| **Flax Typhoon** | -- | Taiwan, defense | SOHO router compromise |
| **Volt Typhoon** | -- | Critical infrastructure | Pre-positioning, LotL |
| **Mustang Panda** | TA416 | Government, NGOs | PlugX, spear-phishing |
| **Jewelbug** | -- | Espionage + crypto fraud | Dual-use infrastructure |

### Russian APTs
| Group | Aliases | Targets | TTPs |
|---|---|---|---|
| **APT29** | Cozy Bear | Government, diplomats | Supply chain, identity theft |
| **APT28** | Fancy Bear | Military, elections | Spear-phishing, CVE exploitation |
| **Berserk Bear** | Dragonfly | Energy, water, OT/ICS | SNMP exploitation |
| **Sandworm** | -- | Ukraine, critical infra | Destructive malware, OT |

### North Korean APTs
| Group | Aliases | Targets | TTPs |
|---|---|---|---|
| **Lazarus** | Hidden Cobra | Defense, crypto, developers | DLL sideload, zero-days, Dream Job |
| **Andariel** | Stonefly | Healthcare, non-profits | Medusa RaaS, custom tools |
| **BlueNoroff** | -- | Banks, crypto exchanges | SWIFT fraud, supply chain |

### Iranian APTs
| Group | Aliases | Targets | TTPs |
|---|---|---|---|
| **APT33** | Elfin | Aviation, defense | Spear-phishing, destructive malware |
| **APT34** | OilRig | Government, finance | DNS tunneling, backdoors |
| **APT35** | Charming Kitten | Researchers, journalists | Social engineering, phishing |

### APT Reference Sources
| Source | URL |
|---|---|
| MITRE ATT&CK Groups | https://attack.mitre.org/groups/ |
| Mandiant APT Profiles | https://www.mandiant.com/resources/insights/apt-groups |
| CrowdStrike Adversary Intelligence | https://www.crowdstrike.com/adversaries/ |
| Malpedia Threat Actors | https://malpedia.caad.fkie.fraunhofer.de/actors |

---

## 6. 2026 Threat Reports & Research Articles

### Annual Threat Reports
| Report | Publisher | URL | Key Stat |
|---|---|---|---|
| **M-Trends 2026** | Mandiant / Google Cloud | https://cloud.google.com/security/resources/m-trends | Dwell time: 14 days |
| **2026 Global Threat Report** | CrowdStrike | https://www.crowdstrike.com/resources/reports/global-threat-report/ | Breakout: 29 min avg |
| **2026 Threat Hunting Report** | CrowdStrike | https://www.crowdstrike.com/resources/reports/threat-hunting-report/ | 89% increase AI attacks |
| **IBM Cost of Data Breach 2026** | IBM | https://www.ibm.com/reports/data-breach | Record high avg cost |
| **Cyber Security Report 2026** | Check Point | https://pages.checkpoint.com/cyber-security-report-2026.html | Ransomware +48% YoY |
| **OT/ICS Year in Review 2026** | Dragos | https://www.dragos.com/year-in-review/ | OT threat diversity |
| **Global Cybersecurity Outlook 2026** | WEF | https://www.weforum.org/publications/global-cybersecurity-outlook-2026/ | Geopolitical fragmentation |
| **State of Ransomware 2026** | Sophos | https://www.sophos.com/en-us/content/state-of-ransomware | Encryptionless shift |
| **FortiGuard Threat Landscape** | Fortinet | https://www.fortinet.com/blog/threat-research | 5-day time-to-exploit |

### Key 2026 Incidents (Real Sources)
| Incident | Date | Primary Source |
|---|---|---|
| Tata Electronics breach (Apple/Tesla data stolen) | Jun 2026 | https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents |
| JadePuffer AI-automated ransomware campaign | Jul 2026 | https://www.cm-alliance.com/cybersecurity-blog/ |
| Coca-Cola Fairlife ransomware disruption | Jul 2026 | https://www.cm-alliance.com/cybersecurity-blog/ |
| Russia FSB espionage on govt smartphones | Jun 2026 | https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents |
| Lazarus CVE-2026-68820 zero-day (Troy backdoor) | Aug 2026 | https://thehackernews.com/ |
| Jaguar Land Rover supply chain attack | Late 2025 | https://industrialcyber.co/ |

### Ongoing Cybersecurity News Sources
| Source | URL | Focus |
|---|---|---|
| **The Hacker News** | https://thehackernews.com/ | Breaking news, APT, CVEs |
| **BleepingComputer** | https://www.bleepingcomputer.com/ | Malware, ransomware incidents |
| **SecurityWeek** | https://www.securityweek.com/ | Enterprise security news |
| **The Record** | https://therecord.media/ | Recorded Future news desk |
| **DarkReading** | https://www.darkreading.com/ | Threat intelligence |
| **Krebs on Security** | https://krebsonsecurity.com/ | In-depth investigations |
| **CSIS Significant Incidents** | https://www.csis.org/programs/strategic-technologies-program/significant-cyber-incidents | Curated incident database |
| **Securelist** (Kaspersky) | https://securelist.com/ | APT, malware research |
| **EclecticIQ Blog** | https://blog.eclecticiq.com/ | Threat intelligence research |
| **Help Net Security** | https://www.helpnetsecurity.com/ | Daily security news |
| **Industrial Cyber** | https://industrialcyber.co/ | OT/ICS/SCADA threats |
| **Cybersecurity Insiders** | https://www.cybersecurity-insiders.com/ | Industry news |

---

## 7. India-Specific Cybersecurity Sources

| Source | URL | Description |
|---|---|---|
| **CERT-In Official** | https://www.cert-in.org.in/ | India's national CERT |
| CERT-In Advisories | https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01 | Vulnerability notes |
| CERT-In Alerts | https://www.cert-in.org.in/s2cMainServlet?pageid=PUBALERTS01 | Real-time alerts |
| **NCIIPC** | https://nciipc.gov.in/ | National Critical Info Infra Protection |
| **MeitY Cyber** | https://www.meity.gov.in/ | Govt digital/cyber policy |
| **PIB Cyber Press Releases** | https://pib.gov.in/ | Official govt cyber incident releases |
| **Seqrite Threat Reports** | https://www.seqrite.com/resources/ | India-focused threat reports |
| **CyberPeace Foundation** | https://cyberpeace.org/ | India cyber research |
| **Eventus Security** | https://eventussecurity.com/ | India threat landscape reports |
| **DSCI** | https://www.dsci.in/ | Data Security Council of India |
| **CloudSEK Blog** | https://cloudsek.com/blog | India incident research |

### Key India 2026 Stats
- CERT-In handled **29.44 lakh (2.94 million) incidents** in 2025
- **265+ million malware detections** H1 2026
- New **12-hour patch mandate** from CERT-In
- **6-hour mandatory incident reporting** window for critical sectors
- Peak ransomware detections: March 2026
- Top targeted sectors: Education, Government, Business Services

---

## 8. Open Datasets for RAG Ingestion

### Cybersecurity Datasets
| Dataset | URL | Size | Use |
|---|---|---|---|
| **MITRE ATT&CK STIX** | GitHub (see Section 1) | ~30 MB | Technique lookup, mapping |
| **CISA KEV** | JSON feed (see Section 3) | ~1 MB, updated daily | Exploited CVE lookup |
| **NVD CVE** | API (see Section 3) | 48K+ CVEs (2025 alone) | Vulnerability details |
| **CIC-IDS2017** | https://www.unb.ca/cic/datasets/ids-2017.html | 2.3M flows | Anomaly detection |
| **LANL Cyber 2015** | https://csr.lanl.gov/data/cyber1/ | 11.2M auth events | Lateral movement |
| **UNSW-NB15** | https://research.unsw.edu.au/projects/unsw-nb15-dataset | Mixed | Benchmark |
| **CTU-13** | https://www.stratosphereips.org/datasets-ctu13 | Botnet traffic | Botnet detection |
| **EMBER** | https://github.com/elastic/ember | 1M PE files | PE malware detection |
| **Malpedia** | https://malpedia.caad.fkie.fraunhofer.de/ | Malware family DB | Actor attribution |

### IOC / Indicator Feeds (Live, Ingestible)
| Feed | URL | Update Frequency |
|---|---|---|
| CISA KEV JSON | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | As needed |
| URLhaus Full CSV | https://urlhaus.abuse.ch/downloads/csv/ | Every 5 minutes |
| ThreatFox IOC CSV | https://threatfox.abuse.ch/export/csv/recent/ | Daily |
| Feodo Tracker IPs | https://feodotracker.abuse.ch/downloads/ipblocklist.txt | Every 5 minutes |
| SSL Blacklist | https://sslbl.abuse.ch/blacklist/sslblacklist.csv | Daily |
| PhishTank JSON | https://data.phishtank.com/data/online-valid.json.gz | Hourly |
| AlienVault OTX Pulses | https://otx.alienvault.com/api/v1/pulses/subscribed | Real-time (API) |
| MalwareBazaar Recent | https://bazaar.abuse.ch/export/json/recent/ | Every 60 minutes |

---

## 9. Proposed Retrieval System Architecture

```
+--------------------------------------------------------------+
|                    DATA INGESTION LAYER                      |
|  [ATT&CK STIX]  [ATLAS STIX]  [CISA KEV]  [NVD API]        |
|  [MalwareBazaar] [OTX Pulses] [CERT-In RSS] [Malpedia]      |
+--------------------------------------------------------------+
                          | scrape / fetch / parse
+--------------------------------------------------------------+
|                  CHUNKING & EMBEDDING                        |
|   sentence-transformers/all-MiniLM-L6-v2 (already in use)  |
|   Chunk by: technique | advisory | malware family | CVE     |
|   Metadata: source, date, technique_id, severity, actor     |
+--------------------------------------------------------------+
                          | index
+--------------------------------------------------------------+
|                     VECTOR STORE                             |
|   ChromaDB (local dev)  |  Qdrant (production)              |
|   FAISS (offline / air-gap)                                  |
+--------------------------------------------------------------+
                          | query
+--------------------------------------------------------------+
|           RETRIEVAL API  (new FastAPI endpoint)              |
|   GET /retrieve?q=<query>&top_k=10&filter=technique          |
|   Returns: chunks + source + confidence + ATT&CK IDs        |
+--------------------------------------------------------------+
```

### Recommended Stack
| Component | Choice | Notes |
|---|---|---|
| Embedding model | all-MiniLM-L6-v2 | Already in project (src/engine2/) |
| Vector store | ChromaDB to Qdrant | Zero-infra local to prod upgrade path |
| Scheduler | APScheduler | Periodic feed refresh |
| STIX parser | stix2 Python library | For MITRE ATT&CK / ATLAS data |
| RSS/HTML parser | feedparser + BeautifulSoup | For CERT-In, news sources |
| Deduplication | SHA-256 content hash | Avoid re-indexing unchanged docs |

---

## 10. Python Snippet -- Fetch Key Feeds

```python
import requests, hashlib

# ---- Core feed URLs ----
FEEDS = {
    "cisa_kev":           "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "attack_enterprise":  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "attack_ics":         "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
    "attack_mobile":      "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "malwarebazaar":      "https://bazaar.abuse.ch/export/json/recent/",
    "threatfox_csv":      "https://threatfox.abuse.ch/export/csv/recent/",
    "urlhaus_csv":        "https://urlhaus.abuse.ch/downloads/csv/",
    "feodo_ips":          "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}

# ---- NVD CVE API 2.0 ----
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_cves(api_key=None, pub_start="2026-01-01T00:00:00.000"):
    headers = {"apiKey": api_key} if api_key else {}
    params  = {"pubStartDate": pub_start, "resultsPerPage": 2000}
    r = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json()

# ---- CERT-In alerts page ----
CERT_IN_ALERTS = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBALERTS01"

# ---- Generic fetcher with dedup hash ----
def fetch_feed(name: str, url: str) -> dict:
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    content = r.content
    fingerprint = hashlib.sha256(content).hexdigest()
    payload = r.json() if url.endswith(".json") else r.text
    return {"name": name, "url": url, "hash": fingerprint, "data": payload}

# ---- AlienVault OTX (requires free API key from otx.alienvault.com) ----
def fetch_otx_pulses(api_key: str):
    headers = {"X-OTX-API-KEY": api_key}
    r = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                     headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()
```

---

*Last updated: August 2026 | Maintained by nextATT&CKs / resilience-graph-ai team*
*All URLs are public/live -- validate freshness before ingestion into vector store.*
