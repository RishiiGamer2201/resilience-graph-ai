# How to Build the Manual CERT-In Sequences (Task E2.2b)

**Who this is for:** any teammate — you do **not** need to be a cybersecurity expert.
**Time:** ~20–30 min per sequence.
**Goal:** turn 3–5 real Indian attack reports into ordered lists of MITRE ATT&CK
technique IDs, so our next-technique predictor is tested on *real* attacker
timelines (not our auto-generated ones).

> **Why this matters (30-sec version):** our 199 auto-sequences are ordered by a
> rule (recon → … → impact). A judge can say *"your prediction is just re-learning
> that rule."* These hand-made sequences are ordered by **what actually happened**
> in real incidents, so they're the honest proof our model works. Also: they're
> **India-specific** (APT36, RedEcho, ransomware), which scores big on Business Impact.

---

## Setup (one-time) — only if you'll RUN the pipeline

The `.venv` is **not** in git (too big), so make your own from the repo root:
```bash
py -3.10 -m venv .venv          # or:  python -m venv .venv
.venv\Scripts\activate           # Windows;  source .venv/bin/activate on Mac/Linux
pip install -r requirements.txt
```
**If you only want to VERIFY technique IDs** (not run the model), you don't need any
of this — use the browser method in Step 6, Option A. No Python required.

---

## The big picture (what you're actually doing)

You read a report that says things like *"the attackers sent a phishing email with a
malicious attachment…"* and you translate each action into a **technique ID** like
`T1566.001`. Then you keep them **in the order the report describes**. That's it.

```
Report sentence                              →   ATT&CK technique ID
"phishing email with malicious attachment"   →   T1566.001
"victim opened the document"                 →   T1204.002
"it ran a PowerShell script"                 →   T1059.001
"...encrypted all the files (ransomware)"    →   T1486
```

---

## Step-by-step

### Step 1 — Pick a real report
Use one of these sources (in order of preference):

1. **CERT-In advisories** — https://www.cert-in.org.in/ → "Advisories". These are the
   ideal source (Indian national CERT). Note: many are *vulnerability* notes with
   little attacker-behavior detail — pick ones that describe an actual attack/malware.
2. **MITRE ATT&CK group pages** for India-relevant actors (already partly done for you):
   - APT36 / Transparent Tribe: https://attack.mitre.org/groups/G0134/
   - RedEcho: https://attack.mitre.org/groups/G1042/
   - SideWinder: https://attack.mitre.org/groups/G0121/
3. **Vendor incident reports** on Indian targets (CYFIRMA, Recorded Future, Cisco Talos, SEQRITE).

**Write down the exact URL** — we cite it.

### Step 2 — Read it and list the attacker's actions *in order*
Read the report once. Jot the actions in plain English, top to bottom, as they happened:

```
1. sent phishing email with a .pdf.lnk attachment
2. user opened it, which ran mshta
3. mshta launched PowerShell
4. malware added itself to the Startup folder to survive reboot
5. disguised itself as a legit process
6. talked to its server over HTTPS
7. stole and uploaded documents
```

### Step 3 — Map each action to a technique ID
Use the **cheat-sheet below**, or look it up:
- Search the action on https://attack.mitre.org/ (top-right search), or
- Use our local lookup (fastest, offline):
  ```bash
  ./.venv/Scripts/python.exe -c "import pickle; d=pickle.load(open('data/processed/mitre_attack/attack_lookups.pkl','rb'))['technique_to_name']; print({k:v for k,v in d.items() if 'phish' in v.lower()})"
  ```
  (change `'phish'` to any keyword to find matching techniques)

### Step 4 — Keep the report's order (do NOT reorder)
The order **is** the data. Leave it exactly as the report tells the story, even if it
"jumps around" tactics. That real ordering is the whole point.

### Step 5 — Add it to the JSON file
Edit `data/manual/cert_in_sequences.json` (same folder as this guide). Format:

```json
{
  "actor": "Short name of the campaign/actor",
  "source": "Report name + who published it",
  "source_url": "https://the-exact-report-url",
  "verified": true,
  "note": "anything worth flagging",
  "ordered_technique_ids": [
    "T1566.001",
    "T1204.002",
    "T1059.001"
  ]
}
```
- Set `"verified": true` **only after** you've checked every ID against the report.
- Minimum **2** techniques (aim for 5–9). Comma between items, no trailing comma.

### Step 6 — Verify your technique IDs are real
Typos are the #1 mistake. Pick whichever option suits you:

**Option A — no tools, just a browser (recommended if you have no Python):**
Every technique has a page at `https://attack.mitre.org/techniques/<ID>` — for a
sub-technique, replace the dot with a slash:
- `T1486` → https://attack.mitre.org/techniques/T1486
- `T1566.001` → https://attack.mitre.org/techniques/T1566/001

If the page loads **and** its description matches the action you meant, the ID is
correct. (A 404 = wrong/typo'd ID.)

**Option B — with Python (needs the Setup above):**
```bash
./.venv/Scripts/python.exe -c "import json,pickle; ids=[t for s in json.load(open('data/manual/cert_in_sequences.json')) for t in s['ordered_technique_ids']]; names=pickle.load(open('data/processed/mitre_attack/attack_lookups.pkl','rb'))['technique_to_name']; [print(t, '->', names.get(t,'MISSING')) for t in ids]"
```
Every line must show a name, not `MISSING`.

### Step 7 — Rebuild and check
```bash
./.venv/Scripts/python.exe -m src.engine2.build_sequences
./.venv/Scripts/python.exe -m src.engine2.build_predictor
```
Then open `reports/sequences.md` (should show your verified count) and
`reports/prediction_eval.md` (the "Non-circular headline" section shows accuracy
on your sequences).

### Step 8 — Commit on a branch (don't push straight to main)
```bash
git checkout -b m3/cert-in-sequences
git add data/manual/cert_in_sequences.json
git commit -m "E2.2b: verified CERT-In sequences (<your name>)"
git push -u origin m3/cert-in-sequences
```
Then open a Pull Request.

---

## Full worked example (APT36 — do one like this)

**Source:** MITRE ATT&CK G0134 + CYFIRMA reporting on APT36 vs Indian govt/defense.

| # | What the report says | Technique | ID |
|---|---|---|---|
| 1 | Spear-phishing email with malicious attachment | Spearphishing Attachment | `T1566.001` |
| 2 | Victim opens the malicious file | User Execution: Malicious File | `T1204.002` |
| 3 | Uses mshta to run code | Mshta | `T1218.005` |
| 4 | PowerShell downloader executes | PowerShell | `T1059.001` |
| 5 | Adds Startup-folder entry to persist | Registry Run Keys / Startup Folder | `T1547.001` |
| 6 | Disguises as a legit process | Masquerading | `T1036` |
| 7 | Payload is obfuscated | Obfuscated Files or Information | `T1027` |
| 8 | Beacons to C2 over HTTPS | Web Protocols | `T1071.001` |
| 9 | Exfiltrates documents over C2 | Exfiltration Over C2 Channel | `T1041` |

→ becomes:
```json
"ordered_technique_ids": ["T1566.001","T1204.002","T1218.005","T1059.001","T1547.001","T1036","T1027","T1071.001","T1041"]
```

---

## Cheat-sheet: common report phrases → technique IDs

| If the report says… | Technique | ID |
|---|---|---|
| phishing email w/ attachment | Spearphishing Attachment | `T1566.001` |
| phishing link | Spearphishing Link | `T1566.002` |
| user opened file / ran macro | User Execution: Malicious File | `T1204.002` |
| PowerShell | PowerShell | `T1059.001` |
| command shell / cmd / bash | Command & Scripting Interpreter | `T1059` |
| mshta | Mshta | `T1218.005` |
| exploited an internet-facing app/server | Exploit Public-Facing Application | `T1190` |
| VPN / RDP / exposed remote service access | External Remote Services | `T1133` |
| added Run key / Startup persistence | Registry Run Keys / Startup Folder | `T1547.001` |
| stole passwords / dumped credentials | OS Credential Dumping | `T1003` |
| used stolen valid account | Valid Accounts | `T1078` |
| scanned/looked around the network | System / Network Discovery | `T1082` / `T1046` |
| moved to other machines | Remote Services | `T1021` |
| downloaded more tools/malware | Ingress Tool Transfer | `T1105` |
| C2 over HTTP/HTTPS | Web Protocols | `T1071.001` |
| used a proxy (e.g., FRP) | Proxy | `T1090` |
| hid as a legit process/file | Masquerading | `T1036` |
| encrypted/obfuscated payload | Obfuscated Files or Information | `T1027` |
| stole/uploaded data over C2 | Exfiltration Over C2 Channel | `T1041` |
| uploaded data to a website/cloud | Exfiltration Over Web Service | `T1567` |
| ransomware encrypted files | Data Encrypted for Impact | `T1486` |
| deleted backups / shadow copies | Inhibit System Recovery | `T1490` |

> Not in the list? Search https://attack.mitre.org/ or the local lookup (Step 3).
> Sub-techniques (the `.001` part) are optional — `T1566` alone is fine if unsure.

---

## Do / Don't

✅ **Do**
- Keep the **report's order**.
- Cite the **exact URL**.
- Verify every ID (Step 6) before `verified: true`.
- Prefer real CERT-In advisories over the placeholders.

❌ **Don't**
- Don't reorder into "recon → … → impact" — that defeats the purpose.
- Don't invent technique IDs — if unsure, look it up or use the parent (`T1566`).
- Don't push straight to `main` — use a branch + PR.
- Don't set `verified: true` on the 2 placeholder entries until you've replaced them
  with a real advisory.

---

## What "done" looks like
- 3–5 sequences, each with a real `source_url` and `verified: true`.
- Step 6 shows **no ❌ MISSING**.
- `reports/sequences.md` shows `verified: N/N`.
- One PR opened. 🎉

Questions? Ping in the team chat or check the parent task in
`research/claude/implementation_plan.md` (task **E2.2b**).
