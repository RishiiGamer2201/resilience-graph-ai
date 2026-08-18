<#
.SYNOPSIS
  One command that says whether this repository is demo-ready.

.DESCRIPTION
  Runs, in order: artifact presence checks, backend tests, module self-checks,
  frontend lint and build, and an offline API smoke test. Every step that is
  skipped says why it was skipped rather than passing silently.

.PARAMETER Docker
  Additionally build the deploy image and smoke-test the running container.

.PARAMETER SkipFrontend
  Skip npm lint/build (useful when node_modules is not installed).

.EXAMPLE
  .\scripts\verify.ps1
  .\scripts\verify.ps1 -Docker
#>
[CmdletBinding()]
param(
    [switch]$Docker,
    [switch]$SkipFrontend
)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$script:results = @()

function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ""
    Write-Host "-- $Name" -ForegroundColor Cyan
    $start = Get-Date
    try {
        $outcome = & $Body
        $secs = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
        if ($outcome -eq 'skip') {
            $script:results += [pscustomobject]@{ Step = $Name; Result = 'SKIP'; Seconds = $secs }
        } else {
            $script:results += [pscustomobject]@{ Step = $Name; Result = 'PASS'; Seconds = $secs }
        }
    } catch {
        $secs = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
        Write-Host "   FAILED: $($_.Exception.Message)" -ForegroundColor Red
        $script:results += [pscustomobject]@{ Step = $Name; Result = 'FAIL'; Seconds = $secs }
    }
}

# Prefer the project venv; fall back to whatever python is on PATH.
$py = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path $py)) { $py = 'python' }

function Invoke-Checked {
    param([string]$Exe, [string[]]$Args, [string]$Cwd = $root)
    Push-Location $Cwd
    try {
        & $Exe @Args
        if ($LASTEXITCODE -ne 0) { throw "$Exe $($Args -join ' ') exited $LASTEXITCODE" }
    } finally { Pop-Location }
}

Write-Host "nextATT&CKs verification" -ForegroundColor White
Write-Host "python: $py"

# --------------------------------------------------------------------------
Step 'Required runtime artifacts' {
    $required = @(
        'data/processed/mitre_attack/attack_lookups.pkl',
        'models/next_technique_markov.pkl',
        'api/cache/score_ref.json',
        'configs/vuln_priority.json',
        'reports/metrics.json'
    )
    $missing = $required | Where-Object { -not (Test-Path (Join-Path $root $_)) }
    if ($missing) { throw "missing: $($missing -join ', ')" }

    # These degrade rather than fail, but the operator should know.
    $optional = @{
        'models/ae_lanl.npz'                     = 'detector falls back to IsolationForest'
        'data/processed/evidence/index.json.gz'  = 'evidence stage will be skipped (python -m scripts.build_evidence_index)'
        'api/cache/overview.json'                = 'cached GETs will 503 (python -m scripts.build_cache)'
        'data/demo/scenarios/asset_inventory.json' = 'no vulnerability findings'
    }
    foreach ($k in $optional.Keys) {
        if (-not (Test-Path (Join-Path $root $k))) {
            Write-Host "   DEGRADED: $k absent - $($optional[$k])" -ForegroundColor Yellow
        }
    }
    Write-Host "   all required artifacts present"
}

Step 'Dockerfile COPY sources exist' {
    Invoke-Checked $py @('-m', 'scripts.check_dockerfile')
}

Step 'Backend tests (pytest)' {
    Invoke-Checked $py @('-m', 'pytest', 'tests/', '-q')
}

Step 'Module self-checks' {
    foreach ($m in @('src.shared.nethttp', 'src.shared.detector', 'src.shared.predictor',
                     'src.shared.evidence', 'src.shared.vuln', 'src.shared.twin',
                     'src.shared.rbac', 'src.shared.audit', 'src.shared.scoreboard',
                     'src.shared.explain', 'src.shared.workflow')) {
        Invoke-Checked $py @('-m', $m)
    }
}

Step 'Documented metrics are not stale' {
    Invoke-Checked $py @('-m', 'scripts.audit_stale')
}

Step 'Offline API smoke test' {
    # No server, no network: TestClient exercises the real app in-process.
    $code = @'
import json
from fastapi.testclient import TestClient
from api.main import app
c = TestClient(app)

assert c.get("/api/health").json()["ok"] is True
ready = c.get("/api/readiness").json()
assert ready["ready"], f"not ready: {ready['missing_required']}"
caps = c.get("/api/capabilities").json()
assert caps["keys_required"] == [], caps["keys_required"]
board = c.get("/api/scoreboard").json()
assert board["summary"]["missing_reports"] == [], board["summary"]["missing_reports"]

r = c.post("/api/investigate", json={"scenario": "aiims_ransomware"},
           headers={"X-Role": "analyst", "X-Actor": "verify@ci"})
assert r.status_code == 200, r.text
b = r.json()
assert b["ok"] and b["action"]["executed"] == 0
nodes = [n["node"] for n in b["trace"]["nodes"]]
assert nodes[0] == "understand" and nodes[-1] == "action", nodes
assert nodes.count("evidence") <= 2, "replan is not bounded"

# authorisation must be enforced by the server, not the UI
assert c.post("/api/investigate", json={"scenario": "aiims_ransomware"},
              headers={"X-Role": "viewer"}).status_code == 403
assert c.get("/api/audit/verify", headers={"X-Role": "viewer"}).json()["verified"]

print(f"   smoke ok: {len(nodes)} node runs in {b['trace']['total_ms']:.0f} ms, "
      f"{board['summary']['measured']} measured metrics, "
      f"{len(b['evidence'].get('citations', []))} citations, 0 actions executed")
'@
    $tmp = Join-Path $env:TEMP "nextattack_smoke_$PID.py"
    Set-Content -Path $tmp -Value $code -Encoding utf8
    try { Invoke-Checked $py @('-W', 'ignore', $tmp) } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

Step 'Frontend lint' {
    if ($SkipFrontend) { Write-Host "   skipped (-SkipFrontend)"; return 'skip' }
    if (-not (Test-Path (Join-Path $root 'frontend\node_modules'))) {
        Write-Host "   skipped: frontend/node_modules absent - run 'npm install' in frontend/" -ForegroundColor Yellow
        return 'skip'
    }
    Invoke-Checked 'npm' @('run', 'lint') (Join-Path $root 'frontend')
}

Step 'Frontend build' {
    if ($SkipFrontend) { Write-Host "   skipped (-SkipFrontend)"; return 'skip' }
    if (-not (Test-Path (Join-Path $root 'frontend\node_modules'))) {
        Write-Host "   skipped: frontend/node_modules absent" -ForegroundColor Yellow
        return 'skip'
    }
    Invoke-Checked 'npm' @('run', 'build') (Join-Path $root 'frontend')
}

Step 'Docker build + container health' {
    if (-not $Docker) { Write-Host "   skipped (pass -Docker to include)"; return 'skip' }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host "   skipped: docker not on PATH" -ForegroundColor Yellow
        return 'skip'
    }
    & docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   skipped: docker is installed but the daemon is not running" -ForegroundColor Yellow
        return 'skip'
    }
    Invoke-Checked 'docker' @('build', '-t', 'nextattacks:verify', '.')
    $name = "nextattacks-verify-$PID"
    & docker run -d --rm --name $name -p 8099:8000 nextattacks:verify | Out-Null
    try {
        $ok = $false
        foreach ($i in 1..30) {
            Start-Sleep -Seconds 2
            try {
                $h = Invoke-RestMethod -Uri 'http://127.0.0.1:8099/api/readiness' -TimeoutSec 3
                if ($h.ready) { $ok = $true; break }
            } catch { }
        }
        if (-not $ok) { throw "container did not become ready within 60s" }
        $inv = Invoke-RestMethod -Uri 'http://127.0.0.1:8099/api/investigate' -Method Post `
            -ContentType 'application/json' -Headers @{ 'X-Role' = 'analyst' } `
            -Body '{"scenario":"aiims_ransomware"}' -TimeoutSec 30
        if ($inv.action.executed -ne 0) { throw "container executed an action" }
        $spa = Invoke-WebRequest -Uri 'http://127.0.0.1:8099/investigate' -TimeoutSec 10
        if ($spa.StatusCode -ne 200) { throw "SPA deep link returned $($spa.StatusCode)" }
        Write-Host "   container ready, investigation ran, SPA served"
    } finally {
        & docker stop $name 2>$null | Out-Null
    }
}

# --------------------------------------------------------------------------
Write-Host ""
Write-Host "Summary" -ForegroundColor White
$script:results | Format-Table -AutoSize

$failed = @($script:results | Where-Object { $_.Result -eq 'FAIL' })
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) step(s) FAILED" -ForegroundColor Red
    exit 1
}
$skipped = @($script:results | Where-Object { $_.Result -eq 'SKIP' })
Write-Host "All checks passed ($($skipped.Count) skipped)." -ForegroundColor Green
exit 0
