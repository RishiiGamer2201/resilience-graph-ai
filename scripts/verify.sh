#!/usr/bin/env bash
# POSIX equivalent of scripts/verify.ps1 — one command that says whether this
# repository is demo-ready. Every skipped step says why.
#
#   bash scripts/verify.sh            # tests + self-checks + lint + build + smoke
#   bash scripts/verify.sh --docker   # additionally build and smoke-test the image
#   bash scripts/verify.sh --skip-frontend
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
DOCKER=0
SKIP_FRONTEND=0
for arg in "$@"; do
  case "$arg" in
    --docker) DOCKER=1 ;;
    --skip-frontend) SKIP_FRONTEND=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$ROOT/.venv/Scripts/python.exe"
[ -x "$PY" ] || PY="$(command -v python3 || command -v python)"
echo "nextATT&CKs verification"
echo "python: $PY"

RESULTS=()
FAILED=0

step() {                       # step "Name" command...
  local name="$1"; shift
  echo; echo "-- $name"
  local start; start=$(date +%s)
  if "$@"; then
    RESULTS+=("PASS  $name  $(( $(date +%s) - start ))s")
  else
    local rc=$?
    if [ "$rc" -eq 42 ]; then
      RESULTS+=("SKIP  $name")
    else
      echo "   FAILED (exit $rc)"
      RESULTS+=("FAIL  $name  $(( $(date +%s) - start ))s")
      FAILED=$((FAILED + 1))
    fi
  fi
}

check_artifacts() {
  local missing=()
  for f in data/processed/mitre_attack/attack_lookups.pkl \
           models/next_technique_markov.pkl \
           api/cache/score_ref.json \
           configs/vuln_priority.json \
           reports/metrics.json; do
    [ -f "$f" ] || missing+=("$f")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "   missing required: ${missing[*]}"
    return 1
  fi
  [ -f models/ae_lanl.npz ] || echo "   DEGRADED: models/ae_lanl.npz absent - detector falls back to IsolationForest"
  [ -f data/processed/evidence/index.json.gz ] || echo "   DEGRADED: evidence index absent - run python -m scripts.build_evidence_index"
  [ -f api/cache/overview.json ] || echo "   DEGRADED: sample cache absent - run python -m scripts.build_cache"
  echo "   all required artifacts present"
}

self_checks() {
  for m in src.shared.nethttp src.shared.detector src.shared.predictor \
           src.shared.evidence src.shared.vuln src.shared.twin src.shared.rbac \
           src.shared.audit src.shared.scoreboard src.shared.explain src.shared.claims \
           src.shared.casefile src.shared.crosscheck src.shared.rollout src.shared.enrich src.shared.attribution \
           src.shared.workflow; do
    "$PY" -m "$m" || return 1
  done
}

smoke() {
  PYTHONIOENCODING=utf-8 "$PY" -m scripts.smoke_api
}

frontend() {                   # frontend lint|build
  [ "$SKIP_FRONTEND" -eq 0 ] || { echo "   skipped (--skip-frontend)"; return 42; }
  [ -d frontend/node_modules ] || { echo "   skipped: frontend/node_modules absent - run npm install"; return 42; }
  ( cd frontend && npm run "$1" )
}

docker_smoke() {
  [ "$DOCKER" -eq 1 ] || { echo "   skipped (pass --docker to include)"; return 42; }
  command -v docker >/dev/null || { echo "   skipped: docker not on PATH"; return 42; }
  docker info >/dev/null 2>&1 || { echo "   skipped: docker is installed but the daemon is not running"; return 42; }
  docker build -t nextattacks:verify . || return 1
  local name="nextattacks-verify-$$"
  docker run -d --rm --name "$name" -p 8099:8000 nextattacks:verify >/dev/null || return 1
  local ok=0
  for _ in $(seq 1 30); do
    sleep 2
    if curl -sf --max-time 3 http://127.0.0.1:8099/api/readiness | grep -q '"ready":true'; then ok=1; break; fi
  done
  if [ "$ok" -ne 1 ]; then docker stop "$name" >/dev/null 2>&1; echo "   container never became ready"; return 1; fi
  local body
  body=$(curl -sf --max-time 30 -X POST http://127.0.0.1:8099/api/investigate \
           -H 'Content-Type: application/json' -H 'X-Role: analyst' \
           -d '{"scenario":"aiims_ransomware"}')
  docker stop "$name" >/dev/null 2>&1
  echo "$body" | grep -q '"executed":0' || { echo "   container executed an action"; return 1; }
  echo "   container ready, investigation ran, nothing executed"
}

step 'Required runtime artifacts' check_artifacts
step 'Dockerfile COPY sources exist' "$PY" -m scripts.check_dockerfile
step 'Backend tests (pytest)'      "$PY" -m pytest tests/ -q
step 'Module self-checks'          self_checks
step 'Documented metrics are not stale' "$PY" -m scripts.audit_stale
step 'Offline API smoke test'      smoke
step 'Frontend lint'               frontend lint
step 'Frontend build'              frontend build
step 'Docker build + container health' docker_smoke

echo; echo "Summary"
printf '  %s\n' "${RESULTS[@]}"
if [ "$FAILED" -gt 0 ]; then
  echo "$FAILED step(s) FAILED"
  exit 1
fi
echo "All checks passed."
