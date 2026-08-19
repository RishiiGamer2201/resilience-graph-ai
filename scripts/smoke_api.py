"""Offline API smoke test — the shortest path that proves the demo works.

No server, no network: FastAPI's TestClient exercises the real app in-process.
Asserts the things that would ruin a demo if they broke, in the order they would
be noticed: the service is ready, it needs no credentials, the scoreboard's
evidence exists, the investigation runs bounded and executes nothing, and
authorisation is enforced by the API rather than the UI.

One implementation, called by `scripts/verify.sh`, `scripts/verify.ps1` and CI.
It used to be three inline copies; the CI one was a heredoc inside YAML, which
did not parse and failed the workflow in 0s before any job started.

Run:
    ./.venv/Scripts/python.exe -m scripts.smoke_api
"""
from __future__ import annotations

import sys
import warnings

warnings.filterwarnings("ignore")


def main() -> int:
    from fastapi.testclient import TestClient

    from api.main import app

    c = TestClient(app)

    assert c.get("/api/health").json()["ok"] is True

    ready = c.get("/api/readiness").json()
    assert ready["ready"], f"not ready: {ready['missing_required']}"

    caps = c.get("/api/capabilities").json()
    assert caps["keys_required"] == [], caps["keys_required"]
    assert caps["capabilities"]["llm"]["provider"] == "none"

    board = c.get("/api/scoreboard").json()
    assert board["summary"]["missing_reports"] == [], board["summary"]["missing_reports"]

    r = c.post("/api/investigate", json={"scenario": "aiims_ransomware"},
               headers={"X-Role": "analyst", "X-Actor": "smoke@ci"})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["ok"] and b["action"]["executed"] == 0
    nodes = [n["node"] for n in b["trace"]["nodes"]]
    assert nodes[0] == "understand" and nodes[-1] == "action", nodes
    assert nodes.count("evidence") <= 2, "replan is not bounded"

    # authorisation must be enforced by the server, not by hiding a button
    assert c.post("/api/investigate", json={"scenario": "aiims_ransomware"},
                  headers={"X-Role": "viewer"}).status_code == 403
    assert c.get("/api/audit/verify", headers={"X-Role": "viewer"}).json()["verified"]

    print(f"   smoke ok: {len(nodes)} node runs in {b['trace']['total_ms']:.0f} ms, "
          f"{board['summary']['measured']} measured metrics, "
          f"{len(b['evidence'].get('citations', []))} citations, 0 actions executed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
