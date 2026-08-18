"""Static check: every Dockerfile COPY source exists and survives .dockerignore.

This exists because of a real bug. The Dockerfile never copied
`models/ae_lanl.npz`, so the deployed container silently fell back to the
IsolationForest and scored differently from the build we measured — a failure
that produces no error, only quietly worse numbers on stage.

`docker build` would catch a missing source, but only when a daemon is available.
This runs anywhere, in a second, and also catches the subtler mistake: a file that
exists but is excluded by `.dockerignore`, which `docker build` reports as a
confusing "file not found".

Run:
    ./.venv/Scripts/python.exe -m scripts.check_dockerfile
"""
from __future__ import annotations

import re
import sys
from fnmatch import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"


def parse_dockerignore() -> tuple[list[str], list[str]]:
    """Return (exclude patterns, re-include patterns) in file order."""
    excludes: list[str] = []
    includes: list[str] = []
    if not DOCKERIGNORE.exists():
        return excludes, includes
    for raw in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        (includes if line.startswith("!") else excludes).append(line.lstrip("!"))
    return excludes, includes


def _matches(path: str, pattern: str) -> bool:
    """Docker-ish match: a pattern also matches everything beneath it."""
    return fnmatch(path, pattern) or fnmatch(path, pattern.rstrip("/") + "/*") \
        or path.startswith(pattern.rstrip("/") + "/")


def ignored(path: str, excludes: list[str], includes: list[str]) -> bool:
    """Last matching rule wins, and a `!` rule re-includes."""
    result = False
    for pat in excludes:
        if _matches(path, pat):
            result = True
    for pat in includes:
        if _matches(path, pat) or pat.startswith(path.rstrip("/") + "/"):
            result = False
    return result


def copy_sources() -> list[tuple[int, str]]:
    """Every host-side source in a COPY that is not `--from=` a build stage."""
    out: list[tuple[int, str]] = []
    for n, raw in enumerate(DOCKERFILE.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not re.match(r"^COPY\s", line, re.I):
            continue
        parts = line.split()[1:]
        if any(p.startswith("--from=") for p in parts):
            continue                       # produced by an earlier build stage
        parts = [p for p in parts if not p.startswith("--")]
        if len(parts) < 2:
            continue
        for src in parts[:-1]:             # last token is the destination
            out.append((n, src))
    return out


def main() -> int:
    if not DOCKERFILE.exists():
        print(f"no Dockerfile at {DOCKERFILE}")
        return 1
    excludes, includes = parse_dockerignore()
    problems: list[str] = []
    checked = 0

    for line_no, src in copy_sources():
        checked += 1
        path = ROOT / src
        if not path.exists():
            problems.append(f"Dockerfile:{line_no}: COPY source does not exist: {src}")
            continue
        rel = src.rstrip("/")
        if ignored(rel, excludes, includes):
            problems.append(
                f"Dockerfile:{line_no}: COPY source '{src}' exists but .dockerignore "
                f"excludes it — the build will fail with a confusing 'not found'")

    # The artifacts the runtime genuinely needs must be inside the image, not just
    # present on the developer's disk.
    must_ship = [
        "models/ae_lanl.npz",
        "models/next_technique_markov.pkl",
        "data/processed/mitre_attack/attack_lookups.pkl",
        "data/processed/evidence/index.json.gz",
        "configs/vuln_priority.json",
        "reports/metrics.json",
        "api/cache/score_ref.json",
    ]
    copied = {s for _, s in copy_sources()}
    for need in must_ship:
        if any(need == c or need.startswith(c.rstrip("/") + "/") for c in copied):
            continue
        problems.append(f"required runtime artifact is never COPYed into the image: {need}")

    if problems:
        for p in problems:
            print(f"  FAIL {p}")
        return 1
    print(f"dockerfile ok: {checked} COPY sources exist and survive .dockerignore; "
          f"{len(must_ship)} required runtime artifacts are in the image")
    return 0


if __name__ == "__main__":
    sys.exit(main())
