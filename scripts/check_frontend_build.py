"""
Guard against a build that silently ships the wrong app.

During the TypeScript migration `npm run build` produced the OLD JSX app for a
while and said nothing. `main.tsx` imports `@/App` with no extension, and Vite's
default `resolve.extensions` puts `.jsx` ahead of `.tsx`, so every extensionless
import resolved to the pre-redesign file while both existed. `@/App` ->
`App.jsx`, `@/components/Layout` -> `Layout.jsx`, and so on down the tree. No
error, no warning: the entire redesign was dead code in a green build.

That is the worst class of build bug, because every signal says success. These
checks are cheap and they fail loudly.

    python -m scripts.check_frontend_build
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
SRC = FRONTEND / "src"
DIST = FRONTEND / "dist"


def fail(msg: str) -> None:
    print(f"  FAIL  {msg}")
    fail.count += 1  # type: ignore[attr-defined]


fail.count = 0  # type: ignore[attr-defined]


def check_extension_order() -> None:
    """`.ts`/`.tsx` must resolve before `.js`/`.jsx`.

    Only matters while both exist side by side, which is exactly when it is
    dangerous and exactly when nobody is looking for it.
    """
    cfg = FRONTEND / "vite.config.ts"
    if not cfg.exists():
        fail("frontend/vite.config.ts is missing")
        return
    text = cfg.read_text(encoding="utf-8")
    m = re.search(r"extensions:\s*\[([^\]]+)\]", text)
    if not m:
        fail("vite.config.ts does not pin resolve.extensions; a .jsx file can "
             "shadow its .tsx replacement and the build will not say so")
        return
    exts = [e.strip().strip("'\"") for e in m.group(1).split(",") if e.strip()]
    for ts, js in ((".ts", ".js"), (".tsx", ".jsx")):
        if ts in exts and js in exts and exts.index(ts) > exts.index(js):
            fail(f"resolve.extensions puts {js} before {ts}: {exts}")
    print(f"  ok    resolve.extensions pins TypeScript first: {exts}")


def check_no_shadowed_modules() -> None:
    """No module may exist as both .jsx and .tsx (or .js and .ts).

    Whichever the bundler picks, one of the two is a stale copy nobody is
    editing, and a reader cannot tell which is live.
    """
    shadowed: list[str] = []
    for tsx in list(SRC.rglob("*.tsx")) + list(SRC.rglob("*.ts")):
        if tsx.name.endswith(".d.ts"):
            continue
        twin = tsx.with_suffix(".jsx" if tsx.suffix == ".tsx" else ".js")
        if twin.exists():
            shadowed.append(str(twin.relative_to(FRONTEND)))
    if shadowed:
        fail("these modules exist as BOTH TypeScript and JavaScript; delete the "
             "stale copy:\n        " + "\n        ".join(sorted(shadowed)))
    else:
        print("  ok    no module exists as both .tsx and .jsx")


def check_entry_is_typescript() -> None:
    html = FRONTEND / "index.html"
    if not html.exists():
        fail("frontend/index.html is missing")
        return
    text = html.read_text(encoding="utf-8")
    if "/src/main.tsx" not in text:
        fail("index.html does not load /src/main.tsx")
    else:
        print("  ok    index.html loads the TypeScript entry")


def check_build_output() -> None:
    """The built bundle must contain the app we think we built.

    Skipped when dist/ is absent, so this runs the same in a fresh clone.
    """
    if not DIST.exists():
        print("  skip  frontend/dist not built")
        return
    js = list((DIST / "assets").glob("*.js")) if (DIST / "assets").exists() else []
    if not js:
        fail("frontend/dist has no JS assets")
        return
    blob = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in js)

    # A marker only the pre-redesign app contained. Its presence means the old
    # tree was bundled.
    if "login-card" in blob:
        fail("the built bundle contains markers from the pre-redesign JSX app; "
             "an extensionless import resolved to a .jsx file")
    else:
        print("  ok    the bundle carries no pre-redesign markers")

    stubs = blob.count("not yet ported")
    if stubs:
        print(f"  note  {stubs} screen(s) still render the port placeholder")


def check_no_hardcoded_fallbacks() -> None:
    """The two fabricated fallbacks removed in the port must stay removed.

    `predictNext` used to answer with five constant ATT&CK techniques when the
    backend was unreachable, and `scoreEvent` with a hand-tuned formula standing
    in for the trained detector. Both rendered as confident answers nobody had
    computed. If either comes back, this fails.
    """
    api = SRC / "lib" / "api.ts"
    if not api.exists():
        fail("frontend/src/lib/api.ts is missing")
        return
    # Strip comments first. The file DESCRIBES both removals in its header, and
    # a check that cannot tell prose from code fails on the documentation of the
    # very thing it is guarding.
    text = _strip_comments(api.read_text(encoding="utf-8"))
    for banned, why in (
        ("FALLBACK_NEXT", "the hardcoded next-technique list"),
        ("live: false", "the live:false flag that labelled invented data"),
        ("live:false", "the live:false flag that labelled invented data"),
    ):
        if banned in text:
            fail(f"api.ts code contains {banned}: {why} is back")
    print("  ok    api.ts has no fabricated fallback in code")


def _strip_comments(src: str) -> str:
    """Remove /* */ and // comments. Crude, and good enough: it only has to
    stop a docstring about a removed fallback reading as the fallback."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"^\s*//.*$", "", src, flags=re.M)


def main() -> int:
    print("frontend build integrity")
    check_extension_order()
    check_no_shadowed_modules()
    check_entry_is_typescript()
    check_no_hardcoded_fallbacks()
    check_build_output()
    n = fail.count  # type: ignore[attr-defined]
    print("PASS" if not n else f"FAILED with {n} problem(s)")
    return 1 if n else 0


if __name__ == "__main__":
    sys.exit(main())
