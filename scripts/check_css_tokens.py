"""Every CSS custom property the frontend uses must be defined somewhere.

An undefined custom property does not raise, warn, or show up in a build. It
resolves to nothing: `background: var(--surface-sunken)` on an undefined token is
a transparent background, and `border: 1px solid var(--border-soft)` is no border
at all. In both themes, forever, until someone opens the screen and squints.

Four of these shipped before anyone noticed. `--text-muted`, `--surface-raised`
and `--border-soft` were used in 13 places across four screens and had never been
defined in any palette. `--surface-sunken` was used in nine more, including the
Digital Twin chat, where it made assistant bubbles invisible against the page.
The commit that fixed the first three introduced a comment congratulating itself
and did not catch the fourth.

This runs against the SOURCE rather than the build, so it fails before a bundle
is produced and names the file and line.

Run:
    python -m scripts.check_css_tokens
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "frontend" / "src"

DEFINE = re.compile(r"--([a-zA-Z0-9-]+)\s*:")
USE = re.compile(r"var\(\s*--([a-zA-Z0-9-]+)\s*(,|\))")

# A `var(--x, fallback)` is legitimate: the fallback is the definition. Only
# bare uses are errors.
USE_BARE = re.compile(r"var\(\s*--([a-zA-Z0-9-]+)\s*\)")


def _files() -> list[Path]:
    return sorted(
        [p for p in SRC.rglob("*.css")]
        + [p for p in SRC.rglob("*.jsx")]
        + [p for p in SRC.rglob("*.js")]
    )


def main() -> int:
    defined: set[str] = set()
    for path in _files():
        for m in DEFINE.finditer(path.read_text(encoding="utf-8")):
            defined.add(m.group(1))

    problems: list[str] = []
    for path in _files():
        for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            for m in USE_BARE.finditer(line):
                tok = m.group(1)
                if tok not in defined:
                    rel = path.relative_to(ROOT)
                    problems.append(f"{rel}:{i}  var(--{tok}) is never defined")

    if problems:
        print(f"{len(problems)} undefined CSS custom propert"
              f"{'y' if len(problems) == 1 else 'ies'}:\n")
        for p in problems:
            print(f"  {p}")
        print("\nAn undefined property resolves to nothing: transparent "
              "backgrounds, absent borders, inherited text colour.")
        print("Define it in frontend/src/theme.css, or give the use a fallback.")
        return 1

    print(f"css tokens ok: {len(defined)} defined, every bare var() resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
