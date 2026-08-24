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

    drift = _dark_blocks_agree()
    if drift:
        print(f"{len(drift)} token(s) differ between the two dark palettes:\n")
        for d in drift:
            print(f"  {d}")
        print("\nPlain CSS cannot share one block between a media query and an\n"
              "attribute selector, so the dark palette is written twice. A token\n"
              "changed in one and not the other means the theme toggle and the OS\n"
              "setting disagree -- which is how a contrast fix landed in the media\n"
              "query, missed the attribute block, and appeared to do nothing.")
        return 1

    print(f"css tokens ok: {len(defined)} defined, every bare var() resolves, "
          "both dark palettes agree")
    return 0


def _dark_blocks_agree() -> list[str]:
    """The two dark palettes must define the same tokens with the same values.

    There is no light equivalent to check: the light palette exists once, on
    :root, because the dark media rule is scoped `:not([data-theme="light"])`
    and an explicit light choice falls through to it.
    """
    theme = (ROOT / "frontend/src/theme.css").read_text(encoding="utf-8")

    def block(start: str) -> dict[str, str]:
        i = theme.find(start)
        if i < 0:
            return {}
        body = theme[i + len(start):theme.index("}", i + len(start))]
        # Comments first, then split. A comment can contain a semicolon --
        # "3.62:1; now 5.38" did -- and splitting first tears it in half, which
        # made this check report the NEXT token as missing.
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        out = {}
        for decl in body.split(";"):
            decl = decl.strip()
            if decl.startswith("--") and ":" in decl:
                k, v = decl.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    media = block('@media (prefers-color-scheme:dark){ :root:not([data-theme="light"]){')
    attr = block(':root[data-theme="dark"]{')
    if not media or not attr:
        return ["could not find both dark blocks in theme.css"]

    out = []
    for k in sorted(set(media) | set(attr)):
        a, b = media.get(k), attr.get(k)
        if a != b:
            out.append(f"{k}: media says {a or '(missing)'}, "
                       f"[data-theme=dark] says {b or '(missing)'}")
    return out


if __name__ == "__main__":
    sys.exit(main())
