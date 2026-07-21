"""
Convert the supplied colour figures to monochrome for the submission document.

The document is specified as single black colour. My own figures were restyled
at the source (their HTML is in this repo). These two arrived as flat PNGs with
no source, so the conversion happens on the pixels instead.

Deliberately grayscale rather than pure black and white: both figures use white
text on mid-tone fills (the 01..04 plane pills, the table header row). Hard
thresholding pushes those fills to white and the white text vanishes with them.
Grayscale removes all colour while keeping every label readable.

    ./.venv/Scripts/python.exe -m scripts.mono_figures
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageEnhance

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "reports" / "doc"

JOBS = [
    ("technical_architecture_final.png", "architecture_mono.png"),
    ("scaling_chart_detailed.png", "scaling_mono.png"),
]


def convert(src: Path, dst: Path) -> None:
    im = Image.open(src).convert("RGB")
    gray = im.convert("L")
    # mild contrast lift so mid-tone fills separate from black rules and text,
    # without crushing the white-on-fill labels
    gray = ImageEnhance.Contrast(gray).enhance(1.18)
    gray.save(dst, optimize=True)
    print(f"{src.name} -> {dst.relative_to(ROOT)}  {gray.size[0]}x{gray.size[1]}")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for src_name, dst_name in JOBS:
        src = ROOT / "reports" / src_name
        if not src.exists():
            raise SystemExit(f"missing source figure: {src}")
        convert(src, OUT_DIR / dst_name)


if __name__ == "__main__":
    main()
