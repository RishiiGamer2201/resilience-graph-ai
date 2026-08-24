"""Render docs/PITCH_BRIEF.md to a readable PDF.

Built for reading on a phone or a laptop on a plane: generous leading, real
tables, and no dependency on a browser or a network.
"""
import pathlib
import re
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

ROOT = pathlib.Path(r"c:\developer\hackathons\ET_HACK_26")
SRC = ROOT / "docs" / "PITCH_BRIEF.md"
OUT = ROOT / "docs" / "nextATTACKs-Pitch-Brief.pdf"

INK = colors.HexColor("#14202e")
DIM = colors.HexColor("#4a5768")
FAINT = colors.HexColor("#7b8798")
ACCENT = colors.HexColor("#1f5bd7")
RULE = colors.HexColor("#d7dee9")
BG = colors.HexColor("#f4f7fb")
CRIT = colors.HexColor("#c0392b")

ss = getSampleStyleSheet()


def st(name, **kw):
    base = dict(fontName="Helvetica", fontSize=9.5, leading=14, textColor=INK,
                alignment=TA_LEFT, spaceAfter=6)
    base.update(kw)
    return ParagraphStyle(name, **base)


S = {
    "h1": st("h1", fontName="Helvetica-Bold", fontSize=19, leading=23,
             textColor=INK, spaceBefore=4, spaceAfter=10),
    "h2": st("h2", fontName="Helvetica-Bold", fontSize=13.5, leading=17,
             textColor=INK, spaceBefore=14, spaceAfter=6),
    "h3": st("h3", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
             textColor=ACCENT, spaceBefore=10, spaceAfter=4),
    "p": st("p"),
    "li": st("li", leftIndent=11, bulletIndent=2, spaceAfter=3),
    "quote": st("quote", fontName="Helvetica-Oblique", fontSize=10, leading=15,
                textColor=ACCENT, leftIndent=10, spaceBefore=6, spaceAfter=8),
    "code": st("code", fontName="Courier", fontSize=7.6, leading=10,
               textColor=DIM, leftIndent=8, spaceBefore=4, spaceAfter=8),
    "cell": st("cell", fontSize=8.4, leading=11.5, spaceAfter=0),
    "cellh": st("cellh", fontName="Helvetica-Bold", fontSize=8, leading=11,
                textColor=DIM, spaceAfter=0),
    "cover_t": st("cover_t", fontName="Helvetica-Bold", fontSize=30, leading=34,
                  spaceAfter=4),
    "cover_s": st("cover_s", fontSize=12, leading=17, textColor=DIM, spaceAfter=16),
}

INLINE = [
    (re.compile(r"\*\*(.+?)\*\*"), r"<b>\1</b>"),
    (re.compile(r"(?<!\*)\*([^*]+?)\*(?!\*)"), r"<i>\1</i>"),
    (re.compile(r"`(.+?)`"), r'<font face="Courier" size="8.4">\1</font>'),
]


def inline(t: str) -> str:
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for pat, rep in INLINE:
        t = pat.sub(rep, t)
    return t


def build_table(rows: list[list[str]]):
    if not rows:
        return None
    head, body = rows[0], rows[1:]
    ncols = max(len(r) for r in rows)
    data = [[Paragraph(inline(c), S["cellh"]) for c in head + [""] * (ncols - len(head))]]
    for r in body:
        data.append([Paragraph(inline(c), S["cell"]) for c in r + [""] * (ncols - len(r))])

    avail = 170 * mm
    first = min(0.42, max(0.22, 1.6 / ncols))
    widths = [avail * first] + [avail * (1 - first) / (ncols - 1)] * (ncols - 1) \
        if ncols > 1 else [avail]

    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BG),
        ("LINEBELOW", (0, 0), (-1, 0), 0.7, RULE),
        ("LINEBELOW", (0, 1), (-1, -2), 0.3, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.4, RULE),
    ]))
    return t


def parse(md: str):
    flow = []
    lines = md.split("\n")
    i = 0
    in_code = False
    code: list[str] = []
    table: list[list[str]] = []

    def flush_table():
        nonlocal table
        if table:
            t = build_table(table)
            if t:
                flow.append(Spacer(1, 3))
                flow.append(t)
                flow.append(Spacer(1, 8))
            table = []

    while i < len(lines):
        ln = lines[i]

        if ln.strip().startswith("```"):
            if in_code:
                flow.append(Paragraph(
                    "<br/>".join(
                        c.replace("&", "&amp;").replace("<", "&lt;")
                         .replace(">", "&gt;").replace(" ", "&nbsp;")
                        for c in code),
                    S["code"]))
                code, in_code = [], False
            else:
                flush_table()
                in_code = True
            i += 1
            continue
        if in_code:
            code.append(ln)
            i += 1
            continue

        if ln.lstrip().startswith("|") and ln.count("|") >= 2:
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if not all(set(c) <= set("-: ") and c for c in cells):
                table.append(cells)
            i += 1
            continue
        flush_table()

        s = ln.strip()
        if not s:
            i += 1
            continue

        if s.startswith("# "):
            if any(isinstance(f, (Paragraph, Table)) for f in flow):
                flow.append(PageBreak())
            flow.append(Paragraph(inline(s[2:]), S["h1"]))
            flow.append(HRFlowable(width="100%", thickness=1.1, color=ACCENT,
                                   spaceAfter=10))
        elif s.startswith("## "):
            flow.append(Paragraph(inline(s[3:]), S["h2"]))
        elif s.startswith("### "):
            flow.append(Paragraph(inline(s[4:]), S["h3"]))
        elif s.startswith("> "):
            flow.append(Paragraph(inline(s[2:]), S["quote"]))
        elif re.match(r"^[-*] ", s):
            flow.append(Paragraph(inline(s[2:]), S["li"], bulletText="\u2022"))
        elif re.match(r"^\d+\. ", s):
            n, rest = s.split(". ", 1)
            flow.append(Paragraph(inline(rest), S["li"], bulletText=f"{n}."))
        elif set(s) <= set("-") and len(s) >= 3:
            flow.append(HRFlowable(width="100%", thickness=0.4, color=RULE,
                                   spaceBefore=4, spaceAfter=8))
        else:
            flow.append(Paragraph(inline(s), S["p"]))
        i += 1

    flush_table()
    return flow


def cover():
    return [
        Spacer(1, 52 * mm),
        Paragraph("nextATT&amp;CKs", S["cover_t"]),
        Paragraph("Pitch Brief — everything, basic to advanced", S["cover_s"]),
        HRFlowable(width="55%", thickness=2, color=ACCENT, spaceAfter=14),
        Paragraph("ET AI Hackathon 2026", st("x", fontSize=11, textColor=INK)),
        Paragraph("Problem Statement 7 — AI-Driven Cyber Resilience for "
                  "Critical National Infrastructure",
                  st("x2", fontSize=10, textColor=DIM, spaceAfter=22)),
        Paragraph("Every figure in this brief is produced by an evaluation "
                  "script in the repository. Nothing is rounded up and nothing "
                  "is aspirational. Where something was not measured, this "
                  "document says so in the same words the product does.",
                  st("note", fontSize=9.5, leading=14, textColor=DIM)),
        Spacer(1, 10),
        Paragraph("Read Part 13 first if you are short of time.",
                  st("tip", fontSize=9.5, textColor=CRIT,
                     fontName="Helvetica-Bold")),
        PageBreak(),
    ]


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(FAINT)
    if doc.page > 1:
        canvas.drawString(20 * mm, 12 * mm, "nextATT&CKs — Pitch Brief · PS7")
        canvas.drawRightString(190 * mm, 12 * mm, str(doc.page))
    canvas.restoreState()


def main() -> int:
    md = SRC.read_text(encoding="utf-8")
    doc = SimpleDocTemplate(
        str(OUT), pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=20 * mm,
        title="nextATT&CKs — Pitch Brief",
        author="nextATT&CKs", subject="ET AI Hackathon 2026, PS7",
    )
    doc.build(cover() + parse(md), onFirstPage=footer, onLaterPages=footer)
    kb = OUT.stat().st_size // 1024
    print(f"wrote {OUT.relative_to(ROOT)} ({kb} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
