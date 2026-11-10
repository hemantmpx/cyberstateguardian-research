#!/usr/bin/env python3
"""Render selected diagram Markdown walkthroughs as Word documents."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS = ROOT / "docs" / "diagrams"
DEFAULT_NAMES = (
    "system-architecture",
    "telemetry-reconciliation-flow",
    "research-experiment-workflow",
)


def add_inline_runs(paragraph, text: str) -> None:
    token = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))")
    cursor = 0
    for match in token.finditer(text):
        paragraph.add_run(text[cursor : match.start()])
        value = match.group(0)
        if value.startswith("**"):
            run = paragraph.add_run(value[2:-2])
            run.bold = True
        elif value.startswith("`"):
            run = paragraph.add_run(value[1:-1])
            run.font.name = "Menlo"
            run.font.size = Pt(9)
        else:
            label, target = re.match(r"\[([^\]]+)\]\(([^)]+)\)", value).groups()
            run = paragraph.add_run(f"{label} ({target})")
            run.font.color.rgb = RGBColor(35, 96, 137)
        cursor = match.end()
    paragraph.add_run(text[cursor:])


def parse_table_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def add_markdown_table(document: Document, rows: list[str]) -> None:
    values = [parse_table_row(row) for row in rows]
    values = [row for row in values if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in row)]
    if not values:
        return
    width = max(map(len, values))
    table = document.add_table(rows=1, cols=width)
    table.style = "Light Shading Accent 1"
    table.autofit = True
    for row_index, row in enumerate(values):
        cells = table.rows[0].cells if row_index == 0 else table.add_row().cells
        for col_index in range(width):
            cell = cells[col_index]
            cell.text = ""
            paragraph = cell.paragraphs[0]
            add_inline_runs(paragraph, row[col_index] if col_index < len(row) else "")
            if row_index == 0:
                for run in paragraph.runs:
                    run.bold = True


def render(markdown_path: Path, image_dir: Path) -> Path:
    document = Document()
    section = document.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.65)
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)
    normal = document.styles["Normal"]
    normal.font.name = "Aptos"
    normal.font.size = Pt(10)
    for style_name, size, color in (
        ("Title", 25, "174A63"),
        ("Heading 1", 19, "174A63"),
        ("Heading 2", 14, "147D78"),
        ("Heading 3", 11, "37566B"),
    ):
        style = document.styles[style_name]
        style.font.name = "Aptos Display"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor.from_string(color)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer.add_run("CyberStateGuardian | Architecture walkthrough").font.size = Pt(8)

    lines = markdown_path.read_text(encoding="utf-8").splitlines()
    index = 0
    in_code = False
    while index < len(lines):
        line = lines[index].strip()
        if line.startswith("```"):
            in_code = not in_code
            index += 1
            continue
        if in_code:
            paragraph = document.add_paragraph()
            paragraph.paragraph_format.left_indent = Inches(0.25)
            run = paragraph.add_run(lines[index])
            run.font.name = "Menlo"
            run.font.size = Pt(9)
            index += 1
            continue
        if not line or line == "---":
            index += 1
            continue
        if line.startswith("| ") or line.startswith("|"):
            table_rows = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_rows.append(lines[index].strip())
                index += 1
            add_markdown_table(document, table_rows)
            continue
        image_match = re.match(r"!\[[^]]*\]\(([^)]+)\)", line)
        if image_match:
            stem = Path(image_match.group(1)).stem
            image_path = image_dir / f"{stem}.png"
            if image_path.is_file():
                paragraph = document.add_paragraph()
                paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
                paragraph.add_run().add_picture(str(image_path), width=Inches(6.4))
            index += 1
            continue
        if line.startswith("### "):
            paragraph = document.add_heading(level=3)
            add_inline_runs(paragraph, line[4:])
        elif line.startswith("## "):
            paragraph = document.add_heading(level=2)
            add_inline_runs(paragraph, line[3:])
        elif line.startswith("# "):
            paragraph = document.add_paragraph(style="Title")
            add_inline_runs(paragraph, line[2:])
        elif line.startswith("- "):
            parts = [line[2:]]
            next_index = index + 1
            while (
                next_index < len(lines)
                and lines[next_index].startswith("  ")
                and lines[next_index].strip()
            ):
                parts.append(lines[next_index].strip())
                next_index += 1
            paragraph = document.add_paragraph(style="List Bullet")
            add_inline_runs(paragraph, " ".join(parts))
            index = next_index
            continue
        elif re.match(r"\d+\. ", line):
            parts = [re.sub(r"^\d+\. ", "", line)]
            next_index = index + 1
            while (
                next_index < len(lines)
                and lines[next_index].startswith("  ")
                and lines[next_index].strip()
            ):
                parts.append(lines[next_index].strip())
                next_index += 1
            paragraph = document.add_paragraph(style="List Number")
            add_inline_runs(paragraph, " ".join(parts))
            index = next_index
            continue
        elif line.startswith("> "):
            paragraph = document.add_paragraph(style="Quote")
            add_inline_runs(paragraph, line[2:])
        else:
            parts = [line]
            next_index = index + 1
            while next_index < len(lines):
                candidate = lines[next_index].strip()
                if (
                    not candidate
                    or candidate == "---"
                    or candidate.startswith(("# ", "## ", "### ", "```", "|", "![", "- ", "> "))
                    or re.match(r"\d+\. ", candidate)
                ):
                    break
                parts.append(candidate)
                next_index += 1
            paragraph = document.add_paragraph()
            add_inline_runs(paragraph, " ".join(parts))
            index = next_index
            continue
        index += 1

    output_path = markdown_path.with_suffix(".docx")
    document.core_properties.title = markdown_path.stem.replace("-", " ").title()
    document.core_properties.subject = "CyberStateGuardian research architecture"
    document.save(output_path)
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", type=Path, default=Path("/tmp/csg-architecture-diagrams"))
    parser.add_argument("names", nargs="*", default=DEFAULT_NAMES)
    args = parser.parse_args()
    for name in args.names:
        source = DIAGRAMS / f"{name}-explained.md"
        if not source.is_file():
            parser.error(f"Missing Markdown explanation: {source}")
        output = render(source, args.image_dir)
        print(output.relative_to(ROOT))


if __name__ == "__main__":
    main()
