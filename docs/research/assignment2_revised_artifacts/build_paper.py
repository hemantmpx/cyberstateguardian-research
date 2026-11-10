"""Build the Assignment 2 paper from retained evidence; no live endpoint access.

Requires python-docx, matplotlib, reportlab and PyMuPDF.
Run from any directory: python path/to/build_paper.py
"""

from pathlib import Path
import csv
import hashlib
import html
import json
import math
import re
from datetime import datetime
from statistics import median

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from docx import Document
from docx.enum.section import WD_SECTION_START
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
import pymupdf as fitz
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, KeepTogether, PageTemplate, Paragraph,
    Spacer, Table, TableStyle, PageBreak, NextPageTemplate,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE.parent
STEM = "Assignment530_CyberStateGuardian_Methodology_Results_Revised"
FIG = HERE / "figures"
FIG.mkdir(exist_ok=True)
TEMPLATE = (HERE / "manuscript.template.md").read_text()
REFS = json.loads((HERE / "references.json").read_text())
SOURCES = {}


def read_source(relative):
    path = ROOT / relative
    raw = path.read_bytes()
    SOURCES[relative] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return json.loads(raw)


RUNS = "experiments/results/runs/"
BASE8 = RUNS + "20261008/windows-apt-paired-20261008T022048Z/"
norm = read_source(BASE8 + "dataset/v3/normalization-coverage.json")
reg7 = read_source(RUNS + "20261007/wazuh-fim-csg-registry-comparison-v3-verified-10s/fim-evidence-and-analysis.json")
reg8 = read_source(BASE8 + "analysis/holdout-r1-audited/aggregate.json")
replay = read_source(BASE8 + "replay/holdout-r1-v4/aggregate.json")
service = read_source(RUNS + "20261010/reconciliation-confirmatory/samehost-distractor-v1/comparison/evaluation/aggregate.json")
dwell = read_source(RUNS + "20261011/transition-capture/service-dwell-response-pooled-v1/analysis/pooled-summary.json")
task = read_source(RUNS + "20261012/scheduled-task-distractor-confirmatory-v3/analysis.json")
control = read_source(RUNS + "20261012/scheduled-task-no-change-control/analysis/v6/audit.json")
omission = read_source(RUNS + "20261012/scheduled-task-eventid-filter-confirmatory-v2/analysis.json")
omission3 = read_source(RUNS + "20261012/scheduled-task-eventid-filter-confirmatory-v3/analysis.json")
lifecycle = read_source("docs/research/assignment2_revised_artifacts/lifecycle_plot_data.json")
fixtures = read_source(RUNS + "20261004/transition-capture-fixtures/transition-fixtures-20261004T182921Z-f677546b/aggregate.json")
task_replay = read_source(RUNS + "20261011/reconciliation-calibration/pilot/scheduled-task-complete-distractor-extension-v10/replay/paired-task-distractor-v1/analysis/analysis.json")
positive_audit = read_source(RUNS + "20261012/positive-control-telemetry-coverage-audit-v1/coverage.json")
historical_service = read_source(RUNS + "20261005/service-confirmatory-holdout-v3/analysis.json")
historical_registry = read_source(RUNS + "20261005/registry-reconciliation-confirmatory-holdout-v1/analysis/analysis.json")

assert norm["dataset"]["event_count"] == 102011
assert norm["normalization"]["semantic_events"] == 23069
assert norm["normalization"]["generic_dataset_events"] == 78942
assert sum(norm["normalization"]["counts_by_type"].values()) == 102011
assert reg7["trial_count"] == 30
assert reg7["summary"]["registry_complete"]["exact_target_fim_at_decision"] == 6
assert all(x["analysis_passed"] == 10 for x in reg8["conditions"].values())
assert len(replay["conditions"]) == 9
assert all(x["passed"] == 10 and x["failed"] == 0 for x in replay["conditions"].values())
assert task["intention_to_treat"]["pass"] == 10
assert task["evaluable_trial_metrics"]["false_distractor_citations"] == 0
assert control["audited_passes"] == 10
assert omission["assigned_trials"] == 10 and omission["trials_passing_all_gates"] == 9
assert omission["latency_summaries"]["reconciliation_finalization"]["median_seconds"] == 5327.7188
assert omission3["assigned_trials"] == 10 and omission3["trials_passing_all_gates"] == 10
assert omission3["campaign_controller_status"] == "COMPLETED_WITH_VALIDITY_GAPS"
for entry in lifecycle["sha256_ledger"]:
    assert hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
for cohort_key, expected_n in [("v2", 9), ("v3", 10)]:
    cohort = lifecycle["cohorts"][cohort_key]
    assert cohort["assigned_n"] == 10
    assert cohort["finalized_unexplained_n"] == expected_n
    assert cohort["controller_status"] == "COMPLETED_WITH_VALIDITY_GAPS"
    assert cohort["analysis_preregistered"] is False
    for row in cohort["trial_rows"]:
        for kind in ("runner", "wrapper"):
            provenance = row["provenance"]
            assert hashlib.sha256((ROOT / provenance[kind]).read_bytes()).hexdigest() == provenance[kind + "_sha256"]
        for endpoint in ("first", "latest"):
            timestamps = row["timestamps"]
            interval = row["intervals_seconds"][f"evidence_deadline_to_{endpoint}_final_seconds"]
            if interval is not None:
                final = datetime.fromisoformat(timestamps[f"{endpoint}_final_at"].replace("Z", "+00:00"))
                deadline = datetime.fromisoformat(timestamps[f"{endpoint}_final_evidence_deadline"].replace("Z", "+00:00"))
                assert math.isclose((final - deadline).total_seconds(), interval, abs_tol=0.00001)
                history = [v for v in row["reconciliation_history"] if v["finalized"]]
                selected = min(history, key=lambda v: v["finalized_at"]) if endpoint == "first" else max(history, key=lambda v: v["finalized_at"])
                assert selected["version"] == timestamps[f"{endpoint}_final_version"]
def lifecycle_median(cohort_key, metric):
    values = [r["intervals_seconds"][metric] for r in lifecycle["cohorts"][cohort_key]["trial_rows"] if r["intervals_seconds"][metric] is not None]
    return median(values)
assert math.isclose(lifecycle_median("v2", "evidence_deadline_to_first_final_seconds"), 401.018072, abs_tol=0.00001)
assert math.isclose(lifecycle_median("v2", "evidence_deadline_to_latest_final_seconds"), 5327.718780, abs_tol=0.00001)
assert math.isclose(lifecycle_median("v3", "evidence_deadline_to_first_final_seconds"), 251.2408, abs_tol=0.0001)
assert lifecycle["cohorts"]["v3"]["controller_wait_actual_seconds"] == 0.032108
assert fixtures["passed"] == 21 and fixtures["failed"] == 0
assert task_replay["eligible_live_parents"] == 10
assert len(task_replay["conditions"]) == 6
assert all(x["passed"] == 10 for x in task_replay["conditions"].values())
assert historical_service["trial_count_with_artifacts"] == 30
assert historical_service["conditions"]["complete"]["metrics"]["csg_exact_consistent_add_and_modify"]["successes"] == 10
assert historical_registry["assigned_trials"] == 90
assert all(x["outcome"]["successes"] == 30 for x in historical_registry["condition_outcomes"].values())
assert positive_audit["families"]["service_start_mode"]["csg_exact_target_reconciliation"]["successes"] == 5
assert positive_audit["families"]["scheduled_task_creation"]["csg_finalized_exact_target_reconciliation"]["successes"] == 5


def wilson(k, n):
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    center = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, center - half), min(1, center + half)


method = {x["method"]: x for x in service["method_summaries"] if x.get("session_id") is None}
assert len(method) == 6
assert method["full_csg"]["target_detection_correct"]["successes"] == 20
assert method["full_csg"]["false_corroboration"]["successes"] == 0
assert method["loose_host_type_time_matcher"]["false_corroboration"]["successes"] == 20
assert method["strong_identity_matcher"]["false_corroboration"]["successes"] == 0

BLUE = "#1b4965"
from render_results import build_exhibits
TABLES, CAPTIONS, FIGFILES = build_exhibits(HERE,norm,reg7,reg8,service,dwell,task,control,omission,omission3,lifecycle)
curve=dwell["pooled_dwell_capture"]
for key,spec in TABLES.items():
    with (HERE/(key.lower()+".csv")).open("w",newline="") as handle:
        writer=csv.writer(handle);writer.writerow(spec["headers"]);writer.writerows(spec["rows"])


def plain(s):
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", s)
    return s.replace("**", "").replace("*", "")


def rich(s):
    s = html.escape(s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<link href="\2" color="#1b4965">\1</link>', s)
    s = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"\*(.*?)\*", r"<i>\1</i>", s)
    # Use the embedded body font's ordinary digits for a reliable PDF exponent.
    s = s.replace("10⁻⁶", "10<super>-6</super>")
    return s


def blocks():
    for b in TEMPLATE.split("\n\n"):
        b = b.strip()
        if b:
            yield b


def section_words():
    result = {}
    sections = [("III. Methodology", "IV. Results & Evaluation"), ("IV. Results & Evaluation", "V. Discussion & Limitations"), ("V. Discussion & Limitations", "VI. Conclusion")]
    for a, b in sections:
        txt = TEMPLATE.split("## " + a + "\n")[1].split("## " + b + "\n")[0]
        txt = re.sub(r"^###.*$", "", txt, flags=re.M)
        txt = re.sub(r"\[\[.*?\]\]|\[\d[^\]]*\]", "", txt)
        result[a] = len(re.findall(r"\b[\w]+(?:[’'–-][\w]+)*\b", txt))
    assert 900 <= result["III. Methodology"] <= 1300
    assert 900 <= result["IV. Results & Evaluation"] <= 1300
    assert 400 <= result["V. Discussion & Limitations"] <= 700
    return result


md = TEMPLATE.replace("[[REFERENCES]]", "\n\n".join(REFS))
for key, spec in TABLES.items():
    lines = ["**" + spec["caption"] + "**", "", "| " + " | ".join(spec["headers"]) + " |", "| " + " | ".join(["---"] * len(spec["headers"])) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in spec["rows"]]
    lines += ["", "*" + spec["note"] + "*"]
    md = md.replace("[[" + key + "]]", "\n".join(lines))
for key, stem in FIGFILES.items():
    md = md.replace("[[" + key + "]]", f"![{CAPTIONS[key]}](assignment2_revised_artifacts/figures/{stem}.png)\n\n*{CAPTIONS[key]}*")
(OUT / (STEM + ".md")).write_text(md)

FONTDIR = Path("/System/Library/Fonts/Supplemental")
for name, file in [("Paper", "Times New Roman.ttf"), ("Paper-Bold", "Times New Roman Bold.ttf"), ("Paper-Italic", "Times New Roman Italic.ttf"), ("Paper-BoldItalic", "Times New Roman Bold Italic.ttf")]:
    pdfmetrics.registerFont(TTFont(name, str(FONTDIR / file)))
pdfmetrics.registerFontFamily("Paper", normal="Paper", bold="Paper-Bold", italic="Paper-Italic", boldItalic="Paper-BoldItalic")
STYLE = {
    "body": ParagraphStyle("Body", fontName="Paper", fontSize=10, leading=11.5, alignment=TA_JUSTIFY, spaceAfter=4.3),
    "heading": ParagraphStyle("Heading", fontName="Paper-Bold", fontSize=10.2, leading=12, alignment=TA_CENTER, spaceBefore=8, spaceAfter=6, keepWithNext=True),
    "subheading": ParagraphStyle("Subheading", fontName="Paper-Italic", fontSize=10, leading=11.5, spaceBefore=4, spaceAfter=4, keepWithNext=True),
    "caption": ParagraphStyle("Caption", fontName="Paper", fontSize=8.3, leading=9.2, spaceAfter=6),
    "tabtitle": ParagraphStyle("TableTitle", fontName="Paper-Bold", fontSize=8.4, leading=9.3, alignment=TA_CENTER, spaceAfter=5),
    "cell": ParagraphStyle("Cell", fontName="Paper", fontSize=8.1, leading=9.2),
    "cellhead": ParagraphStyle("Cellhead", fontName="Paper-Bold", fontSize=8.1, leading=9.2),
    "reference": ParagraphStyle("Reference", fontName="Paper", fontSize=8.1, leading=9.2, spaceAfter=4, leftIndent=17, firstLineIndent=-17),
}
PW, PH = 612, 792
MARGIN, GAP = 43, 18
CW = (PW - MARGIN * 2 - GAP) / 2
diagram_image = Image(str(FIG / (FIGFILES['FIGURE_1'] + '.png')))
diagram_natural_width, diagram_natural_height = diagram_image.imageWidth, diagram_image.imageHeight
diagram_image.drawWidth = PW - 2*MARGIN
diagram_image.drawHeight = diagram_natural_height * diagram_image.drawWidth / diagram_natural_width
diagram_caption = Paragraph(rich(CAPTIONS['FIGURE_1']), STYLE['caption'])
_, diagram_caption_height = diagram_caption.wrap(PW-2*MARGIN,100)
diagram_body_top = PH-43-diagram_image.drawHeight-diagram_caption_height-16


def draw_page(canvas, doc):
    canvas.saveState()
    if doc.page == 1:
        doc.handle_nextPageTemplate("Diagram")
        title = Paragraph(rich(TEMPLATE.splitlines()[0][2:]), ParagraphStyle("Title", fontName="Paper-Bold", fontSize=16.5, leading=18.5, alignment=TA_CENTER))
        w, h = title.wrap(PW - 2 * MARGIN, 100)
        title.drawOn(canvas, MARGIN, PH - 40 - h)
        author = Paragraph("Hemant Upadhyay<br/>CY 530: Network Security Research Paper — Assignment 2<br/><font size='9'>Topic area: Endpoint security monitoring, complementary evidence, and state–event reconciliation</font>", ParagraphStyle("Author", fontName="Paper", fontSize=10, leading=12, alignment=TA_CENTER))
        aw, ah = author.wrap(PW - 2 * MARGIN, 70)
        author.drawOn(canvas, MARGIN, PH - 47 - h - ah)
    else:
        canvas.setFont("Paper", 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(MARGIN, PH - 27, "CY 530  •  CyberStateGuardian  •  Methodology & Results")
        canvas.setStrokeColor(colors.HexColor("#dddddd"))
        canvas.line(MARGIN, PH - 32, PW - MARGIN, PH - 32)
    if doc.page == 2:
        doc.handle_nextPageTemplate("Body")
        diagram_image.drawOn(canvas,MARGIN,PH-43-diagram_image.drawHeight)
        diagram_caption.drawOn(canvas,MARGIN,PH-47-diagram_image.drawHeight-diagram_caption_height)
    canvas.setFont("Paper", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(MARGIN, 23, "Hemant Upadhyay  |  October 12, 2026")
    canvas.drawRightString(PW - MARGIN, 23, str(doc.page))
    canvas.restoreState()


def frames(top):
    return [Frame(MARGIN, 42, CW, top - 42, id="left", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0), Frame(MARGIN + CW + GAP, 42, CW, top - 42, id="right", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)]


pdfpath = OUT / (STEM + ".pdf")
doc = BaseDocTemplate(str(pdfpath), pagesize=(PW, PH), title=STEM.replace("_", " "), author="Hemant Upadhyay", allowSplitting=True)
doc.addPageTemplates([PageTemplate(id="First", frames=frames(PH - 142), onPage=draw_page), PageTemplate(id="Diagram", frames=frames(diagram_body_top), onPage=draw_page), PageTemplate(id="Body", frames=frames(PH - 43), onPage=draw_page)])
story = []
for b in blocks():
    if b.startswith("# ") or b.startswith("**Hemant"):
        continue
    if b.startswith("## "):
        story.append(Paragraph(rich(b[3:]).upper(), STYLE["heading"]))
    elif b.startswith("### "):
        story.append(Paragraph(rich(b[4:]), STYLE["subheading"]))
    elif b == "[[REFERENCES]]":
        story.extend(KeepTogether([Paragraph(rich(r), STYLE["reference"])]) for r in REFS)
    elif b.startswith("[[TABLE_"):
        key = b[2:-2]
        spec = TABLES[key]
        data = [[Paragraph(rich(t), STYLE["cellhead"]) for t in spec["headers"]]] + [[Paragraph(rich(t), STYLE["cell"]) for t in row] for row in spec["rows"]]
        tab = Table(data, colWidths=[x * CW for x in spec["widths"]], repeatRows=1, hAlign="LEFT")
        tab.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#edf2f5")), ("LINEABOVE", (0,0), (-1,0), .7, colors.HexColor(BLUE)), ("LINEBELOW", (0,0), (-1,0), .5, colors.HexColor(BLUE)), ("LINEBELOW", (0,-1), (-1,-1), .7, colors.HexColor(BLUE)), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f7f8f9")]), ("VALIGN", (0,0), (-1,-1), "TOP"), ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4), ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4)]))
        story.append(KeepTogether([Spacer(1,4), Paragraph(rich(spec["caption"]), STYLE["tabtitle"]), tab, Spacer(1,4), Paragraph(rich(spec["note"]), STYLE["caption"])]))
    elif b.startswith("[[FIGURE_"):
        key = b[2:-2]
        if key == 'FIGURE_1':
            continue  # Full-width floating diagram is drawn atop page 2.
        im = Image(str(FIG / (FIGFILES[key] + ".png")))
        im.drawHeight = im.imageHeight * CW / im.imageWidth
        im.drawWidth = CW
        story.append(KeepTogether([Spacer(1,4), im, Spacer(1,4), Paragraph(rich(CAPTIONS[key]), STYLE["caption"])]))
    else:
        story.append(Paragraph(rich(b.replace("\n", " ")), STYLE["body"]))
doc.build(story)

# Editable Word version mirrors the same paper and six exhibits.
word = Document()
for section in word.sections:
    section.top_margin = Inches(.58)
    section.bottom_margin = Inches(.58)
    section.left_margin = Inches(.6)
    section.right_margin = Inches(.6)
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
normal = word.styles["Normal"]
normal.font.name = "Times New Roman"
normal.font.size = Pt(10)
normal.paragraph_format.space_after = Pt(4)
normal.paragraph_format.line_spacing = 1.0
p = word.add_paragraph()
p.alignment = 1
r = p.add_run(plain(TEMPLATE.splitlines()[0][2:]))
r.bold = True
r.font.size = Pt(16)
p = word.add_paragraph("Hemant Upadhyay\nCY 530: Network Security Research Paper — Assignment 2\nTopic area: Endpoint security monitoring, complementary evidence, and state–event reconciliation")
p.alignment = 1
sec = word.add_section(WD_SECTION_START.CONTINUOUS)
cols = sec._sectPr.xpath("./w:cols")[0]
cols.set(qn("w:num"), "2")
cols.set(qn("w:space"), "260")


def add_docx_text(p, txt):
    for part in re.split(r"(\*\*.*?\*\*)", plain(txt) if "**" not in txt else re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", txt)):
        content = part[2:-2] if part.startswith("**") else part.replace("*", "")
        for segment in re.split(r"(⁻⁶)", content):
            r = p.add_run("-6" if segment == "⁻⁶" else segment)
            r.bold = part.startswith("**")
            if segment == "⁻⁶":
                r.font.superscript = True


for b in blocks():
    if b.startswith("# ") or b.startswith("**Hemant"):
        continue
    if b.startswith("## ") or b.startswith("### "):
        sub = b.startswith("### ")
        p = word.add_paragraph()
        p.paragraph_format.keep_with_next = True
        p.paragraph_format.space_before = Pt(6)
        r = p.add_run(b[4:] if sub else b[3:].upper())
        r.bold, r.italic = not sub, sub
        if not sub:
            p.alignment = 1
    elif b == "[[REFERENCES]]":
        for ref in REFS:
            p = word.add_paragraph(plain(ref))
            p.paragraph_format.left_indent = Inches(.2)
            p.paragraph_format.first_line_indent = Inches(-.2)
            for r in p.runs:
                r.font.size = Pt(8)
    elif b.startswith("[[TABLE_"):
        spec = TABLES[b[2:-2]]
        p = word.add_paragraph(spec["caption"])
        p.alignment = 1
        p.paragraph_format.keep_with_next = True
        for r in p.runs:
            r.font.size = Pt(8)
            r.bold = True
        t = word.add_table(rows=1, cols=len(spec["headers"]))
        t.autofit = False
        t.style = "Light Shading Accent 1"
        for c, width in zip(t.columns, spec["widths"]):
            c.width = Inches(3.45 * width)
        for i, txt in enumerate(spec["headers"]):
            t.rows[0].cells[i].text = txt
        for row in spec["rows"]:
            cells = t.add_row().cells
            for i, txt in enumerate(row):
                cells[i].text = txt
        for row in t.rows:
            for cell, width in zip(row.cells, spec["widths"]):
                cell.width = Inches(3.45 * width)
                for p in cell.paragraphs:
                    p.paragraph_format.space_after = Pt(2)
                    for r in p.runs:
                        r.font.size = Pt(8)
        p = word.add_paragraph(spec["note"])
        for r in p.runs:
            r.font.size = Pt(8)
    elif b.startswith("[[FIGURE_"):
        key = b[2:-2]
        if key == 'FIGURE_1':
            wide = word.add_section(WD_SECTION_START.CONTINUOUS)
            wide._sectPr.xpath('./w:cols')[0].set(qn('w:num'),'1')
        p = word.add_paragraph()
        p.paragraph_format.keep_with_next = True
        p.add_run().add_picture(str(FIG / (FIGFILES[key] + ".png")), width=Inches(7.25 if key == 'FIGURE_1' else 3.45))
        p = word.add_paragraph(CAPTIONS[key])
        for r in p.runs:
            r.font.size = Pt(8)
        if key == 'FIGURE_1':
            narrow = word.add_section(WD_SECTION_START.CONTINUOUS)
            narrow._sectPr.xpath('./w:cols')[0].set(qn('w:num'),'2')
    else:
        p = word.add_paragraph()
        p.paragraph_format.alignment = 3
        add_docx_text(p, b.replace("\n", " "))
word.core_properties.title = plain(TEMPLATE.splitlines()[0][2:])
word.core_properties.author = "Hemant Upadhyay"
word.core_properties.subject = "CY 530 Assignment 2: Methodology and Results"
footer = word.sections[0].footer.paragraphs[0]
footer.alignment = 2
footer.add_run("Hemant Upadhyay  |  ")
field = OxmlElement("w:fldSimple")
field.set(qn("w:instr"), "PAGE")
footer._p.append(field)
for run in footer.runs:
    run.font.size = Pt(8)
word.save(OUT / (STEM + ".docx"))

paper_pdf = fitz.open(pdfpath)
text = "\n".join(page.get_text() for page in paper_pdf)
assert "[[" not in text
assert all(t in text for t in ["TABLE I.", "TABLE II.", "TABLE III.", "Fig. 1.", "Fig. 2.", "Fig. 3."])
assert "[26]" in text
word_counts = section_words()
report = {"section_prose_word_counts": word_counts, "reference_count": len(REFS), "table_count": len(TABLES), "figure_count": len(FIGFILES), "pdf_pages": len(paper_pdf), "pdf_body_font_points": 10, "source_numeric_assertions_passed": True, "unresolved_markers": False, "evidence_cutoff": "2026-10-12", "page_text_counts": [len(page.get_text().split()) for page in paper_pdf]}
(HERE / "validation_report.json").write_text(json.dumps(report, indent=2) + "\n")
ledger = {"scope": "Read-only build from retained artifacts; no experiment reruns or live queries.", "sources": SOURCES, "figure2_data": curve, "figure3_source": "lifecycle_plot_data.json", "replay_original_parents": 30, "replay_derived_rows": 90, "statistical_note": "Wilson intervals and McNemar p-value are nominal descriptive within-host summaries; live repeated trials do not represent independent hosts."}
(HERE / "paper_evidence.json").write_text(json.dumps(ledger, indent=2) + "\n")
(HERE / "paper_pdf_extracted.txt").write_text(text)
for i, page in enumerate(paper_pdf):
    page.get_pixmap(matrix=fitz.Matrix(1.35, 1.35)).save(HERE / f"preview_page_{i+1}.png")
print(json.dumps(report, indent=2))
