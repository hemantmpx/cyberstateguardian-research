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
    Spacer, Table, TableStyle,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE.parent
STEM = "Assignment530_CyberStateGuardian_Methodology_Results"
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

BLUE, ORANGE, GREEN = "#1b4965", "#b6512a", "#427c66"
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 7.5,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.labelcolor": "#222222", "text.color": "#222222",
    "svg.fonttype": "none", "pdf.fonttype": 42,
})


def save_figure(fig, name):
    for ext in ("png", "pdf", "svg"):
        fig.savefig(FIG / f"{name}.{ext}", dpi=450, bbox_inches="tight", facecolor="white")
    plt.close(fig)


fig, axes = plt.subplots(2, 1, figsize=(3.55, 3.1), gridspec_kw={"height_ratios": [4, 3]})
signal_rows = [
    ("Configured Wazuh: target event", "configured_wazuh_alert_fim"),
    ("Raw events: target event", "raw_event_only"),
    ("Native probe: target state", "native_probe_only"),
    ("Full CSG: target state", "full_csg"),
]
false_rows = [
    ("Loose host/type/time", "loose_host_type_time_matcher"),
    ("Strong exact identity", "strong_identity_matcher"),
    ("Full CSG", "full_csg"),
]
for ax, rows, metric, color, title in [
    (axes[0], signal_rows, "target_detection_correct", BLUE, "A  Exact target signal at cutoff"),
    (axes[1], false_rows, "false_corroboration", ORANGE, "B  Wrong-object corroboration"),
]:
    for i, (label, key) in enumerate(rows):
        m = method[key][metric]
        k, n = m["successes"], m["denominator"]
        p, (lo, hi) = k / n * 100, wilson(k, n)
        ax.errorbar(p, i, xerr=[[p - 100 * lo], [100 * hi - p]], fmt="o", color=color, markersize=4, capsize=2, lw=1.2)
        ax.text(55, i, f"{k}/{n}", va="center", ha="center", fontsize=7, color="#555555")
    ax.set_yticks(range(len(rows)), [r[0] for r in rows], fontsize=6.6)
    ax.invert_yaxis()
    ax.set_xlim(-5, 105)
    ax.set_xticks([0, 50, 100], ["0%", "50%", "100%"])
    ax.set_title(title, loc="left", fontsize=8, fontweight="bold", pad=7)
    ax.grid(axis="x", color="#e5e5e5", lw=0.7)
    ax.set_axisbelow(True)
fig.subplots_adjust(left=0.51, right=0.98, hspace=0.67, top=0.93, bottom=0.08)
save_figure(fig, "figure1_paired_service")

curve = dwell["pooled_dwell_capture"]
assert [x["captured"] for x in curve] == [0, 9, 19, 20]
assert all(x["trials"] == 20 for x in curve)
fig, ax = plt.subplots(figsize=(3.55, 2.8))
xs = list(range(4))
ys = [100 * x["rate"] for x in curve]
low = [y - 100 * x["wilson_95_interval"][0] for x, y in zip(curve, ys)]
high = [100 * x["wilson_95_interval"][1] - y for x, y in zip(curve, ys)]
ax.errorbar(xs, ys, yerr=[low, high], fmt="o-", color=BLUE, lw=1.7, capsize=3, markersize=5, label="Native transition: combined n=20")
for ci, (offset, marker, label) in enumerate([(-0.065, "s", "Cohort 1: n=10"), (0.065, "^", "Extension: n=10")]):
    vals = [100 * x["cohort_results"][ci]["rate"] for x in curve]
    ax.scatter([x + offset for x in xs], vals, marker=marker, s=20, facecolors="white", edgecolors=BLUE, alpha=0.9, zorder=4, label=label)
ax.plot(xs, [100] * 4, "--", color=GREEN, lw=1.3, label="Exact Wazuh events retrieved later")
for x, y, row in zip(xs, ys, curve):
    ax.annotate(f'{row["captured"]}/{row["trials"]}', (x, y), xytext=(0, 8 if y < 90 else -15), textcoords="offset points", ha="center", fontsize=7.5, fontweight="bold")
ax.set_xticks(xs, ["0.25", "2", "6", "12"])
ax.set_xlabel("Temporary Automatic-mode dwell (seconds)")
ax.set_ylabel("Exact target visibility (%)")
ax.set_ylim(-5, 113)
ax.set_xlim(-0.25, 3.25)
ax.grid(axis="y", color="#e5e5e5", lw=0.7)
ax.legend(loc="lower right", fontsize=6.0, frameon=False, handlelength=1.5)
fig.tight_layout(pad=0.5)
save_figure(fig, "figure2_dwell_response")

TABLES = {
    "TABLE_1": {
        "caption": "TABLE I. Evidence sources and experimental units",
        "headers": ["Evidence source", "Size / unit", "Evaluation role"],
        "rows": [
            ["Windows-APT 2025 V3", "102,011 events; 36-scenario catalogue", "External normalization; behavior selection"],
            ["Registry V3 (Oct. 7)", "30 live windows: 10 per arm", "Exact archive links; omission; configured FIM"],
            ["Registry (Oct. 8)", "30 live windows + 90 derived rows", "Separate replication; synthetic replay"],
            ["Service paired study", "20 live trials; six paired methods", "Common-pool wrong-object contrast"],
            ["Task studies (Oct. 12)", "Three separate 10-window cohorts", "Distractor; no change; collection filter"],
            ["Service dwell", "Two 50-trial cohorts", "Four dwell groups; stable controls"],
            ["Other software validation", "21 fixtures; 60 derived task rows", "Trajectory semantics; separate task replay"],
        ],
        "note": "A window may contain no action; derived rows and method outputs are not additional live trials. All live studies use one endpoint.",
        "widths": [0.31, 0.33, 0.36],
    },
    "TABLE_2": {
        "caption": "TABLE II. Separate live registry campaign outcomes",
        "headers": ["Campaign / condition", "State", "Exact event", "Final target result"],
        "rows": [],
        "note": "Every row has n=10. C = CONSISTENT; U = UNEXPLAINED; FF = false target finding. A 10/10 proportion has Wilson 95% interval 72.2%–100%; 0/10 has 0%–27.8%. Campaigns are not pooled.",
        "widths": [0.35, 0.16, 0.18, 0.31],
    },
    "TABLE_3": {
        "caption": "TABLE III. Separate scheduled-task cohorts (Oct. 12)",
        "headers": ["Verified outcome", "Complete + distractor", "No change", "4698 filter"],
        "rows": [
            ["Assigned windows", "10", "10", "10"],
            ["Direct target change observed", "10/10", "N/A", "10/10"],
            ["Exact target Wazuh event", "10/10", "N/A", "0/10"],
            ["Full protocol gates passed", "10/10", "10/10", "9/10"],
            ["Final C / U outcomes", "C: 10/10", "N/A", "U: 9/10"],
            ["False distractor citation", "0/10", "N/A", "N/A"],
            ["No-change false finding", "N/A", "0/10", "N/A"],
            ["Cleanup / restoration", "10/10", "10/10", "10/10"],
        ],
        "note": "The omission assignment lacking ADD/finding remains a failure. For no action, target-event detection is not applicable. All-gate Wilson intervals: 10/10, 72.2%–100%; 9/10, 59.6%–98.2%. The archived no-change exact interval is 69.2%–100%.",
        "widths": [0.43, 0.20, 0.17, 0.20],
    },
}
for date, data in [("Oct. 7", reg7["summary"]), ("Oct. 8", reg8["conditions"])]:
    for cond, label in [("registry_complete", "Complete"), ("registry_wrong_object", "Wrong object"), ("registry_no_change", "No change")]:
        state = data[cond]["csg_state_present"] if date == "Oct. 7" else data[cond]["state_observed"]["successes"]
        exact = (reg7["summary"][cond]["trials_with_exact_target_sysmon_index_event"] if date == "Oct. 7" else replay["exploratory_live_method_comparison"][{"registry_complete": "captured_complete", "registry_wrong_object": "same_host_wrong_object_live", "registry_no_change": "no_change_control"}[cond]]["exact_target_events_observed"])
        result = "C: 10/10" if cond == "registry_complete" else "U: 10/10" if cond == "registry_wrong_object" else "FF: 0/10"
        TABLES["TABLE_2"]["rows"].append([f"{date}: {label}", f"{state}/10" if cond != "registry_no_change" else "No change", f"{exact}/10" if cond != "registry_no_change" else "N/A", result])

CAPTIONS = {
    "FIGURE_1": "Fig. 1. Paired service study (20 shared trials). A: exact target event signals versus independent target-state observations. B: false attribution of a different service's event. Bars are nominal Wilson 95% intervals. The loose matcher is a deliberate ablation; strong identity and CSG both reject it.",
    "FIGURE_2": "Fig. 2. Service transition visibility at five-second polling. Native pooled counts are 0/20, 9/20, 19/20, and 20/20; bars show descriptive Wilson 95% intervals and open markers retain each cohort. Dashed line shows later exact Wazuh-event retrieval in 20/20 treatments per group, not real-time ingestion. The extension followed first-cohort inspection.",
}
FIGFILES = {"FIGURE_1": "figure1_paired_service", "FIGURE_2": "figure2_dwell_response"}

for key, spec in TABLES.items():
    with (HERE / (key.lower() + ".csv")).open("w", newline="") as handle:
        w = csv.writer(handle)
        w.writerow(spec["headers"])
        w.writerows(spec["rows"])


def plain(s):
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", s)
    return s.replace("**", "").replace("*", "")


def rich(s):
    s = html.escape(s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<link href="\2" color="#1b4965">\1</link>', s)
    s = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"\*(.*?)\*", r"<i>\1</i>", s)
    return s


def blocks():
    for b in TEMPLATE.split("\n\n"):
        b = b.strip()
        if b:
            yield b


def section_words():
    result = {}
    sections = [("I. Methodology", "II. Results & Evaluation"), ("II. Results & Evaluation", "III. Discussion & Limitations"), ("III. Discussion & Limitations", "AI Use Disclosure and Results Integrity")]
    for a, b in sections:
        txt = TEMPLATE.split("## " + a + "\n")[1].split("## " + b + "\n")[0]
        txt = re.sub(r"^###.*$", "", txt, flags=re.M)
        txt = re.sub(r"\[\[.*?\]\]|\[\d[^\]]*\]", "", txt)
        result[a] = len(re.findall(r"\b[\w]+(?:[’'–-][\w]+)*\b", txt))
    assert 900 <= result["I. Methodology"] <= 1300
    assert 900 <= result["II. Results & Evaluation"] <= 1300
    assert 400 <= result["III. Discussion & Limitations"] <= 700
    return result


md = TEMPLATE.replace("[[REFERENCES]]", "\n\n".join(REFS))
for key, spec in TABLES.items():
    lines = ["**" + spec["caption"] + "**", "", "| " + " | ".join(spec["headers"]) + " |", "| " + " | ".join(["---"] * len(spec["headers"])) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in spec["rows"]]
    lines += ["", "*" + spec["note"] + "*"]
    md = md.replace("[[" + key + "]]", "\n".join(lines))
for key, stem in FIGFILES.items():
    md = md.replace("[[" + key + "]]", f"![{CAPTIONS[key]}](assignment2_artifacts/figures/{stem}.png)\n\n*{CAPTIONS[key]}*")
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


def draw_page(canvas, doc):
    canvas.saveState()
    if doc.page == 1:
        title = Paragraph("CyberStateGuardian: Empirical Evaluation of Independent Windows State Observation and Exact Event Reconciliation", ParagraphStyle("Title", fontName="Paper-Bold", fontSize=16.5, leading=18.5, alignment=TA_CENTER))
        w, h = title.wrap(PW - 2 * MARGIN, 100)
        title.drawOn(canvas, MARGIN, PH - 40 - h)
        author = Paragraph("Hemant Upadhyay<br/>CY 530: Network Security Research Paper — Assignment 2 of 2<br/><font size='9'>Topic area: Endpoint security monitoring, state–event reconciliation, and evidence-grounded incident analysis<br/>Evidence cutoff: October 12, 2026</font>", ParagraphStyle("Author", fontName="Paper", fontSize=10, leading=12, alignment=TA_CENTER))
        aw, ah = author.wrap(PW - 2 * MARGIN, 70)
        author.drawOn(canvas, MARGIN, PH - 47 - h - ah)
    else:
        canvas.setFont("Paper", 8)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(MARGIN, PH - 27, "CY 530  •  CyberStateGuardian  •  Methodology & Results")
        canvas.setStrokeColor(colors.HexColor("#dddddd"))
        canvas.line(MARGIN, PH - 32, PW - MARGIN, PH - 32)
    canvas.setFont("Paper", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(MARGIN, 23, "Hemant Upadhyay  |  October 12, 2026")
    canvas.drawRightString(PW - MARGIN, 23, str(doc.page))
    canvas.restoreState()


def frames(top):
    return [Frame(MARGIN, 42, CW, top - 42, id="left", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0), Frame(MARGIN + CW + GAP, 42, CW, top - 42, id="right", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)]


pdfpath = OUT / (STEM + ".pdf")
doc = BaseDocTemplate(str(pdfpath), pagesize=(PW, PH), title=STEM.replace("_", " "), author="Hemant Upadhyay", allowSplitting=True)
doc.addPageTemplates([PageTemplate(id="First", frames=frames(PH - 160), onPage=draw_page, autoNextPageTemplate="Body"), PageTemplate(id="Body", frames=frames(PH - 43), onPage=draw_page)])
story = []
for b in blocks():
    if b.startswith("# ") or b.startswith("**Hemant"):
        continue
    if b.startswith("## "):
        story.append(Paragraph(rich(b[3:]).upper(), STYLE["heading"]))
    elif b.startswith("### "):
        story.append(Paragraph(rich(b[4:]), STYLE["subheading"]))
    elif b == "[[REFERENCES]]":
        story.extend(Paragraph(rich(r), STYLE["reference"]) for r in REFS)
    elif b.startswith("[[TABLE_"):
        key = b[2:-2]
        spec = TABLES[key]
        data = [[Paragraph(rich(t), STYLE["cellhead"]) for t in spec["headers"]]] + [[Paragraph(rich(t), STYLE["cell"]) for t in row] for row in spec["rows"]]
        tab = Table(data, colWidths=[x * CW for x in spec["widths"]], repeatRows=1, hAlign="LEFT")
        tab.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#edf2f5")), ("LINEABOVE", (0,0), (-1,0), .7, colors.HexColor(BLUE)), ("LINEBELOW", (0,0), (-1,0), .5, colors.HexColor(BLUE)), ("LINEBELOW", (0,-1), (-1,-1), .7, colors.HexColor(BLUE)), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f7f8f9")]), ("VALIGN", (0,0), (-1,-1), "TOP"), ("LEFTPADDING", (0,0), (-1,-1), 4), ("RIGHTPADDING", (0,0), (-1,-1), 4), ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4)]))
        story.append(KeepTogether([Spacer(1,4), Paragraph(rich(spec["caption"]), STYLE["tabtitle"]), tab, Spacer(1,4), Paragraph(rich(spec["note"]), STYLE["caption"])]))
    elif b.startswith("[[FIGURE_"):
        key = b[2:-2]
        im = Image(str(FIG / (FIGFILES[key] + ".png")))
        im.drawHeight = im.imageHeight * CW / im.imageWidth
        im.drawWidth = CW
        story.append(KeepTogether([Spacer(1,4), im, Spacer(1,4), Paragraph(rich(CAPTIONS[key]), STYLE["caption"])]))
    else:
        story.append(Paragraph(rich(b.replace("\n", " ")), STYLE["body"]))
doc.build(story)

# Editable Word version mirrors the same paper and five exhibits.
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
p = word.add_paragraph("Hemant Upadhyay\nCY 530: Network Security Research Paper — Assignment 2 of 2\nTopic area: Endpoint security monitoring, state–event reconciliation, and evidence-grounded incident analysis\nEvidence cutoff: October 12, 2026")
p.alignment = 1
sec = word.add_section(WD_SECTION_START.CONTINUOUS)
cols = sec._sectPr.xpath("./w:cols")[0]
cols.set(qn("w:num"), "2")
cols.set(qn("w:space"), "260")


def add_docx_text(p, txt):
    for part in re.split(r"(\*\*.*?\*\*)", plain(txt) if "**" not in txt else re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", txt)):
        r = p.add_run(part[2:-2] if part.startswith("**") else part.replace("*", ""))
        r.bold = part.startswith("**")


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
        p = word.add_paragraph()
        p.paragraph_format.keep_with_next = True
        p.add_run().add_picture(str(FIG / (FIGFILES[key] + ".png")), width=Inches(3.45))
        p = word.add_paragraph(CAPTIONS[key])
        for r in p.runs:
            r.font.size = Pt(8)
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
assert all(t in text for t in ["TABLE I.", "TABLE II.", "TABLE III.", "Fig. 1.", "Fig. 2."])
assert "[26]" in text
word_counts = section_words()
report = {"section_prose_word_counts": word_counts, "reference_count": len(REFS), "table_count": len(TABLES), "figure_count": len(FIGFILES), "pdf_pages": len(paper_pdf), "pdf_body_font_points": 10, "source_numeric_assertions_passed": True, "unresolved_markers": False, "evidence_cutoff": "2026-10-12", "page_text_counts": [len(page.get_text().split()) for page in paper_pdf]}
(HERE / "validation_report.json").write_text(json.dumps(report, indent=2) + "\n")
ledger = {"scope": "Read-only build from retained artifacts; no experiment reruns or live queries.", "sources": SOURCES, "chart1_metric_sources": signal_rows + false_rows, "chart2_data": curve, "replay_original_parents": 30, "replay_derived_rows": 90, "statistical_note": "Wilson intervals and McNemar p-value are nominal descriptive within-host summaries; live repeated trials do not represent independent hosts."}
(HERE / "paper_evidence.json").write_text(json.dumps(ledger, indent=2) + "\n")
(HERE / "paper_pdf_extracted.txt").write_text(text)
for i, page in enumerate(paper_pdf):
    page.get_pixmap(matrix=fitz.Matrix(1.35, 1.35)).save(HERE / f"preview_page_{i+1}.png")
print(json.dumps(report, indent=2))
