"""Draw every diagram and chart used in the report and the presentation.

All charts read report/data/*.json, so no number is typed by hand here. The
live-run chart reads the sensor database in read-only mode.

    python make_figures.py <project root> <output folder>
"""

from __future__ import annotations

import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon, Rectangle  # noqa: E402

ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
MODELS = json.loads((ROOT / "report/data/model_evaluation.json").read_text(encoding="utf-8"))
SCEN = json.loads((ROOT / "report/data/scenario_evaluation.json").read_text(encoding="utf-8"))
CIC, UNSW = MODELS["cic"], MODELS["unsw"]

# Validated categorical palette (dataviz reference), one sequential blue ramp for
# severity, and quiet ink for everything that is not data.
BLUE, ORANGE, AQUA, YELLOW, MAGENTA = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"
INK, MUTED, GRID = "#111111", "#52514e", "#dcdbd6"
SEV = {"HIGH": "#0f3f7a", "MEDIUM": "#2a78d6", "LOW": "#9cc3ee", "No alert": "#e4e3de"}
FILL = {"decoy": "#e8f1fb", "detect": "#fdeee7", "act": "#e6f6f0", "ui": "#fdf4dd", "data": "#f0efec"}

plt.rcParams.update({
    "font.family": "Times New Roman", "font.size": 10.5, "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED, "axes.linewidth": 0.7,
    "axes.titlesize": 11, "axes.titleweight": "bold", "legend.frameon": False,
    "savefig.dpi": 300, "savefig.bbox": "tight", "savefig.pad_inches": 0.04,
})

CURVE_COLORS = {
    "Random Forest (project)": BLUE, "Hist. Gradient Boosting": ORANGE, "Decision Tree": AQUA,
    "Logistic Regression": YELLOW, "Gaussian Naive Bayes": MAGENTA,
}


def save(fig, name):
    fig.savefig(OUT / f"{name}.png", facecolor="white")
    plt.close(fig)
    print("saved", name, flush=True)


def clean(ax, grid="y"):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    if grid:
        ax.grid(axis=grid, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)


# ---------------------------------------------------------------------------
# Diagram helpers
# ---------------------------------------------------------------------------

def canvas(width, height):
    fig, ax = plt.subplots(figsize=(width, height))
    ax.set_xlim(0, width)
    ax.set_ylim(0, height)
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, text, fill="#ffffff", size=9.5, bold=False, edge=INK, lw=0.9, style="round"):
    shape = "round,pad=0,rounding_size=0.06" if style == "round" else "square,pad=0"
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=shape, facecolor=fill, edgecolor=edge, linewidth=lw))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, color=INK,
            fontweight="bold" if bold else "normal", linespacing=1.15)


def arrow(ax, start, end, label=None, both=False, lw=1.0, rad=0.0, label_pos=0.5, offset=(0, 0.07),
          size=8.5, dashed=False, color=INK):
    style = "<|-|>" if both else "-|>"
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=9, linewidth=lw, color=color,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0,
                                 linestyle="--" if dashed else "-"))
    if label:
        x = start[0] + (end[0] - start[0]) * label_pos + offset[0]
        y = start[1] + (end[1] - start[1]) * label_pos + offset[1]
        ax.text(x, y, label, ha="center", va="bottom", fontsize=size, color=INK,
                bbox=dict(facecolor="white", edgecolor="none", pad=0.6))


def poly_arrow(ax, points, label=None, dashed=False, lw=1.0, label_at=None, size=8.5):
    for a, b in zip(points[:-2], points[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=INK, linewidth=lw, linestyle="--" if dashed else "-", solid_capstyle="butt")
    arrow(ax, points[-2], points[-1], lw=lw, dashed=dashed)
    if label and label_at:
        ax.text(label_at[0], label_at[1], label, ha="center", va="center", fontsize=size,
                bbox=dict(facecolor="white", edgecolor="none", pad=0.6))


def diamond(ax, cx, cy, w, h, text, size=9, fill="#fdeee7"):
    ax.add_patch(Polygon([(cx - w / 2, cy), (cx, cy + h / 2), (cx + w / 2, cy), (cx, cy - h / 2)],
                         closed=True, facecolor=fill, edgecolor=INK, linewidth=0.9))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=size, linespacing=1.1)


# ---------------------------------------------------------------------------
# Diagrams
# ---------------------------------------------------------------------------

def architecture():
    fig, ax = canvas(7.4, 6.0)
    box(ax, 2.2, 5.5, 3.0, 0.42, "Attacker / scanner on the network", "#ffffff", 10, True)

    ax.add_patch(Rectangle((0.05, 4.05), 7.3, 1.2, facecolor=FILL["decoy"], edgecolor=MUTED, linewidth=0.7))
    ax.text(0.14, 5.1, "Decoy and telemetry layer", fontsize=9.5, fontweight="bold", va="center")
    box(ax, 0.15, 4.15, 1.45, 0.78, "SSH decoy\n(paramiko)\nport 2222", "#ffffff")
    box(ax, 1.75, 4.15, 1.45, 0.78, "HTTP decoy\nfake web app\nport 8080", "#ffffff")
    box(ax, 3.35, 4.15, 2.15, 0.78, "Bait services: FTP, Telnet,\nSMTP, POP3, MSSQL, MySQL,\nRedis, Elasticsearch, MongoDB", "#ffffff", 8.4)
    box(ax, 5.65, 4.15, 1.6, 0.78, "Firewall log reader\n(closed ports,\nICMP sweeps)", "#ffffff", 9)
    arrow(ax, (3.7, 5.5), (3.7, 5.25))

    ax.add_patch(Rectangle((0.05, 2.5), 7.3, 1.3, facecolor=FILL["detect"], edgecolor=MUTED, linewidth=0.7))
    ax.text(0.14, 3.65, "Detection engine", fontsize=9.5, fontweight="bold", va="center")
    box(ax, 0.15, 2.6, 2.2, 0.9, "Behavioural rules\nsliding windows,\n13 attack classes", "#ffffff")
    box(ax, 2.6, 2.6, 2.2, 0.9, "ML scoring\nRandom Forest (CIC-IDS2017)\nRandom Forest (UNSW-NB15)", "#ffffff", 8.3)
    box(ax, 5.05, 2.6, 2.2, 0.9, "Score fusion\nscore = rule + ML points\nLOW / MEDIUM / HIGH", "#ffffff")
    arrow(ax, (3.7, 4.05), (3.7, 3.8), None)
    ax.text(3.82, 3.925, "events", fontsize=8.5, va="center")
    arrow(ax, (2.35, 3.05), (2.6, 3.05), None)
    arrow(ax, (4.8, 3.05), (5.05, 3.05), None)

    ax.add_patch(Rectangle((0.05, 1.3), 7.3, 0.98, facecolor=FILL["act"], edgecolor=MUTED, linewidth=0.7))
    ax.text(0.14, 2.14, "Automated response and storage", fontsize=9.5, fontweight="bold", va="center")
    box(ax, 0.15, 1.38, 1.75, 0.62, "Adaptive deception\nUCB1 learning policy", "#ffffff", 9)
    box(ax, 2.05, 1.38, 1.75, 0.62, "Block manager\nsafety checks, TTL", "#ffffff", 9)
    box(ax, 3.95, 1.38, 1.5, 0.62, "Windows Defender\nFirewall (netsh)", "#ffffff", 9)
    box(ax, 5.6, 1.38, 1.65, 0.62, "SQLite store\nevents, findings, blocks", "#ffffff", 8.2)
    arrow(ax, (3.8, 1.69), (3.95, 1.69))
    arrow(ax, (6.15, 2.5), (6.15, 2.28), None)
    # Feedback from deception to the decoys, along the left margin.
    poly_arrow(ax, [(0.15, 1.69), (-0.1, 1.69), (-0.1, 4.54), (0.15, 4.54)], dashed=True)
    ax.text(-0.17, 3.1, "persona and engagement feedback", fontsize=8.5, rotation=90, va="center", ha="center")

    ax.add_patch(Rectangle((0.05, 0.02), 7.3, 1.05, facecolor=FILL["ui"], edgecolor=MUTED, linewidth=0.7))
    ax.text(0.14, 0.93, "Analyst interfaces", fontsize=9.5, fontweight="bold", va="center")
    box(ax, 0.15, 0.1, 1.75, 0.68, "Threat intelligence\nprofiles, campaigns,\nindicators (JSON, CSV)", "#ffffff", 8.8)
    box(ax, 2.05, 0.1, 1.75, 0.68, "Operator console\n127.0.0.1:9100\ntoken protected", "#ffffff", 8.8)
    box(ax, 3.95, 0.1, 1.5, 0.68, "FastAPI bridge\n127.0.0.1:8000", "#ffffff", 8.8)
    box(ax, 5.6, 0.1, 1.65, 0.68, "React dashboard\nport 5173", "#ffffff", 8.8)
    arrow(ax, (5.45, 0.44), (5.6, 0.44), both=True)
    arrow(ax, (3.8, 0.44), (3.95, 0.44), both=True)
    arrow(ax, (1.9, 0.44), (2.05, 0.44), both=True)
    arrow(ax, (6.15, 1.3), (6.15, 1.07))
    ax.set_xlim(-0.3, 7.4)
    save(fig, "architecture")


def methodology():
    fig, ax = canvas(7.4, 3.25)
    ax.text(0.02, 3.1, "Offline model development", fontsize=10, fontweight="bold")
    steps = ["CIC-IDS2017,\nUNSW-NB15\nCSV files", "Cleaning:\ninf to NaN,\nimputation,\nencoding",
             "Leakage control:\nde-duplication,\n70/10/20 split", "Random Forest\nand 4 baselines,\nvalidation grid",
             "Held-out test,\ncross-validation,\nother-day tests", "Pipelines saved\nas .joblib\nfor the sensor"]
    width = 1.11
    for i, text in enumerate(steps):
        x = 0.02 + i * (width + 0.145)
        box(ax, x, 2.12, width, 0.82, text, FILL["data"] if i in (0, 5) else FILL["detect"], 8.3)
        if i:
            arrow(ax, (x - 0.145, 2.53), (x, 2.53))
    ax.text(0.02, 1.68, "Online detection", fontsize=10, fontweight="bold")
    online = ["Decoys and\nfirewall log\nemit events", "Enrichment:\nML scores,\nhoneytokens", "Rules over\nsliding windows\nper source IP",
              "Fusion: score\nand severity,\ncooldown check", "Adapt decoy,\ndecide on block,\nstore finding", "Console,\ndashboard,\nthreat intel"]
    for i, text in enumerate(online):
        x = 0.02 + i * (width + 0.145)
        box(ax, x, 0.68, width, 0.82, text, FILL["decoy"] if i == 0 else FILL["act"] if i == 4 else FILL["ui"] if i == 5 else FILL["detect"], 8.3)
        if i:
            arrow(ax, (x - 0.145, 1.09), (x, 1.09))
    # Deployed pipelines feed the enrichment step.
    last_x = 0.02 + 5 * (width + 0.145) + width / 2
    enrich_x = 0.02 + 1 * (width + 0.145) + width / 2
    poly_arrow(ax, [(last_x, 2.12), (last_x, 1.84), (enrich_x, 1.84), (enrich_x, 1.5)], label="trained pipelines", label_at=(4.2, 1.84), dashed=True)
    # Deception feedback to the decoys.
    adapt_x = 0.02 + 4 * (width + 0.145) + width / 2
    decoy_x = 0.02 + width / 2
    poly_arrow(ax, [(adapt_x, 0.68), (adapt_x, 0.38), (decoy_x, 0.38), (decoy_x, 0.68)], label="persona and engagement feedback to the decoys", label_at=(2.9, 0.38), dashed=True)
    ax.set_ylim(0.25, 3.25)
    save(fig, "methodology")


def flowchart():
    fig, ax = canvas(6.3, 8.0)
    cx = 2.55
    w = 2.9

    def step(y, text, fill="#ffffff", h=0.44):
        box(ax, cx - w / 2, y, w, h, text, fill, 8.7)

    step(7.5, "Start: listener emits one event", FILL["decoy"])
    step(6.84, "Connection: score flow with both models\nHTTP or SSH: check for honeytoken reuse", FILL["detect"])
    step(6.2, "Store event; update per-IP history;\ndrop events older than 900 s", FILL["data"])
    step(5.56, "Evaluate all rules over\ntheir sliding windows", FILL["detect"])
    arrow(ax, (cx, 7.5), (cx, 7.28))
    arrow(ax, (cx, 6.84), (cx, 6.64))
    arrow(ax, (cx, 6.2), (cx, 6.0))
    arrow(ax, (cx, 5.56), (cx, 5.3))

    diamond(ax, cx, 4.88, 2.3, 0.84, "Any rule\nfired?")
    arrow(ax, (cx, 4.46), (cx, 4.24))
    ax.text(cx + 0.08, 4.34, "Yes", fontsize=9)
    step(3.8, "rule = min(90, strongest + 10 × (n − 1))\nscore = min(100, rule + ML points)", FILL["detect"])
    arrow(ax, (cx, 3.8), (cx, 3.56))
    diamond(ax, cx, 3.14, 2.5, 0.84, "Same class in cooldown\nand not escalated?")
    arrow(ax, (cx, 2.72), (cx, 2.52))
    ax.text(cx + 0.08, 2.6, "No", fontsize=9)
    step(2.08, "Create finding; adapt persona and\nengagement; record reason", FILL["act"])
    arrow(ax, (cx, 2.08), (cx, 1.86))
    diamond(ax, cx, 1.46, 2.5, 0.8, "Blocking class and\nscore at least 75?")
    arrow(ax, (cx, 1.06), (cx, 0.86))
    ax.text(cx + 0.08, 0.93, "No", fontsize=9)
    step(0.44, "Store finding; show it in console\nand dashboard", FILL["ui"])
    arrow(ax, (cx, 0.44), (cx, 0.24))
    box(ax, cx - 0.55, 0.0, 1.1, 0.24, "End", FILL["data"], 9.3)

    # Right-hand column: the side paths.
    rx = 5.0
    box(ax, rx - 0.82, 4.62, 1.64, 0.52, "ML-only agreement\nover 3+ strong flows?", FILL["detect"], 8.6)
    arrow(ax, (cx + 1.15, 4.88), (rx - 0.82, 4.88))
    ax.text(cx + 1.28, 4.93, "No", fontsize=9)
    poly_arrow(ax, [(rx, 4.62), (rx, 4.02), (cx + w / 2, 4.02)])
    ax.text(rx + 0.08, 4.3, "Yes", fontsize=9)

    box(ax, rx - 0.82, 1.08, 1.64, 0.76, "Protected address?\nYes: refuse.\nNo: rule or dry run,\nwith expiry (TTL)", FILL["act"], 8.5)
    arrow(ax, (cx + 1.25, 1.46), (rx - 0.82, 1.46))
    ax.text(cx + 1.34, 1.51, "Yes", fontsize=9)
    poly_arrow(ax, [(rx, 1.08), (rx, 0.66), (cx + w / 2, 0.66)])

    # "Finish without a finding" line on the far right.
    ex = 6.15
    poly_arrow(ax, [(rx + 0.82, 4.88), (ex, 4.88), (ex, 0.12), (cx + 0.55, 0.12)])
    ax.text(ex - 0.26, 4.93, "No", fontsize=9)
    poly_arrow(ax, [(cx + 1.25, 3.14), (ex, 3.14)])
    ax.text(cx + 1.34, 3.19, "Yes", fontsize=9)
    save(fig, "flowchart")


def dfd0():
    fig, ax = canvas(7.0, 2.4)
    ax.add_patch(plt.Circle((3.5, 1.2), 0.74, facecolor=FILL["detect"], edgecolor=INK, linewidth=0.9))
    ax.text(3.5, 1.2, "AI-Adaptive\nHoneypot\nSystem", ha="center", va="center", fontsize=10, fontweight="bold")
    box(ax, 0.02, 0.9, 1.05, 0.6, "Attacker", "#ffffff", 10, style="square")
    box(ax, 5.9, 1.62, 1.08, 0.6, "Operator", "#ffffff", 10, style="square")
    box(ax, 5.9, 0.2, 1.08, 0.6, "Windows\nFirewall", "#ffffff", 10, style="square")
    arrow(ax, (1.07, 1.34), (2.8, 1.34), "probes, logins, requests", offset=(0, 0.02))
    arrow(ax, (2.8, 1.06), (1.07, 1.06), "decoy responses", offset=(0, -0.25))
    arrow(ax, (4.16, 1.55), (5.9, 2.02), "alerts, indicators", offset=(-0.1, 0.1))
    arrow(ax, (5.9, 1.76), (4.23, 1.32), "block, persona commands", offset=(0.2, -0.3))
    arrow(ax, (4.14, 0.84), (5.9, 0.5), "block and unblock rules", offset=(-0.1, -0.3))
    save(fig, "dfd0")


def dfd1():
    fig, ax = canvas(7.2, 3.6)

    def proc(cx, cy, text, r=0.58, fill=FILL["detect"]):
        ax.add_patch(plt.Circle((cx, cy), r, facecolor=fill, edgecolor=INK, linewidth=0.9))
        ax.text(cx, cy, text, ha="center", va="center", fontsize=8.8, linespacing=1.1)

    def store(x, y, w, text):
        ax.plot([x, x + w], [y + 0.34, y + 0.34], color=INK, linewidth=0.9)
        ax.plot([x, x + w], [y, y], color=INK, linewidth=0.9)
        ax.text(x + w / 2, y + 0.17, text, ha="center", va="center", fontsize=8.8)

    box(ax, 0.02, 2.7, 0.92, 0.5, "Attacker", "#ffffff", 9.5, style="square")
    proc(1.95, 2.95, "1.0\nDecoy\nservices", fill=FILL["decoy"])
    proc(3.75, 2.95, "2.0\nEnrich\nand store")
    proc(5.55, 2.95, "3.0\nRules and\nscoring")
    proc(5.55, 1.0, "4.0\nAdapt and\nrespond", fill=FILL["act"])
    proc(3.3, 0.72, "5.0\nThreat\nintelligence", fill=FILL["ui"])
    store(2.9, 1.82, 1.7, "D1  SQLite store")
    box(ax, 6.42, 2.7, 0.76, 0.5, "Models", "#ffffff", 9, style="square")
    box(ax, 6.42, 0.76, 0.76, 0.5, "Firewall", "#ffffff", 9, style="square")
    box(ax, 0.75, 0.47, 1.0, 0.5, "Operator", "#ffffff", 9.5, style="square")
    arrow(ax, (0.94, 3.05), (1.37, 3.05), both=False)
    arrow(ax, (1.37, 2.82), (0.94, 2.82))
    arrow(ax, (2.53, 2.95), (3.17, 2.95), "events", offset=(0, 0.03))
    arrow(ax, (4.33, 2.95), (4.97, 2.95), "history", offset=(0, 0.03))
    arrow(ax, (6.42, 2.95), (6.13, 2.95))
    arrow(ax, (3.75, 2.37), (3.75, 2.16), None)
    arrow(ax, (5.55, 2.37), (5.55, 1.58), "finding", offset=(0.3, -0.05))
    arrow(ax, (6.13, 1.0), (6.42, 1.0))
    arrow(ax, (4.98, 1.25), (4.6, 1.88), None)
    arrow(ax, (3.5, 1.82), (3.4, 1.3), None)
    arrow(ax, (2.72, 0.72), (1.75, 0.72), "indicators", offset=(0, 0.03))
    poly_arrow(ax, [(6.03, 1.32), (6.27, 1.65), (6.27, 3.76), (1.95, 3.76), (1.95, 3.53)], dashed=True,
               label="persona and engagement feedback", label_at=(4.0, 3.76))
    ax.set_ylim(0.1, 3.95)
    save(fig, "dfd1")


def usecase():
    fig, ax = canvas(6.6, 3.5)

    def actor(x, y, name):
        ax.add_patch(plt.Circle((x, y + 0.42), 0.09, facecolor="white", edgecolor=INK, linewidth=0.9))
        ax.plot([x, x], [y + 0.33, y + 0.05], color=INK, linewidth=0.9)
        ax.plot([x - 0.14, x + 0.14], [y + 0.24, y + 0.24], color=INK, linewidth=0.9)
        ax.plot([x, x - 0.11], [y + 0.05, y - 0.13], color=INK, linewidth=0.9)
        ax.plot([x, x + 0.11], [y + 0.05, y - 0.13], color=INK, linewidth=0.9)
        ax.text(x, y - 0.27, name, ha="center", fontsize=9.5)

    def case(x, y, text, w=1.65, h=0.42, fill=FILL["decoy"]):
        ax.add_patch(matplotlib.patches.Ellipse((x, y), w, h, facecolor=fill, edgecolor=INK, linewidth=0.8))
        ax.text(x, y, text, ha="center", va="center", fontsize=8.8)

    ax.add_patch(Rectangle((0.95, 0.06), 4.7, 3.36, facecolor="none", edgecolor=MUTED, linewidth=0.8))
    ax.text(3.3, 3.28, "AI-Adaptive Honeypot System", ha="center", va="center", fontsize=9.5, fontweight="bold")
    actor(0.42, 1.7, "Attacker")
    actor(6.15, 1.7, "Operator")
    left = [("Scan decoy ports", 2.9), ("Grab service banners", 2.3), ("Probe web paths", 1.7), ("Guess SSH passwords", 1.1), ("Reuse a honeytoken", 0.5)]
    right = [("View alerts and evidence", 2.9), ("Inspect attacker timeline", 2.3), ("Change persona or level", 1.7), ("Block or unblock an IP", 1.1), ("Export indicators", 0.5)]
    for text, y in left:
        case(2.0, y, text, fill=FILL["decoy"])
        arrow(ax, (0.62, 1.85), (1.18, y), lw=0.7)
    for text, y in right:
        case(4.6, y, text, w=1.8, fill=FILL["ui"])
        arrow(ax, (5.95, 1.85), (5.5, y), lw=0.7)
    save(fig, "usecase")


def sequence():
    fig, ax = canvas(7.2, 3.9)
    names = ["Attacker", "Decoy\nlistener", "Detection\nengine", "ML\nmodels", "Deception\npolicy", "Block\nmanager", "SQLite\nstore"]
    xs = [0.45 + i * 1.05 for i in range(7)]
    for x, name in zip(xs, names):
        box(ax, x - 0.44, 3.42, 0.88, 0.46, name, FILL["data"], 8.8)
        ax.plot([x, x], [0.08, 3.42], color=MUTED, linewidth=0.7, linestyle="--")
    rows = [
        (0, 1, 3.2, "probe, login or request", False),
        (1, 0, 2.96, "persona response", True),
        (1, 2, 2.72, "event", False),
        (2, 3, 2.48, "score flow", False),
        (3, 2, 2.24, "probabilities", True),
        (2, 6, 2.0, "store event", False),
        (2, 2, 1.76, "", False),
        (2, 4, 1.46, "finding", False),
        (4, 2, 1.22, "persona, level, reason", True),
        (2, 5, 0.98, "consider block", False),
        (5, 2, 0.74, "decision", True),
        (2, 6, 0.5, "store finding", False),
        (4, 1, 0.26, "next response uses new persona", False),
    ]
    for a, b, y, text, back in rows:
        if a == b:
            ax.text(xs[a] + 0.07, y - 0.02, "evaluate rules, fuse score, check cooldown", fontsize=8.5, va="center",
                    bbox=dict(facecolor="white", edgecolor="none", pad=0.4))
            continue
        arrow(ax, (xs[a], y), (xs[b], y), dashed=back, lw=0.85)
        ax.text((xs[a] + xs[b]) / 2, y + 0.015, text, fontsize=8.3, ha="center", va="bottom",
                bbox=dict(facecolor="white", edgecolor="none", pad=0.3))
    save(fig, "sequence")


def classdiagram():
    fig, ax = canvas(7.2, 3.55)

    def cls(x, y, w, h, name, attrs, methods, fill):
        ax.add_patch(Rectangle((x, y), w, h, facecolor=fill, edgecolor=INK, linewidth=0.9))
        ax.text(x + w / 2, y + h - 0.13, name, ha="center", va="center", fontsize=9.3, fontweight="bold")
        ax.plot([x, x + w], [y + h - 0.26, y + h - 0.26], color=INK, linewidth=0.7)
        ax.text(x + 0.05, y + h - 0.31, "\n".join(attrs), fontsize=7.9, va="top", linespacing=1.15)
        split = y + h - 0.35 - 0.15 * len(attrs)
        ax.plot([x, x + w], [split, split], color=INK, linewidth=0.7)
        ax.text(x + 0.05, split - 0.04, "\n".join(methods), fontsize=7.9, va="top", linespacing=1.15)

    cls(2.55, 1.75, 2.1, 1.75, "DetectionEngine", ["thresholds, service_ports", "history, last_finding", "stats"],
        ["observe(event)", "rules(history, now)", "ml_points(ip, now)", "evaluate(ip, now)"], FILL["detect"])
    cls(0.05, 2.0, 1.95, 1.5, "ModelBundle", ["cic, unsw (pipelines)", "cic_weight, unsw_weight"],
        ["predict(flow, recent)", "combined_points(pred)", "status()"], FILL["detect"])
    cls(5.2, 2.0, 1.95, 1.5, "DecoyPolicy", ["state per IP", "PERSONAS, MAX_LEVEL"],
        ["on_finding(finding)", "http_response(...)", "honeytoken(ip, kind)"], FILL["act"])
    cls(0.05, 0.05, 1.95, 1.45, "Event", ["kind, src_ip, dst_port", "service, ts, detail"], ["(dataclass)"], FILL["decoy"])
    cls(2.55, 0.05, 2.1, 1.45, "Store", ["SQLite connection", "events, findings, blocks"],
        ["insert_event(event)", "insert_finding(finding)", "active_blocks()"], FILL["data"])
    cls(5.2, 0.05, 1.95, 1.65, "BlockManager", ["enforce, ttl_minutes", "allowlist, max_active"],
        ["consider(finding)", "block(ip, reason)", "unblock(ip)", "expire_due(now)"], FILL["act"])
    arrow(ax, (2.55, 2.75), (2.0, 2.75), "uses", offset=(0, 0.02))
    arrow(ax, (4.65, 2.75), (5.2, 2.75), "adapts", offset=(0, 0.02))
    arrow(ax, (3.6, 1.75), (3.6, 1.5), None)
    ax.text(3.68, 1.62, "stores", fontsize=8.5, va="center")
    arrow(ax, (4.65, 1.82), (5.2, 1.5), "decides", offset=(0.02, 0.03))
    arrow(ax, (2.55, 1.82), (2.0, 1.5), "observes", offset=(-0.05, 0.03))
    save(fig, "classdiagram")


def timeline():
    phases = [
        ("Topic finalization and planning", 1, 1), ("Literature survey, objectives", 2, 2),
        ("Data, preprocessing, model design", 3, 3), ("Implementation part 1", 4, 4),
        ("Implementation part 2", 5, 5), ("Model evaluation and testing", 6, 6),
        ("Mentor review and iteration", 7, 7), ("Report preparation", 8, 8),
        ("Final submission and presentation", 9, 9), ("Final evaluation", 10, 10),
    ]
    fig, ax = plt.subplots(figsize=(6.6, 2.6))
    for i, (_name, start, end) in enumerate(phases):
        ax.barh(i, end - start + 1, left=start - 1, height=0.62, color=BLUE)
    ax.set_yticks(range(len(phases)), [p[0] for p in phases], color=INK, fontsize=9.5)
    ax.invert_yaxis()
    ax.set_xticks(range(0, 11))
    ax.set_xlabel("Project week")
    clean(ax, "x")
    ax.tick_params(length=0)
    ax.set_xlim(0, 10)
    save(fig, "timeline")


# ---------------------------------------------------------------------------
# Dataset figures
# ---------------------------------------------------------------------------

def sample_table(rows, columns, headers, name, width=7.2, formats=None):
    fig, ax = plt.subplots(figsize=(width, 0.27 * (len(rows) + 1) + 0.06))
    ax.axis("off")
    formats = formats or {}
    cells = []
    for row in rows:
        out = []
        for column in columns:
            value = row.get(column)
            if column in formats and value is not None:
                out.append(formats[column](value))
            elif isinstance(value, float) and value != value:
                out.append("-")
            else:
                out.append(str(value).strip())
        cells.append(out)
    table = ax.table(cellText=cells, colLabels=headers, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9.5)
    table.scale(1, 1.32)
    for (r, _c), cell in table.get_celld().items():
        cell.set_edgecolor(MUTED)
        cell.set_linewidth(0.5)
        if r == 0:
            cell.set_facecolor("#e6e5df")
            cell.set_text_props(fontweight="bold")
    save(fig, name)


def samples():
    rows = CIC["samples"]["BENIGN"][:3] + CIC["samples"]["PortScan"][:3]
    sample_table(
        rows,
        ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "Label"],
        ["Dst Port", "Flow Duration", "Fwd Pkts", "Bwd Pkts", "Flow Bytes/s", "Flow Pkts/s", "SYN", "Label"],
        "sample_cic",
        formats={"Destination Port": lambda v: f"{v:.0f}", "Flow Duration": lambda v: f"{v:.0f}",
                 "Total Fwd Packets": lambda v: f"{v:.0f}", "Total Backward Packets": lambda v: f"{v:.0f}",
                 "Flow Bytes/s": lambda v: f"{v:,.1f}", "Flow Packets/s": lambda v: f"{v:,.1f}",
                 "SYN Flag Count": lambda v: f"{v:.0f}"},
    )
    rows = UNSW["samples"]["Normal"][:3] + UNSW["samples"]["Reconnaissance"][:3]
    sample_table(
        rows,
        ["dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "rate", "attack_cat"],
        ["dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "rate", "attack_cat"],
        "sample_unsw",
        formats={"dur": lambda v: f"{v:.6f}", "rate": lambda v: f"{v:,.1f}"},
    )


def class_distribution():
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.45))
    groups = [
        (axes[0], "CIC-IDS2017 Friday PortScan file",
         ["As supplied", "After de-duplication"], "BENIGN", "PortScan",
         [CIC["class_counts"]["BENIGN"], CIC["after_dedup_counts"]["BENIGN"]],
         [CIC["class_counts"]["PortScan"], CIC["after_dedup_counts"]["PortScan"]]),
        (axes[1], "UNSW-NB15, two-class subset",
         ["Training file", "Testing file"], "Normal", "Reconnaissance",
         [UNSW["train_two_class"]["Normal"], UNSW["test_two_class"]["Normal"]],
         [UNSW["train_two_class"]["Reconnaissance"], UNSW["test_two_class"]["Reconnaissance"]]),
    ]
    for ax, title, ticks, label_a, label_b, a, b in groups:
        positions = range(len(ticks))
        ax.bar([p - 0.19 for p in positions], a, 0.36, color=BLUE, label=label_a)
        ax.bar([p + 0.19 for p in positions], b, 0.36, color=ORANGE, label=label_b)
        for p, value in zip(positions, a):
            ax.text(p - 0.19, value, f"{value:,}", ha="center", va="bottom", fontsize=9, color=INK)
        for p, value in zip(positions, b):
            ax.text(p + 0.19, value, f"{value:,}", ha="center", va="bottom", fontsize=9, color=INK)
        ax.set_xticks(list(positions), ticks, color=INK)
        ax.set_title(title, fontsize=10.5)
        ax.set_ylabel("Rows")
        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v / 1000:.0f}k"))
        ax.set_ylim(0, max(a + b) * 1.2)
        clean(ax)
        ax.tick_params(length=0)
        ax.legend(loc="upper right", fontsize=9)
    fig.tight_layout(w_pad=2)
    save(fig, "class_distribution")


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

def confusion():
    rf_cic = CIC["held_out"]["Random Forest (project)"]
    rf_unsw = UNSW["held_out"]["Random Forest (project)"]
    fig, axes = plt.subplots(1, 2, figsize=(6.4, 2.65))
    panels = [(axes[0], rf_cic, "CIC-IDS2017 held-out test", ["BENIGN", "PortScan"]),
              (axes[1], rf_unsw, "UNSW-NB15 official test", ["Normal", "Recon."])]
    for ax, m, title, labels in panels:
        grid = [[m["tn"], m["fp"]], [m["fn"], m["tp"]]]
        totals = [m["tn"] + m["fp"], m["fn"] + m["tp"]]
        for r in range(2):
            for c in range(2):
                share = grid[r][c] / totals[r]
                ax.add_patch(Rectangle((c, 1 - r), 1, 1, facecolor=SEV["HIGH"] if share > 0.5 else "#eef3fa",
                                       edgecolor="white", linewidth=2))
                ax.text(c + 0.5, 1 - r + 0.58, f"{grid[r][c]:,}", ha="center", va="center", fontsize=13,
                        fontweight="bold", color="white" if share > 0.5 else INK)
                ax.text(c + 0.5, 1 - r + 0.3, f"{share:.2%} of row", ha="center", va="center", fontsize=8.8,
                        color="white" if share > 0.5 else MUTED)
        ax.set_xlim(0, 2)
        ax.set_ylim(0, 2)
        ax.set_xticks([0.5, 1.5], labels, color=INK)
        ax.set_yticks([1.5, 0.5], labels, color=INK)
        ax.set_xlabel("Predicted class")
        ax.set_ylabel("Actual class")
        ax.set_title(title, fontsize=10.5)
        ax.tick_params(length=0)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_aspect("equal")
    fig.tight_layout(w_pad=2.5)
    save(fig, "confusion")


def roc_pr():
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.0))
    all_curves = {"Random Forest (project)": UNSW["curves"], **UNSW["baseline_curves"]}
    order = ["Random Forest (project)", "Hist. Gradient Boosting", "Decision Tree", "Logistic Regression", "Gaussian Naive Bayes"]
    for name in order:
        curve = all_curves[name]
        lw = 2 if name.startswith("Random") else 1.3
        z = 5 if name.startswith("Random") else 2
        axes[0].plot(curve["fpr"], curve["tpr"], color=CURVE_COLORS[name], linewidth=lw, label=name, zorder=z)
        axes[1].plot(curve["recall"], curve["precision"], color=CURVE_COLORS[name], linewidth=lw, label=name, zorder=z)
    axes[0].plot([0, 1], [0, 1], color=MUTED, linewidth=0.7, linestyle="--")
    axes[0].set_xlabel("False positive rate")
    axes[0].set_ylabel("True positive rate (recall)")
    axes[0].set_title("ROC curves", fontsize=10.5)
    axes[1].set_xlabel("Recall")
    axes[1].set_ylabel("Precision")
    axes[1].set_title("Precision-recall curves", fontsize=10.5)
    for ax in axes:
        clean(ax, "both")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.02)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=3, fontsize=9, bbox_to_anchor=(0.5, -0.12))
    fig.tight_layout(w_pad=2)
    save(fig, "roc_pr")


def thresholds():
    rows = UNSW["threshold_sweep"]
    x = [r["threshold"] for r in rows]
    fig, ax = plt.subplots(figsize=(5.4, 2.5))
    ax.plot(x, [r["precision"] for r in rows], color=BLUE, linewidth=2, marker="o", markersize=4.5, label="Precision")
    ax.plot(x, [r["recall"] for r in rows], color=ORANGE, linewidth=2, marker="s", markersize=4.5, label="Recall")
    ax.axvline(0.5, color=MUTED, linewidth=0.8, linestyle="--")
    ax.text(0.51, 0.66, "default threshold 0.5", fontsize=9, color=MUTED)
    ax.set_xlabel("Decision threshold on the attack probability")
    ax.set_ylabel("Score")
    ax.set_ylim(0.6, 1.02)
    ax.legend(loc="lower right", fontsize=9.5)
    clean(ax, "both")
    save(fig, "thresholds")


LIVE_CIC = {
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes", "SYN Flag Count",
    "ACK Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Max Packet Length", "Min Packet Length", "Packet Length Mean",
}
LIVE_UNSW = {
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload", "smean", "dmean",
    "trans_depth", "is_ftp_login", "ct_ftp_cmd", "is_sm_ips_ports", "ct_srv_src", "ct_src_ltm",
    "ct_dst_ltm", "ct_dst_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_srv_dst", "ct_flw_http_mthd",
}


def importance():
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.0))
    panels = [(axes[0], CIC["importances"][:10], LIVE_CIC, "CIC-IDS2017 PortScan model"),
              (axes[1], UNSW["importances"][:10], LIVE_UNSW, "UNSW-NB15 reconnaissance model")]
    for ax, rows, live, title in panels:
        names = [r["feature"] for r in rows][::-1]
        values = [r["importance"] for r in rows][::-1]
        colors = [BLUE if n in live or n.split("_")[0] in ("proto", "service", "state") else ORANGE for n in names]
        ax.barh(names, values, color=colors, height=0.66)
        ax.set_title(title, fontsize=10.5)
        ax.set_xlabel("Gini importance")
        ax.tick_params(axis="y", labelcolor=INK, length=0)
        clean(ax, "x")
    handles = [Rectangle((0, 0), 1, 1, color=BLUE), Rectangle((0, 0), 1, 1, color=ORANGE)]
    fig.legend(handles, ["Measured by the live sensor", "Not measured live (imputed)"], loc="lower center",
               ncol=2, fontsize=9.5, bbox_to_anchor=(0.5, -0.07))
    fig.tight_layout(w_pad=1.5)
    save(fig, "importance")


def scenario_outcomes():
    rows = SCEN["scenarios"]
    names = [r["scenario"] for r in rows]
    fig, ax = plt.subplots(figsize=(7.2, 5.4))
    positions = []
    y = 0
    previous = None
    for r in rows:
        if previous and r["group"] != previous:
            y += 0.6
        positions.append(y)
        previous = r["group"]
        y += 1
    left = [0.0] * len(rows)
    for level in ("HIGH", "MEDIUM", "LOW"):
        values = [r[level.lower()] for r in rows]
        ax.barh(positions, values, left=left, height=0.72, color=SEV[level], label=level, edgecolor="white", linewidth=1)
        for pos, value, start in zip(positions, values, left):
            if value >= 6:
                ax.text(start + value / 2, pos, str(value), ha="center", va="center", fontsize=9,
                        color="white" if level != "LOW" else INK)
        left = [a + b for a, b in zip(left, values)]
    none = [r["trials"] - r["detected"] for r in rows]
    ax.barh(positions, none, left=left, height=0.72, color=SEV["No alert"], label="No alert", edgecolor="white", linewidth=1)
    for pos, value, start in zip(positions, none, left):
        if value >= 6:
            ax.text(start + value / 2, pos, str(value), ha="center", va="center", fontsize=9, color=MUTED)
    ax.set_yticks(positions, names, color=INK, fontsize=9.5)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Randomized sessions out of 100, by strongest alert raised")
    ax.tick_params(length=0)
    clean(ax, None)
    ax.spines["left"].set_visible(False)
    group_labels = {"attack": "Attack", "evasive": "Low and slow", "benign": "Normal use"}
    seen = set()
    for r, pos in zip(rows, positions):
        if r["group"] not in seen:
            seen.add(r["group"])
            ax.text(101, pos - 0.1, group_labels[r["group"]], fontsize=9.5, fontweight="bold", va="center", color=INK)
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, 1.09), ncol=4, fontsize=9.5)
    save(fig, "scenario_outcomes")


def score_parts():
    rows = [r for r in SCEN["scenarios"] if r["group"] == "attack"]
    names = [r["scenario"] for r in rows]
    rules = [r["mean_rule_points"] for r in rows]
    ml = [r["mean_ml_points"] for r in rows]
    fig, ax = plt.subplots(figsize=(6.6, 2.7))
    ax.barh(names, rules, color=BLUE, height=0.66, label="Rule points", edgecolor="white", linewidth=1)
    ax.barh(names, ml, left=rules, color=ORANGE, height=0.66, label="ML points", edgecolor="white", linewidth=1)
    for i, (a, b) in enumerate(zip(rules, ml)):
        ax.text(a + b + 1, i, f"{a + b:.1f}", va="center", fontsize=9.5, color=INK)
    ax.axvline(75, color=MUTED, linewidth=0.8, linestyle="--")
    ax.axvline(45, color=MUTED, linewidth=0.8, linestyle="--")
    ax.text(75.5, -0.82, "HIGH", fontsize=9, color=MUTED)
    ax.text(45.5, -0.82, "MEDIUM", fontsize=9, color=MUTED)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Mean score of the strongest finding")
    ax.tick_params(axis="y", labelcolor=INK, length=0)
    ax.legend(loc="lower right", fontsize=9.5)
    clean(ax, "x")
    save(fig, "score_parts")


ADAPT = json.loads((ROOT / "report/data/adaptive_evaluation.json").read_text(encoding="utf-8"))


def adaptive_curve():
    fig, ax = plt.subplots(figsize=(6.2, 2.9))
    colors = {"oracle": MUTED, "learning": BLUE, "static": ORANGE, "rotation": AQUA}
    labels = {"oracle": "Oracle (upper bound)", "learning": "Learning policy (UCB1)",
              "static": "Static decoy", "rotation": "Round-robin rotation"}
    for name in ("oracle", "learning", "rotation", "static"):
        curve = ADAPT["policies"][name]["curve_per_50"]
        x = [50 * (i + 1) for i in range(len(curve))]
        ax.plot(x, curve, color=colors[name], linewidth=2.2 if name == "learning" else 1.5,
                linestyle="--" if name == "oracle" else "-", marker="o", markersize=3.5, label=labels[name])
    ax.set_xlabel("Simulated attacker sessions seen so far")
    ax.set_ylabel("Mean interactions per session")
    ax.set_ylim(0, 13)
    ax.legend(loc="lower right", fontsize=9.5, ncol=2)
    clean(ax, "y")
    save(fig, "adaptive_curve")


def live_run():
    db = sqlite3.connect(f"file:{ROOT / 'honeypot-backend/sensor/data/sensor.sqlite3'}?mode=ro", uri=True)
    rows = db.execute("select classification, severity, count(*) from findings group by 1, 2").fetchall()
    events = dict(db.execute("select kind, count(*) from events group by 1").fetchall())
    summary = {
        "events": sum(events.values()), "events_by_kind": events,
        "findings": sum(r[2] for r in rows),
        "findings_by_class_severity": [list(r) for r in rows],
        "sources": db.execute("select count(distinct src_ip) from events").fetchone()[0],
        "decoy_actions": db.execute("select count(*) from decoy_actions").fetchone()[0],
        "honeytokens": db.execute("select count(*) from honeytokens").fetchone()[0],
        "blocks": [list(r) for r in db.execute("select status, mode, source, count(*) from blocks group by 1, 2, 3")],
        "mean_ml_points": db.execute("select avg(ml_points) from findings").fetchone()[0],
        "mean_rule_points": db.execute("select avg(rule_points) from findings").fetchone()[0],
        "first_utc": db.execute("select datetime(min(ts), 'unixepoch') from events").fetchone()[0],
        "last_utc": db.execute("select datetime(max(ts), 'unixepoch') from events").fetchone()[0],
    }
    db.close()
    (ROOT / "report/data/live_run_summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    classes = sorted({r[0] for r in rows}, key=lambda c: -sum(r[2] for r in rows if r[0] == c))
    table = Counter({(r[0], r[1]): r[2] for r in rows})
    fig, ax = plt.subplots(figsize=(6.2, 2.25))
    left = [0] * len(classes)
    for level in ("HIGH", "MEDIUM", "LOW"):
        values = [table[(c, level)] for c in classes]
        ax.barh(classes, values, left=left, color=SEV[level], label=level, height=0.66, edgecolor="white", linewidth=1)
        for i, value in enumerate(values):
            if value:
                ax.text(left[i] + value / 2, i, str(value), ha="center", va="center", fontsize=9.5,
                        color="white" if level != "LOW" else INK)
        left = [a + b for a, b in zip(left, values)]
    ax.invert_yaxis()
    ax.set_xlabel("Findings logged by the sensor")
    ax.tick_params(axis="y", labelcolor=INK, length=0)
    ax.legend(loc="lower right", fontsize=9.5)
    clean(ax, "x")
    save(fig, "live_run")


def main():
    import matplotlib.ticker  # noqa: F401
    for draw in (architecture, methodology, flowchart, dfd0, dfd1, usecase, sequence, classdiagram, timeline,
                 samples, class_distribution, confusion, roc_pr, thresholds, importance,
                 scenario_outcomes, score_parts, adaptive_curve, live_run):
        draw()


if __name__ == "__main__":
    main()
