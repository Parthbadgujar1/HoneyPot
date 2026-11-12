"""Build the seminar presentation on the department's PPT format file.

    python build_ppt.py <PPT format.pptx> <output.pptx>
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from PIL import Image  # noqa: E402
from pptx import Presentation  # noqa: E402
from pptx.dml.color import RGBColor  # noqa: E402
from pptx.enum.text import PP_ALIGN  # noqa: E402
from pptx.util import Emu, Inches, Pt  # noqa: E402

from facts import (AD, BM, CIC, LEARN, LIVE, ORACLE, ROOT, SC, SCB, ST, STB, STATIC, TESTS_EXT, TESTS_LOOP,  # noqa: E402
                   TESTS_ORIGINAL, TESTS_TOTAL, UNSW, GAIN, n, pct, f3, f4)

SRC, OUT = Path(sys.argv[1]), Path(sys.argv[2])
FIG, SHOT = ROOT / "report" / "figures", ROOT / "report" / "screens_web"
TITLE = "AI-Adaptive Honeypot for Network Deception and Threat Intelligence"
FONT = "Times New Roman"
RED, NAVY, GREY = RGBColor(0xC0, 0, 0), RGBColor(0, 0x20, 0x60), RGBColor(0x59, 0x59, 0x59)
RF = "Random Forest (project)"
STUDENTS = [("Parth Badgujar", "AI3305"), ("Srujal Zanwar", "AI3331")]
CLASS_DIV = "T.Y. AI & DS"
GUIDE = "Prof. Y. R. Tayade"
CH, UH = CIC["held_out"], UNSW["held_out"]

prs = Presentation(str(SRC))
layout = prs.slides[1].slide_layout
footer_src = [sh for sh in prs.slides[1].shapes if sh.is_placeholder and sh.placeholder_format.idx in (10, 11, 12)]
notes: dict = {}


def style(run, size, bold=False, italic=False, color=None):
    run.font.name = FONT
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    if color is not None:
        run.font.color.rgb = color


def new_slide(title, note=""):
    slide = prs.slides.add_slide(layout)
    for element in footer_src:
        slide.shapes._spTree.append(copy.deepcopy(element._element))
    t = slide.shapes.title
    t.left, t.top, t.width, t.height = Inches(0.6), Inches(0.25), Inches(12.1), Inches(0.9)
    t.text_frame.text = title
    for run in t.text_frame.paragraphs[0].runs:
        style(run, 36, True, color=RED)
    if note:
        slide.notes_slide.notes_text_frame.text = note
    return slide


def body(slide):
    for sh in slide.placeholders:
        if sh.placeholder_format.idx == 1:
            return sh
    return None


def bullets(slide, items, left=0.7, top=1.4, width=11.9, height=5.3, size=20, space=8, ph=True):
    shape = body(slide) if ph else None
    if shape is None:
        shape = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
        shape.text_frame.word_wrap = True
    shape.left, shape.top, shape.width, shape.height = Inches(left), Inches(top), Inches(width), Inches(height)
    tf = shape.text_frame
    tf.word_wrap = True
    first = True
    for item in items:
        text, level = (item, 0) if isinstance(item, str) else item
        para = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        para.level = level
        para.space_after = Pt(space)
        bold_prefix, _, rest = text.partition("||")
        if rest:
            r1 = para.add_run()
            r1.text = bold_prefix
            style(r1, size - 2 * level, True)
            r2 = para.add_run()
            r2.text = rest
            style(r2, size - 2 * level)
        else:
            r = para.add_run()
            r.text = text
            style(r, size - 2 * level)
    return shape


def drop_body(slide):
    shape = body(slide)
    if shape is not None:
        shape._element.getparent().remove(shape._element)


def picture(slide, path, left, top, max_w, max_h):
    with Image.open(path) as im:
        w, h = im.size
    scale = min(max_w / w, max_h / h)
    pw, ph = w * scale, h * scale
    return slide.shapes.add_picture(str(path), Inches(left + (max_w - pw) / 2), Inches(top + (max_h - ph) / 2), Inches(pw), Inches(ph))


def caption(slide, text, left, top, width, size=12):
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(0.4))
    box.text_frame.word_wrap = True
    para = box.text_frame.paragraphs[0]
    para.alignment = PP_ALIGN.CENTER
    run = para.add_run()
    run.text = text
    style(run, size, italic=True, color=GREY)


def table(slide, header, rows, left, top, width, col_w, size=14, row_h=0.4):
    shape = slide.shapes.add_table(len(rows) + 1, len(header), Inches(left), Inches(top), Inches(width), Inches(row_h * (len(rows) + 1)))
    tbl = shape.table
    total = sum(col_w)
    for i, w in enumerate(col_w):
        tbl.columns[i].width = Inches(width * w / total)
    for r, values in enumerate([header] + rows):
        tbl.rows[r].height = Inches(row_h)
        for c, value in enumerate(values):
            cell = tbl.cell(r, c)
            cell.margin_left = cell.margin_right = Inches(0.06)
            cell.margin_top = cell.margin_bottom = Inches(0.03)
            tf = cell.text_frame
            tf.word_wrap = True
            run = tf.paragraphs[0].add_run()
            run.text = str(value)
            style(run, size, bold=(r == 0), color=RGBColor(255, 255, 255) if r == 0 else None)
            if r == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(0xED, 0x7D, 0x31)
    return shape


# ----------------------------------------------------------------------
# Slide 1: title
# ----------------------------------------------------------------------
s1 = prs.slides[0]
title_shape = next(sh for sh in s1.shapes if sh.name == "Title 1" and sh.is_placeholder)
para = title_shape.text_frame.paragraphs[0]
runs = para.runs
for run in runs:
    if run.text.startswith("Title"):
        run.text = TITLE
        run.font.size = Pt(34)
for run in runs[-1:]:
    if run.text == "":
        pass
for shape in s1.shapes:
    if shape.has_text_frame:
        for p_ in shape.text_frame.paragraphs:
            for run in p_.runs:
                if run.text.strip().startswith("Prof."):
                    run.text = GUIDE
    if shape.has_table:
        for row, (name, roll) in enumerate(STUDENTS, start=1):
            for col, value in ((1, name), (2, CLASS_DIV), (3, roll)):
                frame = shape.table.cell(row, col).text_frame
                para0 = frame.paragraphs[0]
                if para0.runs:
                    para0.runs[0].text = value
                    for extra in para0.runs[1:]:
                        extra.text = ""
                else:
                    run = para0.add_run()
                    run.text = value
                    style(run, 14)
s1.notes_slide.notes_text_frame.text = (f"Introduce the project title, the guide ({GUIDE}) and the team: "
                                        + " and ".join(f"{a} ({b})" for a, b in STUDENTS) + ".")

# ----------------------------------------------------------------------
# Content slides
# ----------------------------------------------------------------------
s = new_slide("Introduction", "Reconnaissance is the first step of most attacks. A honeypot turns that around: anything that touches it is suspicious.")
bullets(s, [
    "Attacks start with reconnaissance: port scans, banner grabs, sensitive-file requests, password guessing.",
    "A honeypot is a decoy: no legitimate user needs it, so every interaction is suspicious (Spitzner, 2003).",
    "Static decoys are easy to fingerprint; adaptive decoys react to what the attacker does.",
    "This project: an AI-adaptive honeypot sensor on one Windows machine, connecting decoys, detection, learning deception, guarded response and threat-intelligence export.",
], size=26, space=16)

s = new_slide("Problem Statement", "State the problem as a decision problem and say how success is measured.")
bullets(s, [
    "Design a honeypot sensor that detects reconnaissance and common web attacks in real time, with explainable evidence.",
    "It must adapt the decoy to each attacker using feedback from the attacker’s own behaviour.",
    "It must respond safely and reversibly, and export structured threat intelligence.",
    "Success is measured by: detection recall, precision and false alarms; interactions per attacker session; and safety (no input executed, no self-blocking).",
], size=26, space=16)

s = new_slide("Literature Survey (Summary of Existing Methods)", "25 studies from 2023 to 2026 were reviewed; these eight show the range.")
drop_body(s)
table(s, ["Study", "Method", "Reported result"], [
    ["Q-Cowrie (2026)", "Reinforcement learning on Cowrie SSH honeypot", "Adaptive responses from an MDP of attackers"],
    ["Varadarajan (2026)", "Seq2Seq + Deep Q-learning web honeypot", "Session length 3.2 to 7.8 exchanges"],
    ["shelLM (2024)", "LLM-generated Linux shell", "True-negative rate 0.90 (human judges)"],
    ["Lim (2026)", "Clustering of SSH honeypot command chains", "176 patterns in 18 clusters, mapped to ATT&CK"],
    ["Lanka (2024)", "LLM analysis of honeypot data", "Faster detection reported"],
    ["More (2024)", "Random Forest on UNSW-NB15", "Accuracy 98.63%, F1 97.80%"],
    ["Lanvin (2023)", "Audit of CICIDS2017", "Dataset errors change measured results"],
    ["Elangovan (2026)", "Cross-dataset generalisation", "Macro-F1 0.84–0.96 falls to 0.69–0.78"],
], 0.6, 1.4, 12.1, [2.2, 4.6, 4.6], size=16, row_h=0.6)

s = new_slide("Limitations / Research Gap of Existing Methods", "Each gap maps to a part of this project.")
drop_body(s)
table(s, ["Gap in the literature", "Response in this project"], [
    ["Adaptive honeypots cover one protocol (SSH or HTTP)", "SSH, HTTP and 9 bait services with one persona"],
    ["Adaptation rarely closed with detection and response", "One loop: detect, profile, adapt, respond, export"],
    ["ML results from offline files; live-feature mismatch unmeasured", "Coverage measured; behaviour model trained on the sensor's own features"],
    ["Benchmark duplicates and errors inflate scores", "De-duplication, overlap removal, other-day tests"],
    ["Few honest adaptive-versus-static comparisons", "Static, rotation, learning and oracle compared with stated assumptions"],
], 0.6, 1.5, 12.1, [5.6, 6.0], size=18, row_h=0.85)

s = new_slide("Proposed Research Objectives", "Each objective can be checked against a test or a measurement.")
bullets(s, [
    "Implement SSH, HTTP and nine bait decoys that never execute attacker input.",
    "Detect 7 reconnaissance and 6 web-attack classes with explainable evidence and a 0–100 score.",
    "Add two Random Forests (CIC-IDS2017, UNSW-NB15), re-evaluate them leakage-free, and train a behaviour model on the sensor's own events.",
    "Learn which decoy persona keeps each attack class engaged (UCB1).",
    "Respond with guarded blocks (Windows or Linux, optional approval); export ATT&CK indicators and STIX 2.1.",
    f"Measure with tests, {n(sum(x['trials'] for x in SC['scenarios']))} randomised sessions and a simulation; report limits.",
], size=24, space=12)

s = new_slide("Methodology", "Two tracks: offline model development and the online sensor.")
drop_body(s)
picture(s, FIG / "methodology.png", 0.6, 1.4, 12.1, 4.7)
caption(s, "Offline: clean, de-duplicate, split, train, validate, test. Online: events, enrichment, rules, fusion, adapt, respond, export.", 0.6, 6.2, 12.1, 14)

s = new_slide("Proposed System Architecture", "Four layers with a feedback path from the deception policy to the decoys.")
drop_body(s)
picture(s, FIG / "architecture.png", 0.5, 1.3, 6.9, 5.5)
bullets(s, [
    "Decoys||: SSH (Paramiko), HTTP, 9 bait services, firewall-log reader",
    "Detection||: 13 rule classes, two pretrained Random Forests, behaviour model",
    "Response||: profile-steered learning persona policy, guarded block manager (netsh / iptables, approval), SQLite store",
    "Interfaces||: operator console, FastAPI bridge, React dashboard, STIX export",
], left=7.6, top=1.6, width=5.2, height=4.8, size=19, space=14, ph=False)

s = new_slide("Detection Flow and Score Fusion", "How one event becomes a finding.")
drop_body(s)
picture(s, FIG / "flowchart.png", 0.5, 1.2, 5.0, 5.65)
bullets(s, [
    "Rule points R = min(90, strongest + 10 × (k − 1))",
    "Model points ML = round(30·p_CIC + 10·p_UNSW) + B (behaviour model, ≤ 20)",
    "Score S = min(100, R + ML); LOW < 45 ≤ MEDIUM < 75 ≤ HIGH",
    "Cooldown 120 s stops repeated findings unless severity rises",
    "Block only if class is blocking and S ≥ 75, never for protected addresses; optionally after approval",
], left=5.8, top=1.6, width=7.0, height=4.8, size=20, space=14, ph=False)

s = new_slide("Datasets", "Two public datasets, one binary task each.")
drop_body(s)
table(s, ["Item", "CIC-IDS2017 (port scan)", "UNSW-NB15 (reconnaissance)"], [
    ["Features", "78 flow features", "42 (39 numeric, 3 categorical)"],
    ["Positive class", f"PortScan {n(CIC['class_counts']['PortScan'])}", f"Reconnaissance {n(UNSW['train_two_class']['Reconnaissance'])} train / {n(UNSW['test_two_class']['Reconnaissance'])} test"],
    ["Negative class", f"BENIGN {n(CIC['class_counts']['BENIGN'])}", f"Normal {n(UNSW['train_two_class']['Normal'])} / {n(UNSW['test_two_class']['Normal'])}"],
    ["Cleaning", f"{n(CIC['duplicate_rows'])} duplicates removed, 727 inf values fixed", f"{n(UNSW['train_rows_also_in_test'])} train rows also in test removed"],
    ["Split", "Stratified 70 / 10 / 20, seed 42", "Official train and test; 87.5 / 12.5 train and validation"],
], 0.6, 1.5, 12.1, [1.6, 4.6, 5.0], size=17, row_h=0.8)

s = new_slide("Technology Stack (Methods / Techniques / Algorithms)", "Versions were read from the project environment.")
drop_body(s)
table(s, ["Layer", "Technology"], [
    ["Language and ML", "Python 3.13, scikit-learn 1.6.1 (Random Forest, Isolation Forest), pandas, NumPy"],
    ["Decoys", "Paramiko 5.1 (SSH), Starlette / Uvicorn (HTTP), asyncio bait listeners"],
    ["Storage", "SQLite (sensor); SQLAlchemy and PostgreSQL (original backend)"],
    ["Response", "Windows Firewall (netsh) or Linux iptables; UCB1 learning policy; Docker image"],
    ["Intelligence", "MITRE ATT&CK mapping, STIX 2.1 export, JSON / CSV indicators"],
    ["Interfaces", "FastAPI 0.147, React 19, Vite 8, Recharts 3"],
    ["Quality", f"{TESTS_TOTAL} automated tests (unittest), sandbox run with browser tests"],
], 0.6, 1.4, 12.1, [2.4, 9.2], size=16, row_h=0.62)

s = new_slide("Algorithms", "Three small algorithms: fusion, Random Forest scoring and the UCB1 persona policy.")
bullets(s, [
    "Random Forest||: 100 trees, balanced class weights; p(x) = mean of the trees’ probabilities",
    "UCB1 persona choice||: a* = argmax [ mean reward + 0.8 × √( ln N / n_a ) ]",
    "Reward||: r = min(1, m / 10), where m = events from the attacker in the 300 s after the persona is shown",
    "Safety||: the hand-written persona is only a weak prior; every change is stored with its reason",
    "Reward measures continued interaction, not proof that the attacker was deceived",
], size=24, space=16)

s = new_slide("Performance Analysis: Model Results", "Held-out test results after de-duplication and leakage control.")
drop_body(s)
order = [("Random Forest (project)", "Random Forest"), ("Hist. Gradient Boosting", "Gradient boosting"), ("Decision Tree", "Decision tree"),
         ("Logistic Regression", "Logistic regression"), ("Gaussian Naive Bayes", "Naive Bayes")]
table(s, ["Model", "CIC-IDS2017 F1", "UNSW precision", "UNSW recall", "UNSW F1", "UNSW ROC-AUC"],
      [[label, f4(CH[k]["f1"]), pct(UH[k]["precision"], 1), pct(UH[k]["recall"], 1), f4(UH[k]["f1"]), f4(UH[k]["roc_auc"])] for k, label in order],
      0.6, 1.4, 12.1, [2.6, 1.8, 1.8, 1.7, 1.5, 1.8], size=17, row_h=0.62)
bullets(s, [
    f"5-fold cross-validation F1: {CIC['cv']['f1']['mean']:.4f} (CIC), {UNSW['cv']['f1']['mean']:.4f} (UNSW)",
    "The deployed models’ own scores cannot be trusted as held-out results, so retrained models are reported",
], left=0.7, top=5.4, width=12.0, height=1.4, size=18, space=6, ph=False)

s = new_slide("Performance Analysis: Confusion Matrices and Curves", "Tree models separate the classes well on UNSW-NB15.")
drop_body(s)
picture(s, FIG / "confusion.png", 0.4, 1.4, 6.1, 3.0)
picture(s, FIG / "roc_pr.png", 6.6, 1.4, 6.4, 3.3)
bullets(s, [
    f"CIC-IDS2017: {CH[RF]['fp']} false positive and {CH[RF]['fn']} false negatives in {n(CH[RF]['n'])} test flows",
    f"UNSW-NB15: precision {pct(UH[RF]['precision'], 1)}, recall {pct(UH[RF]['recall'], 1)}, ROC-AUC {f4(UH[RF]['roc_auc'])}",
    "Naive Bayes and logistic regression raise many false alarms on the imbalanced UNSW data",
], left=0.7, top=4.9, width=12.0, height=2.0, size=19, space=6, ph=False)

s = new_slide("Reality Check: Features a Live Sensor Can Measure", "The most important honest finding about the models.")
drop_body(s)
table(s, ["Model", "Features measured live", "Recall", "ROC-AUC"], [
    ["CIC-IDS2017 PortScan", f"{CIC['live_measured_features']} of 78", pct(CIC["held_out_live_features_only"]["recall"], 1), f4(CIC["held_out_live_features_only"]["roc_auc"])],
    ["UNSW-NB15 Reconnaissance", f"{UNSW['live_measured_features']} of 42", pct(UNSW["held_out_live_features_only"]["recall"], 1), f4(UNSW["held_out_live_features_only"]["roc_auc"])],
], 0.6, 1.5, 12.1, [3.6, 3.0, 2.0, 2.0], size=19, row_h=0.7)
bullets(s, [
    "The CIC model degrades gracefully with only 40% of its features.",
    "The UNSW model needs recalibration: the ranking is good (AUC 0.996) but probabilities fall below 0.5.",
    "So these models add only about 0–3.5 of a possible 40 points; this led to the behaviour model (next slides).",
    "Benchmark scores say little about live use (Lanvin 2023; Flood 2024; Elangovan 2026).",
], left=0.7, top=3.5, width=12.0, height=3.4, size=20, space=10, ph=False)

s = new_slide("Performance Analysis: Detection Engine", f"{n(sum(x['trials'] for x in SC['scenarios']))} randomised sessions through the real engine.")
drop_body(s)
picture(s, FIG / "scenario_outcomes.png", 0.3, 1.25, 7.6, 5.6)
bullets(s, [
    f"All {n(ST['attack_detected'])} attack sessions detected, class correct",
    f"Recall {pct(ST['recall'], 1)}, precision {pct(ST['precision'], 1)}, false-alarm rate {pct(ST['fpr'], 0)}",
    "Rules alone missed every low-and-slow session",
    "False alarms: uptime monitor, long browsing",
    f"Mean {SC['event_processing_ms']['mean']:.1f} ms per event",
], left=8.0, top=1.5, width=5.0, height=5.0, size=18, space=12, ph=False)

s = new_slide("Behaviour Model Trained on Sensor Telemetry", "Closes the gap between benchmark features and what the sensor measures.")
drop_body(s)
bullets(s, [
    "Random Forest names the family (benign, recon, credential, web, multi-stage); Isolation Forest flags the unfamiliar",
    "19 features from the sensor's own events: timing, ports, paths, web-attack matches, SSH attempts, honeytokens",
    "Labels from lab scenarios or operator labels, never from the rules",
    f"Lab cross-validation (GroupKFold by session): accuracy {pct(BM['accuracy'], 1)}, macro-F1 {f4(BM['macro_f1'])}, benign FPR {pct(BM['false_positive_rate'], 1)}",
    "Lab scores are not field accuracy: retrain on labelled real sessions",
], size=19, space=10, top=1.4, height=3.0)
table(s, ["Scenario evaluation", "Rules + pretrained", "+ behaviour model"], [
    ["Low-and-slow sessions detected", f"{ST['evasive_detected']} of {ST['evasive_trials']}", f"{STB['evasive_detected']} of {STB['evasive_trials']}"],
    ["Recall", pct(ST["recall"], 1), pct(STB["recall"], 1)],
    ["False-alarm rate", pct(ST["fpr"], 1), pct(STB["fpr"], 1)],
    ["F1-score", f3(ST["f1"]), f3(STB["f1"])],
], 0.9, 4.45, 11.5, [5.1, 3.2, 3.2], size=16, row_h=0.5)

s = new_slide("Performance Analysis: Adaptive Deception", "A simulation with stated assumptions; not field evidence.")
drop_body(s)
picture(s, FIG / "adaptive_curve.png", 0.4, 1.4, 7.2, 3.9)
bullets(s, [
    f"Static decoy: {STATIC['mean_steps']:.2f} interactions per session",
    f"Learning (UCB1): {LEARN['mean_steps']:.2f}  (+{pct(GAIN, 0)})",
    f"Oracle upper bound: {ORACLE['mean_steps']:.2f}",
    "Learns within about 100 sessions",
], left=7.8, top=1.5, width=5.1, height=3.8, size=20, space=12, ph=False)
bullets(s, ["Assumed attacker model: persist with probability 0.92 on the preferred persona, 0.80 otherwise. Real attackers need a field study."],
        left=0.7, top=5.6, width=12.0, height=1.2, size=17, ph=False)

s = new_slide("Results: Dashboard Screenshots", "Real application, started in a sandbox.")
drop_body(s)
picture(s, SHOT / "dashboard_overview.jpg", 0.4, 1.4, 6.2, 4.2)
picture(s, SHOT / "dashboard_alert_detail.jpg", 6.7, 1.4, 6.2, 4.2)
caption(s, "Security overview with live data from the sensor", 0.4, 5.7, 6.2, 14)
caption(s, "Alert detail: reasons, evidence and score", 6.7, 5.7, 6.2, 14)

s = new_slide("Results: Operator Console Screenshots", "Threat intelligence and decoy actions with reasons.")
drop_body(s)
picture(s, SHOT / "console_intel.jpg", 0.4, 1.4, 6.2, 4.2)
picture(s, SHOT / "console_decoys.jpg", 6.7, 1.4, 6.2, 4.2)
caption(s, "Threat intelligence indicators", 0.4, 5.7, 6.2, 14)
caption(s, "Decoy actions and why each was made", 6.7, 5.7, 6.2, 14)

s = new_slide("Testing and Validation", "Unit tests, integration tests on real sockets, and manual sandbox cases.")
bullets(s, [
    f"{TESTS_TOTAL} automated tests pass: {TESTS_ORIGINAL} original sensor, {TESTS_EXT} extension modules, {TESTS_LOOP} adaptive loop.",
    "Tests use a temporary database and a fake firewall runner, so no rule is created.",
    "Integration tests start the SSH, HTTP and bait decoys on loopback ports.",
    "10 manual system cases in a sandbox (decoys, dashboard, console, dry-run block): all passed.",
    f"Development run: {LIVE['events']} events, {LIVE['findings']} findings, 3 real firewall blocks created and released.",
], size=24, space=14)

s = new_slide("Applications", "Always deploy with the network team’s approval.")
bullets(s, [
    "Campus and enterprise early warning: decoys beside production systems",
    "Teaching sensor for reconnaissance and brute-force behaviour",
    "Threat-intelligence sharing with ATT&CK-mapped, STIX 2.1 indicators",
    "Research platform for comparing deception policies",
    "IoT and smart-city decoys (honeypot data improve IoT detection, Ahmed 2024)",
], size=26, space=16)

s = new_slide("Conclusion", "Summarise results and the honest limits.")
bullets(s, [
    "Delivered: one loop from decoy to detection, profile, adaptive persona, guarded response and STIX export.",
    f"Models: F1 {f4(CH[RF]['f1'])} (CIC) and {f4(UH[RF]['f1'])} (UNSW) held-out; rules carry live detection.",
    f"Engine: all attack sessions found; behaviour model raised recall {pct(ST['recall'], 1)} → {pct(STB['recall'], 1)}; learning policy +{pct(GAIN, 0)} (simulation).",
    "Limits: no field data; behaviour model lab-trained; false alarms on monitors; two data stores.",
    "Future: label real sessions and retrain, field comparison with real attackers, Linux host trial, PostgreSQL sync, TLS and roles.",
], size=22, space=14)

REFS_1 = [
    "[1] L. Spitzner, Honeypots: Tracking Hackers. Addison-Wesley, 2003.",
    "[2] M. Var Naseri et al., “Q-Cowrie: An adaptive honeypot to analyse attackers’ behaviour,” Int. J. Inf. Secur., vol. 25, no. 2, 2026.",
    "[3] Varadarajan et al., “Intelligent honeypot for web applications: Leveraging Seq2Seq and reinforcement learning,” ECTI-CIT, vol. 20, no. 2, 2026.",
    "[4] M. Sladić et al., “LLM in the shell: Generative honeypots,” in IEEE EuroS&PW, 2024, pp. 430–435.",
    "[5] C. Lim and K. Hobert, “Enhancing honeypot-based cyber attribution using hierarchical clustering,” Digit. Threats: Res. Pract., 2026.",
    "[6] A. More et al., “Enhanced intrusion detection systems performance with UNSW-NB15 data analysis,” Algorithms, vol. 17, no. 2, 2024.",
    "[7] M. Lanvin et al., “Errors in the CICIDS2017 dataset and the significant differences in detection performances it makes,” Springer LNCS, 2023.",
]
REFS_2 = [
    "[8] R. Flood et al., “Bad design smells in benchmark NIDS datasets,” in IEEE EuroS&P, 2024, pp. 658–675.",
    "[9] Elangovan et al., “Cross-dataset temporal and semantic generalization of intrusion detection models for the future internet,” Future Internet, vol. 18, no. 4, 2026.",
    "[10] I. Sharafaldin et al., “Toward generating a new intrusion detection dataset and intrusion traffic characterization,” in ICISSP, 2018, pp. 108–116.",
    "[11] N. Moustafa and J. Slay, “UNSW-NB15: A comprehensive data set for network intrusion detection systems,” in MilCIS, 2015.",
    "[12] L. Breiman, “Random forests,” Mach. Learn., vol. 45, no. 1, pp. 5–32, 2001.",
    "[13] P. Auer et al., “Finite-time analysis of the multiarmed bandit problem,” Mach. Learn., vol. 47, pp. 235–256, 2002.",
    "[14] MITRE ATT&CK; OASIS, “STIX Version 2.1,” 2021.",
]
s = new_slide("References (1/2)")
bullets(s, REFS_1, size=18, space=12)
s = new_slide("References (2/2)")
bullets(s, REFS_2, size=18, space=12)

# ----------------------------------------------------------------------
# Move the thank-you slide to the end
# ----------------------------------------------------------------------
ids = prs.slides._sldIdLst
thanks = list(ids)[2]
ids.remove(thanks)
ids.append(thanks)

OUT.parent.mkdir(parents=True, exist_ok=True)
prs.save(str(OUT))
print("saved", OUT, "slides:", len(prs.slides))
