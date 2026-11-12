"""Assemble both report versions and build them with real page numbers.

    python assemble.py A|B|all

Version A follows 2.Chapters.docx (five chapters: Introduction, Literature Survey,
System Development, Datasets and Evaluation Parameters, Conclusion and Future
Scope). Version B follows the contents list of 1.front Pages.docx (Introduction,
Literature Survey, Methodology, Result and Discussion, Conclusion and Future Scope).
Front matter follows 1.front Pages.docx; the acknowledgement of version A uses the
wording of 3. references and acknowledge.docx.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pymupdf  # noqa: E402
from docx.enum.text import WD_ALIGN_PARAGRAPH  # noqa: E402
from docx.shared import Cm, Inches, Pt  # noqa: E402

import blocks_1 as b1  # noqa: E402
import blocks_2 as b2  # noqa: E402
import blocks_3 as b3  # noqa: E402
from docx_lib import RED, ROMAN, Doc, roman_lower, set_font  # noqa: E402
from facts import (ALL_REF_KEYS, CIC, LIVE, ROOT, SC, ST, STB, TESTS_TOTAL, UNSW, format_ref, n, pct)  # noqa: E402

TITLE = "AI-Adaptive Honeypot for Network Deception and Threat Intelligence"
STUDENTS = [("Parth Badgujar", "AI3305"), ("Srujal Zanwar", "AI3331")]
GUIDE = "Prof. Y. R. Tayade"
BY_LINE = " and ".join(f"{name} (Roll No. {roll})" for name, roll in STUDENTS)
FIG_DIR = ROOT / "report" / "figures"
SHOT_DIR = ROOT / "report" / "screens_web"
LOGO_BATU = ROOT / "report" / "assets" / "batu.png"
LOGO_CSMSS = ROOT / "report" / "assets" / "csmss.jpg"
OUT_DIR = ROOT / "report" / "output"
WORK = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "report" / "work"
PS_EXPORT = WORK / "to_pdf.ps1"

# ----------------------------------------------------------------------
# Structure of the two versions
# ----------------------------------------------------------------------

def H1(title, key=None): return [("H1", title, key)]
def H1U(title, key=None): return [("H1U", title, key)]
def H2(title, key=None): return [("H2", title, key)]


def structure_A():
    s = []
    s += H1("INTRODUCTION")
    s += H2("Introduction") + b1.intro
    s += H2("Objectives") + b1.objectives
    s += H2("Necessity") + b1.necessity
    s += H2("Challenges") + b1.challenges_field
    s += H2("Applications") + b1.applications
    s += H2("Organization of Report") + b1.org_a
    s += H1("LITERATURE SURVEY")
    s += H2("Literature Survey") + b1.lit_themes
    s += H2("Summary of Literature") + b1.lit_summary
    s += H2("Research Gap and Motivation") + b1.gap
    s += H1("SYSTEM DEVELOPMENT")
    s += H2("Model Development") + b2.model_dev + b2.schedule
    s += H2("Architecture Diagram") + b2.architecture_intro
    s += [("h3", "Decoy services")] + b2.blk_decoys
    s += [("h3", "Telemetry and event normalisation")] + b2.blk_telemetry
    s += [("h3", "Detection engine")] + b2.blk_detection
    s += [("h3", "Attacker profiling and ATT&CK mapping")] + b2.blk_profile
    s += [("h3", "Adaptive deception")] + b2.blk_deception
    s += [("h3", "Response, intelligence and interfaces")] + b2.blk_response
    s += [("h3", "System modelling diagrams")] + b2.uml_blocks
    s += H2("Algorithms", "algo") + b2.algorithms
    s += H2("Technology Stack") + b2.tech_stack
    s += H2("Datasets") + b2.datasets
    s += H1("DATASETS AND EVALUATION PARAMETERS")
    s += H2("Dataset Preprocessing and Splits") + b3.preprocessing + b3.dataset_analysis
    s += H2("Performance Metrics") + b3.metrics
    s += H2("Result Analysis and Discussion")
    s += [("h3", "Model results")] + b3.results_models
    s += [("h3", "Models with live-measurable features")] + b3.results_live_features
    s += [("h3", "Generalisation to other capture days")] + b3.results_other_days
    s += [("h3", "Detection engine")] + b3.results_scenarios
    s += [("h3", "Behaviour model trained on sensor telemetry")] + b3.results_behaviour
    s += [("h3", "Adaptive deception")] + b3.results_adaptive
    s += [("h3", "System testing")] + b3.testing
    s += [("h3", "User interface")] + b3.ui_design
    s += [("h3", "Screenshots")] + b3.screenshots
    s += [("h3", "Run on the development machine")] + b3.results_live
    s += H2("Comparative Analysis") + b3.comparative
    s += H1("CONCLUSION AND FUTURE SCOPE")
    s += H2("Conclusion") + b3.conclusion
    s += H2("Limitations and Future Scope")
    s += [("h3", "Limitations")] + b3.limitations
    s += [("h3", "Future scope")] + b3.future
    return s


def structure_B():
    s = []
    s += H1("INTRODUCTION")
    s += H2("Overview") + b1.intro
    s += H2("Motivation") + b1.necessity
    s += H2("Problem Definition") + b1.problem_def
    s += H2("Objectives") + b1.objectives
    s += H2("Project Scope and Limitation") + b1.scope_limits
    s += H2("Methodologies of Problem Solving") + b1.problem_solving + b2.schedule
    s += H2("Organization of the Report") + b1.org_b
    s += H1("LITERATURE SURVEY")
    s += H2("Existing System (Paragraph and Tabular)") + b1.lit_themes
    s += H2("Research Gap") + b1.gap
    s += H2("Proposed System") + b1.proposed_system
    s += H2("Summary of Literature Survey") + b1.lit_summary
    s += H1("METHODOLOGY")
    s += H2("Overview") + b2.model_dev[:2]
    s += H2("Problem Formulation") + b2.formulation
    s += H2("System Architecture / Block Diagram") + b2.architecture_intro
    s += [("h3", "Block 1: Decoy services")] + b2.blk_decoys
    s += [("h3", "Block 2: Telemetry and event normalisation")] + b2.blk_telemetry
    s += [("h3", "Block 3: Detection engine")] + b2.blk_detection
    s += [("h3", "Block 4: Attacker profiling and ATT&CK mapping")] + b2.blk_profile
    s += [("h3", "Block 5: Adaptive deception")] + b2.blk_deception
    s += [("h3", "Block 6: Response, intelligence and interfaces")] + b2.blk_response
    s += [("h3", "System modelling diagrams")] + b2.uml_blocks
    s += H2("Hardware Requirement") + [b2.tech_stack[0], b2.tech_stack[2]]
    s += H2("Software Requirement") + [b2.tech_stack[1]]
    s += H2("Flow Chart and Explanation") + b2.model_dev[2:]
    s += H2("Algorithm / Pseudocode", "algo") + b2.algorithms
    s += H2("Datasets") + b2.datasets
    s += H1("RESULT AND DISCUSSION")
    s += H2("Dataset Analysis") + b3.preprocessing + b3.dataset_analysis
    s += H2("Performance Evaluation Metrics") + b3.metrics
    s += H2("Result and Comparative Analysis")
    s += [("h3", "Model results")] + b3.results_models
    s += [("h3", "Models with live-measurable features")] + b3.results_live_features
    s += [("h3", "Generalisation to other capture days")] + b3.results_other_days
    s += [("h3", "Detection engine")] + b3.results_scenarios
    s += [("h3", "Behaviour model trained on sensor telemetry")] + b3.results_behaviour
    s += [("h3", "Adaptive deception")] + b3.results_adaptive
    s += [("h3", "Run on the development machine")] + b3.results_live
    s += [("h3", "Comparison with the literature")] + b3.comparative
    s += H2("User Interface Design and Implementation") + b3.ui_design
    s += H2("Testing (Test Cases and Validation)") + b3.testing
    s += H2("Challenges Identified") + b3.challenges_impl
    s += H2("Screenshots") + b3.screenshots
    s += H1("CONCLUSION AND FUTURE SCOPE")
    s += H2("Conclusion") + b3.conclusion
    s += H2("Limitations") + b3.limitations
    s += H2("Future Scope") + b3.future
    s += H2("Application") + b1.applications
    return s


# ----------------------------------------------------------------------
# Numbering scan
# ----------------------------------------------------------------------

CITE = re.compile(r"\{c:([^}]+)\}")
REF = re.compile(r"\{(fig|tab|eq|sec):([^}]+)\}")


def strings_of(block):
    kind = block[0]
    if kind in ("p", "pn"):
        yield block[1]
    elif kind in ("bullets", "numbered"):
        yield from block[1]
    elif kind == "tab":
        yield block[2]
        yield from block[3]
        for row in block[4]:
            yield from row
    elif kind == "fig":
        yield block[3]
    elif kind == "eq":
        yield block[2]


def fix_order(entries):
    """Place the paragraph that explains a figure or table before it when it directly follows it."""
    entries = list(entries)
    changed = True
    while changed:
        changed = False
        for i, block in enumerate(entries):
            if block[0] not in ("fig", "tab"):
                continue
            tag = "{%s:%s}" % (block[0], block[1])
            first = next((j for j in range(len(entries)) if tag in " ".join(strings_of(entries[j]))), None)
            if first is not None and first > i and first - i <= 3 and entries[first][0] == "p":
                entries.insert(i, entries.pop(first))
                changed = True
                break
    return entries


def scan(doc: Doc, entries):
    ch = sec = sub = 0
    counters = {"fig": 0, "tab": 0, "eq": 0}
    doc.sec_no, defined, first_ref, toc, figs, tabs = {}, {}, {}, [], [], []
    for index, block in enumerate(entries):
        kind = block[0]
        if kind == "H1":
            ch += 1
            sec = sub = 0
            counters = {"fig": 0, "tab": 0, "eq": 0}
            toc.append({"level": 1, "num": f"{ch}.", "title": block[1], "head": f"CHAPTER {ROMAN[ch]} – {block[1]}"})
        elif kind == "H1U":
            toc.append({"level": 0, "num": "", "title": block[1], "head": block[1]})
        elif kind == "H2":
            sec += 1
            sub = 0
            number = f"{ch}.{sec}"
            if block[2]:
                doc.sec_no[block[2]] = number
            toc.append({"level": 2, "num": number, "title": block[1], "head": f"{number} {block[1]}"})
        elif kind == "h3":
            sub += 1
            toc.append({"level": 3, "num": f"{ch}.{sec}.{sub}", "title": block[1], "head": f"{ch}.{sec}.{sub} {block[1]}"})
        elif kind in ("fig", "tab", "eq"):
            counters[kind] += 1
            number = f"{ch}.{counters[kind]}"
            {"fig": doc.fig_no, "tab": doc.tab_no, "eq": doc.eq_no}[kind][block[1]] = number
            defined[(kind, block[1])] = index
            if kind == "fig":
                figs.append({"num": number, "title": block[3]})
            if kind == "tab":
                tabs.append({"num": number, "title": block[2]})
        for text in strings_of(block):
            for match in CITE.finditer(text):
                for key in match.group(1).split(","):
                    key = key.strip()
                    if key not in doc.cite_order:
                        doc.cite_order.append(key)
            for match in REF.finditer(text):
                first_ref.setdefault((match.group(1), match.group(2)), index)
    problems = [f"{k} {key} used at {first_ref[(k, key)]} before it appears at {defined[(k, key)]}"
                for (k, key) in defined if (k, key) in first_ref and first_ref[(k, key)] > defined[(k, key)] and k in ("fig", "tab")]
    problems += [f"{k}:{key} placed at {defined[(k, key)]} but first referenced at {first_ref[(k, key)]}" for (k, key) in []]
    unreferenced = [f"{k}:{key}" for (k, key) in defined if (k, key) not in first_ref and k != "eq"]
    return toc, figs, tabs, problems, unreferenced


# ----------------------------------------------------------------------
# Front matter
# ----------------------------------------------------------------------

def line(doc, text="", size=12, bold=False, italic=False, align=WD_ALIGN_PARAGRAPH.CENTER, before=0, after=0,
         spacing=1.15, red=False, pb=False, indent=False, keep=False):
    para = doc.d.add_paragraph()
    para.alignment = align
    pf = para.paragraph_format
    pf.line_spacing, pf.space_before, pf.space_after = spacing, Pt(before), Pt(after)
    pf.page_break_before = pb
    pf.keep_with_next = keep
    if indent:
        pf.first_line_indent = Cm(1.25)
    if text:
        doc.rich(para, text, size, bold, italic, color=RED if red else None)
    return para


def logo(doc, path, width, before=4, after=4):
    para = doc.d.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    para.paragraph_format.space_before, para.paragraph_format.space_after = Pt(before), Pt(after)
    para.paragraph_format.line_spacing = 1.0
    para.add_run().add_picture(str(path), width=Inches(width))
    return para


def cover(doc):
    line(doc, "Dr. Babasaheb Ambedkar Technological University, Lonere", 16, True, spacing=1.2, after=4)
    logo(doc, LOGO_BATU, 1.05)
    line(doc, "A", 12, True, before=6)
    line(doc, "Seminar & Mini-Project Report", 16, True, before=2)
    line(doc, "on", 16, True, before=2)
    line(doc, f"“{TITLE}”", 16, True, spacing=1.25, before=4, after=4)
    line(doc, "Submitted in partial fulfillment of the requirements of the degree of Bachelor of Technology in "
              "Artificial Intelligence and Data Science", 14, spacing=1.25, before=4)
    line(doc, "by", 14, before=4)
    for name, roll in STUDENTS:
        line(doc, name, 14, True, before=8)
        line(doc, f"Roll No.: {roll}", 14, True, before=3)
    line(doc, "Under the guidance of", 14, before=10)
    line(doc, GUIDE, 14, True, before=2)
    logo(doc, LOGO_CSMSS, 1.0, 8, 4)
    line(doc, "Department of Artificial Intelligence and Data Science", 14, True, before=2)
    line(doc, "CSMSS", 14, True, before=6)
    line(doc, "Chh. Shahu College of Engineering,", 14, True, before=2)
    line(doc, "Chh. Sambhajinagar", 14, True, before=2)
    line(doc, "Academic Year: 2026 – 2027", 14, True, before=6)


def signature_table(doc, guide=True):
    rows = [[GUIDE, "Dr. S. R. Zanwar"], ["Guide", "HOD"],
            ["Department of Artificial Intelligence and Data Science", "Department of Artificial Intelligence and Data Science"],
            ["CSMSS Chh. Shahu College of Engineering, Kanchanwadi, Chhatrapati Sambhajinagar",
             "CSMSS Chh. Shahu College of Engineering, Kanchanwadi, Chhatrapati Sambhajinagar"]]
    doc.borderless_table(rows, [2.9, 2.9], 11, ["c", "c"], header=False, line_spacing=1.0, row_pad=1)


def principal_block(doc):
    line(doc, "Dr. G. B. Dongre", 12, before=22)
    line(doc, "Principal", 12, True)
    line(doc, "CSMSS Chh. Shahu College of Engineering, Kanchanwadi,", 12)
    line(doc, "Chhatrapati Sambhajinagar", 12)


def approval_certificate(doc):
    line(doc, "THESIS APPROVAL CERTIFICATE", 14, True, pb=True, before=6, after=10)
    para = line(doc, "", align=WD_ALIGN_PARAGRAPH.JUSTIFY, spacing=1.5, indent=True, after=8)
    doc.rich(para, f"This is to certify that the research work embodied in this thesis entitled **“{TITLE.upper()}”** "
                   f"has been carried out by {BY_LINE}, students of CSMSS's Chh. Shahu College of Engineering, "
                   "Chhatrapati Sambhajinagar, and is hereby approved for the award of the degree of Bachelor of Technology in "
                   "Artificial Intelligence and Data Science of Dr. Babasaheb Ambedkar Technological University, Lonere.", 14)
    line(doc, "Date:", 12, align=WD_ALIGN_PARAGRAPH.LEFT, before=6)
    line(doc, "Place:", 12, align=WD_ALIGN_PARAGRAPH.LEFT, before=3, after=18)
    signature_table(doc)
    line(doc, "Examiners Name & Sign", 13, before=26)
    line(doc, "__________________________________", 13, before=14)
    principal_block(doc)


def certificate(doc):
    logo(doc, LOGO_BATU, 1.05, 0, 6).paragraph_format.page_break_before = True
    line(doc, "CERTIFICATE", 14, True, before=6, after=10)
    para = line(doc, "", align=WD_ALIGN_PARAGRAPH.JUSTIFY, spacing=1.35, indent=True, after=6)
    doc.rich(para, f"This is to certify that the research work embodied in this thesis entitled **“{TITLE}”** has been "
                   f"carried out by **{STUDENTS[0][0]} (Roll No. {STUDENTS[0][1]})** and **{STUDENTS[1][0]} "
                   f"(Roll No. {STUDENTS[1][1]})**, studying at CSMSS's Chh. Shahu College of Engineering, Chhatrapati "
                   "Sambhajinagar, in partial fulfillment of the requirements for the award of the degree of Bachelor of "
                   "Technology in the **Department of Artificial Intelligence and Data Science** of Dr. Babasaheb Ambedkar "
                   "Technological University, Lonere.", 13)
    para = line(doc, "", align=WD_ALIGN_PARAGRAPH.JUSTIFY, spacing=1.35, indent=True, after=6)
    doc.rich(para, "This research work has been carried out under my guidance and supervision and is found satisfactory "
                   "for the submission of the degree of Bachelor of Technology.", 13)
    line(doc, "Date:", 12, True, align=WD_ALIGN_PARAGRAPH.LEFT, before=6)
    line(doc, "Place:", 12, True, align=WD_ALIGN_PARAGRAPH.LEFT, before=3, after=18)
    signature_table(doc)
    principal_block(doc)


ACK_B = [
    "First and foremost, we would like to express our sincere gratitude to Almighty God for His blessings, guidance, and strength "
    "throughout the completion of this project.",
    f"We are deeply indebted to our project guide, {GUIDE}, for invaluable guidance, constant encouragement, insightful "
    "suggestions, and continuous support during the course of this work. Our guide's expertise, patience, and motivation have "
    "been instrumental in the successful completion of this project.",
    "We take this opportunity to express our heartfelt thanks to Dr. S. R. Zanwar, Head of the Department, Artificial "
    "Intelligence and Data Science and, Dr. G. B. Dongre, Principal, CSMSS's Chh. Shahu College of Engineering, Chhatrapati "
    "Sambhajinagar, for providing the necessary facilities, encouragement, and academic environment for carrying out this "
    "project successfully.",
    "We are also grateful to all the faculty members and staff of the Department of Artificial Intelligence and Data Science "
    "for their valuable support and cooperation throughout our academic journey.",
    "We would like to extend our sincere thanks to our families and friends for their unwavering encouragement, moral support, "
    "and motivation, which helped us overcome challenges and successfully complete this project.",
    "Finally, we express our gratitude to everyone who directly or indirectly contributed to the successful completion of this work.",
]
ACK_A = [
    "It gives us great pleasure to submit this Project. This is the only page where we have the opportunity to express our "
    "emotions and gratitude from the bottom of our hearts.",
    f"We express our sincere thanks to our guide **{GUIDE}** for guiding us at every step in the making of this Project. "
    "Our guide motivated us and boosted our confidence, and we must admit that the work would not have been accomplished "
    "without that guidance and encouragement.",
    "We are also thankful to project coordinator **Dr. V. S. Karwande** for guiding and encouraging us as and when required.",
    "We would like to extend our special thanks to Head of the Department **Dr. S. R. Zanwar** and the Principal **Dr. G. B. "
    "Dongre** for spending their valuable time going through our report and providing many helpful suggestions. Lastly, we would "
    "like to thank all the staff members of the Artificial Intelligence and Data Science Department without whom the project "
    "report would not have been completed.",
]


def acknowledgement(doc, version):
    line(doc, "ACKNOWLEDGEMENT", 14, True, pb=True, before=6, after=8)
    for text in (ACK_A if version == "A" else ACK_B):
        para = line(doc, "", align=WD_ALIGN_PARAGRAPH.JUSTIFY, spacing=1.5, indent=True, after=6)
        doc.rich(para, text, 12)
    for i, (name, roll) in enumerate(STUDENTS):
        line(doc, f"{name} (Roll No. {roll})", 12, True, align=WD_ALIGN_PARAGRAPH.RIGHT, before=18 if i == 0 else 2)
    line(doc, "T.Y. (Artificial Intelligence and Data Science)", 12, align=WD_ALIGN_PARAGRAPH.RIGHT, before=2)


def abstract(doc):
    line(doc, "ABSTRACT", 14, True, before=6, after=10)
    live_recall = pct(CIC["held_out_live_features_only"]["recall"], 1)
    texts = [
        "Reconnaissance is the first stage of most network attacks, and conventional honeypots are static and easy to "
        "fingerprint. This project developed an AI-adaptive honeypot sensor for network deception and threat intelligence. "
        "The sensor hosts a fake SSH server, a fake web application and nine bait TCP services, converts every interaction into "
        "a common event record, and scores each source with behavioural rules over sliding windows together with two Random "
        "Forest models trained on CIC-IDS2017 and UNSW-NB15, and a behaviour model (Random Forest with an Isolation Forest) "
        "trained on the sensor's own event format. Thirteen rule classes cover reconnaissance, SSH password guessing, "
        "honeytoken reuse and web attacks. Findings carry an attacker profile and MITRE ATT&CK techniques; a learning policy "
        "(UCB1), steered by the profile, chooses the decoy persona from the attacker's continued engagement; a guarded block "
        "manager acts through Windows Defender Firewall or Linux iptables, optionally after operator approval; and indicators "
        "are exported as STIX 2.1.",
        f"The Random Forests were re-evaluated with de-duplicated, leakage-controlled splits and reached F1-scores of "
        f"{CIC['held_out']['Random Forest (project)']['f1']:.4f} (CIC-IDS2017 port scan) and "
        f"{UNSW['held_out']['Random Forest (project)']['f1']:.4f} (UNSW-NB15 reconnaissance). The sensor can measure only 40% and 60% of "
        f"their features; with the rest masked, the CIC-IDS2017 model kept {live_recall} recall while the UNSW-NB15 model needed "
        f"recalibration. Over {n(sum(s['trials'] for s in SC['scenarios']))} randomised sessions the detection engine found all "
        f"{n(ST['attack_trials'])} attack sessions with the correct class, but with rules alone it missed all low-and-slow "
        f"attacks and raised alerts for {n(ST['fp'])} of {n(ST['neg'])} normal-use sessions. Adding the behaviour model detected "
        f"{n(STB['evasive_detected'])} of the {n(STB['evasive_trials'])} low-and-slow sessions and raised recall from "
        f"{pct(ST['recall'], 1)} to {pct(STB['recall'], 1)} with no new false alarm. In a simulation with stated assumptions, "
        f"the learning policy raised the mean attacker interactions per session by 68% over a static decoy. A suite of "
        f"{TESTS_TOTAL} automated tests passes. The report states the limitations openly: no field deployment, a behaviour "
        "model trained on lab sessions only, and a small contribution of the pretrained models to the live score.",
    ]
    for text in texts:
        para = line(doc, "", align=WD_ALIGN_PARAGRAPH.JUSTIFY, spacing=1.5, indent=True, after=4)
        doc.rich(para, text, 12)
    para = line(doc, "", align=WD_ALIGN_PARAGRAPH.JUSTIFY, spacing=1.5, before=8)
    doc.rich(para, "**KEYWORDS:** Honeypot, Adaptive deception, Reconnaissance detection, Random Forest, Threat intelligence, "
                   "MITRE ATT&CK", 12)


ABBR = [("AI", "Artificial intelligence"), ("API", "Application programming interface"), ("ATT&CK", "Adversarial Tactics, Techniques and Common Knowledge"),
        ("AUC", "Area under the curve"), ("CIC-IDS2017", "Canadian Institute for Cybersecurity intrusion detection dataset 2017"),
        ("CSV", "Comma-separated values"), ("DFD", "Data flow diagram"), ("DDoS", "Distributed denial of service"),
        ("DQN", "Deep Q-network"), ("FPR", "False-positive rate"), ("HTTP", "Hypertext Transfer Protocol"),
        ("ICMP", "Internet Control Message Protocol"), ("IDS", "Intrusion detection system"), ("IoT", "Internet of Things"),
        ("JSON", "JavaScript Object Notation"), ("KNN", "k-nearest neighbours"), ("LLM", "Large language model"),
        ("MCC", "Matthews correlation coefficient"), ("MDP", "Markov decision process"), ("ML", "Machine learning"),
        ("MTD", "Moving target defence"), ("NIDS", "Network intrusion detection system"), ("PR", "Precision–recall"),
        ("RF", "Random Forest"), ("RL", "Reinforcement learning"), ("ROC", "Receiver operating characteristic"),
        ("SQL", "Structured Query Language"), ("SSH", "Secure Shell"), ("SSRF", "Server-side request forgery"),
        ("STIX", "Structured Threat Information Expression"), ("SVM", "Support vector machine"), ("TCP", "Transmission Control Protocol"),
        ("TTL", "Time to live"), ("TTP", "Tactics, techniques and procedures"), ("UCB1", "Upper confidence bound algorithm 1"),
        ("UNSW-NB15", "University of New South Wales network benchmark dataset 2015"), ("XSS", "Cross-site scripting")]


def abbreviations(doc):
    line(doc, "LIST OF ABBREVIATIONS", 14, True, pb=True, before=6, after=8)
    rows = [["SN", "Symbol", "Illustrations"]] + [[str(i), a, b] for i, (a, b) in enumerate(ABBR, 1)]
    doc.borderless_table(rows, [0.5, 1.4, 3.9], 11.5, ["l", "l", "l"], line_spacing=1.1, row_pad=2)


def list_page(doc, heading, rows, label):
    line(doc, heading, 14, True, pb=True, before=6, after=8)
    data = [[label, "Title", "Page No."]] + [[r["num"], r["title"], str(r["page"])] for r in rows]
    doc.borderless_table(data, [0.7, 4.3, 0.8], 11.5, ["l", "l", "c"], line_spacing=1.05, row_pad=2)


def toc_page(doc, toc, extra_front, pages):
    line(doc, "TABLE OF CONTENTS", 14, True, pb=True, before=6, after=8)
    rows = [["Sr. No.", "Title of Chapter", "Page No."]]
    for title, page in extra_front:
        rows.append(["", f"**{title}**", f"**{page}**"])
    for item in toc:
        if item["level"] == 1:
            rows.append([f"**{item['num']}**", f"**{item['title']}**", f"**{pages.get(item['head'], '')}**"])
        elif item["level"] == 0:
            rows.append(["", f"**{item['title']}**", f"**{pages.get(item['head'], '')}**"])
        elif item["level"] == 2:
            rows.append([item["num"], item["title"], str(pages.get(item["head"], ""))])
        else:
            rows.append([item["num"], f" {item['title']}", str(pages.get(item["head"], ""))])
    table = doc.borderless_table(rows, [0.65, 4.65, 0.55], 11, ["c", "l", "c"], line_spacing=1.05, row_pad=1.5)
    return table


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------

def render_main(doc, entries, toc_iter):
    toc = iter(toc_iter)
    for block in entries:
        kind = block[0]
        if kind in ("H1", "H1U", "H2", "h3"):
            item = next(toc)
            if kind in ("H1", "H1U"):
                doc.heading(1, item["head"])
            elif kind == "H2":
                doc.heading(2, item["head"])
            else:
                doc.heading(3, item["head"])
        elif kind == "p":
            doc.p(block[1])
        elif kind == "pn":
            doc.p(block[1], indent=False)
        elif kind == "bullets":
            doc.bullets(block[1])
        elif kind == "numbered":
            doc.numbered(block[1])
        elif kind == "code":
            doc.code(block[1], block[2])
        elif kind == "eq":
            doc.equation(block[1], block[2])
        elif kind == "fig":
            name = block[2]
            path = SHOT_DIR / (name.split(":")[1] + ".jpg") if name.startswith("SCREEN:") else FIG_DIR / name
            doc.figure(block[1], path, block[3], block[4])
        elif kind == "tab":
            doc.table(block[1], block[2], block[3], block[4], block[5], block[6], block[7], block[8])


def references(doc):
    doc.heading(1, "REFERENCES")
    for i, key in enumerate(doc.cite_order, 1):
        para = doc.d.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        pf = para.paragraph_format
        pf.left_indent, pf.first_line_indent = Cm(1.0), Cm(-1.0)
        pf.line_spacing, pf.space_after = 1.5, Pt(2)
        pf.tab_stops.add_tab_stop(Cm(1.0))
        run = para.add_run(f"[{i}]\t")
        set_font(run, 12)
        doc.rich(para, format_ref(key), 12)


def appendices(doc):
    doc.heading(1, "APPENDICES")
    doc.p("Appendix I contains the main source code. Appendices II to IV are provided for the documents that the "
          "department requires and that cannot be generated by the project: the student attaches them here.", indent=False)
    doc.heading(2, "Appendix - I: Code")
    render_main(doc, [b for b in b3.appendix_code if b[0] != "h3_unused"], iter([{"head": b[1]} for b in b3.appendix_code if b[0] == "h3"]))
    for title, note in (("Appendix - II: Publications", "Attach the details or first page of any paper or poster published from this work."),
                        ("Appendix - III: Courses & Certifications", "Attach copies of the courses and certifications completed in connection with this project."),
                        ("Appendix - IV: Plagiarism Report", "Attach the plagiarism report generated by the institute's software for this report.")):
        heading = doc.heading(2, title)
        heading.paragraph_format.page_break_before = True
        doc.p(f"[{note}]", indent=False, italic=True)


def to_pdf(docx: Path, pdf: Path):
    WORK.mkdir(parents=True, exist_ok=True)
    PS_EXPORT.write_text(
        "param([string]$In,[string]$Out)\n$w=New-Object -ComObject Word.Application;$w.Visible=$false;$w.DisplayAlerts=0\n"
        "try{$d=$w.Documents.Open($In,$false,$true);$d.ExportAsFixedFormat($Out,17);Write-Output ('pages='+$d.ComputeStatistics(2));$d.Close(0)}finally{$w.Quit()}\n",
        encoding="utf-8")
    result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(PS_EXPORT),
                             "-In", str(docx), "-Out", str(pdf)], capture_output=True, text=True, timeout=600)
    if not pdf.exists():
        raise SystemExit("PDF export failed: " + result.stdout + result.stderr)
    return result.stdout.strip()


def norm(text):
    return re.sub(r"\s+", " ", text.replace("–", "-").replace("‑", "-")).strip().lower()


def page_map(pdf: Path, toc, figs, tabs):
    doc = pymupdf.open(pdf)
    raw = [re.sub(r"\s+", " ", page.get_text().replace("–", "-")) for page in doc]
    texts = [norm(page.get_text()) for page in doc]
    first_abs = next(i for i, t in enumerate(texts) if "abstract" in t and "keywords:" in t)
    body = next(i for i, t in enumerate(texts) if i > first_abs and norm(toc[0]["head"]) in t)
    pages, cursor = {}, body
    for item in toc:
        upper = item["head"].isupper() or item["head"].startswith("CHAPTER")
        key = re.sub(r"\s+", " ", item["head"].replace("–", "-")) if upper else norm(item["head"])
        haystack = raw if upper else texts
        for i in range(cursor, len(texts)):
            if key in haystack[i]:
                pages[item["head"]] = i - body + 1
                cursor = i
                break
    fig_pages, cursor = {}, body
    for f in figs:
        key = norm(f"Figure {f['num']}:")
        for i in range(cursor, len(texts)):
            if key in texts[i]:
                fig_pages[f["num"]], cursor = i - body + 1, i
                break
    tab_pages, cursor = {}, body
    for t in tabs:
        key = norm(f"Table {t['num']}:")
        for i in range(cursor, len(texts)):
            if key in texts[i]:
                tab_pages[t["num"]], cursor = i - body + 1, i
                break
    marks = {"abstract": first_abs}
    for name, needle in (("toc", "table of contents"), ("abbr", "list of abbreviations"),
                         ("figs", "list of figures"), ("tabs", "list of tables")):
        marks[name] = next((i for i, t in enumerate(texts) if i >= first_abs and needle in t[:60]), first_abs)
    front = {name: roman_lower(i - first_abs + 1) for name, i in marks.items()}
    return pages, fig_pages, tab_pages, front, len(texts), body, len(texts) - body


def clean_caption(text):
    return re.sub(r"\{c:[^}]+\}", "", re.sub(r"[*_`]", "", text)).replace(" ,", ",").strip()


def build(version, pages=None, fig_pages=None, tab_pages=None, front=None, out=None):
    structure = fix_order(structure_A() if version == "A" else structure_B())
    doc = Doc()
    toc, figs, tabs, problems, unref = scan(doc, structure)
    for key in list(doc.cite_order):
        assert key in ALL_REF_KEYS, key
    pages = pages or {}
    fig_pages, tab_pages = fig_pages or {}, tab_pages or {}
    front = front or {k: "i" for k in ("abstract", "toc", "abbr", "figs", "tabs")}

    cover(doc)
    approval_certificate(doc)
    certificate(doc)
    acknowledgement(doc, version)
    doc.new_section("lowerRoman", 1)
    abstract(doc)
    toc_with_refs = toc + [{"level": 0, "num": "", "title": "REFERENCES", "head": "REFERENCES"},
                           {"level": 0, "num": "", "title": "APPENDICES", "head": "APPENDICES"},
                           {"level": 3, "num": "", "title": "Appendix - I: Code", "head": "Appendix - I: Code"},
                           {"level": 3, "num": "", "title": "Appendix - II: Publications", "head": "Appendix - II: Publications"},
                           {"level": 3, "num": "", "title": "Appendix - III: Courses & Certifications", "head": "Appendix - III: Courses & Certifications"},
                           {"level": 3, "num": "", "title": "Appendix - IV: Plagiarism Report", "head": "Appendix - IV: Plagiarism Report"}]
    extra = [("List of Abbreviations", front["abbr"]), ("List of Figures", front["figs"]),
             ("List of Tables", front["tabs"]), ("Abstract", front["abstract"])]
    toc_page(doc, toc_with_refs, extra, pages)
    abbreviations(doc)
    list_page(doc, "LIST OF FIGURES", [{**f, "title": clean_caption(f["title"]), "page": fig_pages.get(f["num"], "")} for f in figs], "SN.")
    list_page(doc, "LIST OF TABLES", [{**t, "title": clean_caption(t["title"]), "page": tab_pages.get(t["num"], "")} for t in tabs], "Table No.")
    doc.new_section("decimal", 1)
    render_main(doc, structure, [dict(t) for t in toc])
    references(doc)
    appendices(doc)
    doc.d.core_properties.title = f"{TITLE} – Seminar & Mini-Project Report"
    doc.d.core_properties.author = ", ".join(name for name, _ in STUDENTS)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(out)
    return doc, toc_with_refs, figs, tabs, problems, unref


def run(version):
    name = "Report_A_Chapters_format" if version == "A" else "Report_B_FrontPages_format"
    docx = OUT_DIR / f"{name}.docx"
    WORK.mkdir(parents=True, exist_ok=True)
    pdf = WORK / f"{name}.pdf"
    doc, toc, figs, tabs, problems, unref = build(version, out=docx)
    print(version, "build 1; citations:", len(doc.cite_order), "| order problems:", problems, "| unreferenced:", unref, flush=True)
    for attempt in range(3):
        info = to_pdf(docx, pdf)
        pages, fig_pages, tab_pages, front, total, body, body_pages = page_map(pdf, toc, figs, tabs)
        print(version, f"pass {attempt + 1}:", info, "| body starts at pdf page", body + 1, "| body pages", body_pages, flush=True)
        key = (tuple(sorted(pages.items())), tuple(sorted(fig_pages.items())), tuple(sorted(tab_pages.items())))
        if attempt and key == last:
            break
        last = key
        build(version, pages, fig_pages, tab_pages, front, out=docx)
    missing = [i["head"] for i in toc if i["head"] not in pages]
    print(version, "headings without page:", missing[:5], "| figs", len(fig_pages), "/", len(figs), "| tabs", len(tab_pages), "/", len(tabs))
    to_pdf(docx, pdf)
    return docx, pdf


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    for v in ("A", "B") if which == "all" else (which,):
        run(v)
