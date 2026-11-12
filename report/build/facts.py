"""Measured numbers, helper constructors and IEEE references for the reports.

Every number in the report text comes from report/data/*.json or from counting
the project files, so the text cannot drift from the experiments.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "report" / "data"
M = json.loads((DATA / "model_evaluation.json").read_text(encoding="utf-8"))
SC = json.loads((DATA / "scenario_evaluation.json").read_text(encoding="utf-8"))
AD = json.loads((DATA / "adaptive_evaluation.json").read_text(encoding="utf-8"))
LIVE = json.loads((DATA / "live_run_summary.json").read_text(encoding="utf-8"))
REFS = json.loads((DATA / "references.json").read_text(encoding="utf-8"))
CIC, UNSW = M["cic"], M["unsw"]


# ----------------------------------------------------------------------
# Block constructors
# ----------------------------------------------------------------------

def P(text): return ("p", text)
def PN(text): return ("pn", text)
def B(items): return ("bullets", items)
def N(items): return ("numbered", items)
def H3(title): return ("h3", title)
def CODE(text, size=9): return ("code", text, size)
def E(key, text): return ("eq", key, text)
def F(key, filename, caption, width=5.6): return ("fig", key, filename, caption, width)
def T(key, caption, header, rows, widths, size=10, align=None, bold_first=False):
    return ("tab", key, caption, header, rows, widths, size, align, bold_first)


# ----------------------------------------------------------------------
# Number formatting
# ----------------------------------------------------------------------

def n(value): return f"{int(round(value)):,}"
def pct(value, digits=2): return f"{value * 100:.{digits}f}%"
def f3(value): return f"{value:.3f}"
def f4(value): return f"{value:.4f}"


def count_lines(pattern_dir: str, glob: str) -> int:
    total = 0
    for path in (ROOT / pattern_dir).glob(glob):
        total += len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    return total


SENSOR_LINES = count_lines("honeypot-backend/sensor", "*.py") + count_lines("honeypot-backend/sensor/listeners", "*.py")
BACKEND_LINES = sum(count_lines("honeypot-backend", name) for name in ("main.py", "models.py", "database.py",
                                                                       "sensor_bridge.py", "recon_detector.py",
                                                                       "deception_engine.py"))
TEST_LINES = count_lines("honeypot-backend/tests", "*.py")
FRONT_LINES = (count_lines("honeypot-frontend/src", "*.jsx") + count_lines("honeypot-frontend/src", "*.js")
               + count_lines("honeypot-frontend/src/components", "*.jsx") + count_lines("honeypot-frontend/src/services", "*.js"))
CONSOLE_LINES = count_lines("honeypot-backend/sensor/admin", "index.html")


# ----------------------------------------------------------------------
# Derived experiment figures
# ----------------------------------------------------------------------

def scenario_totals():
    attack = [s for s in SC["scenarios"] if s["group"] == "attack"]
    evasive = [s for s in SC["scenarios"] if s["group"] == "evasive"]
    benign = [s for s in SC["scenarios"] if s["group"] == "benign"]
    pos = sum(s["trials"] for s in attack + evasive)
    tp = sum(s["detected"] for s in attack + evasive)
    neg = sum(s["trials"] for s in benign)
    fp = sum(s["detected"] for s in benign)
    precision = tp / (tp + fp)
    recall = tp / pos
    return {
        "pos": pos, "tp": tp, "fn": pos - tp, "neg": neg, "fp": fp, "tn": neg - fp,
        "precision": precision, "recall": recall, "fpr": fp / neg,
        "f1": 2 * precision * recall / (precision + recall),
        "attack_trials": sum(s["trials"] for s in attack), "attack_detected": sum(s["detected"] for s in attack),
        "attack_medium_plus": sum(s["medium"] + s["high"] for s in attack),
        "attack_correct": sum(s["correct_class"] for s in attack),
        "n_attack": len(attack), "n_evasive": len(evasive), "n_benign": len(benign),
    }


ST = scenario_totals()
TOTAL_SESSIONS = sum(s["trials"] for s in SC["scenarios"])
N_SCEN = len(SC["scenarios"])
LEARN, STATIC, ROT, ORACLE = (AD["policies"][k] for k in ("learning", "static", "rotation", "oracle"))
GAIN = LEARN["mean_steps"] / STATIC["mean_steps"] - 1


# ----------------------------------------------------------------------
# IEEE references
# ----------------------------------------------------------------------

MANUAL = {
    "spitzner2003": 'L. Spitzner, __Honeypots: Tracking Hackers__. Boston, MA, USA: Addison-Wesley, 2003.',
    "provos2004": 'N. Provos, "A virtual honeypot framework," in __Proc. 13th USENIX Security Symp.__, San Diego, CA, USA, 2004, pp. 1–14.',
    "pedregosa2011": 'F. Pedregosa __et al.__, "Scikit-learn: Machine learning in Python," __J. Mach. Learn. Res.__, vol. 12, pp. 2825–2830, 2011.',
    "auer2002": 'P. Auer, N. Cesa-Bianchi, and P. Fischer, "Finite-time analysis of the multiarmed bandit problem," __Mach. Learn.__, vol. 47, nos. 2–3, pp. 235–256, 2002.',
    "attack": 'MITRE Corporation, "MITRE ATT&CK: Enterprise matrix," 2026. [Online]. Available: https://attack.mitre.org/',
    "stix21": 'OASIS Cyber Threat Intelligence Technical Committee, "STIX Version 2.1," OASIS Standard, Jun. 2021. [Online]. Available: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html',
    "cowrie": 'M. Oosterhof, "Cowrie SSH/Telnet honeypot," GitHub repository. [Online]. Available: https://github.com/cowrie/cowrie',
    "almaiah2025": 'M. A. Almaiah, R. Kadel, __et al.__, "Leveraging ACO, GA, and GWO for enhancing port scan attack detection using machine learning," __J. Cyber Secur. Risk Audit.__, vol. 2025, no. 4, pp. 306–326, 2025, doi: 10.63180/jcsra.thestap.2025.4.9.',
}

JOURNAL_ABBR = {
    "Scientific Reports": "Sci. Rep.", "Electronics": "Electronics", "IET Smart Cities": "IET Smart Cities",
    "Symmetry": "Symmetry", "Mathematics": "Mathematics", "Applied Sciences": "Appl. Sci.", "Sensors": "Sensors",
    "Algorithms": "Algorithms", "Computers": "Computers", "Future Internet": "Future Internet",
    "Modelling": "Modelling", "Applied System Innovation": "Appl. Syst. Innov.", "AI": "AI",
    "Journal of Big Data": "J. Big Data", "International Journal of Information Security": "Int. J. Inf. Secur.",
    "Digital Threats: Research and Practice": "Digit. Threats: Res. Pract.", "Machine Learning": "Mach. Learn.",
    "EURASIP Journal on Information Security": "EURASIP J. Inf. Secur.",
    "ECTI Transactions on Computer and Information Technology (ECTI-CIT)": "ECTI Trans. Comput. Inf. Technol.",
}


def _initials(given: str) -> str:
    parts = re.split(r"[\s]+", given.strip())
    out = []
    for part in parts:
        if not part:
            continue
        pieces = part.split("-")
        out.append("-".join(piece[0] + "." for piece in pieces if piece))
    return " ".join(out)


def _authors(authors) -> str:
    names = [f"{_initials(given)} {family}".strip() for family, given in authors]
    if len(names) > 6:
        return names[0] + " __et al.__"
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + ", and " + names[-1]


def format_ref(key: str) -> str:
    if key in MANUAL:
        return MANUAL[key]
    r = REFS[key]
    title = html.unescape(html.unescape(r["title"]))
    title = re.sub(r"\s*\(UNSW-NB15 network data set\)", "", title)
    venue = html.unescape(html.unescape(r["venue"]))
    text = f'{_authors(r["authors"])}, "{title}," '
    conference = r["type"] in ("proceedings-article",) or "Conference" in venue or "Symposium" in venue \
        or "Workshops" in venue or "Proceedings" in venue
    if conference:
        text += f"in __{venue}__, {r['year']}"
        if r.get("page"):
            text += f", pp. {r['page'].replace('-', chr(0x2013))}"
    elif r["type"] == "book-chapter" or venue == "Lecture Notes in Computer Science":
        text += f"in __{r['series'] if r['series'] != venue else venue}__, Springer, {r['year']}"
        text += f", pp. {r['page'].replace('-', chr(0x2013))}" if r.get("page") else ""
    else:
        text += f"__{JOURNAL_ABBR.get(venue, venue)}__"
        if r.get("volume"):
            text += f", vol. {r['volume']}"
        if r.get("issue"):
            text += f", no. {r['issue']}"
        if r.get("page"):
            text += f", pp. {r['page'].replace('-', chr(0x2013))}"
        elif r.get("article"):
            text += f", Art. no. {r['article']}"
        text += f", {r['year']}"
    return text + f", doi: {r['doi']}."


ALL_REF_KEYS = set(REFS) | set(MANUAL)
