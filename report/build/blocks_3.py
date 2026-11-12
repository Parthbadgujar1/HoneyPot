"""Chapter IV, V and appendix content blocks."""

import re

from facts import *  # noqa: F401,F403

RF = "Random Forest (project)"
CH, UH = CIC["held_out"], UNSW["held_out"]


def m_row(name, d, extra=None):
    row = [name, pct(d["accuracy"], 3), pct(d["precision"], 3), pct(d["recall"], 3), f4(d["f1"]),
           f4(d["mcc"]), f4(d["roc_auc"])]
    return row + (extra or [])


# ----------------------------------------------------------------------
# 4.1 Preprocessing, splits, dataset analysis
# ----------------------------------------------------------------------

preprocessing = [
    P("**CIC-IDS2017.** The file contained "
      f"{n(CIC['file_rows'])} flows with {CIC['missing_values']} missing values and {CIC['infinite_values']} infinite values "
      "in the rate features (division by a zero duration). Infinite values were converted to missing values, and a median "
      "imputer fitted inside the training pipeline filled all missing values, so no statistic of the test part leaked into "
      f"training. The file also held {n(CIC['duplicate_rows'])} exact duplicate rows ({pct(CIC['duplicate_rows'] / CIC['file_rows'], 1)}), "
      "typical of port-scan captures in which many identical probes occur. If left in place, identical rows can fall into both "
      f"the training and the test part and inflate the scores, so they were removed, leaving {n(CIC['after_dedup_rows'])} rows "
      f"({n(CIC['after_dedup_counts']['BENIGN'])} benign, {n(CIC['after_dedup_counts']['PortScan'])} port-scan). No two "
      "identical rows had different labels. The rows were then split with stratification into 70% training, 10% validation "
      "and 20% test parts, with a fixed random seed of 42."),
    P("**UNSW-NB15.** The official training and testing files were kept as the split, because the dataset authors defined "
      f"them. Only the Normal and Reconnaissance categories were used. Of the {n(UNSW['train_two_class']['Normal'] + UNSW['train_two_class']['Reconnaissance'])} "
      f"training rows of these categories, {n(UNSW['train_rows_also_in_test'])} also occurred in the testing file and were "
      f"removed, and exact duplicates were dropped, leaving {n(UNSW['train_after_cleaning']['Normal'] + UNSW['train_after_cleaning']['Reconnaissance'])} rows. "
      "A stratified 87.5/12.5 split of these rows gave the training and validation parts, and the whole two-class testing file "
      "served as the test part. Numeric features were imputed with the median; the categorical features proto, service "
      "and state were imputed with the most frequent value and one-hot encoded inside the pipeline."),
    P("**Prevention of data leakage.** Four measures were applied: (i) de-duplication before splitting, (ii) removal of "
      "training rows that appear in the test file, (iii) fitting every imputer and encoder inside the pipeline on the "
      "training part only, and (iv) use of the validation part, and never the test part, to choose hyperparameters. The "
      "test part was used once for the final numbers. The sizes of the parts are listed in {tab:split}, and the cleaning "
      "steps are summarised in {tab:clean}."),
    P("**Features for live traffic.** The sensor cannot measure every dataset feature. For each connection it fills the "
      "features it can compute: duration, packet and byte counts in each direction, packet sizes, rates, flag counts and, for "
      "UNSW-NB15, connection counts over the recent flows of the same source. Packet counts are estimated from application "
      "data chunks, so they are approximations of what a packet capture would show."),
    T("split", "Training, validation and test parts",
      ["Dataset", "Training", "Validation", "Test", "Positives in test"],
      [["CIC-IDS2017 PortScan", n(CIC["split"]["train"]), n(CIC["split"]["validation"]), n(CIC["split"]["test"]), n(CIC["split"]["test_positive"])],
       ["UNSW-NB15 Reconnaissance", n(UNSW["split"]["train"]), n(UNSW["split"]["validation"]), n(UNSW["split"]["test"]), n(UNSW["split"]["test_positive"])]],
      [2.0, 1.0, 1.0, 1.0, 1.2], size=9.5, align=["l", "c", "c", "c", "c"], bold_first=True),
    T("clean", "Data-cleaning summary",
      ["Item", "CIC-IDS2017", "UNSW-NB15"],
      [["Rows as supplied", n(CIC["file_rows"]), f"{n(UNSW['train_rows'])} train / {n(UNSW['test_rows'])} test"],
       ["Rows of the two classes used", n(CIC["file_rows"]), f"{n(sum(UNSW['train_two_class'].values()))} train / {n(sum(UNSW['test_two_class'].values()))} test"],
       ["Missing / infinite values", f"{CIC['missing_values']} / {CIC['infinite_values']}", f"{UNSW['missing_values_train']} / 0"],
       ["Exact duplicates removed", n(CIC["duplicate_rows"]), n(UNSW["duplicate_rows_train_two_class"])],
       ["Training rows also in test file", "not applicable", n(UNSW["train_rows_also_in_test"])],
       ["Rows after cleaning", n(CIC["after_dedup_rows"]), n(sum(UNSW["train_after_cleaning"].values()))]],
      [2.4, 1.9, 2.0], size=9.5, align=["l", "c", "c"], bold_first=True),
]

dataset_analysis = [
    P("{fig:classdist} shows the class balance before and after cleaning. The CIC-IDS2017 file was roughly balanced, with "
      "a slight majority of port-scan flows that duplicate removal reduced. UNSW-NB15 is strongly imbalanced, with "
      f"reconnaissance forming {pct(UNSW['test_two_class']['Reconnaissance'] / sum(UNSW['test_two_class'].values()), 1)} of the test rows, which is why precision and recall, and not accuracy alone, were "
      "reported and why class weights were balanced in all models."),
    F("classdist", "class_distribution.png", "Class distribution of the datasets", 5.9),
    P("In the full UNSW-NB15 files, reconnaissance is one of nine attack categories (Generic, Exploits, Fuzzers, DoS, "
      f"Reconnaissance, Analysis, Backdoor, Shellcode and Worms). Of the {n(UNSW['test_rows'])} test rows, "
      f"{n(UNSW['test_categories']['Normal'])} are normal and {n(UNSW['test_categories']['Reconnaissance'])} are reconnaissance."),
]

# ----------------------------------------------------------------------
# 4.2 Metrics
# ----------------------------------------------------------------------

metrics = [
    P("Let TP, FP, TN and FN be the numbers of true positives, false positives, true negatives and false negatives, where "
      "the positive class is the attack. The following metrics were computed."),
    H3("Classification metrics"),
    P("Accuracy is the share of correct decisions. It is misleading on imbalanced data, so it is always reported together "
      "with precision and recall:"),
    E("acc", "Accuracy = (TP + TN) / (TP + TN + FP + FN)"),
    P("Precision is the share of raised alarms that are real attacks, and recall is the share of attacks that are found:"),
    E("prec", "Precision = TP / (TP + FP)"),
    E("rec", "Recall = TP / (TP + FN)"),
    P("The F1-score is the harmonic mean of precision and recall, and the false-positive rate is the share of normal "
      "events that raise an alarm:"),
    E("f1", "F1 = 2 · Precision · Recall / (Precision + Recall)"),
    E("fpr", "FPR = FP / (FP + TN)"),
    P("The Matthews correlation coefficient is informative for imbalanced classes, and equals 1 for a perfect classifier and 0 "
      "for a random one:"),
    E("mcc", "MCC = (TP · TN − FP · FN) / √[(TP+FP)(TP+FN)(TN+FP)(TN+FN)]"),
    H3("Ranking metrics"),
    P("The area under the ROC curve (ROC-AUC) measures how well the attack probability separates the classes over all "
      "thresholds. The area under the precision–recall curve (PR-AUC) is more sensitive to the rare class. The "
      "confusion matrix lists the four counts."),
    H3("Detection-engine and engagement metrics"),
    P("For the detection engine, the unit of evaluation was a **session**, the complete activity of one source in one "
      "scenario. A session counted as detected if the engine raised at least one finding for it, and as correctly "
      "classified if one finding had the expected class. Recall, precision and false-alarm rate were then computed over "
      "sessions. Detection latency was measured as the number of events and the simulated time before the first finding. "
      "For the deception policy, engagement was the number of interactions of an attacker session before the attacker "
      "stopped."),
]

# ----------------------------------------------------------------------
# 4.3 Results
# ----------------------------------------------------------------------

def grid_rows(block):
    rows = []
    for g in block["grid"]:
        depth = g["max_depth"] if g["max_depth"] != "None" else "none"
        leaf = g.get("min_samples_leaf", 1)
        rows.append([str(g["n_estimators"]), str(depth), str(leaf), f4(g["val_f1"]), f4(g["val_precision"]),
                     f4(g["val_recall"]), f"{g['fit_s']:.1f}"])
    return rows


def recall_by_category():
    rows = []
    for item in sorted(UNSW["deployed_flag_rate_by_category"], key=lambda r: -r["sum"] / r["count"]):
        rows.append([item["cat"], n(item["count"]), n(item["sum"]), pct(item["sum"] / item["count"], 1)])
    return rows


results_models = [
    P("**Hyperparameters.** Six Random Forest settings were compared on the validation part ({tab:grid}). On CIC-IDS2017 "
      "all unrestricted forests reached the same validation F1-score of 0.9999, so the default 100 trees were kept. On "
      "UNSW-NB15 the F1-score rose slightly with 200 trees (0.9939 against 0.9934 for 100) but at roughly twice the training "
      "time, and limiting the depth to 10 lowered it to 0.9529. The configuration of the deployed models (100 trees, "
      "unrestricted depth, balanced class weights) was therefore retained."),
    T("grid", "Validation results of the hyperparameter search (CIC-IDS2017 above, UNSW-NB15 below)",
      ["Trees", "Max depth", "Min leaf", "F1", "Precision", "Recall", "Fit time (s)"],
      grid_rows(CIC) + [["—"] * 7] + grid_rows(UNSW),
      [0.6, 0.8, 0.8, 0.8, 0.9, 0.8, 0.9], size=9, align=["c"] * 7),
    P("**Comparison with baselines.** The Random Forest was compared with four other classifiers trained on the same data "
      "({tab:cic} and {tab:unsw}). On CIC-IDS2017 every tree-based model scored above 99.97%; the Random Forest produced "
      f"{CH[RF]['fp']} false positive and {CH[RF]['fn']} false negatives on {n(CH[RF]['n'])} test flows. Histogram "
      "gradient boosting was marginally better, and the difference of one or two flows is not meaningful. On UNSW-NB15 the "
      f"picture was different: Naive Bayes ({pct(UH['Gaussian Naive Bayes']['precision'], 1)} precision) and logistic regression "
      f"({pct(UH['Logistic Regression']['precision'], 1)} precision) raised many false alarms, whereas the tree-based models reached "
      f"F1-scores of 0.96–0.97. The Random Forest had the highest ROC-AUC ({f4(UH[RF]['roc_auc'])}) and PR-AUC "
      f"({f4(UH[RF]['pr_auc'])})."),
    T("cic", "Held-out test results on CIC-IDS2017 (benign versus port scan)",
      ["Model", "Accuracy", "Precision", "Recall", "F1", "MCC", "ROC-AUC"],
      [m_row(k, v) for k, v in CH.items()], [1.9, 0.8, 0.8, 0.8, 0.65, 0.65, 0.7], size=9, align=["l"] + ["c"] * 6, bold_first=True),
    T("unsw", "Held-out test results on UNSW-NB15 (normal versus reconnaissance)",
      ["Model", "Accuracy", "Precision", "Recall", "F1", "MCC", "ROC-AUC"],
      [m_row(k, v) for k, v in UH.items()], [1.9, 0.8, 0.8, 0.8, 0.65, 0.65, 0.7], size=9, align=["l"] + ["c"] * 6, bold_first=True),
    F("conf", "confusion.png", "Confusion matrices of the Random Forest on the held-out test parts", 5.6),
    F("rocpr", "roc_pr.png", "ROC and precision–recall curves of the five models on UNSW-NB15", 6.0),
    P("{fig:conf} shows the confusion matrices and {fig:rocpr} the curves. For UNSW-NB15 the Random Forest and the other "
      "tree models are close to the top-left corner, while logistic regression and Naive Bayes trade precision for recall. "
      "{fig:thr} shows how the threshold changes the balance on UNSW-NB15: raising it from 0.5 to 0.9 lifts precision "
      f"from {pct(UNSW['threshold_sweep'][4]['precision'], 1)} to {pct(UNSW['threshold_sweep'][8]['precision'], 1)} and lowers recall from "
      f"{pct(UNSW['threshold_sweep'][4]['recall'], 1)} to {pct(UNSW['threshold_sweep'][8]['recall'], 1)}. A sensor that prefers fewer false "
      "alarms could therefore use a higher threshold."),
    F("thr", "thresholds.png", "Effect of the decision threshold on precision and recall (UNSW-NB15)", 4.7),
    P("**Cross-validation.** Five-fold stratified cross-validation on the training parts gave stable results "
      f"({{tab:cv}}): the F1-score was {CIC['cv']['f1']['mean']:.4f} ± {CIC['cv']['f1']['std']:.4f} on CIC-IDS2017 and "
      f"{UNSW['cv']['f1']['mean']:.4f} ± {UNSW['cv']['f1']['std']:.4f} on UNSW-NB15, which shows that the held-out result "
      "does not depend on one lucky split."),
    T("cv", "Five-fold cross-validation of the Random Forest (mean ± standard deviation)",
      ["Dataset", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC"],
      [[name, *[f"{blk['cv'][k]['mean']:.4f} ± {blk['cv'][k]['std']:.4f}" for k in ("accuracy", "precision", "recall", "f1", "roc_auc")]]
       for name, blk in (("CIC-IDS2017", CIC), ("UNSW-NB15", UNSW))],
      [1.2, 1.0, 1.0, 1.0, 1.0, 1.0], size=8.5, align=["l"] + ["c"] * 5, bold_first=True),
    P("**The deployed models.** The two models inside the sensor were trained before this evaluation, and their training "
      "script and split are not part of the project. Evaluated on the same test parts, the deployed CIC-IDS2017 model "
      f"gave an F1-score of {f4(CIC['deployed_on_test_split_not_held_out']['f1'])}, and the deployed UNSW-NB15 model, on the "
      f"two-class test file, {f4(UNSW['deployed_test']['f1'])} (precision {pct(UNSW['deployed_test']['precision'], 1)}, recall "
      f"{pct(UNSW['deployed_test']['recall'], 1)}). The CIC-IDS2017 figure should not be read as a held-out result, because the "
      "test flows may have been in the model's training data, which cannot be verified. This is why the retrained "
      "models, which were evaluated under controlled conditions, are the numbers reported as performance."),
    P("The project documentation had reported that the UNSW-NB15 model reaches only 61% accuracy and 29% recall on its test "
      f"set. This was reproduced ({pct(UNSW['deployed_test_all_attacks_as_positive']['accuracy'], 1)} accuracy, "
      f"{pct(UNSW['deployed_test_all_attacks_as_positive']['recall'], 1)} recall), and its cause was found: that figure treats "
      "all nine attack categories as positives, whereas the model was trained only for reconnaissance. {tab:cat} shows how often "
      "it flags each category. It flags 96% of reconnaissance rows and many Analysis, Backdoor and DoS rows, but almost no "
      "Generic traffic. The low recall is therefore a property of the task definition, and does not indicate a defect of the "
      "model for the task it was built for."),
    T("cat", "Share of UNSW-NB15 test rows flagged by the deployed model, by category",
      ["Category", "Rows", "Flagged", "Share flagged"],
      recall_by_category(), [1.8, 1.2, 1.2, 1.3], size=9.5, align=["l", "c", "c", "c"], bold_first=True),
    F("imp", "importance.png", "Ten most important features of each retrained Random Forest", 6.0),
    P("**Feature importance.** {fig:imp} lists the ten most important features. For CIC-IDS2017 the leading features are the "
      "total forward bytes, the mean forward packet length and the maximum inter-arrival time of the flow; for UNSW-NB15 they "
      "are the mean destination packet size, the source time-to-live and the destination load, in agreement with the "
      "importance of sttl, sload and dload reported in {c:alkhater2026}. Most of the leading features are measured by the "
      "sensor (shown in blue), but several, such as the inter-arrival time and the time-to-live values, are not (shown in "
      "orange)."),
]

results_live_features = [
    P("**Models with live-measurable features only.** The decisive question for the sensor is not the score on a benchmark "
      "file but the score when only the measurable features are available. The test parts were therefore scored again after "
      f"masking all features that the sensor does not measure ({CIC['live_measured_features']} of 78 measured for CIC-IDS2017, "
      f"{UNSW['live_measured_features']} of 42 for UNSW-NB15). {{tab:live}} gives the outcome."),
    T("live", "Held-out results when only live-measurable features are available",
      ["Model", "Recall", "Precision", "F1", "ROC-AUC", "Features measured"],
      [["CIC-IDS2017 PortScan", pct(CIC["held_out_live_features_only"]["recall"], 2), pct(CIC["held_out_live_features_only"]["precision"], 2),
        f4(CIC["held_out_live_features_only"]["f1"]), f4(CIC["held_out_live_features_only"]["roc_auc"]), f"{CIC['live_measured_features']} / 78"],
       ["UNSW-NB15 Reconnaissance", pct(UNSW["held_out_live_features_only"]["recall"], 2), "0.00%",
        f4(UNSW["held_out_live_features_only"]["f1"]), f4(UNSW["held_out_live_features_only"]["roc_auc"]), f"{UNSW['live_measured_features']} / 42"]],
      [1.9, 0.8, 0.9, 0.7, 0.9, 1.0], size=9.5, align=["l"] + ["c"] * 5, bold_first=True),
    P("The CIC-IDS2017 model degraded gracefully: with only 40% of the features it still found "
      f"{pct(CIC['held_out_live_features_only']['recall'], 1)} of port-scan flows with almost no false alarms. The UNSW-NB15 model "
      "failed at the default threshold: its recall fell to zero, although the ROC-AUC stayed at "
      f"{f4(UNSW['held_out_live_features_only']['roc_auc'])}, which means that the ranking was still informative while the "
      "probabilities were pushed below 0.5 by the imputed values, among them the important time-to-live features. In "
      "short, the UNSW-NB15 model would need recalibration or retraining on the features the sensor can measure. "
      "This agrees with the observation, in the project documentation, that live decoy traffic produces low model scores "
      "(0.04–0.14), and explains the small contribution of the models to the final score reported below."),
]

other_days_rows = []
for item in CIC["other_days"]:
    name = item["file"].split(".pcap")[0].replace("-WorkingHours", "").replace("-workingHours", "")
    benign = next(x for x in item["labels"] if x["label"] == "BENIGN")
    attacks = [x for x in item["labels"] if x["label"] != "BENIGN"]
    attack_text = "; ".join(f"{x['label'].strip().replace('  ', ' ')[:22]} {x['flagged_portscan']}/{x['rows']}" for x in attacks)
    other_days_rows.append([name, n(benign["rows"]), f"{benign['flagged_portscan']} ({pct(benign['flagged_portscan'] / benign['rows'], 2)})", attack_text])

results_other_days = [
    P("**Other capture days.** The retrained CIC-IDS2017 model was applied to the seven other files of the dataset, none of "
      "which it had seen. {tab:days} shows that it rarely flagged benign traffic: the false-positive rate stayed at or below "
      "0.01% on six of the seven days, but reached 0.58% on the Thursday infiltration file. It did not flag brute-force, bot or "
      "most web-attack traffic, which is expected from a port-scan specialist, but it flagged part of the DDoS and "
      "DoS-Hulk traffic, whose short flows resemble scans. This confirms that the model is a reconnaissance indicator and not a "
      "general attack detector, in line with the limited generalisation across domains reported in {c:elangovan2026}."),
    T("days", "Retrained CIC-IDS2017 PortScan model on the other capture days (flagged / rows)",
      ["File", "Benign rows", "Benign flagged", "Attack traffic flagged"],
      other_days_rows, [1.3, 0.9, 1.1, 2.9], size=8.5, align=["l", "c", "c", "l"], bold_first=True),
]


def scen_rows():
    names = {"attack": "Attack", "evasive": "Low-and-slow", "benign": "Normal"}
    rows = []
    for s in SC["scenarios"]:
        rows.append([names[s["group"]], s["scenario"], f"{s['detected']}", f"{s['correct_class']}" if s["group"] == "attack" else "—",
                     f"{s['high']} / {s['medium']} / {s['low']}", f"{s['blocked']}",
                     f"{s['mean_events_to_detect']:.1f}" if s["mean_events_to_detect"] else "—"])
    return rows


results_scenarios = [
    P(f"**Detection engine on randomised sessions.** The engine was exercised with {n(TOTAL_SESSIONS)} sessions: "
      f"{ST['n_attack']} attack scenarios, {ST['n_evasive']} low-and-slow scenarios designed to stay below the thresholds, and "
      f"{ST['n_benign']} normal-use scenarios, 100 randomised sessions each. Events carry the fields the real listeners emit, "
      "time is simulated, and the real rules, the real models, the deception policy and a dry-run block manager were "
      "used. {tab:scen} lists the outcomes and {fig:scen} shows them graphically."),
    T("scen", "Outcomes of the 100 randomised sessions of each scenario",
      ["Group", "Scenario", "Detected", "Class correct", "H / M / L", "Blocked", "Events to detect"],
      scen_rows(), [0.7, 2.2, 0.6, 0.6, 0.8, 0.6, 0.6], size=8, align=["l", "l", "c", "c", "c", "c", "c"]),
    F("scen", "scenario_outcomes.png", "Strongest alert raised in each scenario (100 sessions per scenario)", 6.0),
    P(f"All {n(ST['attack_detected'])} attack sessions were detected and every one carried the expected class. "
      f"{n(ST['attack_medium_plus'])} of them reached at least MEDIUM severity; the others were banner grabbing, protocol "
      "fingerprints and about half of the ICMP sweeps, which the rules deliberately score low. Honeytoken reuse always reached HIGH "
      "and, in dry-run mode, a block decision, as did 59% of TCP scans and 16% of SSH guessing sessions. Detection was quick: "
      "the first finding appeared after a median of three to five events, and the new web-attack rules fire on the first "
      "matching request."),
    P(f"The weaknesses are equally clear. None of the {n(sum(s['trials'] for s in SC['scenarios'] if s['group'] == 'evasive'))} "
      "low-and-slow sessions was detected: one port every 200–280 seconds, one SSH guess every 35–60 seconds, and a "
      "single request for a sensitive file all stay below the window-based thresholds. Among the normal-use scenarios, two "
      "raised alerts: a multi-port uptime monitor, which probes five services in a few seconds and is by definition "
      "indistinguishable from a small scan, and a long browsing session of 6–15 distinct pages, which the endpoint-probing "
      "rule flags at LOW severity. Search text that contains SQL-like words (for example \"union station\" or \"select a "
      "seat\") raised no alert, which confirms that the web-attack signatures need a real attack construct."),
    T("sess", "Session-level detection quality (slow attacks counted as attacks)",
      ["Measure", "Value", "Basis"],
      [["Recall", pct(ST["recall"], 1), f"{n(ST['tp'])} of {n(ST['pos'])} attack sessions"],
       ["Precision", pct(ST["precision"], 1), f"{n(ST['tp'])} of {n(ST['tp'] + ST['fp'])} sessions with an alert"],
       ["False-alarm rate", pct(ST["fpr"], 1), f"{n(ST['fp'])} of {n(ST['neg'])} normal sessions"],
       ["F1-score", f3(ST["f1"]), "Harmonic mean of precision and recall"],
       ["Event processing time", f"{SC['event_processing_ms']['mean']:.1f} ms mean", f"p95 {SC['event_processing_ms']['p95']:.1f} ms, p99 {SC['event_processing_ms']['p99']:.1f} ms over {n(SC['event_processing_ms']['events'])} events"]],
      [1.6, 1.3, 3.2], size=9.5, bold_first=True),
    P("{tab:sess} gives the session-level figures. They describe the engine under scenarios written by the developers of "
      "the engine, including deliberate evasions, and the false-alarm rate in particular is a property of the chosen "
      "normal-use scenarios and not an estimate for a real network. Each event, including the two model scorings, took "
      f"{SC['event_processing_ms']['mean']:.1f} ms on average, which is far below the rate at which a single decoy host "
      "receives events."),
    F("parts", "score_parts.png", "Contribution of rules and models to the mean score of each attack scenario", 5.7),
    P("{fig:parts} separates the two parts of the score. The model points are small: between 0 and about 3.5 points, "
      "out of the 40 they may add, because the models receive few measured features and rate decoy flows as unlikely "
      "to be scans. The rules therefore carry the detection, and the models act as a minor secondary signal, as the design "
      "intended."),
]

results_adaptive = [
    P("**Static versus learning deception.** To test the learning policy, a simulation was run in which each simulated "
      "attacker belongs to one of four attack classes (port scan, SSH guessing, endpoint probing and SQL injection) and "
      "keeps interacting after each step with probability 0.92 when the decoy shows the persona it prefers, and 0.80 "
      "otherwise, up to 60 steps. The preferred personas were assigned so that no single persona suits every class "
      "(Windows server for port scans and SQL injection, legacy Linux for SSH guessing, Ubuntu web for endpoint probing). "
      "**These parameters are assumptions, and the experiment shows whether the policy can find a good persona from "
      "engagement feedback alone; it does not show how real attackers behave.** Four policies were compared on the same "
      f"random attackers, with {AD['seeds']} seeds of {AD['episodes']} sessions: the static default persona, the original "
      "round-robin rotation, the learning policy, and an oracle that always shows the preferred persona."),
    T("adapt", "Mean interactions per simulated attacker session",
      ["Policy", "Mean (all sessions)", "Std. dev. over seeds", "First 50 sessions", "Last 150 sessions"],
      [[label, f"{AD['policies'][key]['mean_steps']:.2f}", f"{AD['policies'][key]['sd_steps']:.2f}",
        f"{AD['policies'][key]['first_50']:.2f}", f"{AD['policies'][key]['last_quarter']:.2f}"]
       for label, key in (("Static decoy", "static"), ("Round-robin rotation", "rotation"), ("Learning (UCB1)", "learning"), ("Oracle (upper bound)", "oracle"))],
      [1.8, 1.2, 1.2, 1.1, 1.1], size=9.5, align=["l", "c", "c", "c", "c"], bold_first=True),
    F("adaptfig", "adaptive_curve.png", "Mean interactions per session as the policies accumulate experience", 5.0),
    P(f"The learning policy obtained {LEARN['mean_steps']:.2f} interactions per session against {STATIC['mean_steps']:.2f} for the static "
      f"decoy, an increase of {pct(GAIN, 0)}, and it reached {pct(LEARN['last_quarter'] / ORACLE['last_quarter'], 0)} of the oracle in the "
      "last 150 sessions ({tab:adapt}, {fig:adaptfig}). The curve rises within the first 100 sessions, since each class "
      "needs a few trials of each persona, and then flattens. Round-robin rotation, which does not look at the attacker's "
      f"reaction, did slightly worse than the static decoy ({ROT['mean_steps']:.2f}). In the static case the one class whose preferred "
      f"persona matches the default (endpoint probing) already reached {STATIC['by_class']['HTTP_ENDPOINT_PROBING']:.1f} interactions, "
      f"whereas the other classes reached about {STATIC['by_class']['PORT_SCAN']:.1f}. Only measurements on real attackers can show "
      "whether the same gain occurs in practice, which is stated as future work."),
]

results_live = [
    P(f"**Run on the development machine.** The sensor was also run on the development computer, with the simulator, the demo "
      f"script and manual probes as the only sources. Its database holds {LIVE['events']} events ({LIVE['events_by_kind']['connection']} connections, "
      f"{LIVE['events_by_kind']['http_request']} HTTP requests, {LIVE['events_by_kind']['ssh_auth']} SSH attempts) from {LIVE['sources']} source "
      f"addresses between {LIVE['first_utc'][:10]} and {LIVE['last_utc'][:10]}, which led to {LIVE['findings']} findings, {LIVE['decoy_actions']} "
      f"persona or engagement changes and {LIVE['honeytokens']} issued honeytokens ({{fig:live}}). Almost all of the traffic came from "
      "the loopback address, which the block manager protects, so no automatic block of these attackers was made; this "
      "behaviour was intended and was shown in the demonstration. The three blocks in the database were created by the "
      "operator against the documentation address 203.0.113.250 and its neighbours with Windows Firewall enforcement, "
      "and were released again, which verified the real `netsh` path. These runs demonstrate that the components work "
      "together; they are not field data and are not used to compute performance."),
    F("live", "live_run.png", "Findings logged by the sensor during the development run, by class and severity", 5.0),
]

comparative = [
    P("{tab:cmp} places the retrained models beside results reported in the literature. The comparison is indicative only: "
      "the studies use different splits, features and class definitions, and several do not state whether duplicates were "
      "removed. The retrained models are in the range of the published results, and the CIC-IDS2017 port-scan figure, in "
      "common with other near-perfect scores {c:nassreddine2025}, should be read together with the dataset-quality "
      "warnings of {c:lanvin2023,flood2024}."),
    T("cmp", "Comparison of model results with the literature",
      ["Study", "Dataset / task", "Model", "Reported result"],
      [["This work", "CIC-IDS2017, benign vs port scan (de-duplicated)", "Random Forest", f"Accuracy {pct(CH[RF]['accuracy'], 2)}, F1 {f4(CH[RF]['f1'])}"],
       ["This work", "UNSW-NB15, normal vs reconnaissance", "Random Forest", f"Accuracy {pct(UH[RF]['accuracy'], 2)}, F1 {f4(UH[RF]['f1'])}"],
       ["{c:more2024}", "UNSW-NB15, attack detection", "Random Forest", "Accuracy 98.63%, F1 97.80%, false alarm 1.36%"],
       ["{c:alkhater2026}", "UNSW-NB15, 5-fold cross-validation", "XGBoost", "Accuracy 0.97, AUC 0.98"],
       ["{c:yin2023}", "UNSW-NB15, multi-class", "MLP with IGRF-RFE", "Accuracy 84.24%"],
       ["{c:nassreddine2025}", "NSL-KDD and CIC-IDS", "Stacked ensemble", "Accuracy 99.99%"],
       ["{c:almaiah2025}", "Port scan detection", "SVM, KNN with metaheuristic selection", "Accuracy above 99%"],
       ["{c:alani2023}", "IoT reconnaissance", "Explainable ensemble", "Accuracy 99%; FPR 0.6%"]],
      [0.9, 2.1, 1.5, 1.8], size=9, bold_first=True),
    P("{tab:feat} compares this system with the adaptive honeypots reviewed in Chapter II in terms of what each covers. "
      "The comparison is of scope, and not of performance, because the studies measure different things."),
    T("feat", "Scope of this system compared with related adaptive honeypots",
      ["Capability", "Q-Cowrie {c:varnaseri2026}", "Web honeypot {c:varadarajan2026}", "shelLM {c:sladic2024}", "This work"],
      [["Services covered", "SSH", "HTTP", "SSH shell", "SSH, HTTP, 9 bait services"],
       ["Adaptation method", "Q-learning", "Seq2Seq + DQN", "LLM generation", "UCB1 bandit on engagement"],
       ["Live detection rules", "No", "No", "No", "13 rule classes"],
       ["Attacker profile", "MDP of behaviour", "No", "No", "5 labels with confidence"],
       ["Automated response", "No", "No", "No", "Guarded firewall block"],
       ["ATT&CK / STIX output", "No", "No", "No", "Yes"],
       ["Evidence in study", "Two experiments", "Offline metrics", "Human judges", "Tests, sessions, simulation"]],
      [1.3, 1.1, 1.2, 1.0, 1.5], size=8.5, bold_first=True),
]

# ----------------------------------------------------------------------
# UI, testing, screenshots
# ----------------------------------------------------------------------

ui_design = [
    P("Two interfaces were built. The **operator console** is a single HTML page served by the sensor itself on the loopback "
      f"address ({CONSOLE_LINES} lines). It requires the admin token and offers eight views: overview, connection events, "
      "threat alerts, attackers, threat intelligence, blocks, decoy actions, and listeners and models. An operator can "
      "change the persona and level of a source, block or unblock an address, and export indicators. The **React "
      f"dashboard** ({n(FRONT_LINES)} lines of JavaScript) provides the monitoring views: security overview with statistic "
      "cards, a connection-activity chart and a severity chart; a connection-event table; and a threat-alert table with a "
      "detail drawer that shows the score, the reasons, the evidence, the model points and the decision taken, with buttons "
      "for engagement and blocking. The dashboard reads from the FastAPI bridge, which calls the console with the token on "
      "the server side. A banner shows whether the sensor is connected, and the footer states whether a firewall action "
      "was applied or only recorded in dry-run mode."),
]

test_rows = [
    ["ConfigTests", "4", "Valid defaults; duplicate ports and non-loopback console rejected"],
    ["StoreTests", "1", "Events, findings and sources round-trip through SQLite"],
    ["EngineRuleTests", "10", "Each rule fires; single probes and ordinary visitors do not; cooldown; loopback never blocked"],
    ["DeceptionTests", "6", "Persona changes, recorded reasons, stable honeytokens, banners and pages"],
    ["FirewallTests", "8", "Dry run, enforce and failure, protected and invalid addresses, expiry, block limit"],
    ["ParserAndLogTests / SignatureTests", "5", "Firewall-log parser and protocol fingerprints"],
    ["MLTests", "4", "Both models load; probabilities valid; feature rows match schemas; points bounded"],
    ["Bait / SSH / HTTP integration", "5", "Real sockets: banner grab, probe payload, auth never granted, fake .env"],
    ["IntelTests", "6", "Campaign linking, generic user agent ignored, no raw passwords in exports"],
    ["Bridge and firewall summary", "4", "Mapping of sensor data to dashboard fields"],
    ["Web-attack signatures", "3", "Each family recognised; double encoding; ordinary requests clean"],
    ["Engine extensions", "4", "SQL injection finding with ATT&CK ids; profile; redaction with honeytoken detection; masking"],
    ["STIX export", "1", "Valid, deterministic bundle with unique ids"],
    ["Learning policy", "4", "Exploration, preference for rewarded persona, exclusion, feedback window, recorded reason"],
    ["Profiler", "3", "Scanner versus credential attacker; empty history; confidence in [0, 1]"],
]

testing = [
    P("The project has an automated suite of 68 tests, 53 written for the original sensor and 15 for the new modules. All "
      "pass. The tests use a temporary database and a fake firewall runner, so none of them creates a firewall rule; the "
      "integration tests start the decoys on free loopback ports. {tab:tests} lists the coverage."),
    T("tests", "Automated test coverage",
      ["Test group", "Tests", "What is verified"], test_rows, [2.0, 0.5, 3.6], size=9, align=["l", "c", "l"], bold_first=True),
    P("In addition, the complete system was started in a sandbox (decoys bound to the loopback address, dry-run blocking, a "
      "copy of the database and a temporary token) and exercised by hand through the simulator and the browser. {tab:gui} "
      "records the test cases and their outcomes, each of which was observed in the screenshots in this chapter."),
    T("gui", "System and interface test cases",
      ["ID", "Action", "Expected result", "Result"],
      [["TC1", "Open the decoy root page in a browser", "Fake sign-in page with persona brand", "Passed"],
       ["TC2", "Request /.env", "Fake configuration with an AWS-style honeytoken", "Passed"],
       ["TC3", "Run the simulator (scan, web probes, 12 SSH guesses)", "Alerts of several classes, HIGH among them", "Passed"],
       ["TC4", "Open the dashboard", "Banner shows Connected; statistic cards filled", "Passed"],
       ["TC5", "Open an alert in the dashboard", "Drawer with score, reasons and model points", "Passed"],
       ["TC6", "Sign in to the console with the token", "Console views load", "Passed"],
       ["TC7", "Open the Threat Intel view", "Indicators with classes and severity", "Passed"],
       ["TC8", "Block 203.0.113.250 manually (dry run)", "Block row with status DRY_RUN", "Passed"],
       ["TC9", "Open Listeners and Models", "11 listeners up; MySQL port reported unavailable", "Passed (3306 reserved by Windows)"],
       ["TC10", "Request a stolen honeytoken again", "HONEYTOKEN_REUSE at HIGH, level 3", "Passed"]],
      [0.5, 2.3, 2.2, 1.2], size=8.5, align=["c", "l", "l", "l"]),
]

SHOTS = [
    ("decoy_login", "Decoy sign-in page served on port 8080"),
    ("decoy_env", "Fake .env file with honeytoken credentials"),
    ("dashboard_overview", "Dashboard overview with statistics, activity chart and severity chart"),
    ("dashboard_events", "Connection events in the dashboard"),
    ("dashboard_alerts", "Threat alerts table in the dashboard"),
    ("dashboard_alert_detail", "Alert detail drawer with detection reasons"),
    ("console_attackers", "Attackers view of the operator console"),
    ("console_intel", "Threat intelligence view with indicators"),
    ("console_blocks", "Blocks view with a manual block and the history"),
    ("console_decoys", "Decoy actions with the reason for every change"),
    ("console_models", "Listeners and models view"),
]

screenshots = [P("The figures below show the running system, captured from the real application started in the sandbox "
                 "described above. The decoy pages are shown in {fig:shot_decoy_login} and {fig:shot_decoy_env}; the "
                 "dashboard in {fig:shot_dashboard_overview}, {fig:shot_dashboard_events}, {fig:shot_dashboard_alerts} and "
                 "{fig:shot_dashboard_alert_detail}; and the operator console in {fig:shot_console_attackers}, "
                 "{fig:shot_console_intel}, {fig:shot_console_blocks}, {fig:shot_console_decoys} and "
                 "{fig:shot_console_models}.")]
for key, caption in SHOTS:
    screenshots.append(F("shot_" + key, "SCREEN:" + key, caption, 5.0))

challenges_impl = [
    P("Several problems were met and solved, or recorded, during implementation."),
    B([
        "**Reserved port.** Windows refused to bind the MySQL bait port 3306 (WinError 10013). The sensor was made to report "
        "such a listener as unavailable and continue with the others.",
        "**Elevation.** `netsh` needs an Administrator shell. Without it each block is recorded as FAILED, and the dashboard "
        "says that the action was not applied.",
        "**Feature mismatch.** The models expect 78 and 42 features; the sensor measures 31 and 25. The coverage is measured, "
        "reported with each score, and the model weight is limited to 40 points.",
        "**Duplicate and overlapping data.** Duplicate flows and train–test overlap were found and removed.",
        "**Protected local attackers.** When test attacks come from the same machine, the block manager rightly refuses to "
        "block them. The demonstration therefore shows the refusal and a separate manual block of a documentation address.",
        "**Plain-text secrets.** Captured passwords were originally stored as typed. They are now replaced by a digest before "
        "storage.",
        "**Low-and-slow evasion and uptime monitors.** Measured and left as known limitations of window-based rules.",
    ]),
]

# ----------------------------------------------------------------------
# Chapter V
# ----------------------------------------------------------------------

conclusion = [
    P("The project produced a working AI-adaptive honeypot sensor in which decoys, detection, profiling, adaptive deception, "
      "response and threat-intelligence export form one loop, together with an operator console, a React dashboard, a test "
      "suite and an evaluation that reports weaknesses as well as strengths. The six objectives were met as follows."),
    N([
        f"Decoys were implemented for SSH, HTTP and nine bait services; no input is ever executed.",
        f"The engine recognises seven reconnaissance classes and six web-attack classes, of which four web-attack classes were "
        f"exercised in the scenarios. In {n(ST['attack_trials'])} randomised attack sessions it detected every session with the correct class.",
        f"Two Random Forests were re-evaluated with de-duplicated, leakage-controlled splits: F1 {f4(CH[RF]['f1'])} on CIC-IDS2017 and "
        f"{f4(UH[RF]['f1'])} on UNSW-NB15. With only live-measurable features, the CIC-IDS2017 model kept {pct(CIC['held_out_live_features_only']['recall'], 1)} "
        "recall, whereas the UNSW-NB15 model needs recalibration.",
        f"A UCB1 policy learns a persona per attack class from engagement feedback; in a simulation with stated assumptions it "
        f"raised the mean number of interactions from {STATIC['mean_steps']:.2f} to {LEARN['mean_steps']:.2f} ({pct(GAIN, 0)}).",
        "Blocking is guarded by safety checks, and indicators are exported with ATT&CK techniques and as STIX 2.1.",
        "68 automated tests pass, and the limitations are documented.",
    ]),
    P("The central finding is that the rules, not the machine-learning models, carry the detection in a live sensor: the "
      "models add 0–3.5 points of a possible 40 because most of their input features cannot be measured by a decoy. A "
      "second finding is that high benchmark scores say little about live use, which confirms the warnings in the "
      "literature {c:lanvin2023,flood2024,elangovan2026}."),
]

limitations = [
    B([
        "**No field evidence.** All attacks came from the same machine or from simulation. Nothing was observed from the open "
        "internet or a campus network, and the adaptive gain was measured only in a simulation with assumed attacker behaviour.",
        "**Slow attacks evade the rules.** None of the 300 low-and-slow sessions was detected.",
        "**False alarms on benign monitors.** An uptime monitor that probes several services and a long browsing session raised "
        "alerts, and the false-alarm rate (" + pct(ST["fpr"], 0) + ") holds for the scenarios chosen, not for a real network.",
        "**Weak model contribution.** The sensor measures 40% and 60% of the model features. The UNSW-NB15 model has zero recall "
        "at the default threshold when only measurable features are available.",
        "**Low-interaction decoys.** No shell or database engine is simulated, and the web decoy is a small set of pages.",
        "**Single platform.** Blocking and the firewall log work only with Windows Defender Firewall.",
        "**Two stores.** The sensor uses SQLite and the original backend uses PostgreSQL; they are not synchronised.",
        "**Access control.** The console has one shared token, runs without TLS on the loopback address, and has no roles.",
        "**Profiling is heuristic.** The behaviour labels are rule-based and their confidence is not a calibrated probability.",
    ]),
]

future = [
    B([
        "Collect labelled telemetry from the sensor itself and train supervised, anomaly-detection and sequence models on it, "
        "which would close the gap between benchmark and live features.",
        "Deploy the sensor, with the approval of the network team, on a campus segment and compare the learning policy with a "
        "static decoy using real attackers, measuring dwell time and useful interactions.",
        "Add a Linux firewall back end (nftables or iptables), a Docker deployment, and human approval for high-impact "
        "blocks.",
        "Unify the SQLite sensor store with PostgreSQL through a defined synchronisation, and add TLS, role-based access and "
        "retention policies.",
        "Add decoys for databases, APIs, file upload and DNS, and consider constrained language-model responses with the "
        "state controls and leak checks described in {c:li2026,magazov2026}.",
        "Publish indicators through a TAXII service, and extend the correlation of campaigns across sensors.",
        "Replace the heuristic profiler by a model trained on collected sessions and calibrate its confidence.",
    ]),
]

# ----------------------------------------------------------------------
# Appendix code excerpts
# ----------------------------------------------------------------------

def grab(path, name, indent="    "):
    lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if re.match(rf"{indent}def {name}\(", line))
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith(indent + "def ") or (lines[j] and not lines[j].startswith(indent) and not lines[j].startswith("#")):
            end = j
            break
    block = lines[start:end]
    while block and not block[-1].strip():
        block.pop()
    return "\n".join(block)


_privacy = (ROOT / "honeypot-backend/sensor/privacy.py").read_text(encoding="utf-8").splitlines()

appendix_code = [
    PN("Appendix I lists the most important parts of the code. The complete source is in the project repository."),
    H3("Rule scoring and finding creation (sensor/engine.py)"),
    CODE(grab("honeypot-backend/sensor/engine.py", "_evaluate"), 7.5),
    H3("Learning persona selection (sensor/policy.py)"),
    CODE(grab("honeypot-backend/sensor/policy.py", "choose") + "\n\n" + grab("honeypot-backend/sensor/policy.py", "credit") +
         "\n\n" + grab("honeypot-backend/sensor/policy.py", "interaction"), 7.5),
    H3("Guarded block decision (sensor/firewall.py)"),
    CODE(grab("honeypot-backend/sensor/firewall.py", "consider") + "\n\n" + grab("honeypot-backend/sensor/firewall.py", "protected_reason"), 7.5),
    H3("Secret redaction (sensor/privacy.py)"),
    CODE("\n".join(_privacy[_privacy.index("import hashlib"):]), 7.5),
]
