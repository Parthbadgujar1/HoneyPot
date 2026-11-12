"""Chapter I and II content blocks (shared by both report versions)."""

from facts import *  # noqa: F401,F403

TOTAL_SESSIONS = sum(s["trials"] for s in SC["scenarios"])
N_SCEN = len(SC["scenarios"])

# ----------------------------------------------------------------------
# Chapter I
# ----------------------------------------------------------------------

intro = [
    P("Almost every network attack begins with reconnaissance. Before an intruder guesses a password or sends an exploit, "
      "the intruder scans for open ports, grabs service banners, requests well-known files such as `/.env`, and tries a few "
      "default credentials. Conventional defences wait for such traffic to reach production systems and then try to "
      "recognise it. A honeypot reverses this arrangement. It is a decoy resource whose only value lies in being probed, so "
      "that every connection to it is suspicious by construction and the traffic it records is unusually rich in attacker "
      "behaviour {c:spitzner2003,provos2004}. Because no legitimate user has a reason to contact a decoy, the number of false "
      "alarms is low, and the decoy can safely record details that a production server would never be allowed to keep."),
    P("Classic honeypots are static. They present the same banner, the same fake pages and the same fake credentials to "
      "everyone, so that an attacker who has seen one decoy can recognise the next. Recent work therefore adds adaptation: "
      "reinforcement learning to choose responses {c:varnaseri2026,zhang2026,varadarajan2026}, large language models to "
      "generate realistic shell output {c:sladic2024,li2026}, and clustering to profile attackers {c:lim2026,xiang2024}. "
      "Most of these studies address one protocol or one component, and rarely connect detection, adaptation, response and "
      "intelligence sharing in a single running system."),
    P(f"This project, titled **AI-Adaptive Honeypot for Network Deception and Threat Intelligence**, developed such a system as a "
      f"working prototype in Python for a single Windows machine. The sensor exposes a fake SSH server, a fake web "
      f"application and nine bait TCP services; records every event in a common format; scores each source with behavioural "
      f"rules and two Random Forest models; changes the persona shown to each attacker and learns from the attacker's "
      f"continued engagement which persona works best; blocks sources through Windows Defender Firewall under strict safety "
      f"checks; and publishes alerts, attacker profiles, ATT&CK-mapped indicators and STIX 2.1 bundles through an operator "
      f"console and a React dashboard. The implementation comprises about {n(SENSOR_LINES)} lines of sensor code, "
      f"{n(BACKEND_LINES)} lines of backend code, {n(FRONT_LINES)} lines of dashboard code and {n(TEST_LINES)} lines of tests."),
    P("The contribution of the work is practical rather than algorithmic. It shows how existing, well-understood techniques "
      "can be integrated into one feedback loop, and it measures that loop honestly: the machine-learning models were "
      "re-evaluated with leakage-controlled splits, the detection engine was exercised with randomised attack, slow-attack "
      "and normal-use sessions, and the learning deception policy was compared with a static decoy in a simulation whose "
      "assumptions are stated openly. Where the results are weak, the report says so."),
]

objectives = [
    P("The objectives were stated so that each can be checked against a measurement or a test. They were:"),
    N([
        "To implement low-interaction decoy services (SSH, HTTP and nine bait TCP services) that record every connection, "
        "login attempt and request without ever executing attacker input.",
        "To develop a detection engine that identifies at least seven reconnaissance classes and four web-attack classes, "
        "each with explainable evidence and a score from 0 to 100.",
        "To integrate two Random Forest models trained on CIC-IDS2017 and UNSW-NB15 as a secondary score, and to evaluate "
        "them again with de-duplicated, leakage-controlled data splits.",
        "To implement adaptive deception that changes the decoy persona and engagement level for each attacker and learns "
        "from engagement feedback which persona suits which attack class.",
        "To provide guarded automatic response through Windows Defender Firewall and threat-intelligence outputs "
        "(attacker profiles, campaigns, MITRE ATT&CK mapping and STIX 2.1 export).",
        f"To measure the system with unit tests, {n(TOTAL_SESSIONS)} randomised sessions in {N_SCEN} scenarios and a "
        "static-versus-learning deception experiment, and to document its limitations.",
    ]),
]

necessity = [
    P("**Practical need.** Organisations, colleges included, usually learn about a scan or a brute-force campaign only "
      "after a production service has been touched. A decoy that is deliberately exposed gives an early, low-noise warning "
      "and keeps the attacker away from real assets. For a college network, where many machines are lightly managed, such "
      "early warning is inexpensive compared with the effort of investigating an incident afterwards."),
    P("**Technical need.** Static decoys are easy to fingerprint, and signature rules alone miss behaviour that is spread "
      "over time or over services. Machine-learning detectors help, but most published results are obtained on offline "
      "benchmark files and have seldom been tested on the traffic a live sensor can actually measure {c:flood2024,elangovan2026}. "
      "A system that couples rules, learned models and a decoy that reacts to what it sees addresses both problems."),
    P("**Economic need.** The prototype runs on one ordinary computer with open-source software, which removes licence and "
      "hardware costs that commercial deception platforms carry. The sensor stores its data in SQLite, so no database "
      "server is required for it to operate."),
    P("**Societal need.** Shared indicators make every defender better informed. Exporting observed sources in the STIX 2.1 "
      "format with ATT&CK technique references allows a small institution to contribute to, and benefit from, community "
      "threat intelligence. At the same time, a honeypot collects data that other people type, so privacy and responsible "
      "operation matter {c:sokol2017}. The prototype therefore redacts captured passwords before storage."),
]

challenges_field = [
    P("The following technical challenges and open research issues shaped the design of the project."),
    B([
        "**Realism and fingerprinting.** Attackers test whether a target is a decoy. Studies on language-model honeypots "
        "show that inconsistent or hallucinated output reveals the decoy {c:li2026}, and that the choice of backend model "
        "affects fidelity, latency and even leakage of the model's own instructions {c:magazov2026}.",
        "**Gap between benchmark and live data.** Models trained on flow statistics from benchmark datasets expect features, "
        "such as inter-arrival times and TTL values, that a decoy process cannot easily measure. Benchmark data also contain "
        "duplicates and labelling errors that inflate scores {c:lanvin2023,flood2024}.",
        "**Generalisation over time.** Detection quality falls when traffic patterns change; one cross-dataset study reports "
        "macro-F1 dropping from 0.84–0.96 inside a dataset to 0.69–0.78 across domains {c:elangovan2026}.",
        "**Low-and-slow behaviour.** An attacker who spaces probes far apart stays below window-based thresholds, a weakness "
        "that this project measured directly (Chapter IV).",
        "**Safe automation.** An automatic block can cut off legitimate users or the sensor's own host, so any response "
        "must be guarded, reversible and explainable.",
        "**Evaluation without real attackers.** A student prototype has no large population of live adversaries, so "
        "evaluation relies on replayed benchmark data and simulations, whose limits must be stated.",
    ]),
]

applications = [
    P("The prototype can serve several domains."),
    B([
        "**Education and campus networks:** a teaching sensor that shows students how reconnaissance appears in logs, and "
        "an early-warning decoy on a college segment, deployed only with the network team's approval.",
        "**Enterprise early warning:** decoy services and honeytokens placed beside production systems to reveal scanning "
        "and credential theft.",
        "**Threat-intelligence sharing:** ATT&CK-mapped indicators and STIX 2.1 bundles for exchange with other teams.",
        "**Security research:** a platform for studying attacker behaviour and for comparing deception policies.",
        "**IoT and smart-city environments:** honeypot data have been shown to improve attack detection in IoT settings "
        "{c:ahmed2024}, and the protocol-agnostic bait listeners can imitate typical device services.",
    ]),
]

org_a = [
    P("The report is organised into five chapters. **Chapter I** introduces the problem, states the objectives, explains the "
      "need for the work, lists the challenges and applications, and outlines the report."),
    P("**Chapter II** surveys 25 recent studies on honeypots, adaptive and language-model deception, machine-learning "
      "intrusion detection, reconnaissance detection, dataset quality and threat intelligence. It ends with a gap analysis "
      "and the motivation for the proposed work."),
    P("**Chapter III** describes the system: the development method, the architecture and each of its blocks, the "
      "algorithms with their equations and pseudocode, the technology stack and the datasets."),
    P("**Chapter IV** presents data preprocessing and splits, the evaluation metrics, and the results for the models, the "
      "detection engine and the adaptive policy, followed by a comparison with the literature, test results and "
      "screenshots."),
    P("**Chapter V** concludes the report, discusses limitations and proposes future work. References and appendices follow."),
]

org_b = [
    P("The report has five chapters. **Chapter 1** gives the overview, motivation, problem definition, objectives, scope and "
      "limitations, the problem-solving approach and this outline. **Chapter 2** reviews the existing systems, identifies the "
      "research gap, introduces the proposed system and summarises the survey. **Chapter 3** explains the methodology: the "
      "problem formulation, the architecture and its blocks, hardware and software requirements, the flow chart and the "
      "algorithms. **Chapter 4** reports the dataset analysis, the evaluation metrics, the results with a comparative "
      "analysis, the user interface, testing, the challenges met and screenshots. **Chapter 5** gives the conclusion, "
      "limitations, future scope and applications. References and appendices close the report."),
]

problem_def = [
    P("Let a honeypot sensor receive a stream of events e₁, e₂, …, each with a source address, a destination "
      "port, a service, a time stamp and protocol details. For every source s, the sensor must decide, as events arrive, "
      "whether the behaviour of s is reconnaissance or attack, how severe it is, what the decoy should show to s next, and "
      "whether s should be blocked."),
    P("The problem was therefore defined as: **to design and implement a honeypot sensor that detects reconnaissance and "
      "common web attacks in real time with explainable evidence, adapts its decoy to each attacker using feedback from the "
      "attacker's behaviour, responds in a safe and reversible way, and exports structured threat intelligence, while its "
      "performance and limits are measured honestly.**"),
]

scope_limits = [
    P("**Scope.** The work covers network-level reconnaissance (port scans, service discovery, banner grabbing, ICMP sweeps), "
      "SSH password guessing, web endpoint probing, four web-attack families (SQL injection, cross-site scripting, command "
      "injection and path traversal), honeytoken reuse, adaptive persona selection, guarded firewall blocking on Windows, "
      "and threat-intelligence export."),
    P("**Limitations.** The decoys are low-interaction: no shell is granted and no attacker command is executed. Blocking "
      "uses Windows Defender Firewall only. The two machine-learning models contribute a small part of the score because "
      "the sensor measures only part of their input features. The sensor and the test attackers ran on one device, so no "
      "observation from the open internet or a campus network is claimed. Slow attacks that stay below the detection "
      "windows are not detected. These limits are measured and discussed in Chapters 4 and 5."),
]

problem_solving = [
    P("The problem was solved in six steps. First, decoy listeners were built so that every interaction becomes a common "
      "event record. Second, rules over sliding windows were written to name each behaviour and to give it points. Third, "
      "two Random Forest classifiers trained on public datasets were wrapped so that they can score a measured flow, and "
      "their scores were added to the rule points. Fourth, a deception policy was added that selects a persona and an "
      "engagement level per attacker, and a bandit algorithm was used to learn from the attacker's continued activity "
      "which persona keeps each attack class engaged. Fifth, a block manager, a threat-intelligence module and a "
      "dashboard were attached. Sixth, the whole system was tested and measured, and the weaknesses found were recorded."),
]

# ----------------------------------------------------------------------
# Chapter II
# ----------------------------------------------------------------------

LIT_ROWS = [
    ["{c:priya2023}", "2023", "Containerised cloud honeypots with an ensemble of research honeypot detectors", "Cloud deployment",
     "Collected data on attacker behaviour and intent", "Descriptive; no detection benchmark"],
    ["{c:lanka2024}", "2024", "Large language model analysis of honeypot data to learn attacker TTPs and flag anomalies", "Real-world scenarios",
     "Reported shorter response time for detecting malicious activity", "No comparison with a static honeypot"],
    ["{c:ahmed2024}", "2024", "Machine learning and neural networks on IoT honeypot datasets", "IoT honeypots",
     "Better attack detection when honeypot data are used", "Honeypots passive, not adaptive"],
    ["{c:alatawi2025}", "2025", "Enhanced Isolation Forest on kernel-level honeypot logs", "BETH dataset",
     "AUROC 0.917 against 0.850 baseline; precision 99.57%, F1 91.69%, accuracy 86.03%", "Process logs, not network deception"],
    ["{c:lim2026}", "2026", "Hierarchical clustering of SSH honeypot command chains mapped to ATT&CK", "SSH honeypot deployments",
     "176 attack patterns grouped into 18 behavioural clusters", "Offline profiling; no feedback to the decoy"],
    ["{c:xiang2024}", "2024", "IP attribution using intrusion data enriched with threat intelligence", "39,707 intrusion entries",
     "Accuracy up to 88.89% for grouping attackers with a common origin", "Needs external intelligence feeds"],
    ["{c:varnaseri2026}", "2026", "Q-Cowrie: reinforcement-learning responses added to the Cowrie honeypot", "Cowrie, two experimental studies",
     "Adaptive decisions learned from an MDP of attacker behaviour", "SSH only"],
    ["{c:zhang2026}", "2026", "Stackelberg game with deep reinforcement learning for software-defined honeypots", "Simulation",
     "No adjustment needed in 80% of rounds, with controlled cost", "Simulation; special hardware assumed"],
    ["{c:varadarajan2026}", "2026", "Seq2Seq response generation with Deep Q-learning for web honeypots", "HTTP request–response pairs",
     "Realism 92.3%, consistency 89.7%; session length 3.2 to 7.8 exchanges", "Web only; needs training corpus"],
    ["{c:sladic2024}", "2024", "shelLM: LLM-generated Linux shell output", "Cloud LLMs",
     "True-negative rate 0.90 as judged by security researchers", "Shell only; human-judged"],
    ["{c:li2026}", "2026", "LLM-SSHH: explicit state snapshot to reduce hallucination", "SSH honeypot",
     "Mean detection rate 0.150, 3–4 times better than existing methods", "Depends on an external model"],
    ["{c:magazov2026}", "2026", "Benchmark of 11 LLM back ends for SSH honeypots", "42-command battery, 8,736 responses",
     "One back end leaked its instructions; back ends were fingerprintable", "Evaluates risk, not detection"],
    ["{c:sun2023}", "2023", "Survey of machine-learning-based moving target defence", "Literature",
     "Summarises mechanisms and shortcomings of MTD", "Survey; no deployment"],
    ["{c:shahin2026}", "2026", "Game-theoretic evaluation of cyber deception", "Computational experiments",
     "Value of deception and price of transparency as measures", "Theoretical; not deployed"],
    ["{c:wang2023}", "2023", "Hybrid IDS combining Random Forest and autoencoder", "Public IDS data",
     "Handles unknown attacks; lower false-positive rate", "Offline classifier only"],
    ["{c:lu2024}", "2024", "Cost-sensitive Random Forest with optimised KPCA", "Public IDS data",
     "5.59% higher accuracy than plain Random Forest", "Offline; no live traffic"],
    ["{c:yin2023}", "2023", "IGRF-RFE feature selection for an MLP", "UNSW-NB15",
     "Features reduced 42 to 23; accuracy 82.25% to 84.24%", "Modest multi-class accuracy"],
    ["{c:more2024}", "2024", "Logistic regression, SVM, decision tree and Random Forest compared", "UNSW-NB15",
     "Random Forest best: F1 97.80%, accuracy 98.63%, false alarm 1.36%", "Single dataset"],
    ["{c:nassreddine2025}", "2025", "Stacked ensemble with correlation and XGBoost feature selection, SMOTE-Tomek", "NSL-KDD, CIC-IDS",
     "Accuracy 99.99% on both sets", "Near-perfect scores need dataset-quality checks"],
    ["{c:alkhater2026}", "2026", "Decision tree, Random Forest, SVM and XGBoost with 5-fold cross-validation", "UNSW-NB15",
     "XGBoost accuracy 0.97, AUC 0.98; sttl, sload, dload most important", "Single dataset"],
    ["{c:alani2023}", "2023", "XRecon: explainable ensemble for IoT reconnaissance detection", "IoT traffic",
     "Accuracy 99%; false-positive rate 0.6%, false-negative rate 0.05%", "IoT traffic only"],
    ["{c:almaiah2025}", "2025", "ACO, GA and GWO feature selection with SVM and KNN for port-scan detection", "Network traffic",
     "Accuracy above 99% in all configurations", "Offline; no live sensor"],
    ["{c:lanvin2023}", "2023", "Analysis of errors in CICIDS2017", "CICIDS2017",
     "Errors change measured detection performance significantly", "Dataset study, no detector"],
    ["{c:flood2024}", "2024", "Manual audit of seven benchmark NIDS datasets", "Seven datasets",
     "Six suspect design patterns found; bias demonstrated", "Dataset study, no detector"],
    ["{c:elangovan2026}", "2026", "Temporal and cross-dataset generalisation of IDS models", "Four datasets, 2017–2024",
     "Macro-F1 0.84–0.96 in dataset, 0.69–0.78 across domains", "Evaluation study, no live sensor"],
]

lit_themes = [
    P("The studies reviewed here were published between 2023 and 2026, apart from foundational works cited for background. "
      "They are grouped by theme rather than reviewed one by one, and {tab:lit} summarises all of them."),
    H3("Honeypot-based detection and threat analysis"),
    P("Honeypots have long been used to observe attackers {c:spitzner2003,provos2004}, and recent work combines them with "
      "learning methods. Containerised honeypots deployed in a cloud were used to track attackers and gather data on their "
      "intent {c:priya2023}. Honeypot data from IoT devices were fed to machine-learning and neural-network classifiers and "
      "improved attack detection {c:ahmed2024}. On the BETH honeypot dataset, an enhanced Isolation Forest raised the "
      "AUROC from 0.850 to 0.917 {c:alatawi2025}, although that dataset consists of kernel-level process logs and not "
      "network deception. A language model was used to learn attacker tactics, techniques and procedures from honeypot "
      "data and to spot anomalies in ordinary activity, with a reported reduction in response time {c:lanka2024}. In "
      "these studies the honeypot is mainly a data source; the decoy itself does not react to the attacker."),
    H3("Adaptive and learning-based deception"),
    P("A second group makes the decoy adaptive. Q-Cowrie adds reinforcement learning to the Cowrie SSH honeypot "
      "{c:cowrie}: attacker behaviour captured by Cowrie was modelled as a Markov decision process, and the learned policy "
      "then selected responses {c:varnaseri2026}. An intelligent web honeypot combined sequence-to-sequence response "
      "generation with Deep Q-learning and lengthened sessions from 3.2 to 7.8 exchanges {c:varadarajan2026}. A "
      "software-defined honeypot used a Stackelberg game with deep reinforcement learning to decide when to change its "
      "deployment, which was unnecessary in 80% of simulated rounds {c:zhang2026}. A game-theoretic framework defines the "
      "value of deception and the price of transparency as measures {c:shahin2026}, and a survey of moving target defence "
      "describes the wider family of changing-defence ideas {c:sun2023}. Each of these studies addresses one protocol or one "
      "decision, and each is evaluated in isolation from a full detection and response pipeline."),
    H3("Language-model honeypots"),
    P("Large language models can generate shell output on demand. shelLM produced credible Linux shell responses, and "
      "researchers judged 90% of the fake responses as plausible {c:sladic2024}. Hallucination and loss of state make such "
      "decoys detectable, which LLM-SSHH addressed with an explicit state snapshot {c:li2026}. A benchmark of eleven "
      "back-end models found large differences in fidelity and latency, one case of an instruction leak and a risk that "
      "the back end itself can be fingerprinted {c:magazov2026}. These findings explain a design decision in this project: "
      "the decoys use deterministic templates and no external model, and the project treats language models as future work."),
    H3("Machine-learning intrusion detection on CIC-IDS2017 and UNSW-NB15"),
    P("The two datasets used here, CIC-IDS2017 {c:sharafaldin2018} and UNSW-NB15 {c:moustafa2015}, are the subject of a large "
      "literature. Random Forest {c:breiman2001} is consistently among the best classifiers: on UNSW-NB15 it reached an F1-score of "
      "97.80% with a false-alarm rate of 1.36% {c:more2024}, and a recent five-fold comparison reports 0.97 accuracy "
      "for XGBoost {c:alkhater2026}. Improvements come from feature selection {c:yin2023,nassreddine2025}, "
      "cost-sensitive learning {c:lu2024} and hybrid models that add an autoencoder for unknown attacks {c:wang2023}. "
      "Scores close to 100% are common, for example 99.99% accuracy on CIC-IDS {c:nassreddine2025}."),
    H3("Reconnaissance and port-scan detection"),
    P("Reconnaissance has its own studies. XRecon uses an explainable ensemble to detect scanning in IoT networks, with "
      "99% accuracy and false-positive and false-negative rates of 0.6% and 0.05% {c:alani2023}. Metaheuristic feature "
      "selection with SVM and KNN detected port scans with more than 99% accuracy {c:almaiah2025}. All of these classify "
      "recorded flows after the fact, using the full set of flow features, and none addresses what a decoy can measure "
      "while the scan is happening."),
    H3("Dataset quality and generalisation"),
    P("The high scores above must be read with care. A study of CICIDS2017 documented errors in the data and showed that "
      "they change measured detection performance {c:lanvin2023}, as an earlier troubleshooting study of the same dataset "
      "had also indicated {c:engelen2021}; an audit of seven benchmark NIDS datasets found six "
      "recurring design flaws that can bias results {c:flood2024}; and a study spanning four datasets from 2017 to 2024 "
      "reported that macro-F1 falls from 0.84–0.96 within a dataset to 0.69–0.78 across domains, with tree-based "
      "ensembles degrading least {c:elangovan2026}. These findings motivated the leakage controls used in Chapter IV."),
    H3("Threat intelligence and attribution"),
    P("Honeypot data are more useful when they become structured intelligence. SSH command chains were clustered into "
      "18 behavioural groups and mapped to MITRE ATT&CK {c:lim2026,attack}, and IP-based attribution combined intrusion data "
      "with external intelligence to group attackers with 88.89% accuracy {c:xiang2024}. The STIX 2.1 standard "
      "{c:stix21} gives a common format for exchanging such indicators."),
    T("lit", "Summary of the literature reviewed",
      ["Ref.", "Year", "Method", "Data / setting", "Key reported result", "Limitation for this work"],
      LIT_ROWS, [0.35, 0.4, 1.35, 0.85, 1.4, 1.1], size=8.5, align=["c", "c", "l", "l", "l", "l"]),
]

lit_summary = [
    P("Four trends emerge from the survey."),
    N([
        "**Adaptation is studied piecemeal.** Reinforcement learning, language models and game theory each improve one "
        "aspect of a decoy, but the studies reviewed do not describe a full loop from detection through profiling and "
        "adaptation to response and intelligence export.",
        "**Offline accuracy is very high and often unquestioned.** Many machine-learning studies report 97–99.99% on "
        "benchmark files, whereas auditing studies show that such files contain duplicates and design flaws "
        "{c:lanvin2023,flood2024} and that performance falls across datasets {c:elangovan2026}.",
        "**Random Forest remains a strong, simple choice.** It is repeatedly competitive with more elaborate models "
        "{c:more2024,alkhater2026}, trains quickly and offers feature importances, which suits a small live sensor.",
        "**Intelligence outputs are moving towards standards.** ATT&CK mapping and STIX 2.1 are the common currency for "
        "sharing what a honeypot learns {c:lim2026,stix21}.",
    ]),
    P("The project accepted these lessons: it used Random Forest, treated benchmark scores with suspicion, and produced "
      "ATT&CK and STIX output."),
]

gap = [
    P("Comparing the surveyed work with the objectives of this project reveals the gaps listed in {tab:gap}."),
    T("gap", "Research gaps and the response of this project",
      ["No.", "Gap found in the literature", "Response in this project"],
      [["G1", "Adaptive honeypots address a single protocol, such as SSH {c:varnaseri2026,li2026} or HTTP {c:varadarajan2026}.",
        "One sensor with SSH, HTTP and nine bait services and a persona applied to all of them."],
       ["G2", "Adaptation is seldom closed with live detection, response and intelligence.",
        "One pipeline: event, rules and models, profile, persona, response, export."],
       ["G3", "Machine-learning results come from offline files; the mismatch with live-measurable features is rarely measured.",
        "Measured-feature coverage reported and models re-tested with unmeasured features masked."],
       ["G4", "Benchmark duplicates and errors inflate scores {c:lanvin2023,flood2024}.",
        "De-duplication, overlap removal, stratified splits and tests on other capture days."],
       ["G5", "Honeypot data are analysed offline.", "Online scoring, attacker profiles, ATT&CK mapping and STIX 2.1 export."],
       ["G6", "Few studies compare adaptive and static decoys with stated assumptions.",
        "Static, rotation, learning and oracle policies compared in a transparent simulation."]],
      [0.4, 2.7, 2.6], size=9.5, align=["c", "l", "l"]),
    P("**Motivation.** These gaps motivated a system that is small enough to run on one computer yet complete enough to "
      "show the whole loop. The focus was on integration, on honest measurement, and on safe behaviour, rather than on "
      "proposing a new classifier."),
]

proposed_system = [
    P("The proposed system is a single Python process, called the sensor, that hosts the decoys, the detection engine, the "
      "deception policy, the block manager and an operator console, together with a FastAPI bridge and a React dashboard. "
      "Every decoy emits events in one common format. The detection engine evaluates behavioural rules over sliding windows, "
      "adds the output of two Random Forest models, maps the result to ATT&CK techniques, assigns a behavioural profile "
      "with a confidence value, and then asks the deception policy to adapt the decoy and the block manager to decide on a "
      "response. All decisions and their reasons are stored, so that an analyst can see why each action was taken."),
]
