"""Chapter III content blocks (system development / methodology)."""

from facts import *  # noqa: F401,F403

schedule = [
    P("The project followed the ten-week timeline set by the department. {fig:timeline} shows how the weeks were used, from "
      "topic finalisation to final evaluation. Implementation was done in two parts: decoys and detection first, then "
      "adaptation, response and the dashboard, with the evaluation and report in the later weeks."),
    F("timeline", "timeline.png", "Project schedule over the ten-week timeline", 5.4),
]

model_dev = [
    P("The system was developed in two connected tracks, shown in {fig:method}. The **offline track** prepared the "
      "machine-learning models: the CIC-IDS2017 and UNSW-NB15 files were cleaned, de-duplicated and split, a Random Forest "
      "and four baseline classifiers were trained, the hyperparameters were chosen on a validation part, and the final "
      "numbers were measured once on a held-out test part. The saved pipelines were then loaded by the sensor. The "
      "**online track** is the running sensor: decoys emit events, the engine enriches and scores them, the deception "
      "policy and the block manager respond, and the console and dashboard display the outcome."),
    F("method", "methodology.png", "Offline model development and online detection and response", 6.2),
    P("The online decision procedure for one event is shown in {fig:flow}. After the event is stored and added to the "
      "per-source history, all rules are evaluated over their sliding windows. If none fires, the models alone may "
      "raise a finding, but only when at least three flows score above 0.5 and the model points reach 25, because "
      "single-flow model scores proved noisy. If a rule fires, the points are combined, a cooldown check suppresses "
      "repeated findings of the same class unless severity rises, and a finding is created. Creating a finding adapts the "
      "decoy and may trigger a block, subject to the safety checks described later."),
    F("flow", "flowchart.png", "Flow chart of the decision made for each event", 4.6),
]

architecture_intro = [
    P("{fig:arch} shows the architecture. Four layers can be distinguished. The decoy and telemetry layer faces the "
      "network. The detection engine turns events into findings. The response and storage layer adapts the decoy, blocks "
      "sources and records everything. The analyst interfaces present the results. A feedback path leads from the "
      "deception policy back to the decoys, so that what an attacker sees depends on what the attacker has already done."),
    F("arch", "architecture.png", "Block diagram of the AI-adaptive honeypot system", 5.7),
]

blk_decoys = [
    P("The SSH decoy is built on Paramiko. It presents a persona-specific banner, accepts password and key authentication "
      "attempts, records the user name and a preview of the secret, and rejects every attempt, so no shell is ever "
      "granted. The HTTP decoy is a small web application that serves a sign-in page, a WordPress login, a phpMyAdmin "
      "page, a fake users API, `/robots.txt`, `/.git/config` and a `/.env` file that contains honeytokens. When the "
      "engagement level of an attacker is 2 or higher, fake database dumps and a backup configuration file are also served. "
      "Nine bait listeners (FTP 21, Telnet 23, SMTP 25, POP3 110, MSSQL 1433, MySQL 3306, Redis 6379, Elasticsearch 9200 "
      "and MongoDB 27017) send persona-specific greetings and record banner grabs and protocol probes. No decoy executes "
      "anything it receives, makes outbound connections or serves real data."),
]

blk_telemetry = [
    P("Every listener emits an `Event` with a kind (connection, SSH authentication, HTTP request or firewall drop), the "
      "source address, destination port, service, a time stamp and a detail dictionary ({tab:event}). Connection events "
      "carry flow statistics measured by the decoy: duration, bytes and packets in each direction, the sizes of the data "
      "chunks, and whether the client closed gracefully or reset. These statistics are the input of the machine-learning "
      "models. An optional reader parses the Windows Defender Firewall log, so that probes of closed ports and ICMP "
      "echo requests, which no decoy would see, are also available to the rules."),
    T("event", "Fields of the common event record",
      ["Field", "Meaning", "Example"],
      [["kind", "Type of event", "connection, ssh_auth, http_request, fw_drop"],
       ["src_ip", "Source address", "203.0.113.45"],
       ["dst_port / service", "Targeted port and decoy service", "6379 / redis"],
       ["ts", "Time stamp (seconds since epoch)", "1798950000.25"],
       ["detail", "Protocol details: path, user agent, user name, flow statistics, signature, web-attack families",
        "{\"path\": \"/.env\", \"status\": 200}"]],
      [1.3, 2.8, 2.0], size=9.5, bold_first=True),
]

blk_detection = [
    P("The detection engine keeps a bounded history for each source (900 seconds, 2,000 events) and evaluates the rules in "
      "{tab:rules} after each event. A rule yields a class, a number of points and a human-readable reason with evidence. "
      "Thresholds are configurable ({tab:thresholds}). The four web-attack rules inspect the decoded request path, query "
      "string and body preview with conservative regular expressions that require an attack construct, for example "
      "`UNION SELECT`, a script tag, `;cat` after a parameter, or a repeated `../` sequence, and not a single keyword. "
      "Up to two layers of percent-encoding are decoded, because double encoding is a common evasion."),
    T("rules", "Detection rules, triggers and points",
      ["Class", "Trigger", "Points"],
      [["PORT_SCAN", "≥ 4 distinct ports within 60 s", "min(70, 40 + 3·extra)"],
       ["SERVICE_DISCOVERY", "≥ 3 decoy service ports within 5 min", "min(50, 20 + 4·extra)"],
       ["BANNER_ENUMERATION", "≥ 3 silent connects, or protocol fingerprints, within 5 min", "min(40, 15 + 3·silent + 10·fp)"],
       ["HOST_DISCOVERY", "≥ 3 ICMP echo requests in the firewall log within 5 min", "min(55, 35 + 3·extra)"],
       ["HTTP_ENDPOINT_PROBING", "≥ 2 sensitive or ≥ 5 distinct paths within 2 min", "min(65, 25 + 6·sens + 2·extra)"],
       ["SSH_BRUTE_FORCE", "≥ 5 authentication attempts within 2 min", "min(75, 40 + 3·extra [+10])"],
       ["HONEYTOKEN_REUSE", "A decoy-issued credential is presented again", "80"],
       ["SQL_INJECTION, XSS, COMMAND_INJECTION, PATH_TRAVERSAL, FILE_UPLOAD_ABUSE, SSRF_LFI",
        "Request text matches an attack signature, within 5 min", "min(85, 60 + 5·(count − 1))"]],
      [1.9, 2.8, 1.6], size=9, bold_first=True),
    T("thresholds", "Default detection and response configuration",
      ["Parameter", "Value", "Parameter", "Value"],
      [["Window for scans", "60 s", "Finding cooldown", "120 s"],
       ["History kept", "900 s", "MEDIUM severity from", "45"],
       ["Scan minimum ports", "4", "HIGH severity from", "75"],
       ["SSH minimum attempts", "5", "Block minimum score", "75"],
       ["HTTP probe minimum paths", "5", "Block expiry (TTL)", "1,440 min"],
       ["Model weights (CIC / UNSW)", "30 / 10", "Maximum active blocks", "200"]],
      [1.9, 1.0, 1.9, 1.0], size=9.5, align=["l", "c", "l", "c"]),
    P("For a connection event, the sensor also builds a CIC-IDS2017 feature row and a UNSW-NB15 feature row from what it "
      f"measured and scores both models. The CIC model expects 78 features and the sensor measured "
      f"{CIC['live_measured_features']} of them ({pct(CIC['live_feature_coverage'], 1)}); for UNSW-NB15 the sensor "
      f"measured {UNSW['live_measured_features']} of 42 ({pct(UNSW['live_feature_coverage'], 1)}). The remaining features are "
      "left missing, and the median imputer stored inside each model pipeline fills them. The coverage is stored with every "
      "finding so that an analyst can judge how far the model score should be trusted."),
]

blk_profile = [
    P("Every finding carries an attacker profile. The profiler computes features from the source's history (event count, "
      "rate, distinct ports and paths, SSH attempts, web-attack matches and honeytoken hits) and scores five behavioural "
      "labels: automated scanner, credential attacker, web-exploit attacker, manual explorer and targeted multi-stage "
      "activity. The confidence value is the share of positive evidence that supports the winning label. It is "
      "a measure of how clearly the behaviour fits a label, and does not identify a person or a group."),
    P("Each class is also mapped to MITRE ATT&CK techniques {c:attack}, as in {tab:attack}. For example, port scans map to "
      "T1046 (Network Service Discovery), SSH guessing to T1110 (Brute Force) and honeytoken reuse to T1078 (Valid Accounts). "
      "The mapping describes what the observed behaviour resembles; it is not proof of a specific adversary."),
    T("attack", "Mapping of detection classes to MITRE ATT&CK techniques",
      ["Detection class", "ATT&CK technique(s)", "Tactic"],
      [["PORT_SCAN, SERVICE_DISCOVERY", "T1046 Network Service Discovery", "Discovery"],
       ["BANNER_ENUMERATION", "T1046; T1592 Gather Victim Host Information", "Discovery; Reconnaissance"],
       ["HOST_DISCOVERY", "T1595.001 Scanning IP Blocks", "Reconnaissance"],
       ["HTTP_ENDPOINT_PROBING", "T1595.003 Wordlist Scanning; T1190", "Reconnaissance; Initial access"],
       ["SSH_BRUTE_FORCE", "T1110 Brute Force", "Credential access"],
       ["HONEYTOKEN_REUSE", "T1078 Valid Accounts; T1552.001", "Defense evasion; Credential access"],
       ["SQL_INJECTION, PATH_TRAVERSAL, SSRF_LFI", "T1190 Exploit Public-Facing Application", "Initial access"],
       ["COMMAND_INJECTION", "T1059 Command and Scripting Interpreter; T1190", "Execution; Initial access"],
       ["XSS", "T1189 Drive-by Compromise", "Initial access"],
       ["FILE_UPLOAD_ABUSE", "T1505.003 Web Shell", "Persistence"]],
      [2.1, 2.5, 1.7], size=9, bold_first=True),
]

blk_deception = [
    P("Each source address has a **persona** and an **engagement level**. A persona is a complete server identity: SSH "
      "banner, HTTP `Server` header, brand name on the sign-in page and greetings of the FTP, SMTP, POP3 and Telnet "
      "services ({tab:persona}). The engagement level, from 1 to 3, controls how much fake content is served; honeytoken "
      "reuse sets it to 3. Persona changes are stored with the reason, so the analyst can inspect each adaptation."),
    T("persona", "Decoy personas",
      ["Persona", "SSH banner", "HTTP server", "Intended appearance"],
      [["ubuntu_web (default)", "OpenSSH 8.9p1 Ubuntu", "Apache 2.4.52 (Ubuntu)", "Ubuntu 22.04 web server"],
       ["windows_server", "OpenSSH_for_Windows_8.1", "Microsoft-IIS/10.0", "Windows Server 2019 with IIS"],
       ["legacy_linux", "OpenSSH_7.4", "nginx/1.14.0 (Ubuntu)", "Legacy Debian 9 host"]],
      [1.5, 1.7, 1.6, 1.5], size=9.5, bold_first=True),
    P("The choice of persona was originally a fixed table, with banner rotation as a countermeasure to repeated "
      "scanning. In the final system the choice is **learned**. For each attack class, every persona is an arm of a "
      "multi-armed bandit, and the reward is the amount of further interaction the attacker shows after the persona has "
      "been presented (Section {sec:algo}). The hand-written choice acts only as a weak prior, worth two pseudo-observations. "
      "When a source repeats a scanning class, the policy picks the best persona other than the current one. This allows "
      "the decoy to discover which identity keeps a given kind of attacker engaged, without that knowledge being coded in advance."),
]

blk_response = [
    P("The **block manager** blocks a source through Windows Defender Firewall by running `netsh advfirewall` with an "
      "argument list and never through a shell. A finding leads to a block only if its class is a blocking class and its "
      "score is at least 75. Several safeguards apply: loopback addresses, the machine's own addresses, the default "
      "gateway and allow-listed networks are never blocked; every block has an expiry time (24 hours by default); the "
      "number of active blocks is limited to 200; and in dry-run mode the decision is recorded but no firewall rule is "
      "created. A worker thread is the only place that calls `netsh`, and each result (active, failed, released) is "
      "stored."),
    P("The **threat-intelligence module** builds a profile per source, links sources into campaigns when they share a "
      "honeytoken, a password hash, a username list, an unusual user agent or a set of ports, and exports indicators in "
      "JSON and CSV. User agents seen from more than ten sources are ignored as generic tooling. A new endpoint exports "
      "the findings of a chosen window as a **STIX 2.1** bundle {c:stix21}, with one indicator per source address, the "
      "ATT&CK attack patterns it evidences and the relationships between them. Identifiers are generated "
      "deterministically, so the same window always yields the same bundle."),
    P("The **operator console** (a single page served on 127.0.0.1:9100, protected by a token) and the **React dashboard** "
      "(port 5173, reading through the FastAPI bridge on port 8000) show alerts with their score breakdown, attacker "
      "timelines, live events, blocks, decoy actions, threat intelligence and the status of listeners and models. The "
      "operator token never reaches the browser of the dashboard. Captured passwords are replaced by a short SHA-256 digest "
      "before they are stored, and form passwords in HTTP bodies are masked; honeytoken matching is performed first on the "
      "raw text, so reuse is still detected."),
]

uml_blocks = [
    P("The structure of the system was modelled with the diagrams below. {fig:dfd0} is the context diagram; {fig:dfd1} "
      "decomposes the sensor into five processes and one data store; {fig:usecase} lists what the attacker and the "
      "operator can do; {fig:seq} shows the order of calls for one probe; and {fig:cls} shows the main classes."),
    F("dfd0", "dfd0.png", "Data flow diagram, level 0 (context)", 5.6),
    F("dfd1", "dfd1.png", "Data flow diagram, level 1", 5.7),
    F("usecase", "usecase.png", "Use case diagram", 5.3),
    F("seq", "sequence.png", "Sequence diagram of one probe through the system", 5.7),
    F("cls", "classdiagram.png", "Class diagram of the main sensor components", 5.7),
]

algorithms = [
    P("**Score fusion.** The score of a finding combines the rule points and the model points. If several rules fire for one "
      "source, the strongest rule sets the class and each additional rule adds ten points, up to 90:"),
    E("rule", "R = min( 90, rₘₐₓ + 10 · (k − 1) )"),
    P("where rₘₐₓ is the largest rule score and k the number of rules that fired. The model points convert the "
      "highest attack probabilities seen in the last 60 seconds into at most 40 points:"),
    E("ml", "ML = round( 30 · pᶜⁱᶜ + 10 · pᵤₙₛᵥ )"),
    E("score", "S = min( 100, R + ML )"),
    P("The severity is LOW below 45, MEDIUM from 45 and HIGH from 75. As an example of a rule score, a port scan with d "
      "distinct ports within 60 seconds receives"),
    E("scan", "r = min( 70, 40 + 3 · (d − 4) ),   d ≥ 4"),
    P("**Random Forest.** Both models are Random Forests {c:breiman2001} of T = 100 trees with balanced class weights, "
      "implemented in scikit-learn {c:pedregosa2011}. Each tree t returns a class probability, and the forest averages them:"),
    E("rf", "p(x) = (1 / T) · Σₜ pₜ(x),   t = 1, …, T"),
    P("The forest was chosen for four reasons: it handles mixed numeric and categorical inputs, it is robust to the "
      "imputed values that the live sensor must use, it is fast enough for single-flow scoring "
      f"(mean {UNSW['deployed_latency_ms']['mean']:.1f} ms for the UNSW-NB15 pipeline and "
      f"{CIC['latency_ms_deployed']['mean']:.1f} ms for the CIC-IDS2017 pipeline), and it provides feature importances. "
      "The time to score one flow grows linearly with the number of trees and with their depth."),
    P("**Learning deception policy.** For each attack class c, let nₐ be the number of times persona a was shown and "
      "x̄ₐ its mean reward. The UCB1 rule {c:auer2002} chooses the persona with the highest upper confidence bound:"),
    E("ucb", "a* = argmaxₐ [ x̄ₐ + β · √( ln N / nₐ ) ],   β = 0.8"),
    P("where N is the total number of choices for the class. A persona that has never been tried is chosen first. The reward "
      "measures how much the attacker kept interacting within 300 seconds after the persona was shown, capped at ten events:"),
    E("reward", "r = min( 1, m / 10 )"),
    P("where m is the number of events from the same source in that window. UCB1 was selected because it is deterministic "
      "given the history, has a single tuning constant and is easy to explain. The reward measures continued "
      "interaction only; it does not show that the attacker was deceived."),
    H3("Pseudocode"),
    CODE("""Algorithm 1: process one event e from source s
 1  if e is a connection: score the flow with both models
 2  if e is HTTP or SSH: check e for honeytokens; classify web attacks
 3  redact secrets in e; store e; append e to history[s]; drop old events
 4  tell the deception policy that s interacted again (feedback)
 5  rules <- evaluate all rules on history[s]
 6  if rules is empty and not ML-only agreement: return nothing
 7  R <- min(90, strongest(rules) + 10 * (len(rules) - 1));  S <- min(100, R + ML)
 8  if same class in cooldown and severity not higher: return nothing
 9  profile <- build_profile(history[s]);  attach ATT&CK techniques
10  persona, level <- deception.on_finding(finding)
11  decision <- blocker.consider(finding)
12  store finding with its reasons, evidence and decision"""),
    CODE("""Algorithm 2: choose a persona for attack class c (UCB1)
 1  for each persona a not excluded: if n[c][a] = 0 then return a
 2  N <- sum of n[c][a] over all personas
 3  for each candidate a: score[a] <- mean[c][a] + 0.8 * sqrt(ln N / n[c][a])
 4  return the persona with the highest score
 5  feedback: after the persona is shown, count follow-up events m in 300 s;
 6            credit(c, a, min(1, m / 10))"""),
    CODE("""Algorithm 3: block decision for a finding
 1  if blocking disabled or class not a blocking class: no action
 2  if score < 75: no action
 3  if source is loopback, this host, the gateway or allow-listed: refuse
 4  if an active block exists: return it; if 200 blocks are active: refuse
 5  record block (PENDING) with expiry = now + TTL
 6  worker: dry run -> mark DRY_RUN; else run netsh add rule -> ACTIVE or FAILED"""),
]

formulation = [
    P("The problem was formulated as a sequential decision problem over a stream of events. Let E(s, t) be the events from "
      "source s up to time t. For each source the sensor computes a rule score R(s, t) and a model score ML(s, t), combines "
      "them as in {eq:score}, and compares the result with two thresholds to obtain a severity. The decoy state of s, a "
      "pair (persona, level), is then updated and a block decision is made."),
    P("Two measurable quantities define success. The first is **detection quality**: for sessions known to be attacks or "
      "normal use, the recall, precision and false-alarm rate of the findings. The second is **engagement**: the mean "
      "number of interactions per attacker session, which the decoy policy tries to maximise. In both cases the "
      "constraint is safety: no decoy may execute attacker input, and no block may affect the sensor's own host."),
]

tech_stack = [
    P("{tab:sw} lists the software used and {tab:hw} the hardware on which all measurements were made. Version numbers "
      "were read from the environment of the project, not copied from documentation."),
    T("sw", "Software and frameworks",
      ["Component", "Technology", "Version", "Role"],
      [["Language", "Python", "3.13.9", "Sensor, backend, evaluation"],
       ["ML", "scikit-learn / pandas / NumPy / joblib", "1.6.1 / 3.0.6 / 2.5.4 / 1.6.0", "Random Forest pipelines, data handling"],
       ["SSH decoy", "Paramiko", "5.1.0", "Fake SSH server"],
       ["Web layer", "FastAPI / Starlette / Uvicorn", "0.147.0 / 1.9.0 / 0.54.0", "HTTP decoy, console API, bridge"],
       ["Storage", "SQLite (sensor); SQLAlchemy / PostgreSQL driver", "2.1.6 / psycopg2 2.9.13", "Telemetry; original backend"],
       ["Validation", "Pydantic / httpx", "2.14.1 / 0.28.1", "Request models; bridge client"],
       ["Dashboard", "React / Vite / Recharts / lucide-react", "19.3.1 / 8.3.5 / 3.10.1 / 1.61.0", "Monitoring interface"],
       ["Runtime", "Node.js / npm", "24.22.0 / 11.19.1", "Dashboard build and server"],
       ["Firewall", "Windows Defender Firewall (netsh advfirewall)", "Windows 11", "Blocking"]],
      [1.0, 2.1, 1.7, 1.5], size=9, bold_first=True),
    T("hw", "Hardware and operating system used",
      ["Item", "Specification"],
      [["Processor", "Intel Core i7-14700, 20 cores, 28 threads"],
       ["Memory", "15.7 GB RAM"],
       ["Storage", "475 GB system disk"],
       ["Operating system", "Windows 11 Home Single Language, build 10.0.26200"]],
      [1.6, 4.4], size=10, bold_first=True),
]

datasets = [
    P("Two public datasets were used. The CIC-IDS2017 dataset {c:sharafaldin2018} contains flows extracted by "
      "CICFlowMeter from five days of traffic, with 78 numeric flow features and a label. The Friday afternoon file, "
      f"which contains benign traffic and a port scan, has {n(CIC['file_rows'])} rows. The UNSW-NB15 dataset "
      f"{{c:moustafa2015}} provides {UNSW['feature_count']} features and ten traffic categories; its official training and "
      f"testing files have {n(UNSW['train_rows'])} and {n(UNSW['test_rows'])} rows. For each dataset a binary task was defined: "
      "benign versus port scan for CIC-IDS2017, and normal versus reconnaissance for UNSW-NB15. {tab:ds} compares them."),
    T("ds", "Description of the datasets",
      ["Item", "CIC-IDS2017 (PortScan task)", "UNSW-NB15 (Reconnaissance task)"],
      [["Source", "Canadian Institute for Cybersecurity", "UNSW Canberra"],
       ["File(s) used", "Friday-WorkingHours-Afternoon-PortScan", "Official training and testing sets"],
       ["Features", f"{CIC['feature_count']} flow features", f"{UNSW['feature_count']} (39 numeric, 3 categorical)"],
       ["Positive class", f"PortScan: {n(CIC['class_counts']['PortScan'])} rows", f"Reconnaissance: {n(UNSW['train_two_class']['Reconnaissance'])} train, {n(UNSW['test_two_class']['Reconnaissance'])} test"],
       ["Negative class", f"BENIGN: {n(CIC['class_counts']['BENIGN'])} rows", f"Normal: {n(UNSW['train_two_class']['Normal'])} train, {n(UNSW['test_two_class']['Normal'])} test"],
       ["Target variable", "Label (BENIGN / PortScan)", "attack_cat (Normal / Reconnaissance)"]],
      [1.3, 2.4, 2.4], size=9.5, bold_first=True),
    P("{fig:cicsample} and {fig:unswsample} show a few records. Port-scan flows are very short and carry one or two packets, "
      "whereas benign flows are longer; in UNSW-NB15 reconnaissance records differ mainly in duration, packet counts and rate."),
    F("cicsample", "sample_cic.png", "Sample records from CIC-IDS2017 (first three BENIGN, first three PortScan)", 5.9),
    F("unswsample", "sample_unsw.png", "Sample records from UNSW-NB15 (first three Normal, first three Reconnaissance)", 5.9),
]
