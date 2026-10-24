# AI-Adaptive Honeypot Sensor

Decoy services, telemetry, ML-assisted reconnaissance detection, adaptive
deception, automatic IP blocking and an operator console, in one Python
process. It runs alongside the existing FastAPI backend and does not depend
on PostgreSQL: the sensor keeps its own SQLite store.

## What it does

| Stage | Component | What it does |
|---|---|---|
| Decoys | `listeners/ssh.py` | Fake SSH server (paramiko). Persona banner, password and key auth attempts recorded, auth never succeeds, no shell is ever granted. |
| Decoys | `listeners/http_decoy.py` | Fake web app: login pages, `/.env` with honeytokens, `/.git/config`, `/wp-login.php`, `/phpmyadmin`, fake users API, 404s. Every request logged. |
| Decoys | `listeners/bait.py` | Banner-grabbing ports for FTP, Telnet, SMTP, POP3, MSSQL, Redis, Elasticsearch, MongoDB. Records banner grabs and protocol probes. |
| Telemetry | `listeners/fwlog.py` | Reads Windows Firewall dropped-packet log, so scans of **closed** ports and ping sweeps are seen too. |
| Telemetry | `store.py` | SQLite: events, findings, blocks, decoy actions, honeytokens. |
| Detection | `engine.py` | Rules over sliding windows: `PORT_SCAN`, `SERVICE_DISCOVERY`, `BANNER_ENUMERATION`, `HOST_DISCOVERY`, `HTTP_ENDPOINT_PROBING`, `SSH_BRUTE_FORCE`, `HONEYTOKEN_REUSE`. |
| ML | `ml.py` | Scores every measured connection with the two trained models in the project root (see below). Their output adds up to 40 points to the score. |
| Adaptive deception | `deception.py` | Changes the attacker's persona (SSH and HTTP banners), engagement level (how much fake content is served), and rotates banners against repeated scanning. Every change is stored with its reason. |
| Response | `firewall.py` | Blocks attacker IPs with Windows Defender Firewall rules (`netsh advfirewall`). Dry-run by default, with allowlist, gateway protection, TTL expiry and a cap on active blocks. |
| Console | `admin_app.py`, `admin/index.html` | Operator console on `127.0.0.1:9100`: alerts, attacker timelines, live events, block/unblock, persona control, listener and model status. |

Scoring: rule points (up to 90) plus ML points (up to 40), capped at 100.
Severity is `LOW` below 45, `MEDIUM` from 45, `HIGH` from 75. A finding in a
blocking class with a score of at least 75 is recorded as a block. A firewall
rule is created only when `response.enforce` is true; otherwise the block is
marked `DRY_RUN`.

## Quick start (on this machine)

```bash
cd honeypot-backend
../venv313/Scripts/python.exe -m sensor.main
```

Startup prints every listener and its state, the firewall mode, and the
model status. The admin token is created on first start in
`sensor/data/admin_token.txt`. Open <http://127.0.0.1:9100/> and paste it.

Test it against your own sensor (loopback by default):

```bash
../venv313/Scripts/python.exe -m sensor.tools.simulate_probes --all
```

Run the test suite:

```bash
../venv313/Scripts/python.exe -m unittest discover -s tests -t . -v
```

The tests use a temporary database and a fake firewall runner, so they never
create a firewall rule.

## Configuration

Defaults are in `sensor/config.json`. Put overrides in any JSON file and
start with `--config path.json` or `HONEYPOT_SENSOR_CONFIG=path.json`.

| Key | Default | Meaning |
|---|---|---|
| `decoys.bind_host` | `0.0.0.0` | Address the decoys listen on. Use the LAN address to restrict them. |
| `decoys.ssh.port` | `2222` | SSH decoy port. Choose 22 only if Windows OpenSSH Server is not installed. |
| `decoys.http.port` | `8080` | Decoy web application (the "decoy URL"): `http://<campus-ip>:8080/`. |
| `decoys.bait.services` | FTP 21, Telnet 23, SMTP 25, POP3 110, MSSQL 1433, MySQL 3306, Redis 6379, ES 9200, Mongo 27017 | Bait TCP ports. A port Windows refuses to bind is reported as `unavailable`, and the sensor keeps running. On this machine, binding 3306 fails with WinError 10013. |
| `admin.host` / `admin.port` | `127.0.0.1` / `9100` | Operator console. The config is rejected if `host` is not a loopback address. |
| `detection.*` | see file | Window sizes and minimum counts for each rule. |
| `ml.cic_weight` / `ml.unsw_weight` | `30` / `10` | Maximum score points each model can add. |
| `firewall_log.enabled` | `false` | Read `pfirewall.log`. Needs `scripts/setup_firewall.ps1` first. |
| `response.enforce` | `false` | **false = dry run** (decisions logged, no firewall rule). **true = real blocks.** |
| `response.block_min_score` | `75` | Score needed for an automatic block. |
| `response.block_classes` | PORT_SCAN, SSH_BRUTE_FORCE, HTTP_ENDPOINT_PROBING, HONEYTOKEN_REUSE, HOST_DISCOVERY | Classes that can trigger a block. |
| `response.block_ttl_minutes` | `1440` | Automatic unblock after 24 h. `0` = permanent. |
| `response.allowlist` | loopback | CIDRs never blocked. Add your IT, DNS and admin networks here. |

Loopback, this machine's own addresses and the default gateway are always
protected, whatever the config says.

## Operator console

- Open `http://127.0.0.1:9100/` on the sensor machine. It is not reachable
  from the network.
- **Alerts**: every finding with score breakdown, reasons and the decision taken.
- **Attackers**: one row per source IP. Change its persona, block or unblock it,
  and open its timeline.
- **Live events**: raw connections, SSH auth attempts and HTTP requests.
- **Blocks**: active and past blocks with status and error text.
- **Decoy actions**: every persona or engagement change and why it happened.
- **Threat intel**: attacker sources linked into campaigns, with the reason for
  each link (shared honeytoken, password hash, user agent, username list or port
  set), plus an indicator table. Export the indicators as JSON or CSV for the
  window you select. Passwords are exported as SHA-256 digests only. Shared
  user agents seen on more than 10 sources are ignored, so common library
  defaults don't link unrelated attackers.
- **Listeners and models**: which ports are open and whether both models loaded.

The admin token is read from `HONEYPOT_ADMIN_TOKEN` if that is set, otherwise
from `sensor/data/admin_token.txt`. Keep that file private.

## Deploying on the college ethernet

Do this only with the network team's approval. Honeypots on a shared network
can break acceptable-use rules, and a decoy can be scanned or attacked by
other students and staff.

1. **Get written approval** from IT: the sensor's IP, the ports it opens, and
   that it will log connection metadata and login attempts from other users.
2. **Find the address**: `ipconfig`. Note the IPv4 address on the campus
   interface. Ask IT to reserve it (DHCP reservation), so the address is stable.
3. **Check the network profile.** Campus networks are often classed as
   `Public`. The firewall script opens decoy ports on all profiles by default.
   Pass `-NetworkProfile Private` only if IT confirms the network is private.
4. **Open the decoy ports and enable firewall logging** from an
   **Administrator** PowerShell:

   ```bash
   powershell -ExecutionPolicy Bypass -File sensor/scripts/setup_firewall.ps1 -WhatIf
   powershell -ExecutionPolicy Bypass -File sensor/scripts/setup_firewall.ps1
   ```

   This creates `HP-DECOY-*` allow rules only for the decoy ports and turns on
   dropped-connection logging. Undo with `-Undo`.
5. **Turn on the firewall log reader**: in `sensor/config.json`, set
   `firewall_log.enabled` to `true`. That lets the sensor see scans of closed
   ports and ping sweeps.
6. **Start in dry-run.** Leave `response.enforce` as `false`. Run the sensor for
   at least a day and read the Alerts and Attackers tabs. Check that no
   legitimate colleague's machine or the gateway shows up as an attacker.
7. **Turn on blocking** only after step 6. Set `response.enforce` to `true` and
   restart the sensor from an **Administrator** shell. Without elevation, the
   sensor logs a warning and each block is recorded as `FAILED`.
8. **Check the gateway and DNS addresses** are in the protected list
   (`GET /api/status`, the Blocks tab). Add any other infrastructure address to
   `response.allowlist`.
9. **Keep the console local.** Do not port-forward 9100 or expose it through
   the campus network. Access it with RDP or a local session only.
10. **Restart after reboot** with Task Scheduler (run at startup, highest
    privileges, working directory `honeypot-backend`).

To stop everything and revert the firewall: stop the sensor, then run
`setup_firewall.ps1 -Undo` as Administrator.

## Monitoring dashboard (port 5173)

The React dashboard reads live sensor data through the FastAPI backend's
`/sensor` routes (`honeypot-backend/sensor_bridge.py`). The backend calls the
sensor console on 127.0.0.1 with the admin token, so the token never reaches
the browser. Keep the backend on 127.0.0.1, and start the sensor first. Set
`VITE_DATA_SOURCE=postgres` in the frontend to go back to the database routes.

## Honest limits

- **ML models.** Both models load and score every connection. The CIC-IDS2017
  PortScan model scores 99.998% accuracy on the Friday PortScan CSV (6 errors in
  286,467 rows). That file may have been in its training data. But it was trained on CICFlowMeter flow statistics.
  A live sensor can only measure a subset of those features, and live decoy flows
  look different from the training data (training scans are about 47 µs long and
  hit random high ports). Against decoy traffic it scores roughly 0.04–0.14, so
  its contribution is small. The UNSW-NB15 model is weaker on its own test set
  (61% accuracy, 29% recall on attacks). The rule engine is the main detector.
  The ML scores are shown with the measured feature coverage so their weight can
  be judged. Better results need a model trained on flows this sensor records,
  which is the next step.
- **Port visibility.** Without the firewall log, the sensor only sees connections
  to its own listening ports. With the log, it also sees drops on every other
  port and ICMP echo requests.
- **Blocking precision.** A blocked IP is a source address. Behind NAT, one IP
  can represent many people. On a campus LAN, each device usually has its own
  address, but check before enforcing.
- **Windows only** for blocking and the firewall log. The listeners are
  portable.
- **Not a full sandbox.** The decoys are simulated and never run commands. Still,
  run the sensor under a non-admin account where possible, keep the machine
  patched, and treat `sensor/data/` as sensitive: it holds attacker-supplied
  passwords and payloads.
- **Privacy.** Credentials typed by others are stored in plain text, as is
  common for honeypot telemetry. Limit access to the database and follow the
  college's data-retention rules.

## File map

```
sensor/
  main.py              process entry point and runtime wiring
  config.py / config.json
  engine.py            detection rules and scoring
  ml.py                model loading, feature building, scoring
  deception.py         personas, fake content, honeytokens
  firewall.py          block manager (netsh), safety checks
  store.py             SQLite store
  events.py            event model
  netinfo.py           local addresses and default gateway
  admin_app.py         operator console API
  admin/index.html     operator console UI
  listeners/           bait.py, ssh.py, http_decoy.py, fwlog.py, common.py
  tools/simulate_probes.py   test traffic against your own sensor
  scripts/setup_firewall.ps1 firewall setup and undo
  data/                created at runtime (database, host key, admin token)
tests/test_sensor.py   unit and integration tests
```
