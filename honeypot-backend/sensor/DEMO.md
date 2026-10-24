# Live demo runbook (one device)

This shows the whole system on one Windows machine: fake services that attract
attackers, live detection, adaptive decoys, blocking, and threat intel.

Everything below runs on this device. Each attack comes from this machine, so
the sensor treats it as protected and will not block it. That is deliberate:
it stops the sensor from cutting off the machine it runs on. The demo shows
that decision, and also shows a manual block that really creates a firewall rule.

---

## 1. What runs where

You need four things running. Open each one in its own window.

| # | What | Window | Command (run from the folder shown) | Where you see it |
|---|------|--------|-------------------------------------|------------------|
| 1 | **Sensor** (decoys, detection, blocking) | **Administrator** PowerShell | `..\venv313\Scripts\python.exe -m sensor.main` in `honeypot-backend` | Operator console: http://127.0.0.1:9100 |
| 2 | **Backend** (bridge to the dashboard) | Normal PowerShell | `..\venv313\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000` in `honeypot-backend` | No page to open; the dashboard uses it in the background |
| 3 | **Dashboard** (monitoring UI) | Normal PowerShell | `npm run dev` in `honeypot-frontend` | Dashboard: http://localhost:5173 |
| 4 | **Decoy** (the fake website and SSH) | Starts with the sensor | nothing to run | Decoy website: http://127.0.0.1:8080 |

**Start order:** sensor, then backend, then dashboard.

The sensor must run in an **Administrator** window. Without that, blocks are
recorded but the firewall rules fail, and the dashboard says "Not applied".

### Commands to copy

Window 1 (Administrator PowerShell):
```powershell
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend
..\venv313\Scripts\python.exe -m sensor.main
```

Window 2 (normal PowerShell):
```powershell
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend
..\venv313\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Window 3 (normal PowerShell):
```powershell
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-frontend
npm run dev
```

### Check that everything is up

Run this in any PowerShell window. It asks the sensor for its status with the admin token:

```powershell
$t = Get-Content C:\Users\Student1\Desktop\HoneyPot\honeypot-backend\sensor\data\admin_token.txt
(Invoke-RestMethod -Uri http://127.0.0.1:9100/api/status -Headers @{Authorization="Bearer $t"}).firewall | Select-Object mode, enforce, elevated
```

You want `enforce True` and `elevated True`. Then open http://localhost:5173.
The footer should say **Sensor: Connected**.

Open the operator console at http://127.0.0.1:9100. Paste the token from
`sensor\data\admin_token.txt` when asked. Treat the token as a password: don't show it on screen.

The firewall decoy rules must be present (created once, they persist):
```powershell
(Get-NetFirewallRule -DisplayName 'HP-DECOY-*').Count   # should print 11
```

---

## 2. The demo, step by step (about 10 minutes)

Keep three browser tabs open: the dashboard (localhost:5173), the operator
console (127.0.0.1:9100), and the decoy website (127.0.0.1:8080).

### Part A: the decoy looks real (1 minute)

1. Open http://127.0.0.1:8080/. It shows a fake "Sign in" page.
2. Open http://127.0.0.1:8080/.env. It shows a fake config file with an AWS-style
   key. These keys are honeytokens: fake values that flag any attacker who reuses them.

**Say:** "An attacker sees plausible fake data. Everything they do is recorded."

### Part B: live detection (3 minutes)

Open a **normal** PowerShell window and run the attack simulator. It
probes the decoys, tries SSH passwords, and reuses the fake key:

```powershell
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend\sensor\scripts
powershell -ExecutionPolicy Bypass -File .\lan_test.ps1 -Target 127.0.0.1 -HoneypotPath C:\Users\Student1\Desktop\HoneyPot\honeypot-backend -PythonExe C:\Users\Student1\Desktop\HoneyPot\venv313\Scripts\python.exe
```

The script prints each step as it runs:
1. reachability
2. port scan of 10 decoy ports
3. banner grab on Redis
4. probing of sensitive web paths
5. SSH brute force (12 password attempts)
6. honeytoken reuse

**Watch:**
- **Dashboard (5173), Threat Alerts:** HIGH and MEDIUM alerts appear within about 15 seconds. Click one to see the reasons, the evidence, and the score breakdown (rules plus ML points).
- **Operator console (9100), Alerts:** the same findings appear within about 10 seconds, with a timeline when you click an IP.

**Say:** "Each probe is scored by rules, plus two trained models. The score decides what happens next."

### Part C: adaptive decoys (1 minute)

1. Console (9100), **Decoy Actions** tab: each row is a change the sensor made, with the reason. For example: "engagement raised to level 3 after HONEYTOKEN_REUSE".
2. Console, **Attackers** tab: the persona assigned to 127.0.0.1 and its engagement level.

**Say:** "After the attacker reuses the fake key, the decoy serves more fake content and changes its banners. That's adaptive deception."

### Part D: blocking (3 minutes): the honest version

**D1. The automatic decision (protected source).**
1. In the dashboard (5173), click a HIGH alert, then in its dialog click **Block source**, then **Confirm block**.
2. The dialog shows: **Block refused: Refusing to block 127.0.0.1: loopback address** (or "this machine or the default gateway" for the LAN address).

**Say:** "The sensor wants to block this attacker, but it refuses to block its own machine. That safety rule is always on."

**D2. A real firewall block (manual).** This uses a documentation address that no real machine uses.
1. Console (9100), **Blocks** tab. Enter IP `203.0.113.250`, reason `demo`, TTL `30`, then click **Block**.
2. In an **Administrator** PowerShell, check the Windows firewall:
   ```powershell
   netsh advfirewall firewall show rule name=HP-BLOCK-203.0.113.250
   ```
   You should see `Action: Block` and `RemoteIP: 203.0.113.250/32`.
3. Dashboard (5173), overview, **Firewall blocks** panel: the address is listed as **ACTIVE**, with its expiry time. The banner says **Applied**.
4. Click **Unblock** in that panel, or in the console's Blocks tab.
5. Check again:
   ```powershell
   netsh advfirewall firewall show rule name=HP-BLOCK-203.0.113.250
   ```
   It should now say "No rules match the specified criteria."

**Say:** "A block is a real Windows Firewall rule. It is created and removed on command, and every block has an expiry."

**Honest note for your mentor:** An automatic block of a real attacker needs the attacker to
be a different machine. On one device, every alert is from a protected address by design.
The manual block shows the enforcement path, and the refusal shows the decision path.

### Part E: threat intel (1 minute)

Console (9100), **Threat Intel** tab. Sources that share honeytokens, passwords,
user agents, usernames, or port sets are grouped into campaigns, and each link shows its reason.
Click **Export CSV** to download the indicators.

### Part F: the tests (1 minute)

```powershell
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend
..\venv313\Scripts\python.exe -m unittest discover -s tests -t .
```

The last line should read `OK` (53 tests).

---

## 3. After the demo

1. Unblock any leftover blocks in the console's **Blocks** tab.
2. Stop each window with **Ctrl+C**. Stop the sensor last.
3. Optional, to remove the decoy firewall rules, run in an **Administrator** PowerShell:
   ```powershell
   cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend\sensor\scripts
   powershell -ExecutionPolicy Bypass -File .\setup_firewall.ps1 -Undo
   ```

---

## 4. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Dashboard shows "Could not refresh" or Sensor disconnected | Sensor not running, or it started after the backend's first request | Start the sensor, then refresh the page |
| Console or dashboard say "Not applied: not running as Administrator" | Sensor window is not elevated | Stop the sensor and start it from an Administrator PowerShell |
| Sensor fails with `WinError 10048` (port in use) | An older sensor is still running | Find the owner: `Get-NetTCPConnection -LocalPort 9100 -State Listen`, then `Stop-Process -Id <OwningProcess>` |
| Bait port 3306 says "unavailable" | Windows reserves that port on this machine | Normal, the other 11 listeners work |
| Console says the token was rejected | Wrong or old token | Copy the current token from `sensor\data\admin_token.txt` |
| No new alerts after running the simulator | Simulator ran before the sensor started, or the dashboard hasn't refreshed | Wait 15 seconds, or click **Refresh data** |
| SSH step is skipped | `-PythonExe` points to a Python without paramiko | Pass the venv Python: `..\venv313\Scripts\python.exe` |

---

## 5. Commands cheat sheet

```powershell
# Start the sensor (Administrator PowerShell)
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend; ..\venv313\Scripts\python.exe -m sensor.main

# Start the backend (normal PowerShell)
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend; ..\venv313\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

# Start the dashboard (normal PowerShell)
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-frontend; npm run dev

# Run the attack simulator (normal PowerShell)
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend\sensor\scripts; powershell -ExecutionPolicy Bypass -File .\lan_test.ps1 -Target 127.0.0.1 -HoneypotPath C:\Users\Student1\Desktop\HoneyPot\honeypot-backend -PythonExe C:\Users\Student1\Desktop\HoneyPot\venv313\Scripts\python.exe

# Check a block in the firewall (Administrator PowerShell)
netsh advfirewall firewall show rule name=HP-BLOCK-203.0.113.250

# Run the tests (normal PowerShell)
cd C:\Users\Student1\Desktop\HoneyPot\honeypot-backend; ..\venv313\Scripts\python.exe -m unittest discover -s tests -t .
```
