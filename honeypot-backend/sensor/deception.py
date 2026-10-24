"""Adaptive deception: decoy personas, fake content and honeytokens.

Every attacker IP gets a *persona* (the server identity the decoys present:
SSH banner, HTTP Server header, FTP/SMTP greetings) and an *engagement
level* that controls how much fake content is served. When the detection
engine reports a finding for an IP, ``DecoyPolicy.on_finding`` may change
either of them and writes the reason to the decoy_actions table, so each
adaptation is explainable.

Everything served here is simulated. No decoy executes commands, opens
outbound connections or serves real data. The honeytokens are random
strings with no valid account behind them; their only purpose is to show
whether an attacker tries to reuse credentials they found.
"""

from __future__ import annotations

import json
import logging
import secrets
import string
import threading
import time

from .store import Store

log = logging.getLogger("sensor.deception")

DEFAULT_PERSONA = "ubuntu_web"

PERSONAS: dict[str, dict] = {
    "ubuntu_web": {
        "label": "Ubuntu 22.04 web server",
        "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "http_server": "Apache/2.4.52 (Ubuntu)",
        "brand": "Acme Internal Portal",
        "ftp": "220 (vsFTPd 3.0.5)",
        "smtp": "220 mail.acme.internal ESMTP Postfix (Ubuntu)",
        "pop3": "+OK Dovecot ready.",
        "telnet": "Ubuntu 22.04 LTS\r\n\r\nlogin: ",
        "elasticsearch_version": "7.17.9",
    },
    "windows_server": {
        "label": "Windows Server 2019 with IIS",
        "ssh_banner": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "http_server": "Microsoft-IIS/10.0",
        "brand": "Acme Intranet",
        "ftp": "220 Microsoft FTP Service",
        "smtp": "220 MAIL01.acme.local Microsoft ESMTP MAIL Service ready",
        "pop3": "+OK POP3 server ready",
        "telnet": "Welcome to Microsoft Telnet Service\r\n\r\nlogin: ",
        "elasticsearch_version": "6.8.23",
    },
    "legacy_linux": {
        "label": "Legacy Debian 9 host",
        "ssh_banner": "SSH-2.0-OpenSSH_7.4",
        "http_server": "nginx/1.14.0 (Ubuntu)",
        "brand": "Legacy Support Console",
        "ftp": "220 ProFTPD 1.3.5 Server (Debian)",
        "smtp": "220 legacy-mail ESMTP Exim 4.89",
        "pop3": "+OK Dovecot ready.",
        "telnet": "Debian GNU/Linux 9\r\n\r\nlogin: ",
        "elasticsearch_version": "5.6.16",
    },
}

# Persona an attacker class is most likely to engage with.
PERSONA_FOR_CLASS = {
    "SSH_BRUTE_FORCE": "legacy_linux",
    "HONEYTOKEN_REUSE": "legacy_linux",
    "HTTP_ENDPOINT_PROBING": "ubuntu_web",
    "HOST_DISCOVERY": "ubuntu_web",
}

# Scanning classes rotate banners so the same attacker cannot fingerprint
# the host reliably across repeated probes.
SCANNING_CLASSES = {
    "PORT_SCAN", "SERVICE_DISCOVERY", "BANNER_ENUMERATION", "HOST_DISCOVERY",
}

MAX_LEVEL = 3

# Minimum time between two banner rotations for the same IP.
ROTATE_COOLDOWN_S = 300

FAKE_USERS = [
    {"id": 1, "username": "j.morgan", "email": "j.morgan@acme.example.invalid", "role": "admin"},
    {"id": 2, "username": "a.patel", "email": "a.patel@acme.example.invalid", "role": "developer"},
    {"id": 3, "username": "svc-backup", "email": "svc-backup@acme.example.invalid", "role": "service"},
]

_TOKEN_ALPHABET = string.ascii_uppercase + string.digits
_SECRET_ALPHABET = string.ascii_letters + string.digits + "/+"


class DecoyPolicy:
    def __init__(self, store: Store, default_persona: str = DEFAULT_PERSONA):
        self._store = store
        self._default = default_persona
        self._lock = threading.Lock()
        # ip -> {"persona", "level", "changed_ts"}; mirrors the decoy_actions table.
        self._state: dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Per-IP state
    # ------------------------------------------------------------------

    def _load(self, ip: str) -> dict:
        with self._lock:
            cached = self._state.get(ip)
        if cached is not None:
            return cached

        latest = self._store.latest_decoy_action(ip)
        state = {
            "persona": latest["persona"] if latest else self._default,
            "level": latest["level"] if latest else 1,
            "changed_ts": latest["ts"] if latest else 0.0,
        }
        with self._lock:
            return self._state.setdefault(ip, state)

    def state_for(self, ip: str) -> tuple[str, int]:
        state = self._load(ip)
        return state["persona"], state["level"]

    def persona_for(self, ip: str) -> dict:
        name, _ = self.state_for(ip)
        return PERSONAS.get(name, PERSONAS[self._default])

    def level_for(self, ip: str) -> int:
        return self.state_for(ip)[1]

    def _store_state(self, ip: str, persona: str, level: int, reason: str) -> None:
        self._store.insert_decoy_action(ip, persona, level, reason)
        with self._lock:
            self._state[ip] = {
                "persona": persona,
                "level": level,
                "changed_ts": time.time(),
            }

    # ------------------------------------------------------------------
    # Adaptation
    # ------------------------------------------------------------------

    def on_finding(self, finding: dict, prior_findings: int = 1) -> dict:
        """Adapt the decoy for the attacker behind ``finding``.

        Persona changes are one-way: an attacker moves from the default
        persona to the one that suits the attack and then stays there.
        Banner rotation is the exception. It is used against repeated
        scanning and rate-limited, so the attacker sees a stable host for
        a while after each rotation.
        """
        ip = finding["src_ip"]
        classification = finding["classification"]
        severity = finding["severity"]
        state = self._load(ip)
        current_persona, current_level = state["persona"], state["level"]

        level = current_level
        if severity == "HIGH" or prior_findings >= 3:
            level = max(level, 2)
        if classification in ("HTTP_ENDPOINT_PROBING", "SSH_BRUTE_FORCE"):
            level = max(level, 2)
        if classification == "HONEYTOKEN_REUSE" or prior_findings >= 6:
            level = MAX_LEVEL
        level = min(level, MAX_LEVEL)

        persona = current_persona
        reasons = []
        now = time.time()

        target = PERSONA_FOR_CLASS.get(classification)
        if target and current_persona == self._default:
            persona = target
            reasons.append(
                f"{classification}: serving {PERSONAS[target]['label']} persona "
                "to keep the attacker engaged with plausible services"
            )
        elif (classification in SCANNING_CLASSES and prior_findings >= 2
              and now - state["changed_ts"] >= ROTATE_COOLDOWN_S):
            persona = self._next_persona(current_persona)
            reasons.append(
                f"{classification} repeated: rotated banners from "
                f"{PERSONAS[current_persona]['label']} to "
                f"{PERSONAS[persona]['label']} to disrupt fingerprinting"
            )

        if level > current_level:
            reasons.append(f"engagement raised to level {level} after {classification}")

        changed = persona != current_persona or level != current_level
        if not reasons:
            reasons.append("no change: current persona and engagement level still apply")

        decision = {
            "persona": persona,
            "level": level,
            "changed": changed,
            "reason": "; ".join(reasons),
        }
        if changed:
            self._store_state(ip, persona, level, decision["reason"])
        return decision

    def set_persona(self, ip: str, persona: str, level: int, reason: str) -> None:
        """Operator override. Recorded like any other adaptation."""
        if persona not in PERSONAS:
            raise ValueError(f"unknown persona: {persona}")
        level = max(1, min(level, MAX_LEVEL))
        self._store_state(ip, persona, level, reason)

    def _next_persona(self, current: str) -> str:
        names = list(PERSONAS)
        index = names.index(current) if current in names else -1
        return names[(index + 1) % len(names)]

    # ------------------------------------------------------------------
    # Fake service banners (bait ports)
    # ------------------------------------------------------------------

    def service_banner(self, service: str, ip: str) -> bytes | None:
        persona = self.persona_for(ip)
        text = persona.get(service)
        if text is None:
            return None
        if not text.endswith("\n"):
            text += "\r\n"
        return text.encode("ascii", errors="replace")

    def service_response(self, service: str, ip: str, payload: bytes) -> bytes | None:
        """Fake reply to the first request a bait service receives."""
        if service == "redis":
            return b"-NOAUTH Authentication required.\r\n"
        if service == "elasticsearch":
            version = self.persona_for(ip)["elasticsearch_version"]
            body = json.dumps({
                "name": "node-1",
                "cluster_name": "acme-logs",
                "version": {"number": version},
                "tagline": "You Know, for Search",
            })
            return (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
            ).encode("utf-8")
        return None

    # ------------------------------------------------------------------
    # Fake HTTP content
    # ------------------------------------------------------------------

    def honeytoken(self, ip: str, kind: str, length: int, alphabet: str) -> str:
        existing = self._store.honeytoken_for_ip(ip, kind)
        if existing:
            return existing
        token = "".join(secrets.choice(alphabet) for _ in range(length))
        if kind == "aws_access_key":
            token = "AKIA" + token
        self._store.add_honeytoken(ip, kind, token)
        return token

    def http_response(
        self,
        method: str,
        path: str,
        ip: str,
        body: str = "",
    ) -> dict:
        """Return {status, content_type, body, headers} for one request."""
        persona = self.persona_for(ip)
        level = self.level_for(ip)
        path = path.rstrip("/") or "/"
        lowered = path.lower()

        def page(status: int, html: str) -> dict:
            return _response(status, "text/html; charset=utf-8", html, persona)

        def text(content: str, content_type: str = "text/plain; charset=utf-8",
                 status: int = 200) -> dict:
            return _response(status, content_type, content, persona)

        if lowered in ("/", "/index.html", "/index.php", "/home"):
            return page(200, _login_page(persona["brand"], "/login"))

        if lowered in ("/login", "/admin", "/administrator", "/user/login", "/signin"):
            if method == "POST":
                return page(401, _login_page(
                    persona["brand"], lowered, "Invalid username or password."
                ))
            return page(200, _login_page(persona["brand"], lowered))

        if lowered in ("/wp-login.php", "/wp-admin", "/wp-admin/"):
            if method == "POST":
                return page(200, _wordpress_login("ERROR: Incorrect password."))
            return page(200, _wordpress_login())

        if lowered.startswith("/phpmyadmin") or lowered.startswith("/pma"):
            return page(200, _phpmyadmin_login())

        if lowered == "/.env":
            key = self.honeytoken(ip, "aws_access_key", 16, _TOKEN_ALPHABET)
            secret = self.honeytoken(ip, "aws_secret_key", 40, _SECRET_ALPHABET)
            return text(
                f"APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:{secret[:32]}=\n"
                f"DB_HOST=10.20.0.15\nDB_DATABASE=portal\nDB_USERNAME=portal_app\n"
                f"DB_PASSWORD=Pr0d-Portal-{secret[:6]}\n"
                f"AWS_ACCESS_KEY_ID={key}\nAWS_SECRET_ACCESS_KEY={secret}\n"
                "AWS_DEFAULT_REGION=eu-west-1\nS3_BUCKET=acme-portal-uploads\n"
            )

        if lowered == "/.git/config":
            return text(
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                "\tbare = false\n[remote \"origin\"]\n"
                "\turl = git@git.acme.internal:portal/portal-web.git\n"
                "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            )

        if lowered == "/.git/head":
            return text("ref: refs/heads/main\n")

        if lowered == "/robots.txt":
            return text("User-agent: *\nDisallow: /admin\nDisallow: /backup\n")

        if lowered in ("/api/v1/users", "/api/users") and method == "GET":
            return text(json.dumps({"users": FAKE_USERS}, indent=2),
                        "application/json")

        if lowered == "/actuator/health":
            return text('{"status":"UP"}', "application/json")

        if lowered == "/server-status":
            return page(403, "<h1>Forbidden</h1>")

        if level >= 2 and lowered in ("/backup.sql", "/db.sql", "/dump.sql"):
            return text(
                "-- Acme portal database dump\nCREATE TABLE users (id int, "
                "username varchar(64), password_hash varchar(128));\n"
                "INSERT INTO users VALUES (1,'j.morgan','$2y$10$fakehashfakehashfakehash');\n"
            )

        if level >= 2 and lowered == "/wp-config.php.bak":
            return text(
                "<?php\ndefine('DB_NAME', 'wp_portal');\ndefine('DB_USER', 'wp_admin');\n"
                "define('DB_PASSWORD', 'Summer2024!');\ndefine('DB_HOST', '10.20.0.15');\n"
            )

        return _response(
            404,
            "text/html; charset=utf-8",
            "<!doctype html><title>404 Not Found</title><h1>Not Found</h1>"
            "<p>The requested URL was not found on this server.</p>",
            persona,
        )


def _response(status: int, content_type: str, body: str, persona: dict) -> dict:
    return {
        "status": status,
        "content_type": content_type,
        "body": body,
        "headers": {"Server": persona["http_server"]},
    }


def _login_page(brand: str, action: str, error: str = "") -> str:
    message = f'<p class="error">{error}</p>' if error else ""
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{brand} - Sign in</title></head>
<body style="font-family: sans-serif; max-width: 360px; margin: 80px auto;">
<h2>{brand}</h2>
{message}
<form method="post" action="{action}">
<label>Username <input name="username" autocomplete="username"></label><br><br>
<label>Password <input type="password" name="password" autocomplete="current-password"></label><br><br>
<button type="submit">Sign in</button>
</form>
</body></html>"""


def _wordpress_login(error: str = "") -> str:
    message = f'<div id="login_error">{error}</div>' if error else ""
    return f"""<!doctype html><html><head><title>Log In &lsaquo; Acme Blog</title></head>
<body class="login">{message}
<form name="loginform" method="post" action="/wp-login.php">
<input name="log" type="text"><input name="pwd" type="password">
<input type="submit" value="Log In"></form></body></html>"""


def _phpmyadmin_login() -> str:
    return """<!doctype html><html><head><title>phpMyAdmin</title></head>
<body><h1>Welcome to phpMyAdmin</h1>
<form method="post"><input name="pma_username"><input name="pma_password" type="password">
<input type="submit" value="Go"></form></body></html>"""


