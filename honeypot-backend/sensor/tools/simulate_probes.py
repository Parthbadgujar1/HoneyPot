"""Generate reconnaissance traffic against YOUR OWN sensor to test detection.

Defaults to loopback. Pointing it at another machine requires
--allow-remote, and you must only do that on a network where you have
permission to test.

Examples (from honeypot-backend):
    python -m sensor.tools.simulate_probes --scan
    python -m sensor.tools.simulate_probes --http
    python -m sensor.tools.simulate_probes --ssh --attempts 8
    python -m sensor.tools.simulate_probes --all
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import time

from ..config import load_config

SENSITIVE_PATHS = [
    "/", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin",
    "/backup.sql", "/actuator/health", "/api/v1/users", "/server-status",
]
SSH_USERNAMES = ["root", "admin", "ubuntu", "pi", "oracle"]
SSH_PASSWORDS = ["123456", "password", "admin", "toor", "letmein", "changeme", "qwerty", "1234"]


def _check_target(host: str, allow_remote: bool) -> None:
    address = ipaddress.ip_address(host)
    if not address.is_loopback and not allow_remote:
        raise SystemExit(
            f"{host} is not loopback. Pass --allow-remote only for hosts you are "
            "authorised to test."
        )


def port_scan(host: str, ports: list[int], timeout: float) -> dict:
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout) as conn:
                # Banner-grab style: connect, read whatever the service sends.
                conn.settimeout(timeout)
                try:
                    conn.recv(64)
                except socket.timeout:
                    pass
                open_ports.append(port)
        except OSError:
            pass
        time.sleep(0.05)
    return {"probed": len(ports), "answered": open_ports}


def http_probe(host: str, port: int, timeout: float) -> dict:
    import http.client

    results = {}
    for path in SENSITIVE_PATHS:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            connection.request("GET", path, headers={"User-Agent": "sim-scanner/1.0"})
            response = connection.getresponse()
            response.read()
            results[path] = response.status
        except OSError as exc:
            results[path] = f"error: {exc}"
        finally:
            connection.close()
    return results


def ssh_bruteforce(host: str, port: int, attempts: int, timeout: float) -> dict:
    import paramiko

    tried = 0
    refused = 0
    for index in range(attempts):
        username = SSH_USERNAMES[index % len(SSH_USERNAMES)]
        password = SSH_PASSWORDS[index % len(SSH_PASSWORDS)]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=timeout, allow_agent=False, look_for_keys=False,
                banner_timeout=timeout, auth_timeout=timeout,
            )
        except paramiko.AuthenticationException:
            tried += 1
        except (paramiko.SSHException, OSError):
            refused += 1
        finally:
            client.close()
    return {"attempts": attempts, "auth_rejected": tried, "connection_errors": refused}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulate recon traffic against the sensor.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--config", default=None)
    parser.add_argument("--scan", action="store_true", help="port scan the decoy ports")
    parser.add_argument("--http", action="store_true", help="probe sensitive HTTP paths")
    parser.add_argument("--ssh", action="store_true", help="SSH password attempts")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args(argv)

    _check_target(args.host, args.allow_remote)
    config = load_config(args.config)
    decoys = config["decoys"]
    ssh_port = int(decoys["ssh"]["port"])
    http_port = int(decoys["http"]["port"])
    bait_ports = sorted(int(p) for p in decoys["bait"]["services"])
    run_all = args.all or not (args.scan or args.http or args.ssh)

    if run_all or args.scan:
        ports = sorted(set(bait_ports + [ssh_port, http_port]))
        print("port scan:", port_scan(args.host, ports, args.timeout))
    if run_all or args.http:
        print("http probe:", http_probe(args.host, http_port, args.timeout))
    if run_all or args.ssh:
        print("ssh brute force:", ssh_bruteforce(args.host, ssh_port, args.attempts, args.timeout))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
