"""Discover this host's own addresses and default gateway(s).

These are always protected from automatic blocking: blocking the gateway
or the sensor's own address would cut the machine off from the campus
network.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def local_addresses() -> set[str]:
    """Return IPv4 addresses bound to this host (best effort)."""
    addresses: set[str] = {"127.0.0.1"}

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass

    # Connecting a UDP socket sends nothing; it only picks the outbound
    # interface, which tells us the address used for the campus LAN.
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("10.255.255.255", 1))
            addresses.add(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass

    return addresses


def default_gateways() -> set[str]:
    """Return default gateway IPv4 addresses (best effort, never raises).

    On Windows, Get-NetRoute is used because it prints the same values on
    every locale. ipconfig labels are translated on non-English systems, so
    they are only a fallback.
    """
    gateways: set[str] = set()
    try:
        if sys.platform.startswith("win"):
            command = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | "
                "Select-Object -ExpandProperty NextHop",
            ]
            output = subprocess.run(
                command, capture_output=True, text=True, timeout=20, check=False,
            ).stdout
            gateways.update(_IPV4.findall(output))
            if not gateways:
                output = subprocess.run(
                    ["ipconfig"], capture_output=True, text=True, timeout=10, check=False,
                ).stdout
                for line in output.splitlines():
                    if "Default Gateway" in line or "Gateway" in line:
                        gateways.update(_IPV4.findall(line))
        else:
            output = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout
            gateways.update(_IPV4.findall(output))
    except (OSError, subprocess.SubprocessError):
        pass
    return gateways
