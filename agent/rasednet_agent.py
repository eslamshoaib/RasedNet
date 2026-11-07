#!/usr/bin/env python3
"""RasedNet endpoint agent (reference).

A tiny, dependency-light agent: it collects this host's name, OS, primary IP/MAC and listening
TCP ports, and reports them to the RasedNet server over HTTPS using an enrollment token. The host
describes itself — the agent never scans anything and only talks to the RasedNet server you give it.

Usage:
    python rasednet_agent.py --server https://rasednet.example.local:8765 --token rsd_XXXX [--once]

Listening-port collection uses psutil if available, otherwise falls back to `ss`/`netstat`.
Standard library only (plus optional psutil). Python 3.9+.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request


def primary_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packet is sent; this just selects the default route's source IP
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def primary_mac() -> str | None:
    try:
        import uuid
        mac = uuid.getnode()
        if (mac >> 40) & 0x1:  # locally administered / random — not a real NIC MAC
            return None
        return ":".join(f"{(mac >> b) & 0xFF:02X}" for b in range(40, -1, -8))
    except Exception:
        return None


def listening_ports() -> list[int]:
    ports: set[int] = set()
    try:
        import psutil  # type: ignore
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                ports.add(int(c.laddr.port))
        return sorted(ports)
    except Exception:
        pass
    # Fallback: parse ss or netstat output.
    for cmd in (["ss", "-ltn"], ["netstat", "-ltn"], ["netstat", "-an"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if not out:
            continue
        for m in re.finditer(r"[\.:](\d{1,5})\s+\S+\s+LISTEN", out):
            ports.add(int(m.group(1)))
        for m in re.finditer(r":(\d{1,5})\s+0\.0\.0\.0:\*?\s*LISTENING", out):  # Windows netstat
            ports.add(int(m.group(1)))
        if ports:
            break
    return sorted(p for p in ports if 1 <= p <= 65535)


def collect() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "ip": primary_ip(),
        "mac": primary_mac(),
        "ports": [{"port": p, "protocol": "tcp"} for p in listening_ports()],
    }


def send(server: str, token: str, report: dict, insecure: bool) -> None:
    url = server.rstrip("/") + "/api/agents/report"
    data = json.dumps(report).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "X-Agent-Token": token})
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:
        print(f"reported ok: {resp.read().decode('utf-8', 'replace')}")


def main() -> int:
    ap = argparse.ArgumentParser(description="RasedNet endpoint agent")
    ap.add_argument("--server", required=True, help="RasedNet base URL, e.g. https://rasednet.local:8765")
    ap.add_argument("--token", required=True, help="enrollment token (rsd_...)")
    ap.add_argument("--interval", type=int, default=0, help="seconds between reports (0 = report once)")
    ap.add_argument("--once", action="store_true", help="report a single time and exit")
    ap.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    args = ap.parse_args()
    while True:
        try:
            send(args.server, args.token, collect(), args.insecure)
        except Exception as exc:  # keep a long-running agent alive
            print(f"report failed: {exc}", file=sys.stderr)
        if args.once or args.interval <= 0:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
