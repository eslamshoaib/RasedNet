"""Discovery diagnostics: explain *why* a given IP is or isn't discoverable, and what to do.

Runs ICMP, a few TCP connects, a couple of UDP probes and a short traceroute from the scanner
host, then returns an Arabic verdict: in an approved scope or not; reachable, silent, or blocked
behind the gateway (segment isolation). This turns a silent miss into an actionable answer.
"""

from __future__ import annotations

import asyncio

from rasednet.discovery.icmp import ping
from rasednet.discovery.traceroute import trace
from rasednet.discovery.udp import UDP_PROBES, probe_port

TCP_PORTS = [80, 443, 22, 445, 3389, 62078]  # web, ssh, smb, rdp, iphone-sync
UDP_DIAG_PORTS = [5353, 137, 161]             # mDNS (phones), NetBIOS, SNMP


async def _tcp(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return "open"
    except TimeoutError:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"      # host is reachable, port just closed
    except OSError:
        return "error"


async def reachability(ip: str, *, in_scope: bool, timeout: float = 2.0) -> dict:
    """Probe ``ip`` several ways and classify why it is (not) discoverable."""
    loop = asyncio.get_running_loop()
    # Run every probe concurrently so the whole diagnostic takes ~one timeout, not the sum.
    udp_ports = [p for p in UDP_DIAG_PORTS if p in UDP_PROBES]
    icmp, tcp_states, udp_states, hops = await asyncio.gather(
        ping(ip, int(timeout * 1000)),
        asyncio.gather(*(_tcp(ip, p, timeout) for p in TCP_PORTS)),
        asyncio.gather(*(probe_port(ip, p, UDP_PROBES[p][1], timeout) for p in udp_ports)),
        loop.run_in_executor(None, trace, ip, 8, 800),
    )
    tcp = dict(zip(TCP_PORTS, tcp_states))
    udp = dict(zip(udp_ports, udp_states))

    tcp_alive = any(v in ("open", "refused") for v in tcp.values())
    udp_alive = any(v == "open" for v in udp.values())
    reachable = bool(icmp.alive) or tcp_alive or udp_alive

    responded = [h for h in hops if h.ip]
    reached_target = any(h.ip == ip for h in hops)
    last_responder = responded[-1].ip if responded else None

    # Verdict.
    from rasednet.i18n import get_lang
    en = get_lang() == "en"
    if reachable:
        if not in_scope:
            verdict = "reachable_out_of_scope"
            reason = ("The device is reachable from the RasedNet server but is outside all approved scan scopes, so it was not scanned. "
                      "Add and approve a scope that covers this address, then run the scan.") if en else (
                "الجهاز قابل للوصول من خادم راصد لكنه خارج كل نطاقات الفحص المعتمدة، لذلك لم يُفحص. "
                "أضف نطاقاً يغطّي هذا العنوان واعتمده ثم شغّل الفحص.")
        else:
            verdict = "reachable"
            reason = ("The device is reachable and inside an approved scope. Re-scan the scope; if it is silent to ICMP, enable ARP/UDP discovery.") if en else (
                "الجهاز قابل للوصول وداخل نطاق معتمد. أعد فحص النطاق؛ إن كان صامتاً لـ ICMP فعّل اكتشاف ARP/UDP.")
    elif reached_target:
        verdict = "silent"
        reason = ("The device is on the path but does not answer any probe (ICMP/TCP/UDP) — a silent device (strict firewall). "
                  "Try a UDP scan (mDNS) or read the ARP/DHCP table from the router to discover it.") if en else (
            "الجهاز على المسار لكنه لا يرد على أي فحص (ICMP/TCP/UDP) — جهاز صامت (جدار ناري صارم). "
            "جرّب فحص UDP (mDNS) أو اقرأ جدول ARP/DHCP من الموجّه لاكتشافه.")
    elif last_responder and not reached_target:
        verdict = "blocked_behind_gateway"
        reason = (f"Packets die after {last_responder}: the router does not forward your network's traffic to this address (client isolation / separate VLAN). "
                  "No scanner on your network can see it. Discover it by reading the router's DHCP/ARP table (SSH/SNMP) or run an agent/scan from inside that network.") if en else (
            f"تموت الحزم بعد {last_responder}: الموجّه لا يمرّر حركة شبكتك إلى هذا العنوان (عزل عملاء/VLAN منفصل). "
            "لا يمكن لأي ماسح على شبكتك رؤيته. اكتشفه عبر قراءة جدول DHCP/ARP من الموجّه (SSH/SNMP) أو شغّل وكيلاً/فحصاً من داخل تلك الشبكة.")
    else:
        verdict = "unreachable"
        reason = ("No response and no path to this address from the RasedNet server. Make sure it is connected and that there is a network route to it.") if en else (
            "لا يوجد أي رد ولا مسار إلى هذا العنوان من خادم راصد. تأكد أنه متصل وأن هناك مساراً شبكياً إليه.")

    return {
        "ip": ip,
        "in_scope": in_scope,
        "reachable": reachable,
        "verdict": verdict,
        "reason_ar": reason,
        "icmp": {"alive": bool(icmp.alive), "ttl": icmp.ttl},
        "tcp": tcp,
        "udp": udp,
        "traceroute": [{"ttl": h.ttl, "ip": h.ip, "rtt_ms": h.rtt_ms} for h in hops],
        "reached_target": reached_target,
        "last_responder": last_responder,
    }
