"""Network map: networks, devices, routers and the observed paths between networks.

Every edge says how it is known:
* ``verified`` — directly observed (device answered inside the network, interface attached to the
  scanner, router answered a TTL-limited probe at that position of the path);
* ``inferred`` — deduced (a silent hop bridged by its neighbours, a device seen with addresses in two
  networks). Physical cabling is never invented: there is no LLDP / switch-table data here.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from rased.config import Settings
from rased.models import Alert, Asset, IpObservation, RouteTrace, ScanScope, Service, utcnow
from rased.scope import ScopeError, validate_scope

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network


def _local_networks() -> list[tuple[IPNet, str, str]]:
    """(network, interface name, scanner address) of attached, up interfaces."""
    try:
        from rased.discovery.networks import is_virtual_interface, read_interfaces

        out = []
        for a in read_interfaces():
            if not a.is_up:
                continue
            net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            if net.is_loopback or net.prefixlen >= 32:
                continue
            out.append((net, a.interface + (" (افتراضية)" if is_virtual_interface(a.interface) else ""), a.address))
        return out
    except Exception:  # noqa: BLE001
        return []


def _addr(ip: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(ip) if ip else None
    except ValueError:
        return None


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def node(self, node_id: str, **data: Any) -> str:
        if node_id not in self.nodes:
            self.nodes[node_id] = {"id": node_id, **data}
        else:
            self.nodes[node_id].update({k: v for k, v in data.items() if v is not None})
        return node_id

    def edge(self, a: str, b: str, kind: str, verified: bool, label_ar: str) -> None:
        if a == b:
            return
        key = (min(a, b), max(a, b), kind)
        existing = self.edges.get(key)
        if existing is None:
            self.edges[key] = {"id": f"{key[0]}|{key[1]}|{kind}", "source": a, "target": b, "kind": kind,
                               "verified": verified, "label_ar": label_ar}
        elif verified:
            existing["verified"] = True


def build_topology(db: Session, settings: Settings, *, include_devices: bool = True, max_devices: int = 3000) -> dict[str, Any]:
    g = _Graph()
    networks: list[IPNet] = []

    def add_network(net: IPNet, kind: str, label: str | None = None) -> str:
        nid = f"net:{net}"
        if net not in networks:
            networks.append(net)
        g.node(nid, type="network", kind=kind, label=label or str(net), cidr=str(net))
        return nid

    scanner = g.node("scanner", type="scanner", label="خادم راصد")
    scanner_ips: list[str] = []
    for net, iface, ip in _local_networks():
        nid = add_network(net, "local", f"{net}\n{iface}")
        scanner_ips.append(ip)
        g.edge(scanner, nid, "attached", True, f"بطاقة الشبكة {iface} ({ip})")
    g.nodes[scanner]["ips"] = scanner_ips

    for scope in db.scalars(select(ScanScope).where(ScanScope.is_active.is_(True))):
        try:
            v = validate_scope(scope.cidr, [], [], allow_public=True, max_hosts=1 << 40)
        except ScopeError:
            continue
        nid = add_network(v.network, "scope", f"{v.network}\n{scope.name}")
        g.nodes[nid]["scope_name"] = scope.name
        g.nodes[nid]["approved"] = scope.is_approved

    def network_of(ip: str | None) -> IPNet | None:
        addr = _addr(ip)
        if addr is None:
            return None
        best = None
        for net in networks:
            if addr.version == net.version and addr in net and (best is None or net.prefixlen > best.prefixlen):
                best = net
        return best

    alert_counts = dict(db.execute(select(Alert.asset_id, func.count()).where(Alert.status == "open").group_by(Alert.asset_id)).all())
    service_counts = dict(db.execute(select(Service.asset_id, func.count()).where(Service.state == "open").group_by(Service.asset_id)).all())
    assets = list(db.scalars(select(Asset).where(Asset.current_ip.is_not(None)).order_by(Asset.id).limit(max_devices)))
    asset_by_ip = {a.current_ip: a for a in assets}

    def asset_node(a: Asset) -> str:
        return g.node(
            f"a:{a.id}", type="device", asset_id=a.id, label=a.display_name or a.hostname or a.current_ip, ip=a.current_ip,
            device_type="router" if a.is_gateway and a.device_type == "unknown" else a.device_type,
            os_family=a.os_family, status=a.status, vendor=a.vendor, model=a.model, is_gateway=a.is_gateway,
            open_alerts=int(alert_counts.get(a.id, 0)), open_services=int(service_counts.get(a.id, 0)),
            hostname=a.hostname, mac=a.mac,
        )

    for a in assets:
        net = network_of(a.current_ip)
        if net is None:
            addr = _addr(a.current_ip)
            if addr is None:
                continue
            net = ipaddress.ip_network(f"{a.current_ip}/{24 if addr.version == 4 else 64}", strict=False)
            add_network(net, "observed", f"{net}\n(مستنتجة من الأجهزة)")
        nid = f"net:{net}"
        if include_devices or a.is_gateway or a.device_type in ("router", "access_point", "switch", "network_device"):
            g.edge(asset_node(a), nid, "member", True, "رُصد داخل هذه الشبكة")
            if a.is_gateway:
                g.edge(f"a:{a.id}", nid, "gateway", True, "البوابة الافتراضية لهذه الشبكة")
        g.nodes[nid]["devices"] = g.nodes[nid].get("devices", 0) + 1
        if a.status == "online":
            g.nodes[nid]["online"] = g.nodes[nid].get("online", 0) + 1

    # Devices seen recently with addresses in two different networks may bridge them.
    since = utcnow() - timedelta(days=7)
    seen: dict[int, set[str]] = defaultdict(set)
    for asset_id, ip in db.execute(select(IpObservation.asset_id, IpObservation.ip).where(IpObservation.last_seen >= since)):
        net = network_of(ip)
        if net is not None:
            seen[asset_id].add(f"net:{net}")
    for asset_id, nets in seen.items():
        if len(nets) > 1 and f"a:{asset_id}" in g.nodes:
            for nid in nets:
                g.edge(f"a:{asset_id}", nid, "multihomed", False, "للجهاز عنوان في هذه الشبكة أيضاً (قد يربط الشبكتين)")

    # Observed paths: scanner -> hop1 -> hop2 -> ... -> target network.
    latest: dict[str, RouteTrace] = {}
    for trace in db.scalars(select(RouteTrace).order_by(RouteTrace.created_at.desc()).limit(500)):
        latest.setdefault(trace.target, trace)
    for trace in latest.values():
        previous, gap = scanner, False
        for hop in trace.hops:
            ip = hop.get("ip")
            if not ip:
                gap = True
                continue
            a = asset_by_ip.get(ip)
            hop_id = asset_node(a) if a is not None else g.node(f"hop:{ip}", type="hop", label=ip, ip=ip, device_type="router")
            g.edge(previous, hop_id, "path", not gap, "مسار مرصود (TTL)" if not gap else "مسار مع قفزات صامتة (مستنتج)")
            hop_net = network_of(ip)
            if hop_net is not None:
                g.edge(hop_id, f"net:{hop_net}", "member", True, "عنوان الموجّه داخل هذه الشبكة")
            previous, gap = hop_id, False
        target_net = network_of(trace.target)
        if target_net is not None and previous != scanner:
            g.edge(previous, f"net:{target_net}", "routes", trace.reached, "يوصل إلى هذه الشبكة" if trace.reached else "آخر قفزة معروفة نحو الشبكة")

    devices = sum(1 for n in g.nodes.values() if n["type"] == "device")
    return {
        "nodes": list(g.nodes.values()),
        "edges": list(g.edges.values()),
        "stats": {"networks": len(networks), "devices": devices, "routers": sum(1 for n in g.nodes.values() if n.get("device_type") == "router"),
                  "paths": len(latest), "truncated": len(assets) >= max_devices},
    }


def default_trace_targets(db: Session, settings: Settings) -> list[str]:
    """One representative address per approved scope, plus each attached network's gateway."""
    targets: list[str] = []
    local = [n for n, _, _ in _local_networks()]
    for scope in db.scalars(select(ScanScope).where(ScanScope.is_active.is_(True), ScanScope.is_approved.is_(True))):
        try:
            v = validate_scope(scope.cidr, scope.excluded_hosts, scope.excluded_ports,
                               allow_public=settings.allow_public_scopes, max_hosts=settings.max_scope_hosts)
        except ScopeError:
            continue
        if any(v.network.version == n.version and v.network.subnet_of(n) for n in local):  # type: ignore[arg-type]
            continue  # attached directly: no routing path to learn
        first = next(v.targets(), None)
        if first:
            targets.append(first)
    for a in db.scalars(select(Asset).where(Asset.is_gateway.is_(True))):
        if a.current_ip:
            targets.append(a.current_ip)
    return list(dict.fromkeys(targets))[:64]
