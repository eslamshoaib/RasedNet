"""Persist scan observations into the asset inventory with identity correlation.

Correlation rules (in priority order) — designed so DHCP re-assignment does not merge
different devices into one asset:

1. A MAC observed for exactly one IP in this job identifies the asset.
   * If no asset has that MAC, an asset currently holding the IP is reused only if it has
     no MAC of its own and no conflicting hostname; otherwise a new asset is created.
   * A *randomised* MAC that is unknown may still match an asset with the same hostname
     whose MAC is also randomised (devices that rotate their address).
2. Without a usable MAC (routed subnet, or a MAC seen on several IPs, e.g. proxy ARP),
   a hostname identifies the asset.
3. Otherwise the asset currently holding the IP is reused, unless its hostname conflicts.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from rased.alerts import add_event, raise_alert, resolve_alerts
from rased.db import Database
from rased.discovery.engine import HostObservation
from rased.discovery.fingerprint import FingerprintInput, classify
from rased.discovery.oui import VIRTUALIZATION_PREFIXES, is_probably_randomized, mac_prefix
from rased.discovery.services import identify_service
from rased.models import (
    Asset,
    AssetIdentifier,
    DeviceFingerprint,
    IpObservation,
    OuiVendor,
    ScanJob,
    ScanResult,
    Service,
    ServiceObservation,
    utcnow,
)
from rased.scope import ValidatedScope

log = logging.getLogger(__name__)


def same_host(a: str, b: str) -> bool:
    """'pc-014' (NetBIOS) and 'pc-014.corp.local' (DNS) name the same machine."""
    return a.split(".")[0].lower() == b.split(".")[0].lower()


def detect_gateways() -> set[str]:
    """Next hops of default routes on this host (the routers of the attached networks)."""
    try:
        from rased.discovery.networks import read_routes

        return {r.next_hop for r in read_routes() if r.prefix in ("0.0.0.0/0", "0.0.0.0") and r.next_hop not in ("", "0.0.0.0")}
    except Exception:  # noqa: BLE001 - optional enrichment
        return set()


def asset_label(asset: Asset) -> str:
    return asset.display_name or asset.hostname or asset.current_ip or f"#{asset.id}"


@dataclass
class _Match:
    asset: Asset | None
    reason: str


class InventoryRecorder:
    def __init__(self, db: Database, job_id: int, scope: ValidatedScope, job_started_at: datetime,
                 gateways: set[str] | None = None) -> None:
        self.db = db
        self.gateways = gateways if gateways is not None else detect_gateways()
        self.job_id = job_id
        self.scope = scope
        self.job_started_at = job_started_at
        self._mac_ips: dict[str, set[str]] = {}
        self._ambiguous_macs: set[str] = set()
        self._vendor_cache: dict[str, str | None] = {}

    # ------------------------------------------------------------------------------
    def record_chunk(self, observations: list[HostObservation], processed: int) -> None:
        """Persist one chunk atomically (a failure leaves earlier chunks intact)."""
        with self.db.session() as session:
            now = utcnow()
            for obs in observations:
                if obs.mac:
                    ips = self._mac_ips.setdefault(obs.mac, set())
                    ips.add(obs.ip)
                    if len(ips) > 1 and obs.mac not in self._ambiguous_macs:
                        self._ambiguous_macs.add(obs.mac)
                        raise_alert(
                            session,
                            kind="duplicate_mac",
                            severity="low",
                            title_ar="عنوان MAC مكرر على أكثر من عنوان IP",
                            message_ar=(
                                f"العنوان الفيزيائي {obs.mac} ظهر لعدة عناوين IP ({', '.join(sorted(ips))}). "
                                "قد يكون السبب وكيل ARP أو جهاز توجيه أو انتحال عنوان؛ لن يُستخدم هذا العنوان لتمييز الأجهزة في هذا الفحص."
                            ),
                            dedup_key=f"duplicate_mac:{obs.mac}",
                            now=now,
                            job_id=self.job_id,
                            details={"mac": obs.mac, "ips": sorted(ips)},
                        )
            open_count = 0
            for obs in observations:
                open_count += self._record_host(session, obs, now)
            job = session.get(ScanJob, self.job_id)
            if job is not None:
                job.processed_hosts += processed
                job.alive_hosts += len(observations)
                job.open_services += open_count

    def finalize(self, completed: bool) -> int:
        """After a *complete* scan, mark in-scope assets that did not respond as offline."""
        if not completed:
            return 0
        marked = 0
        with self.db.session() as session:
            now = utcnow()
            candidates = session.scalars(
                select(Asset).where(
                    Asset.status == "online",
                    Asset.current_ip.is_not(None),
                    Asset.last_seen < self.job_started_at,
                )
            ).all()
            for asset in candidates:
                if not asset.current_ip or not self.scope.contains(asset.current_ip):
                    continue
                asset.status = "offline"
                marked += 1
                label = asset_label(asset)
                add_event(
                    session, kind="asset_offline", now=now, asset_id=asset.id, job_id=self.job_id,
                    message_ar=f"الجهاز {label} ({asset.current_ip}) لم يستجب في الفحص الأخير",
                )
                raise_alert(
                    session, kind="asset_offline", severity="low", title_ar="الجهاز لا يستجيب",
                    message_ar=f"الجهاز {label} ({asset.current_ip}) لم يستجب لأي من طرق الاكتشاف في الفحص الأخير",
                    dedup_key=f"asset_offline:{asset.id}", now=now, asset_id=asset.id, job_id=self.job_id,
                )
        return marked

    # ------------------------------------------------------------------------------
    def _vendor(self, session: Session, mac: str | None) -> str | None:
        if not mac:
            return None
        prefix = mac_prefix(mac)
        if prefix not in self._vendor_cache:
            row = session.get(OuiVendor, prefix)
            self._vendor_cache[prefix] = row.vendor if row else VIRTUALIZATION_PREFIXES.get(prefix)
        return self._vendor_cache[prefix]

    @staticmethod
    def _by_identifier(session: Session, kind: str, value: str) -> Asset | None:
        return session.scalar(
            select(Asset)
            .join(AssetIdentifier, AssetIdentifier.asset_id == Asset.id)
            .where(AssetIdentifier.kind == kind, AssetIdentifier.value == value)
            .order_by(Asset.last_seen.desc(), Asset.id.desc())
            .limit(1)
        )

    @staticmethod
    def _by_current_ip(session: Session, ip: str) -> Asset | None:
        return session.scalar(
            select(Asset).where(Asset.current_ip == ip).order_by(Asset.last_seen.desc(), Asset.id.desc()).limit(1)
        )

    def _match(self, session: Session, ip: str, mac: str | None, randomized: bool, hostname: str | None) -> _Match:
        def conflicts(holder: Asset) -> bool:
            return bool(hostname and holder.hostname and not same_host(holder.hostname, hostname))

        if mac:
            asset = self._by_identifier(session, "mac", mac)
            if asset is not None:
                return _Match(asset, "mac")
            if randomized and hostname:
                candidate = self._by_identifier(session, "hostname", hostname)
                if candidate is not None and candidate.mac_randomized:
                    return _Match(candidate, "hostname+randomized_mac")
            holder = self._by_current_ip(session, ip)
            if holder is not None and holder.mac is None and not conflicts(holder):
                return _Match(holder, "ip_without_mac")
            return _Match(None, "new_mac")
        if hostname:
            asset = self._by_identifier(session, "hostname", hostname)
            if asset is not None:
                return _Match(asset, "hostname")
        holder = self._by_current_ip(session, ip)
        if holder is not None and not conflicts(holder):
            return _Match(holder, "ip")
        return _Match(None, "new")

    @staticmethod
    def _touch_identifier(session: Session, asset: Asset, kind: str, value: str, source: str, now: datetime) -> None:
        for ident in asset.identifiers:
            if ident.kind == kind and ident.value == value:
                ident.last_seen = now
                return
        asset.identifiers.append(
            AssetIdentifier(kind=kind, value=value, source=source, first_seen=now, last_seen=now)
        )

    def _record_host(self, session: Session, obs: HostObservation, now: datetime) -> int:
        mac = obs.mac if obs.mac and obs.mac not in self._ambiguous_macs else None
        randomized = is_probably_randomized(mac) if mac else False
        # A NetBIOS computer name stands in for DNS when the network has no reverse records.
        if obs.hostname is None and obs.netbios is not None and obs.netbios.computer_name:
            obs.hostname = obs.netbios.computer_name
        match = self._match(session, obs.ip, mac, randomized, obs.hostname)
        is_new = match.asset is None
        asset = match.asset or Asset(first_seen=now, status="online")
        if is_new:
            session.add(asset)
        previous_ip = asset.current_ip
        previous_status = asset.status

        asset.current_ip = obs.ip
        asset.last_seen = now
        asset.status = "online"
        asset.last_scan_job_id = self.job_id
        if obs.hostname and not (asset.hostname and "." in asset.hostname and "." not in obs.hostname
                                 and same_host(asset.hostname, obs.hostname)):
            asset.hostname = obs.hostname
        if mac:
            asset.mac = mac
            asset.mac_randomized = randomized
            asset.vendor = self._vendor(session, mac)
        asset.discovery_methods = sorted(set(asset.discovery_methods or []) | set(obs.methods))
        asset.is_gateway = obs.ip in self.gateways
        if obs.netbios is not None:
            asset.netbios_name = obs.netbios.computer_name or asset.netbios_name
            asset.workgroup = obs.netbios.workgroup or asset.workgroup
        if obs.upnp is not None:
            asset.upnp = obs.upnp.as_dict()
            model = " ".join(x for x in (obs.upnp.manufacturer, obs.upnp.model_name, obs.upnp.model_number) if x).strip()
            asset.model = model or obs.upnp.friendly_name or asset.model
            if not asset.vendor and obs.upnp.manufacturer:
                asset.vendor = obs.upnp.manufacturer
        session.flush()  # assigns asset.id

        ip_kind = "ipv6" if ipaddress.ip_address(obs.ip).version == 6 else "ipv4"
        self._touch_identifier(session, asset, ip_kind, obs.ip, "scan", now)
        if mac:
            self._touch_identifier(session, asset, "mac", mac, "arp", now)
        if obs.hostname:
            self._touch_identifier(session, asset, "hostname", obs.hostname, "dns", now)

        ip_obs = session.scalar(
            select(IpObservation).where(IpObservation.asset_id == asset.id, IpObservation.ip == obs.ip)
        )
        if ip_obs is None:
            session.add(
                IpObservation(
                    asset_id=asset.id, ip=obs.ip, mac=mac, first_seen=now, last_seen=now,
                    sightings=1, first_job_id=self.job_id, last_job_id=self.job_id,
                )
            )
        else:
            ip_obs.last_seen = now
            ip_obs.sightings += 1
            ip_obs.last_job_id = self.job_id
            if mac:
                ip_obs.mac = mac

        label = asset_label(asset)
        if is_new:
            add_event(
                session, kind="asset_new", now=now, asset_id=asset.id, job_id=self.job_id,
                message_ar=f"تم اكتشاف جهاز جديد بالعنوان {obs.ip}",
                details={"ip": obs.ip, "mac": mac, "hostname": obs.hostname, "methods": obs.methods},
            )
            raise_alert(
                session, kind="new_asset", severity="medium", title_ar="جهاز جديد متصل بالشبكة",
                message_ar=f"تم اكتشاف جهاز جديد بالعنوان {obs.ip}"
                + (f" واسم {obs.hostname}" if obs.hostname else "")
                + (f" والعنوان الفيزيائي {mac}" if mac else ""),
                dedup_key=f"new_asset:{asset.id}", now=now, asset_id=asset.id, job_id=self.job_id,
                details={"ip": obs.ip, "mac": mac, "hostname": obs.hostname, "open_ports": obs.open_ports},
            )
        else:
            if previous_ip and previous_ip != obs.ip:
                add_event(
                    session, kind="ip_changed", now=now, asset_id=asset.id, job_id=self.job_id,
                    message_ar=f"تغير عنوان الجهاز {label} من {previous_ip} إلى {obs.ip}",
                    details={"old_ip": previous_ip, "new_ip": obs.ip, "matched_by": match.reason},
                )
                raise_alert(
                    session, kind="ip_changed", severity="info", title_ar="تغير عنوان IP الخاص بالجهاز",
                    message_ar=f"تغير عنوان الجهاز {label} من {previous_ip} إلى {obs.ip} (تمت المطابقة عبر {match.reason})",
                    dedup_key=f"ip_changed:{asset.id}:{obs.ip}", now=now, asset_id=asset.id, job_id=self.job_id,
                    details={"old_ip": previous_ip, "new_ip": obs.ip, "matched_by": match.reason},
                )
            if previous_status == "offline":
                add_event(
                    session, kind="asset_online", now=now, asset_id=asset.id, job_id=self.job_id,
                    message_ar=f"عاد الجهاز {label} ({obs.ip}) إلى الاستجابة",
                )
                resolve_alerts(session, f"asset_offline:{asset.id}", now)

        open_count = self._record_services(session, asset, obs, is_new, now)
        self._record_fingerprint(session, asset, obs, is_new, now)
        session.add(
            ScanResult(
                job_id=self.job_id, asset_id=asset.id, ip=obs.ip, mac=mac, hostname=obs.hostname,
                ttl=obs.ttl, liveness_methods=list(obs.methods), open_ports=obs.open_ports, observed_at=now,
            )
        )
        return open_count

    def _record_services(self, session: Session, asset: Asset, obs: HostObservation, is_new: bool, now: datetime) -> int:
        existing = {(s.port, s.protocol): s for s in asset.services}
        observed: list[tuple[Service, str, str | None]] = []
        label = asset_label(asset)
        open_count = 0
        for port, result in sorted(obs.ports.items()):
            svc = existing.get((port, "tcp"))
            if result.state == "open":
                open_count += 1
                tls_ok = bool(result.tls and result.tls.get("handshake") == "ok")
                ident = identify_service(port, result.banner, tls=tls_ok)
                if svc is None:
                    svc = Service(
                        port=port, protocol="tcp", state="open", first_seen=now,
                        service_name=ident.service_name, identification_method=ident.method,
                        identification_confidence=ident.confidence, exposure_category=ident.exposure_category,
                    )
                    asset.services.append(svc)
                    if not is_new:
                        add_event(
                            session, kind="service_opened", now=now, asset_id=asset.id, job_id=self.job_id,
                            message_ar=f"منفذ جديد {port}/tcp ({ident.service_name}) على الجهاز {label}",
                            details={"port": port, "service": ident.service_name},
                        )
                        raise_alert(
                            session, kind="new_port", severity="medium", title_ar="تم اكتشاف منفذ جديد",
                            message_ar=f"تم اكتشاف المنفذ {port}/tcp ({ident.service_name}) مفتوحاً على الجهاز {label} ({obs.ip})",
                            dedup_key=f"new_port:{asset.id}:tcp:{port}", now=now, asset_id=asset.id,
                            job_id=self.job_id, details={"port": port, "protocol": "tcp", "service": ident.service_name},
                        )
                elif svc.state != "open":
                    svc.state = "open"
                    add_event(
                        session, kind="service_reopened", now=now, asset_id=asset.id, job_id=self.job_id,
                        message_ar=f"أعيد فتح المنفذ {port}/tcp على الجهاز {label}",
                        details={"port": port},
                    )
                    raise_alert(
                        session, kind="new_port", severity="medium", title_ar="تم اكتشاف منفذ جديد",
                        message_ar=f"المنفذ {port}/tcp أصبح مفتوحاً مجدداً على الجهاز {label} ({obs.ip})",
                        dedup_key=f"new_port:{asset.id}:tcp:{port}", now=now, asset_id=asset.id,
                        job_id=self.job_id, details={"port": port, "protocol": "tcp"},
                    )
                # Never downgrade a banner-verified identity with a port-number guess.
                if ident.method == "banner" or svc.identification_method != "banner":
                    svc.service_name = ident.service_name
                    svc.product = ident.product
                    svc.version = ident.version
                    svc.identification_method = ident.method
                    svc.identification_confidence = ident.confidence
                    svc.exposure_category = ident.exposure_category
                if ident.banner:
                    svc.banner = ident.banner
                if result.tls is not None:
                    svc.tls = result.tls
                svc.last_seen = now
                svc.last_job_id = self.job_id
                observed.append((svc, "open", ident.banner))
            elif svc is not None and svc.state == "open":
                # Explicitly probed and no longer reachable.
                svc.state = "closed"
                svc.last_job_id = self.job_id
                add_event(
                    session, kind="service_closed", now=now, asset_id=asset.id, job_id=self.job_id,
                    message_ar=f"أُغلق المنفذ {port}/tcp على الجهاز {label}",
                    details={"port": port, "probe_state": result.state},
                )
                resolve_alerts(session, f"new_port:{asset.id}:tcp:{port}", now)
                observed.append((svc, "closed", None))
        session.flush()
        for svc, state, banner in observed:
            session.add(ServiceObservation(service_id=svc.id, job_id=self.job_id, state=state, banner=banner, observed_at=now))
        return open_count

    def _record_fingerprint(self, session: Session, asset: Asset, obs: HostObservation, is_new: bool, now: datetime) -> None:
        open_services = [s for s in asset.services if s.state == "open"]
        classification = classify(
            FingerprintInput(
                open_ports=frozenset(s.port for s in open_services),
                products=tuple(f"{s.product or ''} {s.version or ''}".strip() for s in open_services if s.product),
                banners=tuple(s.banner for s in open_services if s.banner),
                ttl=obs.ttl,
                mac=asset.mac,
                mac_randomized=asset.mac_randomized,
                vendor=asset.vendor,
                hostname=asset.hostname,
                netbios=obs.netbios is not None or bool(asset.netbios_name),
                netbios_file_server=bool(obs.netbios and obs.netbios.file_server),
                netbios_domain_controller=bool(obs.netbios and obs.netbios.domain_controller),
                netbios_null_mac=bool(obs.netbios is not None and obs.netbios.mac is None),
                upnp_type=(asset.upnp or {}).get("device_type"),
                upnp_manufacturer=(asset.upnp or {}).get("manufacturer"),
                upnp_model=(asset.upnp or {}).get("model_name"),
                upnp_server=(asset.upnp or {}).get("server"),
                is_gateway=asset.is_gateway,
            )
        )
        latest = session.scalar(
            select(DeviceFingerprint)
            .where(DeviceFingerprint.asset_id == asset.id)
            .order_by(DeviceFingerprint.created_at.desc(), DeviceFingerprint.id.desc())
            .limit(1)
        )
        evidence = [e.as_dict() for e in classification.evidence]
        unchanged = (
            latest is not None
            and latest.device_type == classification.device_type
            and latest.os_family == classification.os_family
            and abs(latest.device_type_confidence - classification.device_confidence) < 0.01
            and abs(latest.os_confidence - classification.os_confidence) < 0.01
        )
        if unchanged and latest is not None:
            latest.last_confirmed_at = now
            latest.evidence = evidence
        else:
            session.add(
                DeviceFingerprint(
                    asset_id=asset.id, job_id=self.job_id, device_type=classification.device_type,
                    device_type_confidence=classification.device_confidence, os_family=classification.os_family,
                    os_confidence=classification.os_confidence, evidence=evidence, created_at=now, last_confirmed_at=now,
                )
            )
            if not is_new and latest is not None and latest.device_type != classification.device_type:
                add_event(
                    session, kind="classification_changed", now=now, asset_id=asset.id, job_id=self.job_id,
                    message_ar=f"تغير تصنيف الجهاز {asset_label(asset)} من {latest.device_type} إلى {classification.device_type}",
                    details={"old": latest.device_type, "new": classification.device_type},
                )
        asset.device_type = classification.device_type
        asset.device_type_confidence = classification.device_confidence
        asset.os_family = classification.os_family
        asset.os_confidence = classification.os_confidence
