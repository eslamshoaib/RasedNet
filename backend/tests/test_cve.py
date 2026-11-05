"""CVE feed import, version-range matching and service correlation."""

from __future__ import annotations

from rased.cve import (
    correlate,
    import_feed,
    match_entry,
    normalize_feed_entry,
    severity_from_cvss,
    version_in_range,
    version_key,
)
from rased.models import Asset, AssetVulnerability, Service, utcnow
from tests.conftest import login, make_user


def test_severity_from_cvss():
    assert severity_from_cvss(9.8) == "critical"
    assert severity_from_cvss(7.0) == "high"
    assert severity_from_cvss(4.0) == "medium"
    assert severity_from_cvss(0.1) == "low"
    assert severity_from_cvss(0) == "unknown"


def test_version_ordering_and_range():
    assert version_key("1.2.10") > version_key("1.2.9")  # numeric, not lexical
    assert version_in_range("1.2.3", start="1.0.0", end="2.0.0", exact=None)
    assert not version_in_range("2.0.0", start="1.0.0", end="2.0.0", exact=None)  # end exclusive
    assert version_in_range("7.4", start=None, end=None, exact="7.4")
    assert not version_in_range("7.5", start=None, end=None, exact="7.4")


def test_match_entry_product_and_version():
    affected = [{"product": "OpenSSH", "version_start": "0", "version_end": "8.0"}]
    assert match_entry("OpenSSH", "7.4", affected)
    assert match_entry("openssh", "7.4", affected)       # case-insensitive
    assert match_entry("OpenSSH", "9.0", affected) is None   # outside range
    # product-only rule matches any version
    assert match_entry("nginx", "1.2", [{"product": "nginx"}])
    # version unknown still flags a product match (for review)
    assert "غير معروف" in match_entry("nginx", "", [{"product": "nginx", "version_end": "2.0"}])


def test_normalize_tolerates_nvd_shape():
    norm = normalize_feed_entry({
        "cve": {"id": "CVE-2024-0001"}, "cvss": 7.5,
        "affected": [{"product": "Apache httpd", "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.59"}],
    })
    assert norm["cve_id"] == "CVE-2024-0001"
    assert norm["severity"] == "high"
    assert norm["affected"][0]["version_start"] == "2.4.0"
    assert norm["affected"][0]["version_end"] == "2.4.59"
    assert normalize_feed_entry({"no_id": True}) is None


FEED = [
    {"cve_id": "CVE-2023-1111", "cvss_score": 9.8, "description": "RCE in OpenSSH",
     "affected": [{"product": "OpenSSH", "version_start": "0", "version_end": "8.0"}]},
    {"cve_id": "CVE-2023-2222", "cvss_score": 5.0, "description": "nginx info leak",
     "affected": [{"product": "nginx", "version_exact": "1.18.0"}]},
]


def test_import_and_correlate(db):
    now = utcnow()
    with db.session() as s:
        host = Asset(current_ip="10.0.0.5", status="online", device_type="server", first_seen=now, last_seen=now)
        s.add(host)
        s.flush()
        s.add_all([
            Service(asset_id=host.id, port=22, protocol="tcp", state="open", service_name="ssh",
                    product="OpenSSH", version="7.4", first_seen=now, last_seen=now),
            Service(asset_id=host.id, port=80, protocol="tcp", state="open", service_name="http",
                    product="nginx", version="1.20.0", first_seen=now, last_seen=now),
        ])
        s.flush()
        host_id = host.id

    with db.session() as s:
        stats = import_feed(s, FEED)
        assert stats["added"] == 2
        result = correlate(s)
        s.commit()
    assert result["matched"] == 1  # OpenSSH 7.4 is vulnerable; nginx 1.20 != exact 1.18.0

    with db.session() as s:
        import sqlalchemy as sa
        vulns = list(s.scalars(sa.select(AssetVulnerability)))
        assert len(vulns) == 1
        v = vulns[0]
        assert v.cve_id == "CVE-2023-1111"
        assert v.asset_id == host_id
        assert v.severity == "critical"
        assert v.status == "open"


def test_cve_api_import_requires_data_manage(make_client, db):
    make_user(db, "admin", "admin")
    make_user(db, "auditor", "auditor")
    client = make_client()
    csrf = login(client, "admin")

    r = client.post("/api/cve/import", json=FEED, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    assert r.json()["import"]["added"] == 2

    summary = client.get("/api/cve/summary").json()
    assert summary["cve_entries"] == 2

    # Auditor cannot import (no data:manage).
    aud = make_client()
    aud_csrf = login(aud, "auditor")
    assert aud.post("/api/cve/import", json=FEED, headers={"X-CSRF-Token": aud_csrf}).status_code == 403
    # ...but can read the summary.
    assert aud.get("/api/cve/summary").status_code == 200


def test_priority_score_and_band():
    from rased.cve import priority_score, priority_band
    assert priority_score(0.0, 0.0, False) == 0
    assert priority_score(7.5, 0.0, False) == 75
    assert priority_score(5.0, 0.5, False) == 60            # 50 + 0.5*20
    assert priority_score(2.0, 0.0, True) == 90             # KEV floors at 90
    assert priority_score(9.9, 1.0, True) == 100            # clamped
    assert priority_band(95) == "critical" and priority_band(40) == "medium"


def test_import_epss_and_kev(db):
    from rased.cve import import_feed, import_epss, import_kev
    with db.session() as s:
        import_feed(s, [{"cve_id": "CVE-2023-1111", "cvss_score": 5.0, "affected": [{"product": "x"}]},
                        {"cve_id": "CVE-2023-2222", "cvss_score": 4.0, "affected": [{"product": "y"}]}])
        s.commit()
    with db.session() as s:
        e = import_epss(s, "#model 2026\ncve,epss,percentile\nCVE-2023-1111,0.97,0.99\nCVE-9999-0000,0.5,0.5\n")
        k = import_kev(s, {"vulnerabilities": [{"cveID": "CVE-2023-2222", "dateAdded": "2024-05-01"}, {"cveID": "CVE-x"}]})
        s.commit()
    assert e == {"updated": 1, "unmatched": 1}
    assert k == {"flagged": 1, "unmatched": 1}
    with db.session() as s:
        import sqlalchemy as sa
        from rased.models import CveEntry
        c1 = s.scalar(sa.select(CveEntry).where(CveEntry.cve_id == "CVE-2023-1111"))
        c2 = s.scalar(sa.select(CveEntry).where(CveEntry.cve_id == "CVE-2023-2222"))
        assert abs(c1.epss - 0.97) < 1e-6 and c1.kev is False
        assert c2.kev is True and c2.kev_date == "2024-05-01"


def test_vuln_list_prioritises_kev(db):
    from rased.cve import import_feed, import_epss, import_kev, correlate
    from rased.models import Asset, Service, utcnow
    now = utcnow()
    with db.session() as s:
        a = Asset(current_ip="10.0.0.5", status="online", device_type="server", first_seen=now, last_seen=now)
        s.add(a); s.flush()
        s.add_all([
            Service(asset_id=a.id, port=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH", version="7.4", first_seen=now, last_seen=now),
            Service(asset_id=a.id, port=80, protocol="tcp", state="open", service_name="http", product="nginx", version="1.10", first_seen=now, last_seen=now),
        ])
        s.flush()
        import_feed(s, [
            {"cve_id": "CVE-A", "cvss_score": 9.8, "affected": [{"product": "OpenSSH", "version_end": "9.9"}]},  # high cvss, no kev
            {"cve_id": "CVE-B", "cvss_score": 5.0, "affected": [{"product": "nginx", "version_end": "2.0"}]},    # lower cvss, KEV
        ])
        import_kev(s, {"vulnerabilities": [{"cveID": "CVE-B", "dateAdded": "2024-01-01"}]})
        correlate(s)
        s.commit()
    # KEV raises a modest-CVSS finding to top (critical) priority band.
    from rased.cve import priority_score, priority_band
    assert priority_score(5.0, 0.0, True) == 90 and priority_band(90) == "critical"
    assert priority_score(5.0, 0.0, True) > priority_score(5.0, 0.0, False)  # KEV lifts it well above CVSS-only
