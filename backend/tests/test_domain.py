"""Directory (AD/LDAP) parsing, UAC decoding, privilege derivation and summary."""

from __future__ import annotations

from rased.domain import (
    UAC_DISABLED,
    UAC_DONT_EXPIRE_PASSWD,
    _dns_to_base_dn,
    decode_uac,
    discover_domain,
    parse_group,
    parse_user,
    privileges_for,
    rdn_value,
    summarise,
)


def test_rdn_value():
    assert rdn_value("CN=Domain Admins,CN=Users,DC=example,DC=local") == "Domain Admins"
    assert rdn_value("plain") == "plain"


def test_decode_uac_flags():
    flags = decode_uac(UAC_DISABLED | UAC_DONT_EXPIRE_PASSWD)
    assert flags["enabled"] is False
    assert flags["password_never_expires"] is True
    assert decode_uac(512)["enabled"] is True  # 512 = normal account, enabled


def test_privileges_for_maps_wellknown_groups():
    groups = ["CN=Domain Admins,CN=Users,DC=x", "CN=Sales,OU=Groups,DC=x"]
    privs = privileges_for(groups, admin_count=1)
    assert [p["group"] for p in privs] == ["Domain Admins"]
    assert privs[0]["label_ar"] == "مسؤولو النطاق"
    # adminCount alone (no privileged group matched) still flags the account as protected.
    assert privileges_for(["CN=Sales,DC=x"], admin_count=1)[0]["group"] == "adminCount"
    assert privileges_for(["CN=Sales,DC=x"], admin_count=0) == []


def test_parse_user_normalises_and_scores_privilege():
    user = parse_user({
        "sAMAccountName": "jdoe", "displayName": "John Doe",
        "userPrincipalName": "jdoe@example.local", "userAccountControl": UAC_DISABLED | UAC_DONT_EXPIRE_PASSWD,
        "memberOf": ["CN=Enterprise Admins,CN=Users,DC=example,DC=local", "CN=IT,OU=Groups,DC=example,DC=local"],
        "adminCount": 1, "distinguishedName": "CN=John Doe,CN=Users,DC=example,DC=local",
    })
    assert user["sam"] == "jdoe"
    assert user["enabled"] is False
    assert user["flags"]["password_never_expires"] is True
    assert user["group_count"] == 2
    assert user["groups"] == ["Enterprise Admins", "IT"]
    assert user["is_privileged"] is True
    assert user["privileges"][0]["label_ar"] == "مسؤولو المؤسسة"


def test_parse_group_flags_privileged_and_counts_members():
    g = parse_group({
        "cn": "Domain Admins", "sAMAccountName": "Domain Admins",
        "member": ["CN=jdoe,DC=x", "CN=admin,DC=x"], "adminCount": 1,
        "distinguishedName": "CN=Domain Admins,CN=Users,DC=x",
    })
    assert g["privileged"] is True
    assert g["label_ar"] == "مسؤولو النطاق"
    assert g["member_count"] == 2
    assert g["members"] == ["jdoe", "admin"]
    assert parse_group({"cn": "Sales", "member": []})["privileged"] is False


def test_dns_to_base_dn():
    assert _dns_to_base_dn("example.local") == "DC=example,DC=local"
    assert _dns_to_base_dn("corp.example.com") == "DC=corp,DC=example,DC=com"


def test_discover_domain_includes_inventory_controllers(monkeypatch):
    # With no domain environment, discovery still surfaces inventory-supplied controllers.
    monkeypatch.delenv("USERDNSDOMAIN", raising=False)
    monkeypatch.delenv("LOGONSERVER", raising=False)
    d = discover_domain(["10.0.0.1", "10.0.0.2"])
    hosts = {c["host"] for c in d["controllers"]}
    assert {"10.0.0.1", "10.0.0.2"} <= hosts
    assert d["domain"] is None and d["base_dn"] is None
    assert d["integrated_available"] is False  # no USERDNSDOMAIN

    monkeypatch.setenv("USERDNSDOMAIN", "example.local")
    d2 = discover_domain([])
    assert d2["domain"] == "example.local" and d2["base_dn"] == "DC=example,DC=local"


def test_summarise_counts():
    users = [
        parse_user({"sAMAccountName": "a", "userAccountControl": 512,
                    "memberOf": ["CN=Domain Admins,DC=x"], "adminCount": 1}),
        parse_user({"sAMAccountName": "b", "userAccountControl": UAC_DISABLED}),
        parse_user({"sAMAccountName": "c", "userAccountControl": UAC_DONT_EXPIRE_PASSWD}),
    ]
    groups = [parse_group({"cn": "Domain Admins", "member": ["CN=a,DC=x"]}),
              parse_group({"cn": "Sales", "member": []})]
    out = summarise(users, groups, [], {"base_dn": "DC=x"})
    c = out["counts"]
    assert c["users"] == 3
    assert c["enabled_users"] == 2
    assert c["disabled_users"] == 1
    assert c["privileged_users"] == 1
    assert c["privileged_groups"] == 1
    assert c["password_never_expires"] == 1


def test_discover_api_lists_inventory_controllers(make_client, db):
    from rased.models import Asset, Service, utcnow
    from tests.conftest import login, make_user
    now = utcnow()
    with db.session() as s:
        dc = Asset(current_ip="10.0.0.1", status="online", device_type="server", first_seen=now, last_seen=now)
        s.add(dc)
        s.flush()
        s.add(Service(asset_id=dc.id, port=389, protocol="tcp", state="open", service_name="ldap",
                      first_seen=now, last_seen=now))
        s.commit()
    make_user(db, "admin", "admin")
    client = make_client()
    login(client, "admin")
    d = client.get("/api/directory/discover").json()
    assert "integrated_available" in d and "controllers" in d
    assert any(c["host"] == "10.0.0.1" for c in d["controllers"])  # the LDAP host is surfaced
