"""Active Directory attack-path analysis (nested privileged-group reachability)."""

from __future__ import annotations

from rased.attackpaths import build_group_parents, find_paths, summarize

# "Domain Admins" contains the "IT Admins" group, which contains user jdoe (nested escalation).
GROUPS = [
    {"name": "Domain Admins", "members": ["IT Admins", "administrator"]},
    {"name": "IT Admins", "members": ["jdoe"]},
    {"name": "Sales", "members": ["asmith"]},
]
USERS = [
    {"sam": "jdoe", "display_name": "John Doe", "enabled": True, "groups": ["IT Admins"],
     "flags": {"password_never_expires": True}},
    {"sam": "administrator", "display_name": "Admin", "enabled": True, "groups": ["Domain Admins"], "flags": {}},
    {"sam": "asmith", "display_name": "A Smith", "enabled": True, "groups": ["Sales"], "flags": {}},
    {"sam": "olduser", "display_name": "Old", "enabled": False, "groups": ["Domain Admins"], "flags": {}},
]


def test_build_group_parents_captures_nesting():
    parents = build_group_parents(GROUPS)
    assert parents["IT Admins"] == {"Domain Admins"}   # IT Admins is nested under Domain Admins
    assert "Sales" not in parents


def test_find_paths_direct_and_nested():
    paths = {p["user"]: p for p in find_paths(USERS, GROUPS)}
    assert set(paths) == {"jdoe", "administrator", "olduser"}   # asmith (Sales) has no privileged path
    assert paths["administrator"]["direct"] is True and paths["administrator"]["hops"] == 1
    # jdoe reaches Domain Admins only through the nested IT Admins group.
    assert paths["jdoe"]["direct"] is False and paths["jdoe"]["hops"] == 2
    assert paths["jdoe"]["path"] == ["jdoe", "IT Admins", "Domain Admins"]
    assert paths["jdoe"]["label_ar"] == "مسؤولو النطاق"


def test_summarize_flags_risky_accounts():
    s = summarize(USERS, GROUPS)
    assert s["privileged_users"] == 3 and s["nested_escalations"] == 1
    da = next(t for t in s["targets"] if t["group"] == "Domain Admins")
    assert da["reachable_users"] == 3
    risky_users = {r["user"] for r in s["risky"]}
    assert "jdoe" in risky_users       # password-never-expires + nested escalation
    assert "olduser" in risky_users    # disabled but still privileged
    assert "asmith" not in risky_users
