"""Active Directory attack-path analysis (BloodHound-style, read-only).

Given the users, groups and memberships RASED already enumerates over LDAP, this computes which
accounts can reach a highly-privileged group (Domain Admins, Enterprise Admins, Administrators…)
— directly or through *nested* group membership — and the shortest path for each. Nested paths
are the ones a direct membership check misses, and they are where privilege-escalation hides.

Pure functions over plain data; no network, no writes.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from rased.domain import PRIVILEGED_GROUPS, rdn_value

MAX_DEPTH = 8


def build_group_parents(groups: list[dict[str, Any]]) -> dict[str, set[str]]:
    """child-group name → set of groups that directly contain it (parent groups)."""
    names = {g["name"] for g in groups if g.get("name")}
    parents: dict[str, set[str]] = defaultdict(set)
    for g in groups:
        gname = g.get("name")
        if not gname:
            continue
        for member in g.get("members", []):
            m = rdn_value(member)
            if m in names and m != gname:   # the member is itself a group → g is its parent
                parents[m].add(gname)
    return parents


def _is_priv(group_name: str) -> str | None:
    return group_name.strip().lower() if group_name.strip().lower() in PRIVILEGED_GROUPS else None


def find_paths(users: list[dict[str, Any]], groups: list[dict[str, Any]], *, max_depth: int = MAX_DEPTH) -> list[dict[str, Any]]:
    """For each user, the shortest membership path that reaches a privileged group (if any)."""
    parents = build_group_parents(groups)
    paths: list[dict[str, Any]] = []
    for u in users:
        start_groups = [rdn_value(g) for g in u.get("groups", [])]
        visited: set[str] = set()
        dq: deque[tuple[str, list[str]]] = deque((g, [g]) for g in start_groups)
        found: dict[str, Any] | None = None
        while dq and found is None:
            node, trail = dq.popleft()
            if node in visited or len(trail) > max_depth:
                continue
            visited.add(node)
            key = _is_priv(node)
            if key:
                found = {
                    "user": u.get("sam", ""),
                    "display_name": u.get("display_name", ""),
                    "enabled": u.get("enabled", True),
                    "target": node,
                    "label_ar": PRIVILEGED_GROUPS[key],
                    "path": [u.get("sam", "")] + trail,
                    "hops": len(trail),
                    "direct": len(trail) == 1,
                }
                break
            for p in parents.get(node, ()):
                if p not in visited:
                    dq.append((p, trail + [p]))
        if found:
            paths.append(found)
    paths.sort(key=lambda p: (p["hops"], not p["enabled"], p["user"].lower()))
    return paths


def summarize(users: list[dict[str, Any]], groups: list[dict[str, Any]]) -> dict[str, Any]:
    """Attack-path summary: privileged reach, nested-only escalations, risky privileged accounts."""
    paths = find_paths(users, groups)
    by_user = {u.get("sam"): u for u in users}
    per_target: dict[str, int] = defaultdict(int)
    nested_only = 0
    risky: list[dict[str, Any]] = []
    for p in paths:
        per_target[p["target"]] += 1
        if not p["direct"]:
            nested_only += 1
        u = by_user.get(p["user"], {})
        flags = u.get("flags", {}) if isinstance(u, dict) else {}
        reasons = []
        if not p["enabled"]:
            reasons.append("حساب مُعطّل لكنه ما زال متميّزاً")
        if flags.get("password_never_expires"):
            reasons.append("كلمة المرور لا تنتهي")
        if flags.get("password_not_required"):
            reasons.append("لا تتطلب كلمة مرور")
        if flags.get("trusted_for_delegation"):
            reasons.append("موثوق للتفويض (Delegation)")
        if not p["direct"]:
            reasons.append(f"تصعيد عبر عضوية متداخلة ({p['hops']} قفزات)")
        if reasons:
            risky.append({"user": p["user"], "target": p["target"], "hops": p["hops"], "reasons_ar": reasons})
    return {
        "privileged_users": len(paths),
        "nested_escalations": nested_only,
        "targets": [{"group": g, "label_ar": PRIVILEGED_GROUPS.get(g.strip().lower(), ""), "reachable_users": n}
                    for g, n in sorted(per_target.items(), key=lambda kv: -kv[1])],
        "risky": risky,
        "paths": paths,
    }
