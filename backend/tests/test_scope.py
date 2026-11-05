import pytest

from rased.scope import ScopeError, validate_scope


def v(cidr, hosts=(), ports=(), allow_public=False, max_hosts=65536):  # type: ignore[no-untyped-def]
    return validate_scope(cidr, hosts, ports, allow_public=allow_public, max_hosts=max_hosts)


def test_slash24_excludes_network_and_broadcast():
    scope = v("192.168.1.0/24")
    targets = list(scope.targets())
    assert len(targets) == 254
    assert targets[0] == "192.168.1.1" and targets[-1] == "192.168.1.254"


def test_single_host_and_slash31():
    assert list(v("10.0.0.5").targets()) == ["10.0.0.5"]
    assert list(v("10.0.0.4/31").targets()) == ["10.0.0.4", "10.0.0.5"]


def test_host_bits_rejected_with_suggestion():
    with pytest.raises(ScopeError) as exc:
        v("192.168.1.5/24")
    assert "192.168.1.0/24" in str(exc.value)


def test_public_range_rejected_unless_explicitly_allowed():
    with pytest.raises(ScopeError):
        v("8.8.8.0/24")
    assert v("8.8.8.0/24", allow_public=True).target_count() == 254


@pytest.mark.parametrize("cidr", ["224.0.0.0/24", "240.0.0.0/24", "0.0.0.0/32", "garbage", "", "192.168.1.0/33"])
def test_invalid_or_reserved_rejected(cidr):
    with pytest.raises(ScopeError):
        v(cidr, allow_public=True)


def test_large_ipv6_ranges_never_enumerated():
    with pytest.raises(ScopeError):
        v("fd00::/64")
    assert v("fd00::/120").target_count() == 255  # subnet-router anycast excluded


def test_max_hosts_enforced():
    with pytest.raises(ScopeError):
        v("10.0.0.0/8")
    assert v("172.16.0.0/16").target_count() == 65534


def test_exclusions_applied():
    scope = v("192.168.1.0/24", hosts=["192.168.1.1", "192.168.1.128/25"])
    targets = list(scope.targets())
    assert len(targets) == 126
    assert "192.168.1.1" not in targets and "192.168.1.200" not in targets
    assert scope.contains("192.168.1.2")
    assert not scope.contains("192.168.1.1")
    assert not scope.contains("192.168.2.1")
    assert not scope.contains("not-an-ip")


@pytest.mark.parametrize("ports", [[0], [70000], [True], ["22"]])
def test_invalid_excluded_ports(ports):
    with pytest.raises(ScopeError):
        v("192.168.1.0/24", ports=ports)


def test_invalid_exclusion():
    with pytest.raises(ScopeError):
        v("192.168.1.0/24", hosts=["999.1.1.1"])
