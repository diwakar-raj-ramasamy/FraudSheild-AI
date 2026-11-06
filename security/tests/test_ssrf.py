import pytest
from app.core.network_security import (
    is_ip_restricted,
    is_hostname_restricted,
    resolve_safe_ips
)
from app.engines.infrastructure_analyzer import infrastructure_analyzer

def test_private_and_loopback_ips_restricted():
    restricted_test_ips = [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.254",
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "0.0.0.0",
        "224.0.0.1",        # Multicast
        "::1",              # IPv6 loopback
        "fe80::1",          # IPv6 link-local
    ]
    for ip in restricted_test_ips:
        assert is_ip_restricted(ip), f"IP '{ip}' should be restricted"

def test_public_ips_allowed():
    public_test_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "142.250.190.46"
    ]
    for ip in public_test_ips:
        assert not is_ip_restricted(ip), f"Public IP '{ip}' should NOT be restricted"

def test_blocked_hostnames():
    blocked_hosts = [
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "service.local",
        "database.internal",
        "router.lan"
    ]
    for host in blocked_hosts:
        assert is_hostname_restricted(host), f"Hostname '{host}' should be restricted"

def test_infrastructure_analyzer_blocks_ssrf_on_loopback():
    res = infrastructure_analyzer.analyze_domain("127.0.0.1")
    assert res["is_restricted_network"] is True
    assert "SSRF Guard Notice" in res["forensic_note"]
    assert res["ssl_info"]["has_ssl"] is False

def test_infrastructure_analyzer_blocks_ssrf_on_cloud_metadata():
    res = infrastructure_analyzer.analyze_domain("169.254.169.254")
    assert res["is_restricted_network"] is True
    assert "SSRF Guard Notice" in res["forensic_note"]
    assert res["ssl_info"]["has_ssl"] is False

def test_infrastructure_analyzer_blocks_ssrf_on_localhost_hostname():
    res = infrastructure_analyzer.analyze_domain("localhost")
    assert res["is_restricted_network"] is True
    assert "SSRF Guard Notice" in res["forensic_note"]

