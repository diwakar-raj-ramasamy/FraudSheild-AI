"""
FraudShield AI Network Security Utility
Provides strict validation against Server-Side Request Forgery (SSRF),
DNS rebinding, and probes targeting private/loopback/cloud-metadata addresses.
"""

import ipaddress
import socket
from typing import Tuple, List

RESTRICTED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (local)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space / Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local & Cloud Metadata (AWS, GCP, Azure)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

RESTRICTED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "broadcasthost",
    "metadata.google.internal", "metadata", "instance-data",
    "kubernetes.default.svc"
}

def is_ip_restricted(ip_str: str) -> bool:
    """Checks whether an IP address belongs to private, loopback, or reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        if isinstance(ip, ipaddress.IPv4Address):
            for net in RESTRICTED_IPV4_NETWORKS:
                if ip in net:
                    return True
        elif isinstance(ip, ipaddress.IPv6Address):
            for net in RESTRICTED_IPV6_NETWORKS:
                if ip in net:
                    return True
        return False
    except ValueError:
        return True  # Malformed IP is treated as restricted

def is_hostname_restricted(hostname: str) -> bool:
    """Checks whether a hostname matches private, local, or cloud metadata patterns."""
    if not hostname:
        return True
    cleaned = hostname.strip().lower().rstrip(".")
    if cleaned in BLOCKED_HOSTNAMES:
        return True
    if cleaned.endswith((".local", ".localhost", ".internal", ".lan", ".home")):
        return True
    return False

def resolve_safe_ips(domain: str) -> Tuple[bool, List[str], str]:
    """
    Resolves domain DNS and checks each resolved IP against restricted network ranges.
    Returns: (is_safe, resolved_ips, reason)
    """
    if is_hostname_restricted(domain):
        return False, [], f"Hostname '{domain}' is restricted (internal/loopback/cloud-metadata)."

    # Check if already an IP string
    try:
        ip = ipaddress.ip_address(domain)
        if is_ip_restricted(str(ip)):
            return False, [str(ip)], f"IP address '{domain}' is restricted (private/loopback/cloud-metadata)."
        return True, [str(ip)], ""
    except ValueError:
        pass  # Domain name, proceed to DNS resolution

    try:
        addr_info = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
        resolved_ips = list(set([item[4][0] for item in addr_info]))
        if not resolved_ips:
            return False, [], "Domain failed DNS resolution (no A records)."

        for ip_str in resolved_ips:
            if is_ip_restricted(ip_str):
                return False, resolved_ips, f"Domain resolved to restricted IP '{ip_str}' (SSRF prohibited)."

        return True, resolved_ips, ""
    except socket.gaierror:
        return False, [], "Domain failed DNS resolution (NXDOMAIN or DNS unreachable)."
    except Exception as e:
        return False, [], f"DNS lookup error: {str(e)}"

