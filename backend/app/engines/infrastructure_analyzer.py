import socket
import ssl
from typing import Dict, Any, List
from datetime import datetime, timezone
from app.utils.url_utils import is_ip_address
from app.core.network_security import resolve_safe_ips, is_ip_restricted

# Known ASNs / Cloud CDNs to clearly distinguish shared vs isolated hosting
KNOWN_INFRASTRUCTURE = {
    "13335": ("Cloudflare Inc.", "CDN / Reverse Proxy"),
    "15169": ("Google LLC", "Cloud / CDN"),
    "16509": ("Amazon.com Inc.", "AWS Cloud"),
    "8075": ("Microsoft Corporation", "Azure Cloud"),
    "209242": ("Cloudflare London", "CDN"),
    "14061": ("DigitalOcean LLC", "Cloud VPS"),
    "16276": ("OVH SAS", "Dedicated / Cloud Hosting"),
    "24940": ("Hetzner Online GmbH", "Hosting Provider")
}

class InfrastructureAnalyzer:
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Resolves domain infrastructure and returns observed network footprint.
        Forensic Boundary: Strictly categorizes findings as 'Observed Infrastructure IP'
        or 'Resolved Server IP', acknowledging CDN, shared hosting, and cloud multi-tenancy.
        Hardened against SSRF, DNS rebinding, and probes targeting private/internal network ranges.
        """
        result = {
            "domain": domain,
            "observed_infrastructure_ip": None,
            "resolved_server_ips": [],
            "asn": "AS-UNKNOWN",
            "asn_organization": "Unknown Infrastructure",
            "infrastructure_type": "Direct Hosting / VPS",
            "reverse_dns": None,
            "dns_records": {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": []
            },
            "ssl_info": {
                "has_ssl": False,
                "issuer": None,
                "is_expired": False,
                "san_count": 0,
                "grade": "N/A"
            },
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "forensic_note": "Observed IP addresses reflect routing infrastructure and may represent CDNs, shared proxies, or cloud hosts rather than confirmed attacker identity.",
            "is_restricted_network": False
        }

        # Validate against SSRF and check IP restrictions
        is_safe, resolved_ips, reason = resolve_safe_ips(domain)
        if not is_safe:
            result["dns_records"]["A"] = resolved_ips
            result["resolved_server_ips"] = resolved_ips
            result["observed_infrastructure_ip"] = resolved_ips[0] if resolved_ips else None
            result["is_restricted_network"] = True
            result["forensic_note"] = f"SSRF Guard Notice: Network inspection halted. {reason}"
            return result

        result["resolved_server_ips"] = resolved_ips
        result["observed_infrastructure_ip"] = resolved_ips[0]
        result["dns_records"]["A"] = resolved_ips

        # Set socket timeout for fast non-blocking resolution
        socket.setdefaulttimeout(1.5)

        # 1. Reverse DNS pointer lookup
        try:
            rev_name, _, _ = socket.gethostbyaddr(resolved_ips[0])
            result["reverse_dns"] = rev_name
        except Exception:
            result["reverse_dns"] = "No PTR record found"

        # 2. Heuristic ASN & Infrastructure categorization based on IP prefix / reverse DNS
        rev = (result["reverse_dns"] or "").lower()
        obs_ip = result["observed_infrastructure_ip"] or ""
        
        if "cloudflare" in rev or obs_ip.startswith("104.") or obs_ip.startswith("172.67."):
            result["asn"] = "AS13335"
            result["asn_organization"] = "Cloudflare Inc."
            result["infrastructure_type"] = "CDN / Edge Reverse Proxy (Hides Origin Server)"
        elif "google" in rev or obs_ip.startswith("142.250.") or obs_ip.startswith("172.217."):
            result["asn"] = "AS15169"
            result["asn_organization"] = "Google LLC"
            result["infrastructure_type"] = "Google Cloud / CDN"
        elif "amazonaws" in rev or obs_ip.startswith("54.") or obs_ip.startswith("52.") or obs_ip.startswith("3."):
            result["asn"] = "AS16509"
            result["asn_organization"] = "Amazon Web Services"
            result["infrastructure_type"] = "Cloud Infrastructure (AWS EC2 / CloudFront)"
        elif "digitalocean" in rev:
            result["asn"] = "AS14061"
            result["asn_organization"] = "DigitalOcean LLC"
            result["infrastructure_type"] = "Cloud Virtual Private Server (VPS)"
        elif "hetzner" in rev:
            result["asn"] = "AS24940"
            result["asn_organization"] = "Hetzner Online GmbH"
            result["infrastructure_type"] = "Dedicated / Cloud Infrastructure"
        else:
            result["asn"] = "AS-DYNAMIC"
            result["asn_organization"] = "Commercial Hosting / ISP Network"
            result["infrastructure_type"] = "Dedicated or Shared Web Hosting"

        # 3. SSL/TLS Certificate Inspection (Connecting directly to validated IP with SNI to prevent DNS rebinding)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            target_ip = resolved_ips[0]
            with socket.create_connection((target_ip, 443), timeout=2.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        result["ssl_info"]["has_ssl"] = True
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        result["ssl_info"]["issuer"] = issuer.get('organizationName', issuer.get('commonName', 'Unknown Issuer'))
                        result["ssl_info"]["grade"] = "Active TLS"
        except Exception:
            # Fallback if connection times out or port 443 closed
            result["ssl_info"]["has_ssl"] = False
            result["ssl_info"]["grade"] = "Unencrypted or Self-Signed"

        return result

infrastructure_analyzer = InfrastructureAnalyzer()
