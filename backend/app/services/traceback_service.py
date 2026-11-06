from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
from app.models import URLRecord, ScanResult, DetectionEvent, InfrastructureRecord, RedirectChain

class TracebackService:
    def get_investigation_dossier(self, url_id: str, db: Session) -> Optional[Dict[str, Any]]:
        """
        Compiles the complete forensic investigation dossier for a target URL or domain.
        Includes infrastructure tracking, detection velocity, observed server IPs, and XAI evidence.
        """
        url_record = db.query(URLRecord).filter(URLRecord.id == url_id).first()
        if not url_record:
            return None

        # Fetch latest scan result
        latest_scan = db.query(ScanResult).filter(
            ScanResult.url_id == url_id
        ).order_by(ScanResult.created_at.desc()).first()

        # Fetch detection events count & unique endpoints
        events = db.query(DetectionEvent).filter(DetectionEvent.url_id == url_id).all()
        detection_count = len(events)
        unique_device_ids = set([e.device_id for e in events])
        unique_devices_count = len(unique_device_ids)

        # Fetch Infrastructure record
        infra = db.query(InfrastructureRecord).filter(
            InfrastructureRecord.domain == url_record.domain
        ).first()

        infra_detail = None
        if infra:
            infra_detail = {
                "domain": infra.domain,
                "observed_ip": infra.observed_ip,
                "resolved_ips": infra.resolved_ips or [],
                "asn": infra.asn,
                "asn_org": infra.asn_org,
                "country": infra.country,
                "reverse_dns": infra.reverse_dns,
                "dns_records": infra.dns_records or {},
                "ssl_info": infra.ssl_info or {},
                "observed_at": infra.observed_at,
                "forensic_disclaimer": "IP address represents Observed Infrastructure and routing nodes, which may be a shared CDN or cloud provider, not confirmed threat actor identity."
            }

        # Recent detection events timeline
        recent_events = [
            {
                "id": e.id,
                "device_id": e.device_id,
                "risk_score": e.risk_score,
                "classification": e.classification,
                "detected_at": e.detected_at.isoformat(),
                "page_title": e.page_title,
                "referrer": e.referrer
            }
            for e in sorted(events, key=lambda x: x.detected_at, reverse=True)[:10]
        ]

        return {
            "id": url_record.id,
            "url": url_record.normalized_url,
            "domain": url_record.domain,
            "risk_score": url_record.current_risk_score,
            "classification": url_record.classification,
            "attack_types": latest_scan.attack_types if latest_scan else ["SUSPICIOUS_DOMAIN"],
            "first_seen": url_record.first_seen,
            "last_seen": url_record.last_seen,
            "detection_count": max(detection_count, 1),
            "unique_device_count": max(unique_devices_count, 1),
            "findings": latest_scan.findings if latest_scan else [],
            "xai_factors": latest_scan.xai_factors if latest_scan else [],
            "infrastructure": infra_detail,
            "threat_intelligence": latest_scan.threat_intel_data if latest_scan else {},
            "related_events": recent_events
        }

traceback_service = TracebackService()

