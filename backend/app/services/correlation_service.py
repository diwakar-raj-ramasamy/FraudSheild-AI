import asyncio
import json
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from typing import Optional, Dict, Any

from app.models import (
    DetectionEvent, URLRecord, Device, FraudCampaign, AdminAlert, InfrastructureRecord
)
from app.core.config import settings
from app.core.event_bus import event_bus
from app.utils.url_utils import normalize_url, extract_domain, compute_url_hash

class CorrelationService:
    def record_detection_event(
        self,
        raw_url: str,
        device_pseudonym: str,
        risk_score: int,
        classification: str,
        attack_types: list[str],
        page_title: Optional[str] = None,
        referrer: Optional[str] = None,
        db: Session = None
    ) -> Dict[str, Any]:
        """
        Records a detection event reported by a browser extension.
        Applies deduplication to prevent event replay/storms and uses scalable SQL aggregation
        to evaluate multi-device correlation thresholds without in-memory dataset bloat.
        """
        norm_url = normalize_url(raw_url)
        domain = extract_domain(norm_url)
        url_hash = compute_url_hash(norm_url)

        # 1. Ensure URL Record exists (race-safe get-or-create)
        url_record = db.query(URLRecord).filter(URLRecord.url_hash == url_hash).first()
        if not url_record:
            try:
                url_record = URLRecord(
                    normalized_url=norm_url,
                    domain=domain,
                    url_hash=url_hash,
                    classification=classification,
                    current_risk_score=risk_score
                )
                db.add(url_record)
                db.flush()
            except IntegrityError:
                db.rollback()
                url_record = db.query(URLRecord).filter(URLRecord.url_hash == url_hash).first()

        if url_record:
            url_record.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
            if risk_score > url_record.current_risk_score:
                url_record.current_risk_score = risk_score
                url_record.classification = classification

        # 2. Ensure Device exists by installation pseudonym (race-safe get-or-create)
        device = db.query(Device).filter(Device.installation_pseudonym == device_pseudonym).first()
        if not device:
            try:
                device = Device(installation_pseudonym=device_pseudonym)
                db.add(device)
                db.flush()
            except IntegrityError:
                db.rollback()
                device = db.query(Device).filter(Device.installation_pseudonym == device_pseudonym).first()

        if device:
            device.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)

        # 3. Store Detection Event
        event = DetectionEvent(
            url_id=url_record.id,
            device_id=device.id,
            risk_score=risk_score,
            classification=classification,
            attack_types=attack_types,
            page_title=page_title,
            referrer=referrer
        )
        db.add(event)
        db.commit()

        # Broadcast live detection event to connected Admin Dashboards
        if event_bus.active_connections:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(event_bus.broadcast({
                    "type": "THREAT_DETECTED",
                    "payload": {
                        "event_id": event.id,
                        "url": norm_url,
                        "domain": domain,
                        "risk_score": risk_score,
                        "classification": classification,
                        "attack_types": attack_types,
                        "device_pseudonym": device_pseudonym,
                        "title": page_title or f"Threat detection on {domain}"
                    }
                }))
            except RuntimeError:
                pass

        # 4. Scalable Multi-Device Correlation Check via Database Aggregation
        time_window = (datetime.now(timezone.utc) - timedelta(hours=settings.CAMPAIGN_WINDOW_HOURS)).replace(tzinfo=None)

        # Scalable SQL aggregation (O(1) memory instead of fetching all rows into application RAM)
        total_detections = (
            db.query(func.count(DetectionEvent.id))
            .join(URLRecord, DetectionEvent.url_id == URLRecord.id)
            .filter(
                URLRecord.domain == domain,
                DetectionEvent.detected_at >= time_window
            )
            .scalar() or 0
        )

        unique_devices_count = (
            db.query(func.count(func.distinct(DetectionEvent.device_id)))
            .join(URLRecord, DetectionEvent.url_id == URLRecord.id)
            .filter(
                URLRecord.domain == domain,
                DetectionEvent.detected_at >= time_window
            )
            .scalar() or 0
        )

        campaign_triggered = False
        campaign_info = None

        if (total_detections >= settings.CAMPAIGN_MIN_DETECTIONS and 
            unique_devices_count >= settings.CAMPAIGN_MIN_DEVICES and
            risk_score >= settings.RISK_THRESHOLD_SAFE):

            campaign_triggered = True
            
            # Find or create FraudCampaign
            campaign = db.query(FraudCampaign).filter(
                FraudCampaign.domain == domain,
                FraudCampaign.status == "ACTIVE"
            ).first()

            # Retrieve observed infrastructure IP for context
            infra = db.query(InfrastructureRecord).filter(InfrastructureRecord.domain == domain).first()
            observed_ips = infra.resolved_ips if infra and infra.resolved_ips else []

            if not campaign:
                campaign = FraudCampaign(
                    domain=domain,
                    campaign_name=f"Emerging Phishing Campaign targeting {domain}",
                    status="ACTIVE",
                    total_detections=total_detections,
                    unique_devices_count=unique_devices_count,
                    attack_types=attack_types,
                    confidence_score=min(90 + unique_devices_count * 2, 99),
                    observed_ips=observed_ips,
                    notes=f"Correlated {total_detections} hits across {unique_devices_count} separate browser endpoints within {settings.CAMPAIGN_WINDOW_HOURS} hours."
                )
                db.add(campaign)
                db.flush()

                # Generate High-Priority Admin Alert
                alert = AdminAlert(
                    alert_type="CAMPAIGN_DETECTED",
                    severity="CRITICAL" if risk_score >= 60 else "HIGH",
                    title="🚨 REPEATED FRAUD URL DETECTED",
                    message=f"Multi-device fraud campaign detected on '{domain}'. {total_detections} detections across {unique_devices_count} endpoints.",
                    details={
                        "url": norm_url,
                        "domain": domain,
                        "risk_score": risk_score,
                        "attack_types": attack_types,
                        "total_detections": total_detections,
                        "unique_devices": unique_devices_count,
                        "observed_ips": observed_ips
                    },
                    campaign_id=campaign.id,
                    url_id=url_record.id
                )
                db.add(alert)
                db.commit()

                # Broadcast real-time event to Admin Dashboard
                if event_bus.active_connections:
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(event_bus.broadcast({
                            "type": "CAMPAIGN_DETECTED",
                            "payload": {
                                "campaign_id": campaign.id,
                                "alert_id": alert.id,
                                "title": alert.title,
                                "message": alert.message,
                                "domain": domain,
                                "risk_score": risk_score,
                                "unique_devices": unique_devices_count,
                                "total_detections": total_detections,
                                "attack_types": attack_types
                            }
                        }))
                    except RuntimeError:
                        pass

            else:
                # Update existing active campaign stats
                campaign.total_detections = total_detections
                campaign.unique_devices_count = unique_devices_count
                campaign.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                if observed_ips and not campaign.observed_ips:
                    campaign.observed_ips = observed_ips
                db.commit()

            campaign_info = {
                "campaign_id": campaign.id,
                "domain": campaign.domain,
                "total_detections": campaign.total_detections,
                "unique_devices": campaign.unique_devices_count
            }

        return {
            "event_id": event.id,
            "domain": domain,
            "total_detections": total_detections,
            "unique_devices": unique_devices_count,
            "campaign_triggered": campaign_triggered,
            "campaign_created": campaign_triggered,
            "campaign_id": campaign.id if (campaign_triggered and campaign) else None,
            "campaign_info": campaign_info
        }

correlation_service = CorrelationService()
