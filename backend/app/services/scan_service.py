import logging
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.utils.url_utils import normalize_url, extract_domain, compute_url_hash
from app.models import URLRecord, ScanResult, BlocklistEntry, Device, InfrastructureRecord
from app.schemas import ScanRequest, ScanResponse
from app.core.event_bus import event_bus
from app.engines.malicious_url_detector import malicious_url_detector
from app.engines.typosquatting_detector import typosquatting_detector
from app.engines.fake_login_detector import fake_login_detector
from app.engines.financial_scam_detector import financial_scam_detector
from app.engines.xss_indicator_detector import xss_indicator_detector
from app.engines.redirect_analyzer import redirect_analyzer
from app.engines.infrastructure_analyzer import infrastructure_analyzer
from app.engines.threat_intelligence import threat_intelligence_aggregator
from app.engines.scoring_engine import scoring_engine
from app.ml.model import ml_threat_classifier

logger = logging.getLogger("fraudshield.scan_service")

class ScanService:
    async def perform_scan(self, req: ScanRequest, db: Session) -> ScanResponse:
        """
        Executes hybrid threat scanning with complete fault isolation across detection engines.
        An error in an individual detector is safely contained and will not crash the scan pipeline.
        """
        raw_url = req.url
        norm_url = normalize_url(raw_url)
        domain = extract_domain(norm_url)
        url_hash = compute_url_hash(norm_url)

        # 1. Check Centralized Threat Blocklist
        is_blocklist_hit = False
        blocklist_reason = ""
        try:
            block_entry = db.query(BlocklistEntry).filter(
                (BlocklistEntry.target == domain) | (BlocklistEntry.target == norm_url),
                BlocklistEntry.is_active == True
            ).first()
            if block_entry:
                is_blocklist_hit = True
                blocklist_reason = block_entry.reason
        except Exception as ex:
            logger.error(f"Error querying blocklist: {ex}")

        # 2. Fault-Isolated Modular Engine Execution
        try:
            url_analysis = malicious_url_detector.analyze(norm_url)
        except Exception as ex:
            logger.warning(f"malicious_url_detector error: {ex}")
            url_analysis = {"is_suspicious": False, "score": 0, "findings": []}

        try:
            typo_analysis = typosquatting_detector.analyze(domain)
        except Exception as ex:
            logger.warning(f"typosquatting_detector error: {ex}")
            typo_analysis = {"is_typosquat": False, "score": 0}

        try:
            fake_login_analysis = fake_login_detector.analyze(
                current_url=norm_url,
                dom_signals=req.dom_signals or {},
                page_title=req.page_title or ""
            )
        except Exception as ex:
            logger.warning(f"fake_login_detector error: {ex}")
            fake_login_analysis = {"is_fake_login": False, "evidence": []}

        try:
            financial_analysis = financial_scam_detector.analyze(
                text_content=(req.page_title or "") + " " + str(req.dom_signals or {}),
                url=norm_url
            )
        except Exception as ex:
            logger.warning(f"financial_scam_detector error: {ex}")
            financial_analysis = {"is_financial_scam": False, "evidence": []}

        try:
            xss_analysis = xss_indicator_detector.analyze(
                url=norm_url,
                dom_signals=req.dom_signals or {}
            )
        except Exception as ex:
            logger.warning(f"xss_indicator_detector error: {ex}")
            xss_analysis = {"has_xss": False, "evidence": []}

        try:
            redirect_hops = (req.dom_signals or {}).get("redirect_hops", [norm_url])
            redirect_analysis = redirect_analyzer.analyze_chain(redirect_hops)
        except Exception as ex:
            logger.warning(f"redirect_analyzer error: {ex}")
            redirect_analysis = {"is_suspicious": False, "hops_count": 1}

        # 3. Infrastructure Analysis with SSRF Egress Filtering
        try:
            infra_data = infrastructure_analyzer.analyze_domain(domain)
        except Exception as ex:
            logger.warning(f"infrastructure_analyzer error: {ex}")
            infra_data = {
                "observed_infrastructure_ip": None,
                "resolved_server_ips": [],
                "asn": None,
                "asn_organization": None,
                "error": str(ex)
            }

        # 4. Multi-Provider Threat Intelligence Check with Circuit Breakers
        try:
            threat_intel = await threat_intelligence_aggregator.check_all(norm_url)
        except Exception as ex:
            logger.error(f"threat_intelligence_aggregator error: {ex}")
            threat_intel = {
                "overall_match": False,
                "confidence": "low",
                "matched_providers": [],
                "providers_results": {}
            }

        # 5. Machine Learning Inference with Calibrated Fallback
        try:
            ml_prob, _ = ml_threat_classifier.predict_risk(norm_url)
        except Exception as ex:
            logger.warning(f"ML threat classifier error: {ex}")
            ml_prob = 0.1

        # 6. Aggregated Scoring & XAI Breakdown
        score_result = scoring_engine.calculate(
            url_analysis=url_analysis,
            typo_analysis=typo_analysis,
            fake_login_analysis=fake_login_analysis,
            financial_analysis=financial_analysis,
            xss_analysis=xss_analysis,
            redirect_analysis=redirect_analysis,
            infrastructure_analysis=infra_data,
            threat_intel=threat_intel,
            ml_prediction_score=ml_prob,
            is_blocklist_hit=is_blocklist_hit,
            blocklist_reason=blocklist_reason
        )

        # 7. Fault-Tolerant Persistence (Race-safe concurrent insertion)
        try:
            url_record = db.query(URLRecord).filter(URLRecord.url_hash == url_hash).first()
            if not url_record:
                try:
                    url_record = URLRecord(
                        normalized_url=norm_url,
                        domain=domain,
                        url_hash=url_hash,
                        classification=score_result["classification"],
                        current_risk_score=score_result["risk_score"]
                    )
                    db.add(url_record)
                    db.flush()
                except IntegrityError:
                    db.rollback()
                    url_record = db.query(URLRecord).filter(URLRecord.url_hash == url_hash).first()

            if url_record:
                url_record.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                url_record.classification = score_result["classification"]
                url_record.current_risk_score = score_result["risk_score"]

            device_id = None
            if req.device_pseudonym:
                device = db.query(Device).filter(Device.installation_pseudonym == req.device_pseudonym).first()
                if not device:
                    try:
                        device = Device(installation_pseudonym=req.device_pseudonym)
                        db.add(device)
                        db.flush()
                    except IntegrityError:
                        db.rollback()
                        device = db.query(Device).filter(Device.installation_pseudonym == req.device_pseudonym).first()
                if device:
                    device.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
                    device_id = device.id

            if url_record:
                scan_rec = ScanResult(
                    url_id=url_record.id,
                    device_id=device_id,
                    risk_score=score_result["risk_score"],
                    classification=score_result["classification"],
                    attack_types=score_result["attack_types"],
                    findings=[f.model_dump() for f in score_result["findings"]],
                    recommended_actions=[a.model_dump() for a in score_result["recommended_actions"]],
                    ml_score=ml_prob,
                    threat_intel_data=threat_intel,
                    xai_factors=[x.model_dump() for x in score_result["xai_factors"]]
                )
                db.add(scan_rec)

            existing_infra = db.query(InfrastructureRecord).filter(InfrastructureRecord.domain == domain).first()
            if not existing_infra:
                try:
                    new_infra = InfrastructureRecord(
                        domain=domain,
                        observed_ip=infra_data.get("observed_infrastructure_ip"),
                        resolved_ips=infra_data.get("resolved_server_ips", []),
                        asn=infra_data.get("asn"),
                        asn_org=infra_data.get("asn_organization"),
                        reverse_dns=infra_data.get("reverse_dns"),
                        dns_records=infra_data.get("dns_records", {}),
                        ssl_info=infra_data.get("ssl_info", {})
                    )
                    db.add(new_infra)
                    db.flush()
                except IntegrityError:
                    db.rollback()

            db.commit()

            # Real-time event bus broadcast for live dashboard telemetry
            if event_bus.active_connections:
                try:
                    loop = asyncio.get_running_loop()
                    event_payload = {
                        "type": "THREAT_DETECTED" if score_result["risk_score"] >= 25 else "SCAN_COMPLETED",
                        "payload": {
                            "url": norm_url,
                            "domain": domain,
                            "risk_score": score_result["risk_score"],
                            "classification": score_result["classification"],
                            "attack_types": score_result["attack_types"],
                            "title": req.page_title or f"Live Inspection of {domain}"
                        }
                    }
                    loop.create_task(event_bus.broadcast(event_payload))
                except Exception as b_ex:
                    logger.debug(f"Event bus broadcast deferred: {b_ex}")
        except Exception as ex:
            db.rollback()
            logger.error(f"Failed to persist scan result to database: {ex}", exc_info=True)

        return ScanResponse(
            url=raw_url,
            normalized_url=norm_url,
            domain=domain,
            risk_score=score_result["risk_score"],
            classification=score_result["classification"],
            attack_types=score_result["attack_types"],
            hard_override=score_result["hard_override"],
            override_reason=score_result["override_reason"],
            findings=score_result["findings"],
            xai_factors=score_result["xai_factors"],
            recommended_actions=score_result["recommended_actions"],
            threat_intelligence=threat_intel,
            ml_confidence=ml_prob,
            safe_exit_recommended=score_result["safe_exit_recommended"],
            observed_infrastructure=infra_data
        )

scan_service = ScanService()
