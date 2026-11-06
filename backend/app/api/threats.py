from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.database import get_db
from app.core.security import get_current_user_payload
from app.models import URLRecord, ScanResult
from app.services.safety_advisor import safety_advisor

router = APIRouter(prefix="/threats", tags=["Threat Management"])

@router.get("")
def list_threats(
    classification: Optional[str] = None,
    domain: Optional[str] = None,
    min_score: int = Query(0, ge=0, le=100),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=100),
    user: dict = Depends(get_current_user_payload),
    db: Session = Depends(get_db)
):
    query = db.query(URLRecord).filter(URLRecord.current_risk_score >= min_score)
    if classification:
        query = query.filter(URLRecord.classification == classification.upper())
    if domain:
        query = query.filter(URLRecord.domain.ilike(f"%{domain}%"))

    records = query.order_by(URLRecord.last_seen.desc()).offset(skip).limit(limit).all()
    if not records:
        return []

    # High-performance batch load: eliminates N+1 query pattern by fetching all scan results in 1 query
    url_ids = [r.id for r in records]
    scan_results = (
        db.query(ScanResult)
        .filter(ScanResult.url_id.in_(url_ids))
        .order_by(ScanResult.created_at.desc())
        .all()
    )
    latest_by_url = {}
    for sr in scan_results:
        if sr.url_id not in latest_by_url:
            latest_by_url[sr.url_id] = sr

    results = []
    for r in records:
        latest = latest_by_url.get(r.id)
        results.append({
            "id": r.id,
            "url": r.normalized_url,
            "domain": r.domain,
            "risk_score": r.current_risk_score,
            "classification": r.classification,
            "first_seen": r.first_seen,
            "last_seen": r.last_seen,
            "attack_types": latest.attack_types if latest else [],
            "xai_factors": latest.xai_factors if latest else []
        })
    return results

@router.get("/{id}")
def get_threat_detail(
    id: str,
    user: dict = Depends(get_current_user_payload),
    db: Session = Depends(get_db)
):
    record = db.query(URLRecord).filter(URLRecord.id == id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Threat record not found")

    latest_scan = (
        db.query(ScanResult)
        .filter(ScanResult.url_id == id)
        .order_by(ScanResult.created_at.desc())
        .first()
    )
    history = (
        db.query(ScanResult)
        .filter(ScanResult.url_id == id)
        .order_by(ScanResult.created_at.desc())
        .limit(10)
        .all()
    )

    safety_advice = safety_advisor.get_recommendations(
        risk_score=record.current_risk_score,
        classification=record.classification,
        attack_types=latest_scan.attack_types if latest_scan else []
    )

    return {
        "id": record.id,
        "url": record.normalized_url,
        "domain": record.domain,
        "current_risk_score": record.current_risk_score,
        "classification": record.classification,
        "first_seen": record.first_seen,
        "last_seen": record.last_seen,
        "latest_scan": latest_scan,
        "scan_history_count": len(history),
        "safety_advice": safety_advice
    }
