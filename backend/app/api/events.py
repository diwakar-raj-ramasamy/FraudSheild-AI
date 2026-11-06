from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session, joinedload
from typing import List, Optional
from app.core.database import get_db
from app.core.security import get_current_user_payload
from app.schemas import DetectionEventCreate, DetectionEventOut
from app.models import DetectionEvent, URLRecord, Device
from app.services.correlation_service import correlation_service

router = APIRouter(prefix="/events", tags=["Detection Events"])

@router.post("/detection")
async def report_detection(req: DetectionEventCreate, db: Session = Depends(get_db)):
    """
    Called by browser extensions when a threat or high-risk activity is detected.
    Records privacy-conscious event and triggers multi-device campaign correlation.
    """
    res = correlation_service.record_detection_event(
        raw_url=req.url,
        device_pseudonym=req.device_pseudonym,
        risk_score=req.risk_score,
        classification=req.classification,
        attack_types=req.attack_types,
        page_title=req.page_title,
        referrer=req.referrer,
        db=db
    )
    return {
        "status": "success",
        "id": res["event_id"],
        "event_id": res["event_id"],
        "campaign_triggered": res["campaign_triggered"],
        "campaign_info": res.get("campaign_info")
    }

@router.get("", response_model=List[DetectionEventOut])
def get_detection_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=100),
    user: dict = Depends(get_current_user_payload),
    db: Session = Depends(get_db)
):
    """
    Retrieves recent detection events across all connected browser endpoints.
    Eliminates N+1 queries by eager-loading related device and URL records via joinedload.
    """
    events = (
        db.query(DetectionEvent)
        .options(joinedload(DetectionEvent.device), joinedload(DetectionEvent.url_record))
        .order_by(DetectionEvent.detected_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [
        DetectionEventOut(
            id=e.id,
            url_id=e.url_id,
            device_id=e.device_id,
            risk_score=e.risk_score,
            classification=e.classification,
            attack_types=e.attack_types or [],
            page_title=e.page_title,
            detected_at=e.detected_at,
            device_pseudonym=e.device.installation_pseudonym if e.device else "anonymous-endpoint",
            domain=e.url_record.domain if e.url_record else None,
            url=e.url_record.normalized_url if e.url_record else None
        )
        for e in events
    ]
