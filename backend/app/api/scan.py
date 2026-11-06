from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.rate_limiter import scan_rate_limiter
from app.schemas import ScanRequest, ScanResponse
from app.services.scan_service import scan_service

router = APIRouter(prefix="/scan", tags=["Threat Scanning"])

@router.post("/url", response_model=ScanResponse, dependencies=[Depends(scan_rate_limiter)])
async def scan_url(req: ScanRequest, db: Session = Depends(get_db)):
    """
    Primary real-time scan pipeline:
    Analyzes URL, domain similarity, fake credential forms, financial scam cues,
    redirect paths, XSS indicators, infrastructure records, threat intel feeds,
    and machine learning probabilities.
    Returns composite score (0-100), severity, XAI explanation, and safety actions.
    Rate limited to prevent denial-of-service and automated scanning abuse.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL field is required")
    return await scan_service.perform_scan(req, db)
