from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import get_current_user_payload
from app.services.traceback_service import traceback_service

router = APIRouter(prefix="/investigation", tags=["Attack Investigation"])

@router.get("/{id}")
def get_attack_investigation(
    id: str,
    user: dict = Depends(get_current_user_payload),
    db: Session = Depends(get_db)
):
    """
    Returns complete reverse-tracking forensic dossier:
    - URL, Domain, Risk Score, Classification
    - Observed Infrastructure IP Address (clearly delineated from attacker identity)
    - DNS A/AAAA records & Reverse DNS PTR
    - ASN & Network Provider Info
    - SSL/TLS Certificate details
    - Multi-device detection frequency & endpoint count
    - Timeline of detection events
    - Explainable AI feature contributions
    """
    dossier = traceback_service.get_investigation_dossier(id, db)
    if not dossier:
        raise HTTPException(status_code=404, detail="Investigation target not found")
    return dossier

