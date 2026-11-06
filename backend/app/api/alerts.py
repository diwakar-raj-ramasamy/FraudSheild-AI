from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.core.security import require_admin
from app.models import AdminAlert
from app.schemas import AlertOut, AlertUpdate

router = APIRouter(prefix="/alerts", tags=["Admin Alerts"])

@router.get("", response_model=List[AlertOut])
def get_alerts(
    unread_only: bool = False,
    limit: int = Query(50, le=100),
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    query = db.query(AdminAlert)
    if unread_only:
        query = query.filter(AdminAlert.is_read == False)
    return query.order_by(AdminAlert.created_at.desc()).limit(limit).all()

@router.patch("/{id}", response_model=AlertOut)
def update_alert(
    id: str,
    req: AlertUpdate,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    alert = db.query(AdminAlert).filter(AdminAlert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if req.is_read is not None:
        alert.is_read = req.is_read
    if req.is_resolved is not None:
        alert.is_resolved = req.is_resolved

    db.commit()
    db.refresh(alert)
    return alert
