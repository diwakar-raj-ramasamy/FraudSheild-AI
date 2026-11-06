from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.security import require_admin
from app.models import FraudCampaign, BlocklistEntry, BlocklistMeta
from app.schemas import CampaignOut

router = APIRouter(prefix="/campaigns", tags=["Multi-Device Campaign Monitor"])

@router.get("", response_model=List[CampaignOut])
def get_campaigns(
    status: str = Query("ACTIVE"),
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    query = db.query(FraudCampaign)
    if status != "ALL":
        query = query.filter(FraudCampaign.status == status)
    return query.order_by(FraudCampaign.last_seen.desc()).offset(skip).limit(limit).all()

@router.get("/{id}", response_model=CampaignOut)
def get_campaign(
    id: str,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    camp = db.query(FraudCampaign).filter(FraudCampaign.id == id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return camp

@router.post("/{id}/block")
def block_campaign_infrastructure(
    id: str,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Mitigates campaign by adding the domain to the global verified blocklist and updating version."""
    camp = db.query(FraudCampaign).filter(FraudCampaign.id == id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Add domain to Blocklist if not present
    existing = db.query(BlocklistEntry).filter(
        BlocklistEntry.target == camp.domain,
        BlocklistEntry.is_active == True
    ).first()

    if not existing:
        entry = BlocklistEntry(
            target=camp.domain,
            target_type="DOMAIN",
            reason=f"Mitigated via Campaign Monitor: {camp.campaign_name}",
            severity="CRITICAL",
            added_by=admin.get("sub", "ADMIN_CAMPAIGN_MITIGATION")
        )
        db.add(entry)

    # Bump blocklist version
    meta = db.query(BlocklistMeta).first()
    if not meta:
        meta = BlocklistMeta(current_version=2)
        db.add(meta)
    else:
        meta.current_version += 1
        meta.last_updated = datetime.now(timezone.utc)

    camp.status = "MITIGATED"
    db.commit()

    return {
        "status": "success",
        "message": f"Campaign '{camp.campaign_name}' mitigated and '{camp.domain}' added to global blocklist.",
        "campaign_id": camp.id,
        "blocked_domain": camp.domain,
        "new_blocklist_version": meta.current_version
    }
