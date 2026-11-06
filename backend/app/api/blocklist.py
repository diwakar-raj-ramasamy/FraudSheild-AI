from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.security import require_admin
from app.models import BlocklistEntry, BlocklistMeta
from app.schemas import BlocklistCreate, BlocklistEntryOut, BlocklistVersionResponse

router = APIRouter(prefix="/blocklist", tags=["Centralized Threat Blocklist"])

@router.get("", response_model=List[BlocklistEntryOut])
def get_blocklist(
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    return db.query(BlocklistEntry).filter(BlocklistEntry.is_active == True).order_by(BlocklistEntry.created_at.desc()).all()

@router.post("", response_model=BlocklistEntryOut)
def add_blocklist_entry(
    req: BlocklistCreate,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    target_clean = req.target.strip().lower()
    
    # Check if entry already exists
    existing = db.query(BlocklistEntry).filter(
        BlocklistEntry.target == target_clean,
        BlocklistEntry.is_active == True
    ).first()
    if existing:
        return existing

    entry = BlocklistEntry(
        target=target_clean,
        target_type=req.target_type.upper(),
        reason=req.reason,
        severity=req.severity.upper(),
        added_by=admin.get("sub", "ADMIN")
    )
    db.add(entry)

    # Increment blocklist version
    meta = db.query(BlocklistMeta).first()
    if not meta:
        meta = BlocklistMeta(current_version=2)
        db.add(meta)
    else:
        meta.current_version += 1
        meta.last_updated = datetime.now(timezone.utc)

    db.commit()
    db.refresh(entry)
    return entry

@router.get("/version", response_model=BlocklistVersionResponse)
def get_blocklist_version(db: Session = Depends(get_db)):
    """
    Polled or checked by browser extensions to synchronize local threat cache.
    Returns current version number and all active block targets.
    """
    meta = db.query(BlocklistMeta).first()
    if not meta:
        meta = BlocklistMeta(current_version=1)
        db.add(meta)
        db.commit()

    active_entries = db.query(BlocklistEntry.target).filter(BlocklistEntry.is_active == True).all()
    targets = [e[0] for e in active_entries]

    return BlocklistVersionResponse(
        version=meta.current_version,
        last_updated=meta.last_updated,
        entries_count=len(targets),
        entries=targets
    )

@router.delete("/{id}")
def delete_blocklist_entry(
    id: str,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    entry = db.query(BlocklistEntry).filter(BlocklistEntry.id == id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Blocklist entry not found")

    entry.is_active = False
    
    # Increment version
    meta = db.query(BlocklistMeta).first()
    if meta:
        meta.current_version += 1
        meta.last_updated = datetime.now(timezone.utc)

    db.commit()
    return {"status": "success", "message": "Entry removed from blocklist", "new_version": meta.current_version if meta else 1}
