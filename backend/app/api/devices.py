import re
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, field_validator, ConfigDict
from app.core.database import get_db
from app.core.security import require_admin
from app.models import Device

router = APIRouter(prefix="/devices", tags=["Protected Endpoints"])

class DeviceRegisterRequest(BaseModel):
    installation_pseudonym: str
    extension_version: Optional[str] = "1.0.0"
    user_agent: Optional[str] = None

    @field_validator("installation_pseudonym")
    @classmethod
    def validate_pseudonym(cls, v: str) -> str:
        clean = v.strip()
        if not (8 <= len(clean) <= 64):
            raise ValueError("installation_pseudonym must be between 8 and 64 characters")
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean):
            raise ValueError("installation_pseudonym contains invalid characters")
        return clean

class DeviceOut(BaseModel):
    id: str
    installation_pseudonym: str
    extension_version: str
    user_agent: Optional[str]
    created_at: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)

@router.post("/register", response_model=DeviceOut)
def register_device(req: DeviceRegisterRequest, db: Session = Depends(get_db)):
    """
    Registers or updates a privacy-conscious browser extension pseudonym.
    Strict Privacy Rule: Uses randomly generated UUIDs; never collects MAC address or hardware serials.
    """
    device = db.query(Device).filter(
        Device.installation_pseudonym == req.installation_pseudonym
    ).first()

    if not device:
        device = Device(
            installation_pseudonym=req.installation_pseudonym,
            extension_version=req.extension_version or "1.0.0",
            user_agent=req.user_agent
        )
        db.add(device)
    else:
        device.last_seen = datetime.now(timezone.utc)
        if req.extension_version:
            device.extension_version = req.extension_version
        if req.user_agent:
            device.user_agent = req.user_agent

    db.commit()
    db.refresh(device)
    return device

@router.get("", response_model=List[DeviceOut])
def list_devices(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    return db.query(Device).order_by(Device.last_seen.desc()).offset(skip).limit(limit).all()
