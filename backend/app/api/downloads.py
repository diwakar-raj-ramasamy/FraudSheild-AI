from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime, timezone
from app.core.database import get_db
from app.core.security import require_admin
from app.models import DangerousDownload, Device
from app.schemas import DangerousDownloadCreate, DangerousDownloadOut
from app.engines.download_analyzer import download_analyzer
from app.utils.url_utils import extract_domain

router = APIRouter(prefix="/downloads", tags=["Download Protection"])

@router.post("/check", response_model=DangerousDownloadOut)
def check_download(req: DangerousDownloadCreate, db: Session = Depends(get_db)):
    """
    Evaluates download metadata for extension disguise, risky payloads, and MIME mismatch.
    """
    analysis = download_analyzer.analyze(
        filename=req.file_name,
        mime_type=req.mime_type or "",
        download_url=req.download_url
    )

    device_id = None
    if req.device_pseudonym:
        dev = db.query(Device).filter(Device.installation_pseudonym == req.device_pseudonym).first()
        if dev:
            device_id = dev.id

    file_ext = req.file_extension
    if not file_ext:
        parts = req.file_name.rsplit(".", 1)
        file_ext = f".{parts[1]}" if len(parts) > 1 else ""

    src_domain = req.source_domain or extract_domain(req.download_url)

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    download_rec = DangerousDownload(
        file_name=req.file_name,
        file_extension=file_ext,
        mime_type=req.mime_type,
        file_hash=req.file_hash,
        download_url=req.download_url,
        source_domain=src_domain,
        risk_score=analysis["risk_score"],
        reasons=analysis["reasons"],
        device_id=device_id,
        detected_at=now
    )

    if analysis["is_dangerous"]:
        db.add(download_rec)
        db.commit()
        db.refresh(download_rec)

    return DangerousDownloadOut(
        id=download_rec.id or "temp-id",
        file_name=req.file_name,
        file_extension=file_ext,
        mime_type=req.mime_type,
        file_hash=req.file_hash,
        download_url=req.download_url,
        source_domain=src_domain,
        risk_score=analysis["risk_score"],
        reasons=analysis["reasons"],
        detected_at=download_rec.detected_at or now
    )

@router.get("", response_model=List[DangerousDownloadOut])
def list_dangerous_downloads(
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    return db.query(DangerousDownload).order_by(DangerousDownload.detected_at.desc()).limit(50).all()
