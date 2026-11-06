from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.core.security import require_admin
from app.core.rate_limiter import file_rate_limiter
from app.models import FileAnalysis
from app.schemas import FileAnalysisOut
from app.file_analysis.file_validator import validate_uploaded_file
from app.file_analysis.pdf_analyzer import pdf_analyzer
from app.file_analysis.docx_analyzer import docx_analyzer
from app.file_analysis.csv_analyzer import csv_analyzer
from app.file_analysis.xlsx_analyzer import xlsx_analyzer
from app.file_analysis.file_scoring import file_scoring_engine

router = APIRouter(prefix="/files", tags=["Digital File Forensics"])

@router.post("/analyze", response_model=FileAnalysisOut, dependencies=[Depends(file_rate_limiter)])
async def analyze_file(
    file: UploadFile = File(...),
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    FraudShield AI File Analysis & Forensics Center:
    Safely inspects PDF, DOCX, CSV, and XLSX files.
    Extracts metadata, IOCs, hyperlinks, domains, IPs, and suspicious execution patterns.
    Computes SHA-256 hash and provides a transparent XAI risk score.
    Strict Axiom: NEVER executes active content, macros, or scripts.
    Hardened against Zip Bombs, path traversal filenames, and unauthorized uploads.
    """
    content = await file.read()
    file_type, sha256_hash, file_size, safe_filename = validate_uploaded_file(file, content)

    # Route to appropriate safe static parser
    if file_type == "PDF":
        raw_result = pdf_analyzer.analyze(content, safe_filename)
    elif file_type == "DOCX":
        raw_result = docx_analyzer.analyze(content, safe_filename)
    elif file_type == "CSV":
        raw_result = csv_analyzer.analyze(content, safe_filename)
    elif file_type == "XLSX":
        raw_result = xlsx_analyzer.analyze(content, safe_filename)
    else:
        raise HTTPException(status_code=400, detail="Unsupported file format")

    # Score analysis and generate XAI factors
    scored = file_scoring_engine.score_analysis(raw_result, file_type)
    iocs = raw_result.get("iocs", {})

    # Save forensic record
    record = FileAnalysis(
        file_name=safe_filename,
        file_type=file_type,
        file_size=file_size,
        sha256=sha256_hash,
        risk_score=scored["risk_score"],
        classification=scored["classification"],
        metadata_extracted=raw_result.get("metadata", {}),
        indicators_found=raw_result.get("structural_indicators", []),
        extracted_urls=iocs.get("urls", []),
        extracted_domains=iocs.get("domains", []),
        extracted_ips=iocs.get("ips", []),
        extracted_emails=iocs.get("emails", []),
        xai_factors=[x.model_dump() for x in scored["xai_factors"]]
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return record

@router.get("/analyses", response_model=List[FileAnalysisOut])
def list_file_analyses(
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    return db.query(FileAnalysis).order_by(FileAnalysis.created_at.desc()).limit(50).all()

@router.get("/analyses/{id}", response_model=FileAnalysisOut)
def get_file_analysis(
    id: str,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    rec = db.query(FileAnalysis).filter(FileAnalysis.id == id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="File analysis record not found")
    return rec
