import os
import re
import hashlib
import zipfile
import io
from typing import Tuple
from fastapi import HTTPException, UploadFile
from app.core.config import settings

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".csv", ".xlsx"}
MAGIC_SIGNATURES = {
    b"%PDF": "PDF",
    b"PK\x03\x04": "ZIP_BASED",  # DOCX and XLSX are OpenXML zip containers
}

MAX_UNCOMPRESSED_ZIP_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_ZIP_ENTRIES = 1000
MAX_COMPRESSION_RATIO = 100.0

def sanitize_filename(filename: str) -> str:
    """
    Strips directory traversal sequences, control characters, and dangerous symbols from filenames.
    Prevents path traversal and shell injection when storing or displaying filenames.
    """
    if not filename:
        return "unnamed_upload"
    # Extract only the base name (prevents directory traversal e.g. ../../)
    base = os.path.basename(filename.strip().replace("\\", "/"))
    # Allow alphanumeric, periods, dashes, underscores
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', base)
    # Prevent hidden files (.htaccess) or multi-dot extensions (.exe.pdf)
    sanitized = sanitized.lstrip(".")
    if not sanitized:
        return "sanitized_upload"
    return sanitized[:128]

def validate_zip_safety(content: bytes):
    """
    Guards against zip decompression bombs, nested zip bombs, and path traversal in archives.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content), "r") as z:
            infolist = z.infolist()
            if len(infolist) > MAX_ZIP_ENTRIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Archive contains too many entries ({len(infolist)} > {MAX_ZIP_ENTRIES}). Rejected for safety."
                )

            total_uncompressed_size = 0
            compressed_size = max(1, len(content))

            for info in infolist:
                # Check for path traversal in zip entry names
                if ".." in info.filename or info.filename.startswith(("/", "\\")):
                    raise HTTPException(
                        status_code=400,
                        detail="Archive contains dangerous path traversal references in entry names."
                    )
                total_uncompressed_size += info.file_size

                if total_uncompressed_size > MAX_UNCOMPRESSED_ZIP_BYTES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Archive uncompressed size exceeds limit of {MAX_UNCOMPRESSED_ZIP_BYTES // (1024 * 1024)} MB (Zip Bomb protection)."
                    )

            ratio = total_uncompressed_size / compressed_size
            if ratio > MAX_COMPRESSION_RATIO and total_uncompressed_size > (5 * 1024 * 1024):
                raise HTTPException(
                    status_code=400,
                    detail=f"Archive compression ratio ({ratio:.1f}:1) exceeds safety threshold (Zip Bomb protection)."
                )
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Corrupted or malformed OpenXML/Zip container.")

def validate_uploaded_file(file: UploadFile, content: bytes) -> Tuple[str, str, int, str]:
    """
    Validates file extension, size, magic bytes, and archive safety.
    Sanitizes filename and computes SHA-256 hash.
    Never executes the file.
    Returns (file_type, sha256_hash, file_size, safe_filename).
    """
    raw_name = file.filename or "unknown"
    safe_name = sanitize_filename(raw_name)
    _, ext = os.path.splitext(safe_name.lower())

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed types: PDF, DOCX, CSV, XLSX"
        )

    file_size = len(content)
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if file_size > max_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB} MB"
        )

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty (0 bytes).")

    # Magic byte check for PDF
    if ext == ".pdf" and not content.startswith(b"%PDF"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file signature: Content does not match standard PDF header"
        )

    # Magic byte and zip bomb checks for DOCX/XLSX (ZIP header PK\x03\x04)
    if ext in [".docx", ".xlsx"]:
        if not content.startswith(b"PK\x03\x04"):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file signature: '{ext}' document lacks valid OpenXML container header"
            )
        validate_zip_safety(content)

    sha256_hash = hashlib.sha256(content).hexdigest()
    file_type = ext.replace(".", "").upper()

    return file_type, sha256_hash, file_size, safe_name
