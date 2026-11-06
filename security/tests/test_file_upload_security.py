import io
import zipfile
import pytest
from app.file_analysis.file_validator import sanitize_filename, validate_zip_safety, validate_uploaded_file
from fastapi import HTTPException

def test_filename_sanitization_guards_path_traversal():
    traversal_cases = [
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
        ("folder/subfolder/document.pdf", "document.pdf"),
        ("malicious\x00file.docx", "malicious_file.docx"),
        ("path/to/evil;rm.pdf", "evil_rm.pdf"),
        ("../../../boot.ini", "boot.ini")
    ]
    for raw, expected_substr in traversal_cases:
        sanitized = sanitize_filename(raw)
        assert ".." not in sanitized
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert expected_substr in sanitized

def test_unsupported_file_extension_rejected(client, admin_headers):
    # Uploading dangerous executable disguised as .exe
    fake_exe = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00binarycontent")
    res = client.post(
        "/api/files/analyze",
        files={"file": ("malware.exe", fake_exe, "application/octet-stream")},
        headers=admin_headers
    )
    assert res.status_code == 400
    assert "Unsupported file type" in res.json()["detail"]

def test_invalid_pdf_magic_bytes_rejected(client, admin_headers):
    # Plain text file disguised with .pdf extension
    fake_pdf = io.BytesIO(b"This is just plain text, not a valid PDF file.")
    res = client.post(
        "/api/files/analyze",
        files={"file": ("fake.pdf", fake_pdf, "application/pdf")},
        headers=admin_headers
    )
    assert res.status_code == 400
    assert "standard PDF header" in res.json()["detail"]

def test_invalid_docx_magic_bytes_rejected(client, admin_headers):
    # Plain text disguised with .docx extension
    fake_docx = io.BytesIO(b"Not a zip or openxml container.")
    res = client.post(
        "/api/files/analyze",
        files={"file": ("fake.docx", fake_docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
        headers=admin_headers
    )
    assert res.status_code == 400
    assert "OpenXML container header" in res.json()["detail"]

def test_empty_file_rejected(client, admin_headers):
    empty_file = io.BytesIO(b"")
    res = client.post(
        "/api/files/analyze",
        files={"file": ("empty.pdf", empty_file, "application/pdf")},
        headers=admin_headers
    )
    assert res.status_code == 400

def test_zip_bomb_excessive_entries_rejected():
    # Construct in-memory zip archive with > 1000 entries
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        for i in range(1005):
            z.writestr(f"entry_{i}.txt", b"x")
    zip_data = zip_buf.getvalue()

    with pytest.raises(HTTPException) as exc:
        validate_zip_safety(zip_data)
    assert exc.value.status_code == 400
    assert "too many entries" in exc.value.detail

def test_zip_path_traversal_entry_rejected():
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("../../dangerous_overwrite.bin", b"evil payload")
    zip_data = zip_buf.getvalue()

    with pytest.raises(HTTPException) as exc:
        validate_zip_safety(zip_data)
    assert exc.value.status_code == 400
    assert "path traversal references" in exc.value.detail
