import pymupdf as fitz
from typing import Dict, Any
from app.file_analysis.indicator_extractor import extract_indicators_from_text

class PDFAnalyzer:
    def analyze(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Safely parses PDF documents using PyMuPDF and static object inspection.
        Never executes any embedded JavaScript, actions, or stream payloads.
        """
        metadata = {}
        page_count = 0
        extracted_text = []
        pdf_indicators = []

        try:
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            page_count = len(doc)
            doc_meta = doc.metadata or {}
            
            metadata = {
                "author": doc_meta.get("author", "N/A"),
                "creator": doc_meta.get("creator", "N/A"),
                "producer": doc_meta.get("producer", "N/A"),
                "creation_date": doc_meta.get("creationDate", "N/A"),
                "mod_date": doc_meta.get("modDate", "N/A"),
                "page_count": page_count,
                "is_encrypted": doc.is_encrypted
            }

            # Extract plain text safely
            for page_idx in range(min(page_count, 100)):
                page = doc[page_idx]
                extracted_text.append(page.get_text())

            doc.close()
        except Exception as e:
            metadata["parse_error"] = str(e)

        full_text = "\n".join(extracted_text)

        # Comprehensive signature scan across entire raw PDF bytes for risky structural objects
        if b"/JavaScript" in file_bytes or b"/JS" in file_bytes:
            pdf_indicators.append({
                "type": "EMBEDDED_JAVASCRIPT",
                "severity": "HIGH",
                "description": "PDF contains embedded /JavaScript or /JS object stream"
            })
        if b"/Launch" in file_bytes:
            pdf_indicators.append({
                "type": "LAUNCH_ACTION",
                "severity": "CRITICAL",
                "description": "PDF contains /Launch action which attempts to execute external system processes"
            })
        if b"/EmbeddedFiles" in file_bytes:
            pdf_indicators.append({
                "type": "EMBEDDED_FILES",
                "severity": "MEDIUM",
                "description": "PDF contains embedded binary attachments or secondary files"
            })
        if b"/OpenAction" in file_bytes or b"/AA" in file_bytes:
            pdf_indicators.append({
                "type": "AUTO_OPEN_ACTION",
                "severity": "MEDIUM",
                "description": "PDF specifies an automatic execution /OpenAction upon document view"
            })

        iocs = extract_indicators_from_text(full_text)

        return {
            "metadata": metadata,
            "structural_indicators": pdf_indicators,
            "iocs": iocs,
            "text_sample": full_text[:500]
        }

pdf_analyzer = PDFAnalyzer()

