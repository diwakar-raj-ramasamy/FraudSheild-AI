import io
import zipfile
import docx
from typing import Dict, Any
from app.file_analysis.indicator_extractor import extract_indicators_from_text

class DOCXAnalyzer:
    def analyze(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Safely extracts text, relationships, and metadata from OpenXML DOCX files.
        Never executes any embedded macros, templates, or external scripts.
        Guarded against XXE and malicious OpenXML structures.
        """
        metadata = {}
        extracted_text = []
        docx_indicators = []
        hyperlinks = []
        has_xxe = False

        # 1. Structural inspection via ZipFile container
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as z:
                namelist = z.namelist()
                
                # Check for disguised VBA macros
                if any("vbaProject.bin" in n for n in namelist):
                    docx_indicators.append({
                        "type": "EMBEDDED_VBA_MACRO",
                        "severity": "CRITICAL",
                        "description": "Document contains vbaProject.bin executable macro storage within DOCX archive"
                    })

                # Check external relationships (template injection vector) and XXE entities
                for n in namelist:
                    if n.endswith((".rels", ".xml")):
                        try:
                            raw_xml = z.read(n)
                            # XXE entity / external DTD injection defense
                            if b"<!ENTITY" in raw_xml or b"<!DOCTYPE" in raw_xml:
                                has_xxe = True
                                docx_indicators.append({
                                    "type": "XXE_INJECTION_INDICATOR",
                                    "severity": "CRITICAL",
                                    "description": f"Dangerous XML External Entity (XXE) or DTD declaration detected in '{n}'"
                                })
                            
                            content = raw_xml.decode("utf-8", errors="ignore")
                            if 'TargetMode="External"' in content:
                                docx_indicators.append({
                                    "type": "EXTERNAL_RELATIONSHIP",
                                    "severity": "HIGH",
                                    "description": f"Document references external remote template or resource in '{n}'"
                                })
                        except Exception:
                            pass
        except Exception as e:
            metadata["zip_error"] = str(e)

        # 2. Extract content & core metadata via python-docx if not compromised by XXE
        if not has_xxe:
            try:
                doc = docx.Document(io.BytesIO(file_bytes))
                core = doc.core_properties
                metadata = {
                    "author": core.author or "N/A",
                    "last_modified_by": core.last_modified_by or "N/A",
                    "created": str(core.created) if core.created else "N/A",
                    "modified": str(core.modified) if core.modified else "N/A",
                    "revision": core.revision or 1,
                    "title": core.title or "N/A"
                }

                for p in doc.paragraphs:
                    if p.text.strip():
                        extracted_text.append(p.text.strip())

                # Extract Hyperlinks from document part relationships
                for rel in doc.part.rels.values():
                    if "hyperlink" in rel.reltype.lower():
                        target = rel.target_ref
                        if target:
                            hyperlinks.append(target)
            except Exception as e:
                metadata["docx_read_error"] = str(e)

        full_text = " ".join(extracted_text)
        indicators = extract_indicators_from_text(full_text)

        # Merge extracted hyperlinks into indicators
        for hl in hyperlinks:
            if hl.startswith(("http://", "https://")):
                indicators["urls"].append(hl)

        indicators["urls"] = list(set(indicators["urls"]))

        return {
            "metadata": metadata,
            "indicators": indicators,
            "docx_indicators": docx_indicators,
            "text_sample": full_text[:500] if full_text else ""
        }

docx_analyzer = DOCXAnalyzer()
