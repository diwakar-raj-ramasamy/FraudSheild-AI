import io
import zipfile
import openpyxl
from typing import Dict, Any
from app.file_analysis.indicator_extractor import extract_indicators_from_text

class XLSXAnalyzer:
    def analyze(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Parses XLSX workbooks statically without executing macros or dynamic formulas.
        Extracts sheet structures, formulas as raw text, detects external links and guards against XXE.
        """
        metadata = {}
        xlsx_indicators = []
        cell_strings = []
        has_xxe = False

        # 1. Inspect OpenXML container for macro files and XXE payloads
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as z:
                names = z.namelist()
                if any("vbaProject.bin" in n for n in names):
                    xlsx_indicators.append({
                        "type": "DISGUISED_XL_MACRO",
                        "severity": "CRITICAL",
                        "description": "Workbook contains vbaProject.bin macro binary despite .xlsx file extension"
                    })
                # Check external links and XXE
                for n in names:
                    if n.endswith((".xml", ".rels")):
                        try:
                            raw_xml = z.read(n)
                            if b"<!ENTITY" in raw_xml or b"<!DOCTYPE" in raw_xml:
                                has_xxe = True
                                xlsx_indicators.append({
                                    "type": "XXE_INJECTION_INDICATOR",
                                    "severity": "CRITICAL",
                                    "description": f"Dangerous XML External Entity (XXE) or DTD declaration detected in '{n}'"
                                })
                        except Exception:
                            pass

                external_links = [n for n in names if "externalLink" in n]
                if external_links:
                    xlsx_indicators.append({
                        "type": "EXTERNAL_WORKBOOK_LINKS",
                        "severity": "MEDIUM",
                        "description": f"Workbook contains {len(external_links)} external workbook link definitions"
                    })
        except Exception as e:
            metadata["container_error"] = str(e)

        # 2. Parse workbook with openpyxl in read_only mode if not compromised by XXE
        if not has_xxe:
            try:
                wb = openpyxl.load_workbook(filename=io.BytesIO(file_bytes), read_only=True, data_only=False)
                metadata["sheet_names"] = wb.sheetnames
                
                total_rows = 0
                formula_injection_count = 0

                for sheet_name in wb.sheetnames[:5]:  # scan first 5 sheets
                    sheet = wb[sheet_name]
                    for r_idx, row in enumerate(sheet.iter_rows(values_only=True)):
                        if r_idx > 500:
                            break
                        total_rows += 1
                        for cell in row:
                            if cell is not None:
                                val_str = str(cell).strip()
                                cell_strings.append(val_str)
                                
                                # Formula injection check
                                if val_str.startswith(('=', '+', '-', '@')):
                                    lower_val = val_str.lower()
                                    if any(x in lower_val for x in ["cmd", "powershell", "dde", "calc", "mshta", "rundll32", "hyperlink", "importxml", "webservice", "certutil", "wscript", "cscript"]):
                                        formula_injection_count += 1
                                        xlsx_indicators.append({
                                            "type": "DANGEROUS_FORMULA_INJECTION",
                                            "severity": "CRITICAL",
                                            "description": f"High-risk executable command or exfiltration formula in cell: {val_str[:100]}"
                                        })

                metadata["total_scanned_rows"] = total_rows
                metadata["suspicious_formulas_detected"] = formula_injection_count
            except Exception as e:
                metadata["parse_error"] = str(e)

        full_text = " ".join(cell_strings)
        indicators = extract_indicators_from_text(full_text)

        return {
            "metadata": metadata,
            "indicators": indicators,
            "xlsx_indicators": xlsx_indicators,
            "text_sample": full_text[:500] if full_text else ""
        }

xlsx_analyzer = XLSXAnalyzer()
