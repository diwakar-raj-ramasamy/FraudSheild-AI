import io
import pandas as pd
from typing import Dict, Any
from app.file_analysis.indicator_extractor import extract_indicators_from_text

class CSVAnalyzer:
    def analyze(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """
        Parses CSV files in safe static mode.
        Detects CSV formula injection (DDE / Command execution attacks).
        """
        metadata = {}
        csv_indicators = []
        raw_text_chunks = []

        try:
            # Decode text
            text_data = file_bytes.decode("utf-8", errors="replace")
            raw_text_chunks.append(text_data)
            
            # Read into pandas safely with chunked evaluation
            df = pd.read_csv(io.StringIO(text_data), nrows=1000)
            metadata = {
                "row_count": len(df),
                "column_count": len(df.columns),
                "columns": [str(c) for c in df.columns[:25]],
                "sample_preview": df.head(5).to_dict(orient="records")
            }

            # Formula injection check: cells beginning with =, +, -, @, or |
            suspicious_formula_cells = 0
            DANGEROUS_FORMULA_TOKENS = [
                "cmd", "powershell", "dde", "calc", "rundll32", "mshta",
                "hyperlink", "importxml", "webservice", "certutil", "wscript", "cscript"
            ]
            for col in df.columns:
                series = df[col].astype(str)
                for val in series:
                    val_clean = val.strip()
                    if val_clean.startswith(('=', '+', '-', '@', '|')):
                        if any(cmd in val_clean.lower() for cmd in DANGEROUS_FORMULA_TOKENS):
                            suspicious_formula_cells += 1
                            if len(csv_indicators) < 5:
                                csv_indicators.append({
                                    "type": "CSV_FORMULA_INJECTION",
                                    "severity": "CRITICAL",
                                    "description": f"Dangerous formula injection payload found in column '{col}': {val_clean[:60]}"
                                })

            if suspicious_formula_cells > 0:
                metadata["suspicious_formula_cells_total"] = suspicious_formula_cells

        except Exception as e:
            metadata["parse_error"] = str(e)
            text_data = file_bytes.decode("latin-1", errors="ignore")
            raw_text_chunks.append(text_data)

        full_text = "\n".join(raw_text_chunks)
        iocs = extract_indicators_from_text(full_text)

        return {
            "metadata": metadata,
            "structural_indicators": csv_indicators,
            "iocs": iocs,
            "text_sample": full_text[:500]
        }

csv_analyzer = CSVAnalyzer()

