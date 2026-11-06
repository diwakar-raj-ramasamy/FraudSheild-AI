import React, { useEffect, useState, useRef } from "react";
import {
  FileSearch,
  UploadCloud,
  FileText,
  FileSpreadsheet,
  AlertOctagon,
  CheckCircle,
  Hash,
  Link,
  Server,
  Mail,
  ShieldAlert,
  ArrowRight
} from "lucide-react";
import { api } from "../services/api";
import { FileAnalysisItem } from "../types";
import { RiskBadge } from "../components/RiskBadge";
import { XAIExplanationCard } from "../components/XAIExplanationCard";

export const FileAnalysisCenter: React.FC = () => {
  const [analyses, setAnalyses] = useState<FileAnalysisItem[]>([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState<FileAnalysisItem | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadAnalyses();
  }, []);

  async function loadAnalyses() {
    try {
      const data = await api.getFileAnalyses();
      setAnalyses(data);
      if (data.length > 0 && !selectedAnalysis) {
        setSelectedAnalysis(data[0]);
      }
    } catch (err) {
      console.error("Failed to load file analyses:", err);
    }
  }

  async function handleFileUpload(file: File) {
    if (!file) return;
    setUploading(true);
    setUploadError(null);

    try {
      const report = await api.uploadFileForAnalysis(file);
      setAnalyses((prev) => [report, ...prev]);
      setSelectedAnalysis(report);
    } catch (err: any) {
      setUploadError(err.message || "Failed to analyze uploaded file");
    } finally {
      setUploading(false);
    }
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-emerald-400 bg-emerald-950/80 border border-emerald-800/60 px-2 py-0.5 rounded uppercase">
              Static File Forensics
            </span>
          </div>
          <h1 className="text-xl font-black text-white tracking-wide mt-1">
            DIGITAL FILE ANALYSIS & FORENSICS CENTER
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Static IOC extraction, structural anomaly inspection, and XAI risk scoring for PDF, DOCX, CSV, and XLSX documents
          </p>
        </div>
      </div>

      {/* Upload Dropzone */}
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className="border-2 border-dashed border-[#1E2D4A] hover:border-blue-500 bg-[#0C1322] hover:bg-[#111A2E] rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition shadow-xl group"
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pdf,.docx,.csv,.xlsx"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />
        <div className="w-14 h-14 bg-blue-600/10 text-blue-400 rounded-2xl flex items-center justify-center mb-3 group-hover:scale-105 transition border border-blue-500/20">
          <UploadCloud className="w-7 h-7" />
        </div>
        <div className="text-sm font-bold text-white mb-1">
          {uploading ? "Running Safe Static Extraction..." : "Click or Drag & Drop File to Inspect"}
        </div>
        <p className="text-xs text-slate-400 max-w-sm mb-3">
          Supported file types: <span className="text-slate-300 font-semibold">PDF, DOCX, CSV, XLSX</span> (Max 25 MB).
        </p>
        <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold bg-slate-900 px-3 py-1 rounded-full border border-slate-800">
          Zero-Execution Guarantee • No Macros or Active Code Interpreted
        </span>

        {uploadError && (
          <div className="mt-4 p-2.5 bg-red-950/60 border border-red-800 rounded-lg text-xs text-red-300 font-semibold">
            {uploadError}
          </div>
        )}
      </div>

      {/* Main Content Grid: Detailed Forensic Dossier on Left, History on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Selected File Forensic Report */}
        <div className="lg:col-span-2 space-y-5">
          {selectedAnalysis ? (
            <div className="space-y-5">
              {/* Report Header Card */}
              <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5 shadow-xl">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#1E2D4A] pb-4 mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-blue-600/10 text-blue-400 rounded-xl border border-blue-500/20">
                      {selectedAnalysis.file_type === "PDF" || selectedAnalysis.file_type === "DOCX" ? (
                        <FileText className="w-6 h-6" />
                      ) : (
                        <FileSpreadsheet className="w-6 h-6" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h2 className="text-base font-bold text-white font-mono">{selectedAnalysis.file_name}</h2>
                        <span className="text-[10px] bg-slate-800 px-2 py-0.5 rounded font-bold text-slate-300 border border-slate-700">
                          {selectedAnalysis.file_type}
                        </span>
                      </div>
                      <span className="text-xs text-slate-400">{formatBytes(selectedAnalysis.file_size)}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <RiskBadge score={selectedAnalysis.risk_score} classification={selectedAnalysis.classification} />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs mb-4">
                  <div className="bg-[#070B14] p-3 rounded-lg border border-[#1E2D4A]">
                    <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">SHA-256 Hash</span>
                    <span className="font-mono text-slate-300 text-[11px] break-all select-all">
                      {selectedAnalysis.sha256}
                    </span>
                  </div>
                  <div className="bg-[#070B14] p-3 rounded-lg border border-[#1E2D4A]">
                    <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">Inspection Timestamp</span>
                    <span className="font-mono text-slate-300">
                      {new Date(selectedAnalysis.created_at).toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Metadata extracted preview */}
                {Object.keys(selectedAnalysis.metadata_extracted || {}).length > 0 && (
                  <div className="bg-[#070B14] p-3 rounded-lg border border-[#1E2D4A] text-xs">
                    <span className="text-slate-500 text-[10px] uppercase font-bold block mb-2">Document Metadata</span>
                    <div className="grid grid-cols-2 gap-2 text-slate-300 text-[11px]">
                      {Object.entries(selectedAnalysis.metadata_extracted).slice(0, 6).map(([k, v]) => (
                        <div key={k} className="truncate">
                          <span className="text-slate-500 uppercase">{k}:</span> {String(v)}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* XAI Attribution for File Score */}
              <XAIExplanationCard factors={selectedAnalysis.xai_factors} title="File Risk XAI Score Breakdown" />

              {/* Structural Indicators */}
              {selectedAnalysis.indicators_found && selectedAnalysis.indicators_found.length > 0 && (
                <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-white mb-3 flex items-center gap-2">
                    <AlertOctagon className="w-4 h-4 text-red-400" />
                    <span>Structural Anomaly Indicators</span>
                  </h3>
                  <div className="space-y-2">
                    {selectedAnalysis.indicators_found.map((ind, i) => (
                      <div key={i} className="bg-[#070B14] border border-red-900/40 p-3 rounded-lg text-xs">
                        <div className="flex items-center justify-between font-bold text-red-400 mb-1">
                          <span>{ind.type}</span>
                          <span className="text-[10px] uppercase bg-red-950 px-2 py-0.5 rounded border border-red-800">
                            {ind.severity}
                          </span>
                        </div>
                        <p className="text-slate-300">{ind.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Extracted IOCs (URLs, Domains, IPs, Emails) */}
              <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5">
                <h3 className="text-xs font-bold uppercase tracking-wider text-white mb-3">
                  Extracted Indicators of Compromise (IOCs)
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  {/* URLs */}
                  <div className="bg-[#070B14] border border-[#1E2D4A] p-3 rounded-lg">
                    <div className="flex items-center gap-1.5 text-blue-400 font-semibold mb-2">
                      <Link className="w-3.5 h-3.5" />
                      <span>Extracted URLs ({selectedAnalysis.extracted_urls?.length || 0})</span>
                    </div>
                    <div className="space-y-1 max-h-36 overflow-y-auto font-mono text-[11px] text-slate-300">
                      {selectedAnalysis.extracted_urls?.length ? (
                        selectedAnalysis.extracted_urls.map((u, i) => (
                          <div key={i} className="truncate p-1 bg-slate-900 rounded">{u}</div>
                        ))
                      ) : (
                        <span className="text-slate-500">None detected</span>
                      )}
                    </div>
                  </div>

                  {/* IPs & Emails */}
                  <div className="space-y-3">
                    <div className="bg-[#070B14] border border-[#1E2D4A] p-3 rounded-lg">
                      <div className="flex items-center gap-1.5 text-amber-400 font-semibold mb-1.5">
                        <Server className="w-3.5 h-3.5" />
                        <span>IP Addresses ({selectedAnalysis.extracted_ips?.length || 0})</span>
                      </div>
                      <div className="flex flex-wrap gap-1 font-mono text-[11px] text-slate-300">
                        {selectedAnalysis.extracted_ips?.length ? (
                          selectedAnalysis.extracted_ips.map((ip, i) => (
                            <span key={i} className="bg-slate-900 px-2 py-0.5 rounded">{ip}</span>
                          ))
                        ) : (
                          <span className="text-slate-500">None detected</span>
                        )}
                      </div>
                    </div>

                    <div className="bg-[#070B14] border border-[#1E2D4A] p-3 rounded-lg">
                      <div className="flex items-center gap-1.5 text-emerald-400 font-semibold mb-1.5">
                        <Mail className="w-3.5 h-3.5" />
                        <span>Email Addresses ({selectedAnalysis.extracted_emails?.length || 0})</span>
                      </div>
                      <div className="flex flex-wrap gap-1 font-mono text-[11px] text-slate-300">
                        {selectedAnalysis.extracted_emails?.length ? (
                          selectedAnalysis.extracted_emails.map((em, i) => (
                            <span key={i} className="bg-slate-900 px-2 py-0.5 rounded">{em}</span>
                          ))
                        ) : (
                          <span className="text-slate-500">None detected</span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-12 text-center text-slate-500 text-xs">
              Upload a document above to inspect its forensic indicators.
            </div>
          )}
        </div>

        {/* Historical Analysis List */}
        <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5 space-y-3 flex flex-col">
          <h3 className="text-xs font-bold uppercase tracking-wider text-white">Analyzed Files History</h3>
          <div className="space-y-2 overflow-y-auto max-h-[700px] flex-1">
            {analyses.map((a) => {
              const isSelected = selectedAnalysis?.id === a.id;
              return (
                <div
                  key={a.id}
                  onClick={() => setSelectedAnalysis(a)}
                  className={`p-3 rounded-lg border cursor-pointer transition ${
                    isSelected
                      ? "bg-blue-600/15 border-blue-500/50"
                      : "bg-[#070B14] border-[#1E2D4A] hover:bg-[#111A2E]"
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-mono text-white font-bold truncate max-w-[160px]">{a.file_name}</span>
                    <RiskBadge score={a.risk_score} classification={a.classification} showIcon={false} />
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span className="text-slate-500 font-semibold">{a.file_type}</span>
                    <span>{new Date(a.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

