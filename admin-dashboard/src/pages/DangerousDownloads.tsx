import React, { useEffect, useState } from "react";
import { DownloadCloud, AlertTriangle, FileWarning, ExternalLink, RefreshCw, ShieldAlert } from "lucide-react";
import { api } from "../services/api";
import { DangerousDownloadItem } from "../types";
import { RiskBadge } from "../components/RiskBadge";

export const DangerousDownloads: React.FC = () => {
  const [downloads, setDownloads] = useState<DangerousDownloadItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDownloads();
  }, []);

  async function loadDownloads() {
    setLoading(true);
    try {
      const data = await api.getDangerousDownloads();
      setDownloads(data);
    } catch (err) {
      console.error("Failed to load dangerous downloads:", err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-amber-400 bg-amber-950/80 border border-amber-800/60 px-2 py-0.5 rounded uppercase">
              Payload & Binary Trapping
            </span>
          </div>
          <h1 className="text-xl font-black text-white tracking-wide mt-1">DANGEROUS DOWNLOADS MONITOR</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Intercepts deceptive file extensions (.pdf.exe), executable wrappers, and MIME mismatches
          </p>
        </div>

        <button
          onClick={loadDownloads}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg text-xs text-slate-300 font-semibold transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Security Axiom Notice */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 flex items-start gap-3">
        <FileWarning className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-amber-400 block mb-0.5">Zero-Execution Static Forensics Rule:</strong>
          FraudShield AI analyzes file headers, naming patterns, and extension disguises statically. Downloaded binaries and scripts are never executed or interpreted on endpoint systems.
        </div>
      </div>

      {/* Downloads Table */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#070B14] border-b border-[#1E2D4A] text-slate-400 text-[11px]">
                <th className="py-3 px-4 font-semibold">Intercepted Filename</th>
                <th className="py-3 px-4 font-semibold">Risk Score</th>
                <th className="py-3 px-4 font-semibold">Detected Hazard & Anomaly</th>
                <th className="py-3 px-4 font-semibold">Source Host</th>
                <th className="py-3 px-4 font-semibold">MIME Type</th>
                <th className="py-3 px-4 font-semibold">Detection Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/50">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    Loading intercepted downloads...
                  </td>
                </tr>
              ) : downloads.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No dangerous download attempts intercepted yet.
                  </td>
                </tr>
              ) : (
                downloads.map((d) => (
                  <tr key={d.id} className="hover:bg-[#111A2E]/60 transition">
                    <td className="py-3.5 px-4">
                      <div className="font-mono text-white font-bold flex items-center gap-2">
                        <FileWarning className="w-4 h-4 text-red-400 shrink-0" />
                        <span>{d.file_name}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono truncate max-w-sm mt-0.5">
                        {d.download_url}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge score={d.risk_score} classification="CRITICAL" />
                    </td>
                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="space-y-1">
                        {d.reasons.map((r, i) => (
                          <div key={i} className="text-red-300 font-semibold text-[11px] bg-red-950/40 px-2 py-0.5 rounded border border-red-900/40">
                            {r}
                          </div>
                        ))}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-slate-300">{d.source_domain}</td>
                    <td className="py-3.5 px-4 font-mono text-slate-400 text-[11px]">
                      {d.mime_type || "application/octet-stream"}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(d.detected_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

