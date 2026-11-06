import React, { useState } from "react";
import { X, Search, ShieldAlert, CheckCircle, ArrowRight, Server, Globe } from "lucide-react";
import { api } from "../services/api";
import { RiskBadge } from "./RiskBadge";
import { XAIExplanationCard } from "./XAIExplanationCard";

interface QuickScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onInvestigate: (urlId?: string) => void;
}

export const QuickScanModal: React.FC<QuickScanModalProps> = ({ isOpen, onClose, onInvestigate }) => {
  const [urlInput, setUrlInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.scanUrl(urlInput.trim());
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to scan target URL");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-[#1E2D4A] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white">Live Cyber Threat & URL Analyzer</h3>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleScan} className="p-4 border-b border-[#1E2D4A] flex gap-2">
          <input
            type="text"
            placeholder="Paste target URL or domain (e.g. http://paypa1-security.xyz/login)..."
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            className="flex-1 bg-[#070B14] border border-[#1E2D4A] rounded-lg px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold text-xs px-4 py-2 rounded-lg transition"
          >
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </form>

        {/* Content */}
        <div className="p-4 flex-1">
          {error && (
            <div className="p-3 bg-red-950/40 border border-red-800 rounded-lg text-xs text-red-300 mb-3">
              {error}
            </div>
          )}

          {result && (
            <div className="space-y-4">
              <div className="bg-[#111A2E] border border-[#1E2D4A] rounded-xl p-4 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <RiskBadge score={result.risk_score} classification={result.classification} />
                    <span className="text-xs text-slate-400 font-mono">{result.domain}</span>
                  </div>
                  <div className="text-xs text-slate-300 font-mono break-all">{result.normalized_url}</div>
                </div>

                <div className="text-right">
                  <div className="text-2xl font-black text-white">{result.risk_score}/100</div>
                  <span className="text-[10px] text-slate-400">Hybrid Risk Score</span>
                </div>
              </div>

              {/* Observed Infrastructure Pill */}
              {result.observed_infrastructure && (
                <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg p-3 text-xs flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-blue-400" />
                    <span className="text-slate-400">Observed Infrastructure IP:</span>
                    <span className="font-mono text-slate-200 font-bold">
                      {result.observed_infrastructure.observed_infrastructure_ip || "Unresolved"}
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-400">
                    ASN: {result.observed_infrastructure.asn} ({result.observed_infrastructure.asn_organization})
                  </span>
                </div>
              )}

              {/* Attack Types */}
              {result.attack_types && result.attack_types.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {result.attack_types.map((at: string, i: number) => (
                    <span
                      key={i}
                      className="px-2.5 py-1 bg-red-950/50 border border-red-800/60 rounded text-xs text-red-300 font-semibold"
                    >
                      {at}
                    </span>
                  ))}
                </div>
              )}

              {/* XAI Attribution */}
              <XAIExplanationCard factors={result.xai_factors} />
            </div>
          )}

          {!result && !loading && !error && (
            <div className="py-8 text-center text-slate-500 text-xs">
              Enter any URL above to run the hybrid multi-signal inspection pipeline.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

