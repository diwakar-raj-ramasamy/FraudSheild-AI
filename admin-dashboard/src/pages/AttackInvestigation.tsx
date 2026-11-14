import React, { useEffect, useState } from "react";
import {
  SearchCode,
  Server,
  Globe,
  Lock,
  GitFork,
  Clock,
  ShieldAlert,
  Ban,
  CheckCircle,
  AlertTriangle,
  Info,
  Calendar,
  Layers,
  ArrowRight,
  DownloadCloud
} from "lucide-react";
import { api } from "../services/api";
import { InvestigationDossier } from "../types";
import { RiskBadge } from "../components/RiskBadge";
import { XAIExplanationCard } from "../components/XAIExplanationCard";

interface AttackInvestigationProps {
  selectedUrlId?: string;
  onBlocklistAdded?: () => void;
}

export const AttackInvestigation: React.FC<AttackInvestigationProps> = ({
  selectedUrlId,
  onBlocklistAdded
}) => {
  const [dossier, setDossier] = useState<InvestigationDossier | null>(null);
  const [loading, setLoading] = useState(false);
  const [targetId, setTargetId] = useState(selectedUrlId || "");
  const [blockSuccess, setBlockSuccess] = useState(false);

  useEffect(() => {
    if (selectedUrlId) {
      setTargetId(selectedUrlId);
      loadDossier(selectedUrlId);
    } else {
      // Load first threat as default
      api.getThreats().then((threats) => {
        if (threats.length > 0) {
          setTargetId(threats[0].id);
          loadDossier(threats[0].id);
        }
      });
    }
  }, [selectedUrlId]);

  async function loadDossier(id: string) {
    if (!id) return;
    setLoading(true);
    setBlockSuccess(false);
    try {
      const data = await api.getInvestigationDossier(id);
      setDossier(data);
    } catch (err) {
      console.error("Failed to load investigation dossier:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleAddToBlocklist() {
    if (!dossier) return;
    try {
      await api.addBlocklistEntry(
        dossier.domain,
        `Verified during attack investigation (${dossier.attack_types.join(", ")})`,
        "DOMAIN"
      );
      setBlockSuccess(true);
      if (onBlocklistAdded) onBlocklistAdded();
    } catch (err) {
      alert("Failed to add domain to blocklist: " + err);
    }
  }

  function handleExportDossier() {
    if (!dossier) return;
    const str = JSON.stringify(dossier, null, 2);
    const blob = new Blob([str], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Forensic-Dossier-${dossier.domain || "Target"}-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-blue-400 bg-blue-950/80 border border-blue-800/60 px-2 py-0.5 rounded uppercase">
              Forensic Reverse Tracking
            </span>
          </div>
          <h1 className="text-xl font-black text-white tracking-wide mt-1">ATTACK INVESTIGATION & INFRASTRUCTURE</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Deep-dive infrastructure analysis, observed routing nodes, and multi-endpoint detection footprints
          </p>
        </div>

        {dossier && (
          <div className="flex items-center gap-3">
            <button
              onClick={handleExportDossier}
              className="flex items-center gap-2 px-3.5 py-2 bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg text-xs font-bold text-slate-200 transition shadow-md"
            >
              <DownloadCloud className="w-4 h-4 text-blue-400" />
              <span>Export Dossier (JSON)</span>
            </button>

            <button
              onClick={handleAddToBlocklist}
              disabled={blockSuccess}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition shadow-lg ${
                blockSuccess
                  ? "bg-emerald-600 text-white cursor-default"
                  : "bg-red-600 hover:bg-red-500 text-white shadow-red-900/40"
              }`}
            >
              {blockSuccess ? <CheckCircle className="w-4 h-4" /> : <Ban className="w-4 h-4" />}
              <span>{blockSuccess ? "Added to Global Blocklist" : "Add Target to Blocklist"}</span>
            </button>
          </div>
        )}
      </div>

      {loading ? (
        <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-12 text-center text-slate-400 text-xs">
          Loading forensic dossier...
        </div>
      ) : !dossier ? (
        <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-12 text-center text-slate-500 text-xs">
          Select a threat from the Threat Detection Center to initiate reverse tracking.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Main Target Dossier Header */}
          <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5 shadow-xl">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1E2D4A] pb-4 mb-4">
              <div>
                <div className="flex items-center gap-2.5 mb-1.5">
                  <span className="text-lg font-black text-white font-mono">{dossier.domain}</span>
                  <RiskBadge score={dossier.risk_score} classification={dossier.classification} />
                </div>
                <div className="text-xs text-slate-400 font-mono break-all">{dossier.url}</div>
              </div>

              <div className="flex items-center gap-4 text-xs">
                <div className="bg-[#111A2E] border border-[#1E2D4A] px-3.5 py-2 rounded-lg text-center">
                  <div className="text-base font-bold text-white">{dossier.detection_count}</div>
                  <span className="text-[10px] text-slate-400">Total Detections</span>
                </div>
                <div className="bg-[#111A2E] border border-[#1E2D4A] px-3.5 py-2 rounded-lg text-center">
                  <div className="text-base font-bold text-blue-400">{dossier.unique_device_count}</div>
                  <span className="text-[10px] text-slate-400">Unique Endpoints</span>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">First Observed</span>
                <span className="text-slate-300 font-mono">{new Date(dossier.first_seen).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Last Observed</span>
                <span className="text-slate-300 font-mono">{new Date(dossier.last_seen).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Threat Classifications</span>
                <div className="flex flex-wrap gap-1 mt-0.5">
                  {dossier.attack_types.map((at, i) => (
                    <span key={i} className="text-[10px] font-semibold text-red-300 bg-red-950/60 px-1.5 py-0.5 rounded border border-red-800/60">
                      {at}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-bold">Target ID</span>
                <span className="text-slate-400 font-mono text-[11px] truncate block">{dossier.id}</span>
              </div>
            </div>
          </div>

          {/* CRITICAL FORENSIC BOUNDARY NOTICE */}
          <div className="bg-blue-950/30 border border-blue-900/50 rounded-xl p-4 flex items-start gap-3 text-xs text-slate-300">
            <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-blue-300 block mb-0.5">Forensic Attribution Distinction:</strong>
              Observed IP addresses and routing nodes documented below represent infrastructure observed handling network requests (e.g. CDNs, shared web hosting, or reverse proxies). They must not be misconstrued as the confirmed physical identity of the threat actor.
            </div>
          </div>

          {/* Infrastructure Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Network & Observed IP Card */}
            <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5 space-y-4">
              <div className="flex items-center gap-2 border-b border-[#1E2D4A] pb-3">
                <Server className="w-4 h-4 text-blue-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">Observed Infrastructure IP</h3>
              </div>

              {dossier.infrastructure ? (
                <div className="space-y-3 text-xs">
                  <div className="flex items-center justify-between bg-[#070B14] p-3 rounded-lg border border-[#1E2D4A]">
                    <span className="text-slate-400">Observed Server IP:</span>
                    <span className="font-mono text-base font-bold text-white">
                      {dossier.infrastructure.observed_ip || "N/A"}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="bg-[#070B14] p-2.5 rounded-lg border border-[#1E2D4A]">
                      <span className="text-slate-500 text-[10px] uppercase font-bold block">Autonomous System (ASN)</span>
                      <span className="font-mono text-slate-200">{dossier.infrastructure.asn || "N/A"}</span>
                    </div>
                    <div className="bg-[#070B14] p-2.5 rounded-lg border border-[#1E2D4A]">
                      <span className="text-slate-500 text-[10px] uppercase font-bold block">Network Organization</span>
                      <span className="text-slate-200 truncate block">{dossier.infrastructure.asn_org || "N/A"}</span>
                    </div>
                  </div>

                  <div className="bg-[#070B14] p-2.5 rounded-lg border border-[#1E2D4A]">
                    <span className="text-slate-500 text-[10px] uppercase font-bold block">Reverse DNS Pointer (PTR)</span>
                    <span className="font-mono text-slate-300 text-[11px] break-all">{dossier.infrastructure.reverse_dns || "No PTR"}</span>
                  </div>

                  {dossier.infrastructure.resolved_ips && dossier.infrastructure.resolved_ips.length > 1 && (
                    <div className="bg-[#070B14] p-2.5 rounded-lg border border-[#1E2D4A]">
                      <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">All Resolved Server IPs</span>
                      <div className="flex flex-wrap gap-1 font-mono text-[11px] text-slate-300">
                        {dossier.infrastructure.resolved_ips.map((ip, i) => (
                          <span key={i} className="bg-slate-800 px-2 py-0.5 rounded">{ip}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-slate-500 text-xs py-4">No infrastructure record available.</div>
              )}
            </div>

            {/* SSL & DNS Records Card */}
            <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5 space-y-4">
              <div className="flex items-center gap-2 border-b border-[#1E2D4A] pb-3">
                <Lock className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">SSL / TLS & DNS Configuration</h3>
              </div>

              {dossier.infrastructure ? (
                <div className="space-y-3 text-xs">
                  <div className="flex items-center justify-between bg-[#070B14] p-3 rounded-lg border border-[#1E2D4A]">
                    <span className="text-slate-400">TLS Encryption Status:</span>
                    <span className="font-bold text-emerald-400">
                      {dossier.infrastructure.ssl_info.has_ssl ? "Valid Certificate" : "Unencrypted / Invalid"}
                    </span>
                  </div>

                  <div className="bg-[#070B14] p-2.5 rounded-lg border border-[#1E2D4A]">
                    <span className="text-slate-500 text-[10px] uppercase font-bold block">Certificate Authority / Issuer</span>
                    <span className="text-slate-200">{dossier.infrastructure.ssl_info.issuer || "Self-Signed or Unknown"}</span>
                  </div>

                  <div className="bg-[#070B14] p-2.5 rounded-lg border border-[#1E2D4A]">
                    <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">DNS A Records</span>
                    <div className="flex flex-wrap gap-1 font-mono text-[11px] text-slate-300">
                      {(dossier.infrastructure.dns_records.A || []).map((rec: string, i: number) => (
                        <span key={i} className="bg-slate-800 px-2 py-0.5 rounded">{rec}</span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-slate-500 text-xs py-4">No DNS / SSL data cached.</div>
              )}
            </div>
          </div>

          {/* Explainable AI Attribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <XAIExplanationCard factors={dossier.xai_factors} title="Detection Evidence & Feature Weights" />

            {/* Related Detection Timeline */}
            <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5">
              <div className="flex items-center gap-2 border-b border-[#1E2D4A] pb-3 mb-3">
                <Clock className="w-4 h-4 text-purple-400" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-white">Detection Event Timeline</h3>
              </div>

              <div className="space-y-2 max-h-64 overflow-y-auto">
                {dossier.related_events && dossier.related_events.length > 0 ? (
                  dossier.related_events.map((ev, i) => (
                    <div key={i} className="flex items-center justify-between bg-[#070B14] p-2.5 rounded-lg border border-[#1E2D4A]/60 text-xs">
                      <div>
                        <div className="text-slate-200 font-mono text-[11px]">Endpoint: {ev.device_id.substring(0, 8)}...</div>
                        <div className="text-slate-500 text-[10px]">{new Date(ev.detected_at).toLocaleString()}</div>
                      </div>
                      <RiskBadge score={ev.risk_score} classification={ev.classification} />
                    </div>
                  ))
                ) : (
                  <div className="text-slate-500 text-xs py-4 text-center">No individual endpoint hits recorded yet.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

