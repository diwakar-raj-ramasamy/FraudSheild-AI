import React, { useEffect, useState } from "react";
import { Network, Flame, ShieldCheck, Ban, CheckCircle, RefreshCw, Server, AlertTriangle } from "lucide-react";
import { api } from "../services/api";
import { FraudCampaignItem } from "../types";

export const CampaignMonitor: React.FC = () => {
  const [campaigns, setCampaigns] = useState<FraudCampaignItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [mitigatingId, setMitigatingId] = useState<string | null>(null);

  useEffect(() => {
    loadCampaigns();

    // Real-time live telemetry listener: automatically refreshes campaigns when correlation triggers
    const handleLiveCampaignEvent = () => {
      loadCampaigns();
    };
    window.addEventListener("fraudshield_live_event", handleLiveCampaignEvent);
    return () => window.removeEventListener("fraudshield_live_event", handleLiveCampaignEvent);
  }, []);

  async function loadCampaigns() {
    setLoading(true);
    try {
      const data = await api.getCampaigns();
      setCampaigns(data);
    } catch (err) {
      console.error("Failed to load campaigns:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleMitigate(id: string) {
    setMitigatingId(id);
    try {
      await api.blockCampaign(id);
      await loadCampaigns();
    } catch (err) {
      alert("Failed to mitigate campaign: " + err);
    } finally {
      setMitigatingId(null);
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-red-400 bg-red-950/80 border border-red-800/60 px-2 py-0.5 rounded uppercase">
              Distributed Fraud Intelligence
            </span>
          </div>
          <h1 className="text-xl font-black text-white tracking-wide mt-1">MULTI-DEVICE CAMPAIGN MONITOR</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Correlates repeated suspicious detections across multiple endpoint installations to identify coordinated phishing campaigns
          </p>
        </div>

        <button
          onClick={loadCampaigns}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg text-xs text-slate-300 font-semibold transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Correlation Threshold Explanation */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-4 flex items-center justify-between gap-4 text-xs text-slate-400">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <span className="font-bold text-white block">Automated Correlation Logic:</span>
            <span>Threshold: ≥ 3 detections across ≥ 2 unique browser devices within 24 hours triggers Campaign Alert & SOC escalation.</span>
          </div>
        </div>
      </div>

      {/* Campaigns Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {loading ? (
          <div className="col-span-2 py-12 text-center text-slate-500 text-xs">
            Loading campaigns...
          </div>
        ) : campaigns.length === 0 ? (
          <div className="col-span-2 py-12 text-center text-slate-500 text-xs">
            No active or historical fraud campaigns recorded.
          </div>
        ) : (
          campaigns.map((camp) => {
            const isActive = camp.status === "ACTIVE";
            return (
              <div
                key={camp.id}
                className={`bg-[#0C1322] border rounded-2xl p-5 shadow-xl flex flex-col justify-between transition ${
                  isActive ? "border-red-800/80" : "border-[#1E2D4A]"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span
                      className={`text-[10px] font-black uppercase px-2 py-0.5 rounded-full border ${
                        isActive
                          ? "bg-red-950/80 text-red-400 border-red-800/60 animate-pulse"
                          : "bg-emerald-950/60 text-emerald-400 border-emerald-800/50"
                      }`}
                    >
                      {camp.status}
                    </span>
                    <span className="text-xs text-slate-400 font-semibold">
                      Confidence: {camp.confidence_score}%
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-white mb-1">{camp.campaign_name}</h3>
                  <div className="text-xs text-red-400 font-mono mb-4">{camp.domain}</div>

                  {/* Metrics Row */}
                  <div className="grid grid-cols-2 gap-3 mb-4 text-xs">
                    <div className="bg-[#070B14] p-3 rounded-xl border border-[#1E2D4A]">
                      <span className="text-[10px] uppercase font-bold text-slate-500 block">Total Detections</span>
                      <span className="text-xl font-black text-white">{camp.total_detections}</span>
                    </div>
                    <div className="bg-[#070B14] p-3 rounded-xl border border-[#1E2D4A]">
                      <span className="text-[10px] uppercase font-bold text-slate-500 block">Unique Endpoints</span>
                      <span className="text-xl font-black text-blue-400">{camp.unique_devices_count} Devices</span>
                    </div>
                  </div>

                  {/* Observed IPs */}
                  {camp.observed_ips && camp.observed_ips.length > 0 && (
                    <div className="bg-[#070B14] p-3 rounded-xl border border-[#1E2D4A] text-xs mb-4">
                      <div className="flex items-center gap-1.5 text-slate-400 text-[11px] mb-1">
                        <Server className="w-3.5 h-3.5 text-blue-400" />
                        <span>Observed Infrastructure IPs:</span>
                      </div>
                      <div className="flex flex-wrap gap-1 font-mono text-xs text-slate-300">
                        {camp.observed_ips.map((ip, i) => (
                          <span key={i} className="bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Notes / Details */}
                  {camp.notes && (
                    <p className="text-xs text-slate-400 mb-4 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                      {camp.notes}
                    </p>
                  )}
                </div>

                {/* Footer Action */}
                <div className="border-t border-[#1E2D4A] pt-4 flex items-center justify-between">
                  <span className="text-[11px] text-slate-500 font-mono">
                    Last Seen: {new Date(camp.last_seen).toLocaleDateString()}
                  </span>

                  {isActive ? (
                    <button
                      onClick={() => handleMitigate(camp.id)}
                      disabled={mitigatingId === camp.id}
                      className="flex items-center gap-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-bold text-xs py-2 px-3.5 rounded-lg transition shadow-md shadow-red-950"
                    >
                      <Ban className="w-3.5 h-3.5" />
                      <span>{mitigatingId === camp.id ? "Mitigating..." : "Mitigate & Block Domain"}</span>
                    </button>
                  ) : (
                    <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-semibold">
                      <ShieldCheck className="w-4 h-4" />
                      <span>Mitigated in Central Blocklist</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

