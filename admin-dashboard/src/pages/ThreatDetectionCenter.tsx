import React, { useEffect, useState } from "react";
import { Search, Filter, ShieldAlert, ExternalLink, RefreshCw, Eye } from "lucide-react";
import { api } from "../services/api";
import { ThreatItem } from "../types";
import { RiskBadge } from "../components/RiskBadge";

interface ThreatDetectionCenterProps {
  onInvestigate: (urlId: string) => void;
}

export const ThreatDetectionCenter: React.FC<ThreatDetectionCenterProps> = ({ onInvestigate }) => {
  const [threats, setThreats] = useState<ThreatItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");

  useEffect(() => {
    loadThreats();
  }, [filterSeverity]);

  async function loadThreats() {
    setLoading(true);
    try {
      const classFilter = filterSeverity === "ALL" ? undefined : filterSeverity;
      const data = await api.getThreats(classFilter);
      setThreats(data);
    } catch (err) {
      console.error("Failed to load threats:", err);
    } finally {
      setLoading(false);
    }
  }

  const filtered = threats.filter((t) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return t.domain.toLowerCase().includes(term) || t.url.toLowerCase().includes(term);
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-black text-white tracking-wide">THREAT DETECTION CENTER</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time multi-signal security detections across monitored browser installations
          </p>
        </div>
        <button
          onClick={loadThreats}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg text-xs text-slate-300 font-semibold transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-3">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by domain or URL..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#070B14] border border-[#1E2D4A] rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-xs text-slate-400 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Severity:
          </span>
          {["ALL", "CRITICAL", "CAUTION", "SAFE"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                filterSeverity === sev
                  ? "bg-blue-600 text-white"
                  : "bg-[#111A2E] text-slate-400 hover:text-slate-200 border border-[#1E2D4A]"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Threats Table */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#070B14] border-b border-[#1E2D4A] text-slate-400 text-[11px]">
                <th className="py-3 px-4 font-semibold">Target Domain & Destination URL</th>
                <th className="py-3 px-4 font-semibold">Risk Score</th>
                <th className="py-3 px-4 font-semibold">Classification</th>
                <th className="py-3 px-4 font-semibold">Attack Types</th>
                <th className="py-3 px-4 font-semibold">First Seen</th>
                <th className="py-3 px-4 font-semibold">Last Seen</th>
                <th className="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/50">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    Loading threat records...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No threat records match current filters.
                  </td>
                </tr>
              ) : (
                filtered.map((t) => (
                  <tr key={t.id} className="hover:bg-[#111A2E]/60 transition">
                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="font-mono text-white font-bold">{t.domain}</div>
                      <div className="text-[11px] text-slate-500 font-mono truncate">{t.url}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="text-base font-black text-white">{t.risk_score}</div>
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge score={t.risk_score} classification={t.classification} />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1">
                        {t.attack_types.map((at, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-[10px] font-semibold border border-slate-700"
                          >
                            {at}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(t.first_seen).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(t.last_seen).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => onInvestigate(t.id)}
                        className="flex items-center gap-1.5 ml-auto px-3 py-1.5 bg-blue-600/15 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-xs font-semibold transition"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Investigate</span>
                      </button>
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

