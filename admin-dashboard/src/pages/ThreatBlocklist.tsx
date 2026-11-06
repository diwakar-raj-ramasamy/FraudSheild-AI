import React, { useEffect, useState } from "react";
import { Ban, PlusCircle, Trash2, ShieldCheck, Download, RefreshCw, CheckCircle2 } from "lucide-react";
import { api } from "../services/api";
import { BlocklistEntryItem } from "../types";

export const ThreatBlocklist: React.FC = () => {
  const [entries, setEntries] = useState<BlocklistEntryItem[]>([]);
  const [versionInfo, setVersionInfo] = useState<{ version: number; last_updated: string; entries_count: number } | null>(null);
  const [loading, setLoading] = useState(true);

  // New entry modal / form state
  const [newTarget, setNewTarget] = useState("");
  const [newReason, setNewReason] = useState("");
  const [newType, setNewType] = useState<string>("DOMAIN");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const [list, ver] = await Promise.all([
        api.getBlocklist(),
        api.getBlocklistVersion()
      ]);
      setEntries(list);
      setVersionInfo(ver);
    } catch (err) {
      console.error("Failed to load blocklist:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleAddEntry(e: React.FormEvent) {
    e.preventDefault();
    if (!newTarget.trim() || !newReason.trim()) return;
    setSubmitting(true);
    try {
      await api.addBlocklistEntry(newTarget.trim(), newReason.trim(), newType);
      setNewTarget("");
      setNewReason("");
      await loadData();
    } catch (err) {
      alert("Failed to add entry: " + err);
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Are you sure you want to deactivate this blocklist entry?")) return;
    try {
      await api.deleteBlocklistEntry(id);
      await loadData();
    } catch (err) {
      alert("Failed to remove entry: " + err);
    }
  }

  function exportJSON() {
    const jsonStr = JSON.stringify(entries, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fraudshield-blocklist-v${versionInfo?.version || 1}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-red-400 bg-red-950/80 border border-red-800/60 px-2 py-0.5 rounded uppercase">
              Centralized Threat Defense
            </span>
          </div>
          <h1 className="text-xl font-black text-white tracking-wide mt-1">GLOBAL THREAT BLOCKLIST</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Verified threat intelligence repository distributed automatically to all client browser extensions
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportJSON}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg text-xs text-slate-300 font-semibold transition"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={loadData}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg text-xs text-slate-300 font-semibold transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Version Status Card */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-red-600/15 text-red-400 rounded-xl border border-red-500/20">
            <Ban className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-white text-sm">
                Blocklist Version {versionInfo?.version || 1}
              </span>
              <span className="text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded text-[10px] font-semibold border border-emerald-800/40">
                ACTIVE SYNC
              </span>
            </div>
            <p className="text-slate-400 mt-0.5">
              Browser extensions query <code className="text-blue-400">/api/blocklist/version</code> to update their local pre-navigation cache.
            </p>
          </div>
        </div>

        <div className="text-right">
          <div className="text-xl font-black text-white">{entries.length} Entries</div>
          <span className="text-slate-500 text-[11px]">Enforced in real-time</span>
        </div>
      </div>

      {/* Add New Target Form */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5 shadow-xl">
        <h3 className="text-xs font-bold uppercase tracking-wider text-white mb-3 flex items-center gap-2">
          <PlusCircle className="w-4 h-4 text-blue-400" />
          <span>Add New Threat to Global Blocklist</span>
        </h3>

        <form onSubmit={handleAddEntry} className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="text-slate-400 text-[11px] block mb-1">Target Type</label>
            <select
              value={newType}
              onChange={(e) => setNewType(e.target.value)}
              className="w-full bg-[#070B14] border border-[#1E2D4A] rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500"
            >
              <option value="DOMAIN">Domain Name</option>
              <option value="URL">Full URL</option>
              <option value="HASH">SHA-256 Hash</option>
            </select>
          </div>

          <div className="md:col-span-1">
            <label className="text-slate-400 text-[11px] block mb-1">Target Identifier</label>
            <input
              type="text"
              placeholder="e.g. evil-phish-domain.xyz"
              value={newTarget}
              onChange={(e) => setNewTarget(e.target.value)}
              className="w-full bg-[#070B14] border border-[#1E2D4A] rounded-lg px-3 py-2 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="md:col-span-1">
            <label className="text-slate-400 text-[11px] block mb-1">Verification Rationale</label>
            <input
              type="text"
              placeholder="e.g. Confirmed PayPal credential harvesting"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              className="w-full bg-[#070B14] border border-[#1E2D4A] rounded-lg px-3 py-2 text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={submitting || !newTarget.trim() || !newReason.trim()}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold py-2 px-4 rounded-lg transition"
            >
              {submitting ? "Publishing..." : "Add & Bump Version"}
            </button>
          </div>
        </form>
      </div>

      {/* Blocklist Table */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-[#070B14] border-b border-[#1E2D4A] text-slate-400 text-[11px]">
                <th className="py-3 px-4 font-semibold">Blocked Target</th>
                <th className="py-3 px-4 font-semibold">Type</th>
                <th className="py-3 px-4 font-semibold">Reason & Severity</th>
                <th className="py-3 px-4 font-semibold">Added By</th>
                <th className="py-3 px-4 font-semibold">Created Date</th>
                <th className="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/50">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    Loading blocklist entries...
                  </td>
                </tr>
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No active targets on the blocklist.
                  </td>
                </tr>
              ) : (
                entries.map((entry) => (
                  <tr key={entry.id} className="hover:bg-[#111A2E]/60 transition">
                    <td className="py-3.5 px-4 font-mono text-white font-bold max-w-xs truncate">
                      {entry.target}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="text-[10px] font-bold bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
                        {entry.target_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 max-w-sm">
                      <div className="text-slate-300">{entry.reason}</div>
                      <span className="text-[10px] text-red-400 font-bold uppercase">{entry.severity}</span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">{entry.added_by}</td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(entry.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleDelete(entry.id)}
                        className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-950/40 rounded transition"
                        title="Remove from blocklist"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
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

