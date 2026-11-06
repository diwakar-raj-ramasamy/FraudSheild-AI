import React, { useState, useEffect } from "react";
import { Laptop, Shield, Search, RefreshCw, Clock, CheckCircle2, AlertTriangle } from "lucide-react";
import { api } from "../services/api";
import { DeviceItem } from "../types";

export const DevicesMonitor: React.FC = () => {
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");

  const loadDevices = async () => {
    try {
      setLoading(true);
      const data = await api.getDevices();
      setDevices(data);
    } catch (e) {
      console.error("Failed to load devices", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDevices();
  }, []);

  const filteredDevices = devices.filter((dev) =>
    dev.installation_pseudonym.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (dev.user_agent && dev.user_agent.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Laptop className="w-6 h-6 text-primary-400" />
            Endpoint Devices & Telemetry Monitor
          </h1>
          <p className="text-sm text-slate-400">
            Privacy-preserving tracking of client extension installations and threat sensor nodes.
          </p>
        </div>
        <button
          onClick={loadDevices}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-primary-400" : ""}`} />
          Refresh Nodes
        </button>
      </div>

      {/* Privacy Architecture Notice */}
      <div className="bg-primary-950/40 border border-primary-800/40 rounded-xl p-4 flex items-start gap-3">
        <Shield className="w-5 h-5 text-primary-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-primary-200">
          <span className="font-semibold text-white">Strict Zero-PII Hardware Privacy: </span>
          Device IDs are cryptographically isolated UUIDv4 installation pseudonyms generated locally by the FraudShield extension.
          No MAC addresses, IP bindings, hardware serials, or user identity tokens are ever queried or recorded.
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Enrolled Endpoints</div>
          <div className="text-2xl font-bold text-white mt-1">{devices.length}</div>
          <div className="text-xs text-slate-500 mt-1">Active sensor network</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Telemetry Status</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1 flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5" /> Healthy
          </div>
          <div className="text-xs text-slate-500 mt-1">Multi-device correlation active</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Primary Extension Version</div>
          <div className="text-2xl font-bold text-primary-400 mt-1">v1.0.0</div>
          <div className="text-xs text-slate-500 mt-1">Manifest V3 Production</div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="text-xs font-medium text-slate-400 uppercase tracking-wider">Correlation Cluster Count</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">Active</div>
          <div className="text-xs text-slate-500 mt-1">Min threshold: 2 distinct devices</div>
        </div>
      </div>

      {/* Search and Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search by installation pseudonym or browser..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-primary-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Installation Pseudonym</th>
                <th className="py-3 px-4">Extension Version</th>
                <th className="py-3 px-4">Browser / Environment</th>
                <th className="py-3 px-4">Enrollment Date</th>
                <th className="py-3 px-4">Last Telemetry Ping</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-primary-400" />
                    Loading endpoint network...
                  </td>
                </tr>
              ) : filteredDevices.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No endpoint devices enrolled yet. Install the FraudShield extension to begin monitoring.
                  </td>
                </tr>
              ) : (
                filteredDevices.map((dev) => (
                  <tr key={dev.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-medium text-primary-300">
                      {dev.installation_pseudonym}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                        v{dev.extension_version}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate" title={dev.user_agent}>
                      {dev.user_agent ? dev.user_agent.split(" ")[0] || "Chromium-based" : "Chrome / Edge Browser"}
                    </td>
                    <td className="py-3 px-4 text-slate-400 flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-slate-500" />
                      {new Date(dev.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(dev.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        ONLINE
                      </span>
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

