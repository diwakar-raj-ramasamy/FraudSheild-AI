import React, { useEffect, useState } from "react";
import { BellRing, CheckCircle, AlertTriangle, ShieldAlert, Clock, RefreshCw } from "lucide-react";
import { api } from "../services/api";
import { AdminAlertItem } from "../types";

export const AdminAlerts: React.FC = () => {
  const [alerts, setAlerts] = useState<AdminAlertItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAlerts();

    // Real-time live telemetry listener: automatically refreshes alerts on live detection
    const handleLiveAlertEvent = () => {
      loadAlerts();
    };
    window.addEventListener("fraudshield_live_event", handleLiveAlertEvent);
    return () => window.removeEventListener("fraudshield_live_event", handleLiveAlertEvent);
  }, []);

  async function loadAlerts() {
    setLoading(true);
    try {
      const data = await api.getAlerts();
      setAlerts(data);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleResolve(id: string) {
    try {
      await api.resolveAlert(id);
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, is_resolved: true, is_read: true } : a))
      );
    } catch (err) {
      alert("Failed to resolve alert: " + err);
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-amber-400 bg-amber-950/80 border border-amber-800/60 px-2 py-0.5 rounded uppercase">
              Incident Response
            </span>
          </div>
          <h1 className="text-xl font-black text-white tracking-wide mt-1">ADMIN SECURITY ALERTS</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated notifications for multi-device fraud campaigns, high-risk spikes, and defense updates
          </p>
        </div>

        <button
          onClick={loadAlerts}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg text-xs text-slate-300 font-semibold transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Alerts Feed */}
      <div className="space-y-3">
        {loading ? (
          <div className="py-12 text-center text-slate-500 text-xs">Loading alerts...</div>
        ) : alerts.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs bg-[#0C1322] border border-[#1E2D4A] rounded-xl">
            No active alerts at this time. All systems operating within normal parameters.
          </div>
        ) : (
          alerts.map((alt) => {
            const isResolved = alt.is_resolved;
            const isCritical = alt.severity === "CRITICAL";

            return (
              <div
                key={alt.id}
                className={`bg-[#0C1322] border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 transition shadow-lg ${
                  isResolved
                    ? "border-[#1E2D4A] opacity-60"
                    : isCritical
                    ? "border-red-800/80 bg-red-950/15"
                    : "border-amber-800/60 bg-amber-950/15"
                }`}
              >
                <div className="flex items-start gap-3.5">
                  <div
                    className={`p-2 rounded-lg border mt-0.5 ${
                      isCritical
                        ? "bg-red-600/20 text-red-400 border-red-500/30"
                        : "bg-amber-600/20 text-amber-400 border-amber-500/30"
                    }`}
                  >
                    {isCritical ? <ShieldAlert className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
                  </div>

                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-bold text-white">{alt.title}</span>
                      <span
                        className={`text-[10px] font-black uppercase px-2 py-0.5 rounded border ${
                          isCritical
                            ? "bg-red-900/60 text-red-400 border-red-700/60"
                            : "bg-amber-900/60 text-amber-400 border-amber-700/60"
                        }`}
                      >
                        {alt.severity}
                      </span>
                      {isResolved && (
                        <span className="text-[10px] text-emerald-400 font-semibold bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/50">
                          RESOLVED
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-300">{alt.message}</p>

                    {/* Metadata chips */}
                    <div className="flex items-center gap-3 mt-2 text-[11px] text-slate-500">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(alt.created_at).toLocaleString()}
                      </span>
                      <span>Type: {alt.alert_type}</span>
                    </div>
                  </div>
                </div>

                {!isResolved && (
                  <button
                    onClick={() => handleResolve(alt.id)}
                    className="flex items-center justify-center gap-1.5 px-3.5 py-1.5 bg-[#111A2E] hover:bg-emerald-600/20 text-slate-300 hover:text-emerald-300 border border-[#1E2D4A] hover:border-emerald-500/40 rounded-lg text-xs font-semibold transition shrink-0"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Acknowledge / Resolve</span>
                  </button>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

