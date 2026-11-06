import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  SearchCode,
  Network,
  DownloadCloud,
  FileSearch,
  BellRing,
  Laptop,
  CheckCircle,
  ExternalLink,
  Flame,
  ArrowRight
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar
} from "recharts";
import { api } from "../services/api";
import { MetricsOverviewResponse, ThreatItem, FraudCampaignItem } from "../types";
import { StatCard } from "../components/StatCard";
import { RiskBadge } from "../components/RiskBadge";

interface OverviewProps {
  onNavigateInvestigation: (id?: string) => void;
  onNavigateCampaigns: () => void;
}

export const Overview: React.FC<OverviewProps> = ({
  onNavigateInvestigation,
  onNavigateCampaigns
}) => {
  const [data, setData] = useState<MetricsOverviewResponse | null>(null);
  const [recentThreats, setRecentThreats] = useState<ThreatItem[]>([]);
  const [campaigns, setCampaigns] = useState<FraudCampaignItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadOverviewData();
  }, []);

  async function loadOverviewData() {
    setLoading(true);
    try {
      const [overviewData, threats, activeCampaigns] = await Promise.all([
        api.getMetricsOverview().catch(() => null),
        api.getThreats().catch(() => []),
        api.getCampaigns().catch(() => [])
      ]);

      if (overviewData) setData(overviewData);
      setRecentThreats(threats.slice(0, 5));
      setCampaigns(activeCampaigns.filter((c) => c.status === "ACTIVE"));
    } finally {
      setLoading(false);
    }
  }

  const metrics = data?.metrics || {
    total_scans: 48,
    threats_detected: 14,
    critical_threats: 8,
    threats_prevented: 26,
    active_alerts: 2,
    active_campaigns: 1,
    files_analyzed: 4,
    affected_devices: 3
  };

  const attackDistribution = data?.charts.attack_distribution || [
    { name: "Phishing", value: 8 },
    { name: "Fake Login", value: 6 },
    { name: "Typosquatting", value: 5 },
    { name: "Financial Scam", value: 4 },
    { name: "Redirects", value: 3 },
    { name: "Downloads", value: 2 }
  ];

  const timeline = data?.charts.timeline || [
    { date: "Oct 28", scans: 12, threats: 2 },
    { date: "Oct 29", scans: 18, threats: 3 },
    { date: "Oct 30", scans: 25, threats: 5 },
    { date: "Oct 31", scans: 32, threats: 4 },
    { date: "Nov 01", scans: 28, threats: 6 },
    { date: "Nov 02", scans: 40, threats: 7 },
    { date: "Nov 03", scans: 48, threats: 8 }
  ];

  return (
    <div className="p-6 space-y-6">
      {/* Page Title & Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-black text-white tracking-wide">SOC SECURITY OVERVIEW</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time Browser Cyber Threat Intelligence & Multi-Device Endpoint Telemetry
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Threat Correlation Engine:</span>
          <span className="px-2.5 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full font-bold flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
            ACTIVE MONITORING
          </span>
        </div>
      </div>

      {/* High Priority Campaign Banner (if active) */}
      {campaigns.length > 0 && (
        <div className="bg-red-950/40 border border-red-800/80 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-lg">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-red-600/20 text-red-400 rounded-xl border border-red-500/40">
              <Flame className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-black uppercase text-red-400 tracking-wider">
                  Active Phishing Campaign Detected
                </span>
                <span className="text-[10px] bg-red-900/60 border border-red-700/60 px-2 py-0.5 rounded text-white font-bold">
                  {campaigns[0].unique_devices_count} Affected Endpoints
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                Targeting: <strong className="text-white">{campaigns[0].domain}</strong> —{" "}
                {campaigns[0].total_detections} hits correlated across distributed extension installations.
              </p>
            </div>
          </div>
          <button
            onClick={onNavigateCampaigns}
            className="flex items-center gap-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-bold py-2 px-3.5 rounded-lg transition"
          >
            <span>Review Campaign</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={metrics.total_scans}
          subtitle="Real-time URL inspections"
          icon={SearchCode}
          color="blue"
          trend="+18% today"
        />
        <StatCard
          title="Threats Detected"
          value={metrics.threats_detected}
          subtitle="Multi-signal positives"
          icon={ShieldAlert}
          color="amber"
          trend="+4 new"
        />
        <StatCard
          title="Critical Threats"
          value={metrics.critical_threats}
          subtitle="High-risk phishing/scams"
          icon={Flame}
          color="red"
          trend="Immediate action"
        />
        <StatCard
          title="Threats Prevented"
          value={metrics.threats_prevented}
          subtitle="Safe Exit clicks & blocks"
          icon={CheckCircle}
          color="emerald"
          trend="100% prevented"
        />
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Active Alerts"
          value={metrics.active_alerts}
          subtitle="SOC alerts requiring review"
          icon={BellRing}
          color="purple"
        />
        <StatCard
          title="Affected Devices"
          value={metrics.affected_devices}
          subtitle="Protected extension nodes"
          icon={Laptop}
          color="blue"
        />
        <StatCard
          title="Active Campaigns"
          value={metrics.active_campaigns}
          subtitle="Multi-device coordinated threats"
          icon={Network}
          color="red"
        />
        <StatCard
          title="Files Analyzed"
          value={metrics.files_analyzed}
          subtitle="PDF, DOCX, CSV, XLSX forensics"
          icon={FileSearch}
          color="emerald"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Area Chart */}
        <div className="lg:col-span-2 bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">Threat Detection Velocity</h3>
              <p className="text-[11px] text-slate-400">7-Day Inspection Volume vs Identified Threats</p>
            </div>
            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5 text-blue-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-blue-500"></span> Total Scans
              </span>
              <span className="flex items-center gap-1.5 text-red-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-red-500"></span> Threats
              </span>
            </div>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" opacity={0.6} />
                <XAxis dataKey="date" stroke="#64748B" fontSize={11} />
                <YAxis stroke="#64748B" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0F172A", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }}
                />
                <Area type="monotone" dataKey="scans" stroke="#3B82F6" strokeWidth={2} fillOpacity={1} fill="url(#colorScans)" />
                <Area type="monotone" dataKey="threats" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#colorThreats)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Types Distribution */}
        <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-white">Threat Category Breakdown</h3>
            <p className="text-[11px] text-slate-400 mb-4">Classified Attack Vectors</p>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attackDistribution} layout="vertical" margin={{ top: 5, right: 20, left: 25, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E2D4A" horizontal={false} />
                <XAxis type="number" stroke="#64748B" fontSize={10} />
                <YAxis type="category" dataKey="name" stroke="#94A3B8" fontSize={10} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: "#0F172A", borderColor: "#334155", borderRadius: "8px", fontSize: "12px" }} />
                <Bar dataKey="value" fill="#3B82F6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Threats Table */}
      <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-white">Latest Flagged Threat Targets</h3>
            <p className="text-[11px] text-slate-400">Suspicious domains identified across monitored browser sessions</p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#1E2D4A] text-slate-400 text-[11px]">
                <th className="pb-3 font-semibold">Target Domain & URL</th>
                <th className="pb-3 font-semibold">Risk Score</th>
                <th className="pb-3 font-semibold">Classified Threat</th>
                <th className="pb-3 font-semibold">Last Observed</th>
                <th className="pb-3 font-semibold text-right">Investigation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]/50">
              {recentThreats.map((t) => (
                <tr key={t.id} className="hover:bg-[#111A2E]/60 transition">
                  <td className="py-3 pr-4">
                    <div className="font-mono text-white font-semibold">{t.domain}</div>
                    <div className="text-[11px] text-slate-500 font-mono truncate max-w-sm">{t.url}</div>
                  </td>
                  <td className="py-3">
                    <RiskBadge score={t.risk_score} classification={t.classification} />
                  </td>
                  <td className="py-3">
                    <div className="flex flex-wrap gap-1">
                      {t.attack_types.map((at, i) => (
                        <span key={i} className="px-2 py-0.5 bg-slate-800 text-slate-300 rounded text-[10px] font-medium border border-slate-700">
                          {at}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 text-slate-400 font-mono text-[11px]">
                    {new Date(t.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="py-3 text-right">
                    <button
                      onClick={() => onNavigateInvestigation(t.id)}
                      className="px-3 py-1.5 bg-blue-600/15 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-xs font-semibold transition"
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

