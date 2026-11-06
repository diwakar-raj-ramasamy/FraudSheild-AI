import React from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  SearchCode,
  Network,
  DownloadCloud,
  FileSearch,
  BellRing,
  Ban,
  Laptop,
  Settings
} from "lucide-react";

export type PageId =
  | "overview"
  | "threats"
  | "investigation"
  | "campaigns"
  | "downloads"
  | "files"
  | "alerts"
  | "blocklist"
  | "devices"
  | "settings";

interface SidebarProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  unreadAlertsCount: number;
  activeCampaignsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  unreadAlertsCount,
  activeCampaignsCount
}) => {
  const navItems = [
    { id: "overview" as PageId, label: "Security Overview", icon: LayoutDashboard },
    { id: "threats" as PageId, label: "Threat Detection Center", icon: ShieldAlert },
    { id: "investigation" as PageId, label: "Attack Investigation", icon: SearchCode },
    {
      id: "campaigns" as PageId,
      label: "Campaign Monitor",
      icon: Network,
      badge: activeCampaignsCount > 0 ? activeCampaignsCount : undefined,
      badgeColor: "bg-red-500/20 text-red-400 border-red-500/30"
    },
    { id: "downloads" as PageId, label: "Dangerous Downloads", icon: DownloadCloud },
    { id: "files" as PageId, label: "File Analysis & Forensics", icon: FileSearch },
    {
      id: "alerts" as PageId,
      label: "Admin Alerts",
      icon: BellRing,
      badge: unreadAlertsCount > 0 ? unreadAlertsCount : undefined,
      badgeColor: "bg-amber-500/20 text-amber-400 border-amber-500/30"
    },
    { id: "blocklist" as PageId, label: "Threat Blocklist", icon: Ban },
    { id: "devices" as PageId, label: "Protected Endpoints", icon: Laptop },
    { id: "settings" as PageId, label: "Settings & Threat Feeds", icon: Settings }
  ];

  return (
    <aside className="w-64 bg-[#0C1322] border-r border-[#1E2D4A] flex flex-col justify-between shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="py-4 px-3 space-y-1">
        <div className="px-3 pb-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
          Core Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectPage(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition ${
                isActive
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-[#111A2E]"
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? "text-blue-400" : "text-slate-400"}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${item.badgeColor}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Footer system status */}
      <div className="p-4 border-t border-[#1E2D4A] text-[11px] text-slate-500 flex flex-col gap-1 bg-[#070B14]">
        <div className="flex items-center justify-between font-mono">
          <span>Engine Status:</span>
          <span className="text-emerald-400 font-bold">ONLINE</span>
        </div>
        <div className="flex items-center justify-between font-mono">
          <span>Correlation Sync:</span>
          <span className="text-blue-400 font-bold">ACTIVE</span>
        </div>
      </div>
    </aside>
  );
};

