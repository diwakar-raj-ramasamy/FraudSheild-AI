import React from "react";
import { Shield, Bell, Search, Activity, User, PlusCircle } from "lucide-react";

interface NavbarProps {
  onOpenQuickScan: () => void;
  activeAlertCount: number;
  onNavigateAlerts: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenQuickScan,
  activeAlertCount,
  onNavigateAlerts
}) => {
  return (
    <header className="h-16 bg-[#0C1322] border-b border-[#1E2D4A] flex items-center justify-between px-6 sticky top-0 z-40">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-blue-600/20 text-blue-400 rounded-xl border border-blue-500/30">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-black text-sm tracking-wide text-white">FRAUDSHIELD AI</span>
          <span className="ml-2 text-[10px] text-blue-400 bg-blue-950/80 border border-blue-800/60 px-2 py-0.5 rounded uppercase font-semibold">
            Enterprise SOC Console
          </span>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {/* Real-time backend status pill */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-emerald-950/40 border border-emerald-800/40 rounded-full text-xs text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="text-[11px] font-medium">Hybrid Engines Online</span>
        </div>

        {/* Quick Scan Button */}
        <button
          onClick={onOpenQuickScan}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold py-2 px-3.5 rounded-lg transition active:scale-95 shadow-md shadow-blue-900/40"
        >
          <Search className="w-3.5 h-3.5" />
          <span>Analyze URL</span>
        </button>

        {/* Alerts Bell */}
        <button
          onClick={onNavigateAlerts}
          className="relative p-2 text-slate-400 hover:text-white bg-[#111A2E] hover:bg-slate-800 border border-[#1E2D4A] rounded-lg transition"
          title="Security Alerts"
        >
          <Bell className="w-4 h-4" />
          {activeAlertCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-[9px] font-black rounded-full flex items-center justify-center animate-bounce">
              {activeAlertCount}
            </span>
          )}
        </button>

        {/* User Avatar */}
        <div className="flex items-center gap-2 pl-2 border-l border-[#1E2D4A]">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-[#1E2D4A] flex items-center justify-center text-xs font-bold text-slate-300">
            SO
          </div>
          <div className="hidden lg:block text-left">
            <div className="text-xs font-semibold text-slate-200">Security Officer</div>
            <div className="text-[10px] text-slate-400">admin@fraudshield.ai</div>
          </div>
        </div>
      </div>
    </header>
  );
};

