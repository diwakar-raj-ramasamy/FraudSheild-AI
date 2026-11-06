import React from "react";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  color?: "blue" | "red" | "amber" | "emerald" | "purple";
  trend?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  color = "blue",
  trend
}) => {
  const colorMap = {
    blue: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    red: "text-red-400 bg-red-500/10 border-red-500/20",
    amber: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    emerald: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    purple: "text-purple-400 bg-purple-500/10 border-purple-500/20"
  };

  return (
    <div className="bg-[#0C1322] border border-[#1E2D4A] rounded-xl p-4 flex flex-col justify-between hover:border-slate-700 transition">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{title}</span>
        <div className={`p-2 rounded-lg border ${colorMap[color]}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div>
        <div className="text-2xl font-black text-white tracking-tight">{value}</div>
        <div className="flex items-center justify-between mt-1 text-[11px] text-slate-400">
          <span>{subtitle}</span>
          {trend && <span className="text-emerald-400 font-semibold">{trend}</span>}
        </div>
      </div>
    </div>
  );
};

