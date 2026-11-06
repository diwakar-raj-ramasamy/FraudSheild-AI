import React from "react";
import { AlertTriangle, CheckCircle, ShieldAlert } from "lucide-react";

interface RiskBadgeProps {
  score: number;
  classification?: string;
  showIcon?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ score, classification, showIcon = true }) => {
  const isCritical = score >= 60 || classification === "CRITICAL";
  const isCaution = (score >= 25 && score < 60) || classification === "CAUTION";

  let bg = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  let label = "SAFE";
  let Icon = CheckCircle;

  if (isCritical) {
    bg = "bg-red-500/10 text-red-400 border-red-500/30";
    label = "CRITICAL";
    Icon = ShieldAlert;
  } else if (isCaution) {
    bg = "bg-amber-500/10 text-amber-400 border-amber-500/30";
    label = "CAUTION";
    Icon = AlertTriangle;
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${bg}`}>
      {showIcon && <Icon className="w-3.5 h-3.5 shrink-0" />}
      <span>{score}/100</span>
      <span className="opacity-75 text-[10px]">({classification || label})</span>
    </span>
  );
};

