import React from "react";
import { Info, ShieldAlert } from "lucide-react";
import { XAIFactor } from "../types";

interface XAIExplanationCardProps {
  factors: XAIFactor[];
  title?: string;
}

export const XAIExplanationCard: React.FC<XAIExplanationCardProps> = ({
  factors,
  title = "Explainable AI (XAI) Attribution Breakdown"
}) => {
  if (!factors || factors.length === 0) {
    return (
      <div className="bg-[#111A2E] border border-[#1E2D4A] rounded-xl p-4 text-xs text-slate-400">
        No anomalous XAI risk factors identified. Target appears benign.
      </div>
    );
  }

  return (
    <div className="bg-[#111A2E] border border-[#1E2D4A] rounded-xl p-4">
      <div className="flex items-center gap-2 mb-3">
        <Info className="w-4 h-4 text-blue-400" />
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">{title}</h4>
      </div>
      <div className="space-y-2.5">
        {factors.map((f, i) => (
          <div key={i} className="flex flex-col gap-1 bg-[#070B14] border border-[#1E2D4A]/60 rounded-lg p-2.5">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-200">{f.factor}</span>
              <span className="text-red-400 font-bold bg-red-950/60 border border-red-900/60 px-2 py-0.5 rounded text-[11px]">
                +{f.weight} pts
              </span>
            </div>
            <p className="text-[11px] text-slate-400">{f.rationale}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

