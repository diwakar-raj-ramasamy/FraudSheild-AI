import React from "react";
import { ShieldAlert, AlertTriangle, ArrowLeft, ExternalLink, Slash } from "lucide-react";

export default function ThreatWarning() {
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get("url") || "Unknown Malicious URL";

  function isSafeUrl(urlStr: string): boolean {
    try {
      const parsed = new URL(urlStr);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
      return false;
    }
  }

  function handleReturnToSafety() {
    window.location.href = "https://www.google.com";
  }

  function handleProceedAnyway() {
    if (!isSafeUrl(blockedUrl)) {
      alert("Security Violation: The requested URL scheme is unsafe and cannot be opened.");
      return;
    }

    if (confirm("WARNING: Proceeding to a confirmed malicious site risks credential theft, malware infection, and financial fraud. Do you still wish to proceed?")) {
      window.location.href = blockedUrl;
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
      <div className="max-w-xl w-full bg-slate-900 border-2 border-red-800/80 rounded-2xl shadow-2xl p-8 flex flex-col items-center text-center">
        <div className="w-20 h-20 bg-red-600/20 text-red-500 rounded-3xl flex items-center justify-center mb-6 border border-red-500/40">
          <ShieldAlert className="w-12 h-12" />
        </div>

        <span className="text-xs font-black tracking-widest uppercase text-red-400 bg-red-950/80 px-3 py-1 rounded-full border border-red-800/60 mb-2">
          Centralized Threat Defense
        </span>

        <h1 className="text-2xl font-black text-white mb-2">
          Access Blocked to Malicious Website
        </h1>

        <p className="text-sm text-slate-400 mb-6">
          FraudShield AI blocked your navigation to the following destination because it is registered on our verified Centralized Threat Blocklist:
        </p>

        <div className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-red-400 break-all mb-6">
          {blockedUrl}
        </div>

        <div className="w-full bg-red-950/30 border border-red-900/50 rounded-xl p-4 text-xs text-left text-slate-300 space-y-2 mb-8">
          <div className="font-bold text-red-300 flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            Why was this blocked?
          </div>
          <p className="text-slate-400">
            This destination was analyzed and verified as a malicious phishing host, financial scam portal, or malware staging drop. Visiting it may compromise your system or identity.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row items-center gap-3 w-full">
          <button
            onClick={handleReturnToSafety}
            className="w-full sm:flex-1 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-black py-3 px-6 rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-emerald-950 transition active:scale-98"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Safety</span>
          </button>

          <button
            onClick={handleProceedAnyway}
            className="w-full sm:w-auto px-4 py-3 bg-transparent hover:bg-slate-800 border border-slate-700 hover:border-slate-600 text-slate-400 hover:text-red-400 text-xs font-semibold rounded-xl transition flex items-center justify-center gap-1.5"
          >
            <Slash className="w-3.5 h-3.5" />
            <span>Proceed Anyway (Unsafe)</span>
          </button>
        </div>
      </div>
    </div>
  );
}
