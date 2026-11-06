import React, { useState } from "react";
import { ShieldCheck, AlertOctagon, CheckCircle2, Lock, CreditCard, KeyRound, FileWarning, ArrowLeft, ExternalLink } from "lucide-react";

export default function SafeExit() {
  const urlParams = new URLSearchParams(window.location.search);
  const leftUrl = urlParams.get("url") || "Unknown Destination";
  const attack = urlParams.get("attack") || "Possible Phishing & Fake Login";
  const score = urlParams.get("score") || "92";

  const [activeTab, setActiveTab] = useState<"general" | "password" | "banking" | "otp" | "file">("general");

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6">
      <div className="max-w-2xl w-full bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Safe Exit Header Banner */}
        <div className="bg-emerald-950/60 border-b border-emerald-800/40 p-6 flex items-center gap-4">
          <div className="w-14 h-14 bg-emerald-500/20 text-emerald-400 rounded-2xl flex items-center justify-center shrink-0 border border-emerald-500/30">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold tracking-wider uppercase text-emerald-400 bg-emerald-900/60 px-2 py-0.5 rounded border border-emerald-700/50">
                Safe Exit Activated
              </span>
              <span className="text-xs text-slate-400">Risk Score: {score}/100</span>
            </div>
            <h1 className="text-xl font-black text-white mt-1">
              You Have Safely Left a Dangerous Website
            </h1>
            <p className="text-xs text-slate-300 mt-0.5">
              FraudShield AI prevented further interaction with: <span className="font-mono text-red-400 break-all">{leftUrl}</span>
            </p>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 flex flex-col gap-6">
          {/* Threat summary */}
          <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 flex items-start gap-3">
            <AlertOctagon className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <h2 className="text-sm font-bold text-red-300">Detected Threat: {attack}</h2>
              <p className="text-xs text-slate-400 mt-1">
                The target website was flagged by our multi-signal intelligence engine for exhibiting deceptive credential harvesting, domain spoofing, or fraudulent financial patterns.
              </p>
            </div>
          </div>

          {/* Standard Next Steps */}
          <div>
            <h3 className="text-sm font-bold text-slate-200 mb-3 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Recommended Security Actions
            </h3>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs text-slate-300">
              <li className="bg-slate-950/50 border border-slate-800/60 p-3 rounded-lg flex items-start gap-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <span><strong>Do not return:</strong> Avoid re-visiting the link or clicking any email buttons that led you there.</span>
              </li>
              <li className="bg-slate-950/50 border border-slate-800/60 p-3 rounded-lg flex items-start gap-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <span><strong>Do not enter credentials:</strong> Never provide account passwords or personal info on unverified domains.</span>
              </li>
              <li className="bg-slate-950/50 border border-slate-800/60 p-3 rounded-lg flex items-start gap-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <span><strong>Open authentic site manually:</strong> Type the official address directly into your browser URL bar.</span>
              </li>
              <li className="bg-slate-950/50 border border-slate-800/60 p-3 rounded-lg flex items-start gap-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <span><strong>Report suspicious emails:</strong> If received via email, mark as Phishing in your email provider.</span>
              </li>
            </ul>
          </div>

          {/* Post-Exposure Remediation Protocol */}
          <div className="border-t border-slate-800 pt-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-amber-400 flex items-center gap-2">
                <span>⚠️ Did you interact or enter details before leaving?</span>
              </h3>
              <span className="text-[11px] text-slate-500">Select situation for steps</span>
            </div>

            {/* Situation Tabs */}
            <div className="grid grid-cols-4 gap-2 mb-4">
              <button
                onClick={() => setActiveTab("password")}
                className={`flex flex-col items-center justify-center p-2.5 rounded-lg border text-xs font-semibold transition ${
                  activeTab === "password"
                    ? "bg-blue-600/20 border-blue-500 text-blue-300"
                    : "bg-slate-950/40 border-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                <Lock className="w-4 h-4 mb-1" />
                <span>Password</span>
              </button>
              <button
                onClick={() => setActiveTab("banking")}
                className={`flex flex-col items-center justify-center p-2.5 rounded-lg border text-xs font-semibold transition ${
                  activeTab === "banking"
                    ? "bg-blue-600/20 border-blue-500 text-blue-300"
                    : "bg-slate-950/40 border-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                <CreditCard className="w-4 h-4 mb-1" />
                <span>Banking / Card</span>
              </button>
              <button
                onClick={() => setActiveTab("otp")}
                className={`flex flex-col items-center justify-center p-2.5 rounded-lg border text-xs font-semibold transition ${
                  activeTab === "otp"
                    ? "bg-blue-600/20 border-blue-500 text-blue-300"
                    : "bg-slate-950/40 border-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                <KeyRound className="w-4 h-4 mb-1" />
                <span>OTP / 2FA</span>
              </button>
              <button
                onClick={() => setActiveTab("file")}
                className={`flex flex-col items-center justify-center p-2.5 rounded-lg border text-xs font-semibold transition ${
                  activeTab === "file"
                    ? "bg-blue-600/20 border-blue-500 text-blue-300"
                    : "bg-slate-950/40 border-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                <FileWarning className="w-4 h-4 mb-1" />
                <span>Downloaded File</span>
              </button>
            </div>

            {/* Situation Guidance Card */}
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs">
              {activeTab === "general" && (
                <p className="text-slate-400">
                  If you submitted any passwords, financial information, or One-Time Passwords before FraudShield activated, select one of the tabs above for emergency remediation steps.
                </p>
              )}

              {activeTab === "password" && (
                <div className="space-y-2">
                  <div className="font-bold text-red-400">IMMEDIATE ACTION FOR COMPROMISED PASSWORDS:</div>
                  <ol className="list-decimal pl-4 space-y-1.5 text-slate-300">
                    <li>Immediately visit the authentic service website in a clean browser tab and reset your password.</li>
                    <li>If you use the same password on other platforms (e.g. email, social media), change those passwords immediately.</li>
                    <li>Enable Multi-Factor Authentication (MFA / Authenticator App) on your authentic account.</li>
                    <li>Check your account session history and force "Sign out of all other devices".</li>
                  </ol>
                </div>
              )}

              {activeTab === "banking" && (
                <div className="space-y-2">
                  <div className="font-bold text-red-400">CRITICAL ACTION FOR FINANCIAL DETAILS:</div>
                  <ol className="list-decimal pl-4 space-y-1.5 text-slate-300">
                    <li>Call your bank or credit card company immediately using the phone number printed on the back of your card.</li>
                    <li>Request an immediate freeze or cancellation of the card entered on the malicious site.</li>
                    <li>Check your recent transaction history for unauthorized charges or test micro-transactions.</li>
                  </ol>
                </div>
              )}

              {activeTab === "otp" && (
                <div className="space-y-2">
                  <div className="font-bold text-red-400">URGENT ACTION FOR DISCLOSED OTP / 2FA CODES:</div>
                  <ol className="list-decimal pl-4 space-y-1.5 text-slate-300">
                    <li>Treat this with immediate urgency: Attackers use fresh OTPs to complete fraudulent logins in real time.</li>
                    <li>Contact the service provider's emergency security hotline right away.</li>
                    <li>Change your account password immediately to invalidate active authentication tokens.</li>
                  </ol>
                </div>
              )}

              {activeTab === "file" && (
                <div className="space-y-2">
                  <div className="font-bold text-red-400">ACTION FOR SUSPICIOUS DOWNLOADS:</div>
                  <ol className="list-decimal pl-4 space-y-1.5 text-slate-300">
                    <li>DO NOT open, launch, or double-click the downloaded file.</li>
                    <li>Delete the file from your Downloads folder and empty your Recycle Bin/Trash immediately.</li>
                    <li>Run a full system malware scan using your antivirus or operating system security suite.</li>
                  </ol>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-slate-950 border-t border-slate-800 p-4 flex items-center justify-between text-xs text-slate-500">
          <span>Protected by FraudShield AI Endpoint Defense</span>
          <button
            onClick={() => window.close()}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold rounded-lg transition"
          >
            Close Tab
          </button>
        </div>
      </div>
    </div>
  );
}

