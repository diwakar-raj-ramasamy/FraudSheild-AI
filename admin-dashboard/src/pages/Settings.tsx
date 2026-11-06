import React, { useState } from "react";
import { Settings as SettingsIcon, Key, Sliders, ShieldAlert, Cpu, CheckCircle, Save, Database, BellRing } from "lucide-react";

export const Settings: React.FC = () => {
  const [savedSuccess, setSavedSuccess] = useState(false);

  // API Config State
  const [vtKey, setVtKey] = useState("••••••••••••••••••••••••••••••••");
  const [urlhausKey, setUrlhausKey] = useState("");
  const [phishtankKey, setPhishtankKey] = useState("");

  // Scoring Thresholds State
  const [safeMax, setSafeMax] = useState(39);
  const [cautionMax, setCautionMax] = useState(69);
  const [campaignDevices, setCampaignDevices] = useState(2);
  const [campaignWindow, setCampaignWindow] = useState(60);

  // Security Policy Toggles
  const [autoBlockCritical, setAutoBlockCritical] = useState(true);
  const [enforceHardOverrides, setEnforceHardOverrides] = useState(true);
  const [strictZeroExecution, setStrictZeroExecution] = useState(true);
  const [failSafeProviderMode, setFailSafeProviderMode] = useState(true);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 3000);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <SettingsIcon className="w-6 h-6 text-primary-400" />
            System Configuration & Security Policies
          </h1>
          <p className="text-sm text-slate-400">
            Configure backend threat intelligence feeds, scoring thresholds, correlation heuristics, and safety parameters.
          </p>
        </div>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white font-medium text-xs rounded-lg transition shadow-lg shadow-primary-900/30"
        >
          <Save className="w-4 h-4" />
          Save Configurations
        </button>
      </div>

      {savedSuccess && (
        <div className="bg-emerald-950/80 border border-emerald-700 text-emerald-300 p-3.5 rounded-xl text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>Configuration updated successfully. Engine heuristics and threat intelligence providers synchronized.</span>
        </div>
      )}

      {/* Grid of Setting Sections */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Threat Intelligence API Providers */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <Key className="w-4 h-4 text-primary-400" />
            Threat Intelligence Feeds
          </h2>
          <p className="text-xs text-slate-400">
            Connect commercial and community reputation sources. Modular adapters fall back safely when rate-limited.
          </p>

          <div className="space-y-3 pt-1">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">VirusTotal v3 API Key</label>
              <input
                type="password"
                value={vtKey}
                onChange={(e) => setVtKey(e.target.value)}
                placeholder="vt_api_key_xxxxxxxxxxxxxxxx"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-600 focus:outline-none focus:border-primary-500 font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">URLhaus Auth Key</label>
              <input
                type="password"
                value={urlhausKey}
                onChange={(e) => setUrlhausKey(e.target.value)}
                placeholder="Optional token for elevated rate limits"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-600 focus:outline-none focus:border-primary-500 font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">PhishTank Application Key</label>
              <input
                type="password"
                value={phishtankKey}
                onChange={(e) => setPhishtankKey(e.target.value)}
                placeholder="phishtank_api_key"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-600 focus:outline-none focus:border-primary-500 font-mono"
              />
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800/80">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={failSafeProviderMode}
                onChange={(e) => setFailSafeProviderMode(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-primary-500 focus:ring-0"
              />
              <div className="text-xs">
                <span className="font-semibold text-white">Fail-Safe Feed Invariant</span>
                <p className="text-slate-400 text-[11px] mt-0.5">
                  Enforces rule: <em>"Provider unavailable ≠ URL safe"</em>. Missing reputation lookups never downgrade local heuristic risk scores.
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Dynamic Risk Scoring Thresholds */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <Sliders className="w-4 h-4 text-primary-400" />
            Detection & Severity Thresholds (0–100)
          </h2>
          <p className="text-xs text-slate-400">
            Define boundaries for SAFE, CAUTION, and CRITICAL classifications output by the hybrid scoring engine.
          </p>

          <div className="space-y-4 pt-1">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-emerald-400 font-medium">Safe Maximum Threshold</span>
                <span className="font-mono text-white">0 – {safeMax}</span>
              </div>
              <input
                type="range"
                min="10"
                max="50"
                value={safeMax}
                onChange={(e) => setSafeMax(Number(e.target.value))}
                className="w-full accent-emerald-500 bg-slate-800"
              />
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-medium">Caution Boundary</span>
                <span className="font-mono text-white">{safeMax + 1} – {cautionMax}</span>
              </div>
              <input
                type="range"
                min="51"
                max="80"
                value={cautionMax}
                onChange={(e) => setCautionMax(Number(e.target.value))}
                className="w-full accent-amber-500 bg-slate-800"
              />
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-rose-400 font-medium">Critical Threat Cutoff</span>
                <span className="font-mono text-white">{cautionMax + 1} – 100</span>
              </div>
              <div className="text-[11px] text-slate-400 bg-slate-950 p-2.5 rounded border border-slate-800">
                Scores &ge; {cautionMax + 1} trigger full-screen extension blockages, Safe Exit action bars, and admin campaign correlation sweeps.
              </div>
            </div>
          </div>
        </div>

        {/* Multi-Device Correlation Heuristics */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <Cpu className="w-4 h-4 text-primary-400" />
            Multi-Device Correlation Heuristics
          </h2>
          <p className="text-xs text-slate-400">
            Parameters for automatic clustering of repeated suspicious hits into coordinated attack campaigns.
          </p>

          <div className="space-y-3 pt-1">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Minimum Unique Devices Required to Trigger Campaign
              </label>
              <input
                type="number"
                min="2"
                max="10"
                value={campaignDevices}
                onChange={(e) => setCampaignDevices(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-primary-500 font-mono"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">Default: 2 devices (prevents single-user false positive campaigns).</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Correlation Rolling Window (Minutes)
              </label>
              <input
                type="number"
                min="10"
                max="1440"
                value={campaignWindow}
                onChange={(e) => setCampaignWindow(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white focus:outline-none focus:border-primary-500 font-mono"
              />
              <span className="text-[11px] text-slate-500 mt-1 block">Default: 60 minutes.</span>
            </div>
          </div>
        </div>

        {/* Safe Exit & Forensics Policy */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2 border-b border-slate-800 pb-3">
            <ShieldAlert className="w-4 h-4 text-primary-400" />
            Forensics & Active Protection Guards
          </h2>
          <p className="text-xs text-slate-400">
            Strict safety invariants enforced across the backend and extension clients.
          </p>

          <div className="space-y-3 pt-1">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={autoBlockCritical}
                onChange={(e) => setAutoBlockCritical(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-primary-500 focus:ring-0"
              />
              <div className="text-xs">
                <span className="font-semibold text-white">Auto-Publish to Local Extension Blocklists</span>
                <p className="text-slate-400 text-[11px] mt-0.5">
                  When an admin or the AI confirms a campaign, increment blocklist version and push to clients within 60s.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={enforceHardOverrides}
                onChange={(e) => setEnforceHardOverrides(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-primary-500 focus:ring-0"
              />
              <div className="text-xs">
                <span className="font-semibold text-white">Enforce Deterministic Hard Overrides</span>
                <p className="text-slate-400 text-[11px] mt-0.5">
                  Typosquatting + Credential Harvesting form automatically yields minimum score &ge; 95 regardless of other features.
                </p>
              </div>
            </label>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={strictZeroExecution}
                onChange={(e) => setStrictZeroExecution(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 bg-slate-950 text-primary-500 focus:ring-0"
              />
              <div className="text-xs">
                <span className="font-semibold text-white">Zero-Execution Static Forensics Only</span>
                <p className="text-slate-400 text-[11px] mt-0.5">
                  Uploaded files (PDF, DOCX, CSV, XLSX) are inspected via byte structures and AST parsers with execution disabled.
                </p>
              </div>
            </label>
          </div>
        </div>
      </div>
    </div>
  );
};

