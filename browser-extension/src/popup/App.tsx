import React, { useEffect, useState } from "react";
import { Shield, AlertTriangle, CheckCircle, ExternalLink, RefreshCw, LogOut, Info } from "lucide-react";
import { ScanResponse } from "../types";

export default function App() {
  const [loading, setLoading] = useState(true);
  const [currentUrl, setCurrentUrl] = useState("");
  const [scan, setScan] = useState<ScanResponse | null>(null);

  useEffect(() => {
    loadActiveTabScan();
  }, []);

  function loadActiveTabScan() {
    setLoading(true);
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (tab && tab.url) {
          setCurrentUrl(tab.url);
          chrome.runtime.sendMessage(
            { type: "GET_CURRENT_TAB_SCAN", tabId: tab.id },
            (response) => {
              if (response && response.scan) {
                setScan(response.scan);
              }
              setLoading(false);
            }
          );
        } else {
          setLoading(false);
        }
      });
    } else {
      // Demo preview mode
      setCurrentUrl("https://secure-login-paypa1.top/signin.php");
      setScan({
        url: "https://secure-login-paypa1.top/signin.php",
        normalized_url: "http://secure-login-paypa1.top/signin.php",
        domain: "secure-login-paypa1.top",
        risk_score: 92,
        classification: "CRITICAL",
        attack_types: ["PHISHING", "FAKE_LOGIN_PAGE"],
        hard_override: true,
        findings: [
          { rule_id: "R1", title: "Fake Credential Form", description: "Impersonates PayPal", severity: "CRITICAL", contribution: 35 },
          { rule_id: "R2", title: "Typosquatting", description: "paypa1.top visually imitates paypal.com", severity: "HIGH", contribution: 25 }
        ],
        xai_factors: [
          { factor: "Impersonated Login Form", weight: 35, rationale: "Detected credential inputs on counterfeit domain" },
          { factor: "Typosquatting Domain", weight: 25, rationale: "Replaces 'l' with numeral '1'" },
          { factor: "Suspicious TLD (.top)", weight: 15, rationale: "High-abuse registrar namespace" }
        ],
        recommended_actions: [
          { action: "LEAVE THIS WEBSITE", urgency: "IMMEDIATE", description: "Do not enter passwords or personal info" }
        ],
        threat_intelligence: {},
        safe_exit_recommended: true
      });
      setLoading(false);
    }
  }

  function handleSafeExit() {
    if (typeof chrome !== "undefined" && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: "TRIGGER_SAFE_EXIT",
        url: currentUrl,
        attack: scan?.attack_types[0] || "Phishing",
        score: scan?.risk_score || 90
      });
    }
  }

  const score = scan ? scan.risk_score : 0;
  const isCritical = scan?.classification === "CRITICAL" || score >= 60;
  const isCaution = scan?.classification === "CAUTION" || (score >= 25 && score < 60);
  const isSafe = !isCritical && !isCaution;

  return (
    <div className="flex flex-col min-h-[480px] bg-slate-950 text-slate-100 p-4 select-none">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 bg-blue-600/20 text-blue-400 rounded-lg">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wide text-white">FRAUDSHIELD AI</h1>
            <p className="text-[10px] text-slate-400 uppercase tracking-wider">Browser Cyber Defense</p>
          </div>
        </div>
        <button
          onClick={loadActiveTabScan}
          title="Rescan Page"
          className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {loading ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-2 text-slate-400 py-12">
          <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
          <p className="text-xs">Analyzing web signals & threat feeds...</p>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {/* Risk Score Card */}
          <div
            className={`p-4 rounded-xl border flex items-center justify-between ${
              isCritical
                ? "bg-red-950/40 border-red-800/60"
                : isCaution
                ? "bg-amber-950/40 border-amber-800/60"
                : "bg-emerald-950/40 border-emerald-800/60"
            }`}
          >
            <div>
              <div className="flex items-center gap-1.5 mb-1">
                {isCritical ? (
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                ) : isCaution ? (
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                ) : (
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                )}
                <span
                  className={`text-xs font-bold uppercase tracking-wider ${
                    isCritical ? "text-red-400" : isCaution ? "text-amber-400" : "text-emerald-400"
                  }`}
                >
                  {scan ? scan.classification : "SAFE / UNVERIFIED"}
                </span>
              </div>
              <p className="text-xs text-slate-300 truncate max-w-[210px]" title={currentUrl}>
                {scan?.domain || currentUrl}
              </p>
            </div>

            <div className="text-right">
              <div
                className={`text-2xl font-black ${
                  isCritical ? "text-red-400" : isCaution ? "text-amber-400" : "text-emerald-400"
                }`}
              >
                {score}
                <span className="text-xs font-normal text-slate-400">/100</span>
              </div>
              <span className="text-[10px] text-slate-400">Risk Score</span>
            </div>
          </div>

          {/* Safe Exit Primary Action (If high risk) */}
          {isCritical && (
            <button
              onClick={handleSafeExit}
              className="w-full bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-black py-2.5 px-4 rounded-lg flex items-center justify-center gap-2 shadow-lg shadow-emerald-900/40 transition active:scale-98"
            >
              <LogOut className="w-4 h-4" />
              <span>LEAVE THIS WEBSITE</span>
            </button>
          )}

          {/* Threat Types Badges */}
          {scan && scan.attack_types.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {scan.attack_types.map((t, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700"
                >
                  {t}
                </span>
              ))}
            </div>
          )}

          {/* Explainable AI Breakdown */}
          {scan && scan.xai_factors.length > 0 && (
            <div className="bg-slate-900/80 border border-slate-800/80 rounded-lg p-3">
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-300 mb-2">
                <Info className="w-3.5 h-3.5 text-blue-400" />
                <span>Why was this detected?</span>
              </div>
              <div className="flex flex-col gap-1.5">
                {scan.xai_factors.slice(0, 3).map((f, i) => (
                  <div key={i} className="text-xs flex items-start gap-1.5 text-slate-300">
                    <span className="text-red-400 font-bold shrink-0">+{f.weight}</span>
                    <span className="text-slate-200">
                      <strong>{f.factor}:</strong> <span className="text-slate-400">{f.rationale}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action Recommendations */}
          {scan && scan.recommended_actions.length > 0 && (
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-3">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block mb-1.5">
                Safety Guidance
              </span>
              <ul className="text-xs text-slate-300 space-y-1 pl-4 list-disc">
                {scan.recommended_actions.map((act, i) => (
                  <li key={i}>
                    <strong>{act.action}:</strong> {act.description}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <div className="mt-auto pt-3 border-t border-slate-800 flex items-center justify-between text-[10px] text-slate-500">
        <span>FraudShield AI v1.0.0</span>
        <span className="text-emerald-500 font-medium">● Local Cache Active</span>
      </div>
    </div>
  );
}

