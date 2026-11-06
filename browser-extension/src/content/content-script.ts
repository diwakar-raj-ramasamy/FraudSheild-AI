import { DomSignals, ScanResponse } from "../types";
import { isInternalOrBrowserPage } from "../utils/url";

// Safety check: do not inject into browser chrome or extension pages
if (!isInternalOrBrowserPage(window.location.href)) {
  initContentInspector();
}

function initContentInspector() {
  // Collect DOM indicators safely without accessing user keystrokes
  const domSignals: DomSignals = {
    has_password_field: document.querySelectorAll('input[type="password"]').length > 0,
    has_otp_field: document.querySelectorAll(
      'input[autocomplete="one-time-code"], input[name*="otp" i], input[name*="2fa" i], input[id*="otp" i]'
    ).length > 0,
    form_actions: Array.from(document.querySelectorAll('form'))
      .map((f) => f.action)
      .filter(Boolean),
    claimed_brand: detectClaimedBrand(),
    suspicious_inline_scripts: document.querySelectorAll('script:not([src])').length,
    unsafe_dom_sinks: 0,
    eval_occurrences: 0,
    redirect_hops: [window.location.href]
  };

  // Dispatch to background service worker for hybrid AI scanning
  chrome.runtime.sendMessage({
    type: "DOM_SIGNALS_DETECTED",
    payload: {
      url: window.location.href,
      title: document.title,
      referrer: document.referrer,
      domSignals
    }
  });

  // Listen for scan results to render real-time user alert if needed
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "SCAN_RESULT_READY") {
      const scan: ScanResponse = message.payload;
      if (scan.classification === "CRITICAL" || scan.risk_score >= 60) {
        injectThreatWarningBanner(scan);
      }
    }
  });
}

function detectClaimedBrand(): string {
  const textSample = (document.title + " " + document.body?.innerText?.substring(0, 1000)).toLowerCase();
  const brands = [
    "paypal", "google", "apple", "microsoft", "amazon", "netflix",
    "facebook", "chase", "bank of america", "binance", "coinbase", "metamask", "irs"
  ];
  for (const b of brands) {
    if (textSample.includes(b)) {
      return b;
    }
  }
  return "";
}

function injectThreatWarningBanner(scan: ScanResponse) {
  // Prevent duplicate banner injection
  if (document.getElementById("fraudshield-alert-banner")) return;

  const banner = document.createElement("div");
  banner.id = "fraudshield-alert-banner";
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    z-index: 2147483647;
    background: #0F172A;
    color: #F8FAFC;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    border-bottom: 4px solid #EF4444;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6);
    padding: 16px 24px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 12px;
  `;

  const topRow = document.createElement("div");
  topRow.style.cssText = "display: flex; justify-content: space-between; align-items: center;";

  const brandTitle = document.createElement("div");
  brandTitle.style.cssText = "display: flex; align-items: center; gap: 10px;";

  const shieldIcon = document.createElement("span");
  shieldIcon.style.fontSize = "24px";
  shieldIcon.textContent = "🛡️";

  const titleContainer = document.createElement("div");

  const headerTitle = document.createElement("div");
  headerTitle.style.cssText = "font-weight: 800; font-size: 17px; letter-spacing: 0.5px; color: #F87171;";
  headerTitle.textContent = "FRAUDSHIELD AI SECURITY ALERT — HIGH-RISK WEBSITE DETECTED";

  const threatDesc = document.createElement("div");
  threatDesc.style.cssText = "font-size: 12px; color: #94A3B8;";
  const threatsList = (scan.attack_types && scan.attack_types.length > 0)
    ? scan.attack_types.join(", ")
    : "Suspicious Web Activity";
  threatDesc.textContent = `Threats Detected: ${threatsList} • Risk Score: ${scan.risk_score}/100`;

  titleContainer.appendChild(headerTitle);
  titleContainer.appendChild(threatDesc);
  brandTitle.appendChild(shieldIcon);
  brandTitle.appendChild(titleContainer);

  const actionGroup = document.createElement("div");
  actionGroup.style.cssText = "display: flex; align-items: center; gap: 12px;";

  // The primary FraudShield Safe Exit Button
  const safeExitBtn = document.createElement("button");
  safeExitBtn.textContent = "🟢 LEAVE THIS WEBSITE";
  safeExitBtn.style.cssText = `
    background: #10B981;
    color: #064E3B;
    border: none;
    font-weight: 800;
    font-size: 14px;
    padding: 10px 20px;
    border-radius: 6px;
    cursor: pointer;
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.4);
    transition: transform 0.1s ease;
  `;
  safeExitBtn.onmouseover = () => (safeExitBtn.style.transform = "scale(1.03)");
  safeExitBtn.onmouseout = () => (safeExitBtn.style.transform = "scale(1)");
  safeExitBtn.onclick = () => {
    chrome.runtime.sendMessage({
      type: "TRIGGER_SAFE_EXIT",
      url: scan.url,
      attack: scan.attack_types[0] || "Phishing",
      score: scan.risk_score
    });
  };

  const dismissBtn = document.createElement("button");
  dismissBtn.textContent = "Dismiss Warning";
  dismissBtn.style.cssText = `
    background: transparent;
    color: #94A3B8;
    border: 1px solid #334155;
    font-size: 12px;
    padding: 8px 14px;
    border-radius: 6px;
    cursor: pointer;
  `;
  dismissBtn.onclick = () => banner.remove();

  actionGroup.appendChild(safeExitBtn);
  actionGroup.appendChild(dismissBtn);

  topRow.appendChild(brandTitle);
  topRow.appendChild(actionGroup);

  // Why was this detected section (Explainable AI)
  const xaiRow = document.createElement("div");
  xaiRow.style.cssText = `
    background: #1E293B;
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 13px;
    color: #E2E8F0;
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
  `;

  const xaiTitle = document.createElement("div");
  const strongTitle = document.createElement("strong");
  strongTitle.textContent = "Why was this detected?";
  xaiTitle.appendChild(strongTitle);
  xaiRow.appendChild(xaiTitle);

  if (Array.isArray(scan.xai_factors)) {
    scan.xai_factors.slice(0, 3).forEach((f) => {
      const item = document.createElement("div");
      
      const weightSpan = document.createElement("span");
      weightSpan.style.cssText = "color: #F87171; font-weight: bold;";
      weightSpan.textContent = `+${f.weight} `;

      const factorText = document.createTextNode(`${f.factor} — `);
      const rationaleItalic = document.createElement("em");
      rationaleItalic.textContent = f.rationale;

      item.appendChild(weightSpan);
      item.appendChild(factorText);
      item.appendChild(rationaleItalic);
      xaiRow.appendChild(item);
    });
  }

  banner.appendChild(topRow);
  banner.appendChild(xaiRow);

  document.body.prepend(banner);
}
