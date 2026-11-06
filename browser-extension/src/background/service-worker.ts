import { initLocalBlocklist, syncBlocklist, isLocallyBlocked } from "../services/blocklist";
import { scanUrl, reportDetectionEvent, checkDownloadMetadata } from "../services/api";
import { isInternalOrBrowserPage } from "../utils/url";
import { ScanResponse } from "../types";

// In-flight scan promise deduplication map
const inFlightScans = new Map<string, Promise<ScanResponse>>();
// Recent event reporting cache to prevent duplicate events on rapid re-renders
const recentEventDetections = new Map<string, number>();

// --- Storage Persistence for Service Worker Lifecycle Resilience ---

async function persistTabScan(tabId: number, scan: ScanResponse): Promise<void> {
  try {
    const storageKey = `tab_scan_${tabId}`;
    await chrome.storage.local.set({
      [storageKey]: {
        scan,
        timestamp: Date.now()
      }
    });
  } catch (e) {
    console.warn("FraudShield: Failed to persist scan to storage:", e);
  }
}

async function retrieveTabScan(tabId: number): Promise<ScanResponse | null> {
  try {
    const storageKey = `tab_scan_${tabId}`;
    const result = await chrome.storage.local.get([storageKey]);
    return result[storageKey]?.scan || null;
  } catch {
    return null;
  }
}

// Clean up stored state when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove([`tab_scan_${tabId}`]);
});

// 1. Initialize Extension Lifecycle
chrome.runtime.onInstalled.addListener(async () => {
  console.log("🛡️ FraudShield AI Extension initialized.");
  await initLocalBlocklist();
  await syncBlocklist();

  // Set recurring alarm for blocklist sync every 30 minutes
  chrome.alarms.create("sync_blocklist", { periodInMinutes: 30 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "sync_blocklist") {
    syncBlocklist();
  }
});

// 2. Pre-Navigation Fast Local Blocklist Enforcement
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (isInternalOrBrowserPage(url)) return;

  if (isLocallyBlocked(url)) {
    console.warn(`🛡️ FraudShield AI: Blocking access to blocklisted destination: ${url}`);
    const warningUrl = chrome.runtime.getURL(`src/warning/index.html?url=${encodeURIComponent(url)}`);
    chrome.tabs.update(details.tabId, { url: warningUrl });
  }
});

// 3. Tab Badge Indicator
function updateTabBadge(tabId: number, score: number, classification: string) {
  try {
    if (classification === "CRITICAL") {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
      chrome.action.setBadgeText({ tabId, text: `${score}` });
    } else if (classification === "CAUTION") {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
      chrome.action.setBadgeText({ tabId, text: `${score}` });
    } else {
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
      chrome.action.setBadgeText({ tabId, text: "✓" });
    }
  } catch (err) {
    console.warn("Badge update failed (tab may have closed):", err);
  }
}

// 4. Download Monitoring (Static metadata check for dangerous executable disguise patterns)
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const filename = downloadItem.filename || "";
  const parts = filename.split('.');
  const ext = parts.length > 1 ? `.${parts[parts.length - 1]}` : "";

  try {
    const result = await checkDownloadMetadata(
      filename,
      ext,
      downloadItem.finalUrl || downloadItem.url,
      downloadItem.mime || ""
    );

    if (result && result.risk_score >= 60) {
      chrome.notifications?.create({
        type: "basic",
        iconUrl: "assets/shield-alert.png",
        title: "🛡️ FraudShield AI: Dangerous Download Detected",
        message: `High risk detected in '${filename}': ${result.reasons?.[0] || 'Malicious executable pattern'}. Do not open this file!`,
        priority: 2
      });
    }
  } catch (err) {
    console.error("FraudShield download check error:", err);
  }
});

// 5. Secure Message Dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Validate message sender origin (Mitigates unauthorized cross-extension message injection)
  if (sender.id !== chrome.runtime.id) {
    console.warn("FraudShield AI: Rejected message from unauthorized sender:", sender.id);
    return false;
  }

  const tabId = sender.tab?.id;

  if (message.type === "DOM_SIGNALS_DETECTED") {
    const { url, title, referrer, domSignals } = message.payload;
    if (isInternalOrBrowserPage(url)) return false;

    // Deduplicate in-flight requests for the same URL
    let scanPromise = inFlightScans.get(url);
    if (!scanPromise) {
      scanPromise = scanUrl(url, title, referrer, domSignals);
      inFlightScans.set(url, scanPromise);
      // Clean up after 5 seconds
      setTimeout(() => inFlightScans.delete(url), 5000);
    }

    scanPromise
      .then(async (scanResult) => {
        if (tabId) {
          await persistTabScan(tabId, scanResult);
          updateTabBadge(tabId, scanResult.risk_score, scanResult.classification);

          // Deduplicated event reporting (only once per 30s per URL)
          const dedupKey = `${tabId}_${url}`;
          const lastReported = recentEventDetections.get(dedupKey) || 0;
          const now = Date.now();

          if (scanResult.risk_score >= 25 && now - lastReported > 30000) {
            recentEventDetections.set(dedupKey, now);
            await reportDetectionEvent(
              scanResult.url,
              scanResult.risk_score,
              scanResult.classification,
              scanResult.attack_types,
              title,
              referrer
            );
          }

          // Send scan result back to content script
          chrome.tabs.sendMessage(tabId, {
            type: "SCAN_RESULT_READY",
            payload: scanResult
          }).catch(() => {});
        }
        sendResponse({ status: "success", data: scanResult });
      })
      .catch((err) => {
        console.error("Scan error:", err);
        sendResponse({ status: "error", error: err.message });
      });

    return true; // Keep message channel open for async response
  }

  if (message.type === "GET_CURRENT_TAB_SCAN") {
    const reqTabId = message.tabId;
    retrieveTabScan(reqTabId).then((scan) => {
      sendResponse({ scan });
    });
    return true;
  }

  if (message.type === "TRIGGER_SAFE_EXIT") {
    const targetUrl = message.url;
    const safeExitUrl = chrome.runtime.getURL(
      `src/safe-exit/index.html?url=${encodeURIComponent(targetUrl || "")}&attack=${encodeURIComponent(message.attack || "Phishing")}&score=${message.score || 90}`
    );
    if (tabId) {
      chrome.tabs.update(tabId, { url: safeExitUrl });
    } else {
      chrome.tabs.create({ url: safeExitUrl });
    }
    sendResponse({ status: "navigating_to_safety" });
    return false;
  }
});
