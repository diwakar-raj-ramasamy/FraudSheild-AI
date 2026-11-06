import { ScanResponse, DomSignals } from "../types";
import { getInstallationPseudonym } from "../utils/installation";
import { isLocallyBlocked } from "./blocklist";
import { extractDomainFromUrl } from "../utils/url";

const DEFAULT_API_BASE = "http://localhost:8000/api";

export async function getApiBaseUrl(): Promise<string> {
  return new Promise((resolve) => {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(["fs_api_url"], (res) => {
        resolve(res.fs_api_url || DEFAULT_API_BASE);
      });
    } else {
      resolve(DEFAULT_API_BASE);
    }
  });
}

/**
 * Bounded retry wrapper with timeout protection.
 * Catches transient network errors while preventing indefinite blocking.
 */
async function fetchWithTimeout(url: string, options: RequestInit, timeoutMs = 4000): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function fetchWithRetry(url: string, options: RequestInit, retries = 2, delayMs = 400): Promise<Response> {
  let lastError: any = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fetchWithTimeout(url, options);
    } catch (err) {
      lastError = err;
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, delayMs * Math.pow(2, attempt)));
      }
    }
  }
  throw lastError || new Error("Network request failed after retries");
}

export async function scanUrl(
  url: string,
  pageTitle: string = "",
  referrer: string = "",
  domSignals: Partial<DomSignals> = {}
): Promise<ScanResponse> {
  const baseUrl = await getApiBaseUrl();
  const pseudonym = await getInstallationPseudonym();

  try {
    const response = await fetchWithRetry(`${baseUrl}/scan/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        device_pseudonym: pseudonym,
        page_title: pageTitle,
        referrer,
        dom_signals: domSignals
      })
    });

    if (!response.ok) {
      throw new Error(`Scan request failed with HTTP ${response.status}`);
    }

    return await response.json();
  } catch (networkError) {
    console.warn("FraudShield AI: Backend unreachable. Falling back to local offline blocklist inspection.", networkError);
    
    // Offline Graceful Degradation: Check against fast local SQLite/IndexedDB blocklist
    const domain = extractDomainFromUrl(url);
    const blocked = isLocallyBlocked(url) || isLocallyBlocked(domain);

    return {
      url,
      normalized_url: url,
      domain,
      risk_score: blocked ? 100 : 0,
      classification: blocked ? "CRITICAL" : "SAFE",
      attack_types: blocked ? ["LOCAL_BLOCKLIST_MATCH"] : [],
      hard_override: blocked,
      override_reason: blocked ? "Matched local cached blocklist during offline operation" : undefined,
      findings: blocked
        ? [
            {
              rule_id: "RULE-OFFLINE-01",
              title: "Offline Local Blocklist Hit",
              description: "Target destination identified in cached local threat database.",
              severity: "CRITICAL",
              contribution: 100
            }
          ]
        : [],
      xai_factors: [],
      recommended_actions: [],
      threat_intelligence: { offline: true },
      safe_exit_recommended: blocked
    };
  }
}

export async function reportDetectionEvent(
  url: string,
  riskScore: number,
  classification: string,
  attackTypes: string[],
  pageTitle: string = "",
  referrer: string = ""
): Promise<any> {
  const baseUrl = await getApiBaseUrl();
  const pseudonym = await getInstallationPseudonym();

  try {
    const response = await fetchWithRetry(`${baseUrl}/events/detection`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        device_pseudonym: pseudonym,
        risk_score: riskScore,
        classification,
        attack_types: attackTypes,
        page_title: pageTitle,
        referrer
      })
    }, 1, 300);

    return await response.json();
  } catch (err) {
    console.warn("FraudShield AI: Could not report detection event to cloud backend (offline buffer).", err);
    return { status: "buffered_offline" };
  }
}

export async function checkDownloadMetadata(
  fileName: string,
  fileExtension: string,
  downloadUrl: string,
  mimeType: string = ""
): Promise<any> {
  const baseUrl = await getApiBaseUrl();
  const pseudonym = await getInstallationPseudonym();

  try {
    const response = await fetchWithRetry(`${baseUrl}/downloads/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_name: fileName,
        file_extension: fileExtension,
        download_url: downloadUrl,
        mime_type: mimeType,
        device_pseudonym: pseudonym
      })
    });

    return await response.json();
  } catch (err) {
    console.warn("FraudShield AI: Download check failed or offline.", err);
    return {
      is_dangerous: false,
      risk_score: 0,
      reasons: ["Download verification server offline"]
    };
  }
}

export async function fetchBlocklistVersion(): Promise<{ version: number; entries: string[] }> {
  const baseUrl = await getApiBaseUrl();
  const response = await fetchWithRetry(`${baseUrl}/blocklist/version`, { method: "GET" });
  if (!response.ok) {
    throw new Error(`Blocklist sync failed with status ${response.status}`);
  }
  return response.json();
}
