import { fetchBlocklistVersion } from "./api";
import { extractDomainFromUrl } from "../utils/url";

export interface LocalBlocklistCache {
  version: number;
  lastUpdated: number;
  entries: Set<string>;
}

let cachedEntries: Set<string> = new Set();
let cachedVersion = 0;

export async function syncBlocklist(): Promise<void> {
  try {
    const data = await fetchBlocklistVersion();
    if (data.version > cachedVersion) {
      cachedVersion = data.version;
      cachedEntries = new Set(data.entries.map((e) => e.toLowerCase()));
      
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          fs_blocklist_version: cachedVersion,
          fs_blocklist_entries: Array.from(cachedEntries)
        });
      }
    }
  } catch (err) {
    console.warn("FraudShield: Could not sync remote blocklist, using local cache.", err);
  }
}

export async function initLocalBlocklist(): Promise<void> {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["fs_blocklist_version", "fs_blocklist_entries"], (res) => {
      if (res.fs_blocklist_entries) {
        cachedVersion = res.fs_blocklist_version || 1;
        cachedEntries = new Set((res.fs_blocklist_entries as string[]).map((e) => e.toLowerCase()));
      }
    });
  }
}

export function isLocallyBlocked(url: string): boolean {
  const domain = extractDomainFromUrl(url);
  return cachedEntries.has(domain) || cachedEntries.has(url.toLowerCase());
}

