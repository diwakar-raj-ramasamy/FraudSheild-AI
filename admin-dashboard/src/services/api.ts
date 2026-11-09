import {
  MetricsOverviewResponse,
  ThreatItem,
  InvestigationDossier,
  FraudCampaignItem,
  AdminAlertItem,
  BlocklistEntryItem,
  DangerousDownloadItem,
  FileAnalysisItem,
  DeviceItem
} from "../types";

const API_BASE = "http://localhost:8000/api";
const TOKEN_KEY = "fraudshield_admin_jwt";

export function getAuthToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setAuthToken(token: string) {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function removeAuthToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json"
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      ...headers,
      ...(options?.headers || {})
    }
  });

  if (res.status === 401) {
    // Session expired or invalid
    removeAuthToken();
    window.dispatchEvent(new CustomEvent("fraudshield_unauthorized"));
  }

  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    throw new Error(errorBody.detail || `API Error ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Authentication
  login: async (email: string, password: string): Promise<{ access_token: string; role: string }> => {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || "Authentication failed");
    }
    const data = await res.json();
    setAuthToken(data.access_token);
    return data;
  },

  logout: () => {
    removeAuthToken();
    window.location.reload();
  },

  isAuthenticated: (): boolean => {
    return !!getAuthToken();
  },

  getAuthToken: (): string | null => {
    return getAuthToken();
  },

  // Metrics
  getMetricsOverview: () => fetchJson<MetricsOverviewResponse>("/metrics/overview"),

  // Threats & Investigation
  getThreats: (classification?: string) =>
    fetchJson<ThreatItem[]>(`/threats${classification ? `?classification=${classification}` : ""}`),
  getThreatDetail: (id: string) => fetchJson<any>(`/threats/${id}`),
  getInvestigationDossier: (id: string) => fetchJson<InvestigationDossier>(`/investigation/${id}`),

  // Campaigns
  getCampaigns: () => fetchJson<FraudCampaignItem[]>("/campaigns?status=ALL"),
  blockCampaign: (id: string) => fetchJson<any>(`/campaigns/${id}/block`, { method: "POST" }),

  // Alerts
  getAlerts: () => fetchJson<AdminAlertItem[]>("/alerts"),
  resolveAlert: (id: string) =>
    fetchJson<AdminAlertItem>(`/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ is_resolved: true, is_read: true })
    }),

  // Blocklist
  getBlocklist: () => fetchJson<BlocklistEntryItem[]>("/blocklist"),
  getBlocklistVersion: () => fetchJson<{ version: number; last_updated: string; entries_count: number }>("/blocklist/version"),
  addBlocklistEntry: (target: string, reason: string, target_type: string = "DOMAIN") =>
    fetchJson<BlocklistEntryItem>("/blocklist", {
      method: "POST",
      body: JSON.stringify({ target, reason, target_type, severity: "CRITICAL" })
    }),
  deleteBlocklistEntry: (id: string) =>
    fetchJson<any>(`/blocklist/${id}`, { method: "DELETE" }),

  // Downloads
  getDangerousDownloads: () => fetchJson<DangerousDownloadItem[]>("/downloads"),

  // File Analysis
  getFileAnalyses: () => fetchJson<FileAnalysisItem[]>("/files/analyses"),
  getFileAnalysisDetail: (id: string) => fetchJson<FileAnalysisItem>(`/files/analyses/${id}`),
  uploadFileForAnalysis: async (file: File): Promise<FileAnalysisItem> => {
    const token = getAuthToken();
    const formData = new FormData();
    formData.append("file", file);
    const headers: Record<string, string> = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    const res = await fetch(`${API_BASE}/files/analyze`, {
      method: "POST",
      headers,
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `File upload failed with status ${res.status}`);
    }
    return res.json();
  },

  // Devices
  getDevices: () => fetchJson<DeviceItem[]>("/devices"),

  // Live URL Scanner
  scanUrl: (url: string) =>
    fetchJson<any>("/scan/url", {
      method: "POST",
      body: JSON.stringify({ url })
    })
};
