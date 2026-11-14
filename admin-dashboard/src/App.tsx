import React, { useState, useEffect } from "react";
import { Sidebar, PageId } from "./components/Sidebar";
import { Navbar } from "./components/Navbar";
import { QuickScanModal } from "./components/QuickScanModal";
import { LoginModal } from "./components/LoginModal";
import { ErrorBoundary } from "./components/ErrorBoundary";

import { Overview } from "./pages/Overview";
import { ThreatDetectionCenter } from "./pages/ThreatDetectionCenter";
import { AttackInvestigation } from "./pages/AttackInvestigation";
import { CampaignMonitor } from "./pages/CampaignMonitor";
import { DangerousDownloads } from "./pages/DangerousDownloads";
import { FileAnalysisCenter } from "./pages/FileAnalysisCenter";
import { AdminAlerts } from "./pages/AdminAlerts";
import { ThreatBlocklist } from "./pages/ThreatBlocklist";
import { DevicesMonitor } from "./pages/DevicesMonitor";
import { Settings } from "./pages/Settings";
import { api } from "./services/api";

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<PageId>("overview");
  const [investigationThreatId, setInvestigationThreatId] = useState<string | null>(null);
  const [quickScanOpen, setQuickScanOpen] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(api.isAuthenticated());
  const [activeAlertsCount, setActiveAlertsCount] = useState<number>(0);
  const [activeCampaignsCount, setActiveCampaignsCount] = useState<number>(0);
  const [liveToast, setLiveToast] = useState<{ title: string; message: string; severity: string } | null>(null);

  // Poll or fetch initial status count
  const refreshCounts = async () => {
    if (!api.isAuthenticated()) return;
    try {
      const [alerts, campaigns] = await Promise.all([
        api.getAlerts().catch(() => []),
        api.getCampaigns().catch(() => [])
      ]);
      const unresolvedAlerts = alerts.filter((a) => !a.is_resolved).length;
      const activeCamps = campaigns.filter((c) => c.status === "ACTIVE").length;
      setActiveAlertsCount(unresolvedAlerts);
      setActiveCampaignsCount(activeCamps);
    } catch {
      // Graceful fallback
    }
  };

  useEffect(() => {
    const handleUnauthorized = () => {
      setIsAuthenticated(false);
    };
    window.addEventListener("fraudshield_unauthorized", handleUnauthorized);
    return () => window.removeEventListener("fraudshield_unauthorized", handleUnauthorized);
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      refreshCounts();
      const interval = setInterval(refreshCounts, 30000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated]);

  // WebSocket Live Bus - Only connects when authenticated to prevent unauthorized closed connection loops
  useEffect(() => {
    if (!isAuthenticated) return;

    let ws: WebSocket | null = null;
    let reconnectTimeout: any = null;
    let isCancelled = false;

    const connectWs = () => {
      if (isCancelled) return;
      try {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const host = window.location.host;
        const token = api.getAuthToken();
        const wsUrl = token
          ? `${protocol}//${host}/api/ws/events?token=${encodeURIComponent(token)}`
          : `${protocol}//${host}/api/ws/events`;

        ws = new WebSocket(wsUrl);
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === "CAMPAIGN_DETECTED" || data.type === "THREAT_DETECTED" || data.type === "SCAN_COMPLETED") {
              setLiveToast({
                title: data.type === "CAMPAIGN_DETECTED"
                  ? "Emerging Campaign Alert"
                  : (data.payload?.risk_score || 0) >= 60
                  ? "🚨 Critical Threat Intercepted"
                  : "🛡️ Real-Time Telemetry Update",
                message: data.payload?.domain || data.payload?.title || "Live security event recorded.",
                severity: (data.payload?.risk_score || 0) >= 60 ? "CRITICAL" : "HIGH"
              });
              // Refresh badge counts in real time
              refreshCounts();
              // Broadcast to active pages
              window.dispatchEvent(new CustomEvent("fraudshield_live_event", { detail: data }));
              setTimeout(() => setLiveToast(null), 6000);
            }
          } catch {
            // ignore non-json
          }
        };
        ws.onclose = () => {
          if (!isCancelled) {
            reconnectTimeout = setTimeout(connectWs, 5000);
          }
        };
      } catch {
        // Fallback
      }
    };

    connectWs();
    return () => {
      isCancelled = true;
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, [isAuthenticated]);

  const handleNavigateToInvestigation = (threatId?: string) => {
    if (threatId) {
      setInvestigationThreatId(threatId);
    }
    setCurrentPage("investigation");
  };

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    refreshCounts();
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar
        currentPage={currentPage}
        onSelectPage={(page: PageId) => {
          setCurrentPage(page);
          if (page !== "investigation") {
            setInvestigationThreatId(null);
          }
        }}
        unreadAlertsCount={activeAlertsCount}
        activeCampaignsCount={activeCampaignsCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <Navbar
          onOpenQuickScan={() => setQuickScanOpen(true)}
          activeAlertCount={activeAlertsCount}
          onNavigateAlerts={() => setCurrentPage("alerts")}
        />

        {/* Live Event Toast Notification */}
        {liveToast && (
          <div className="mx-6 mt-3 p-3 bg-rose-950/90 border border-rose-600 rounded-xl flex items-center justify-between text-xs text-rose-200 shadow-xl shadow-rose-950/40 animate-bounce">
            <div>
              <span className="font-bold text-white uppercase tracking-wider mr-2">[{liveToast.title}]</span>
              <span>{liveToast.message}</span>
            </div>
            <button
              onClick={() => setLiveToast(null)}
              className="text-rose-400 hover:text-white ml-4 font-mono font-bold"
            >
              ✕
            </button>
          </div>
        )}

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-6">
          <ErrorBoundary fallbackTitle="Page Display Error">
            {currentPage === "overview" && (
              <Overview
                onNavigateInvestigation={handleNavigateToInvestigation}
                onNavigateCampaigns={() => setCurrentPage("campaigns")}
              />
            )}

            {currentPage === "threats" && (
              <ThreatDetectionCenter onInvestigate={handleNavigateToInvestigation} />
            )}

            {currentPage === "investigation" && (
              <AttackInvestigation
                selectedUrlId={investigationThreatId || undefined}
                onBlocklistAdded={() => setCurrentPage("blocklist")}
              />
            )}

            {currentPage === "campaigns" && <CampaignMonitor />}

            {currentPage === "downloads" && <DangerousDownloads />}

            {currentPage === "files" && <FileAnalysisCenter />}

            {currentPage === "alerts" && <AdminAlerts />}

            {currentPage === "blocklist" && <ThreatBlocklist />}

            {currentPage === "devices" && <DevicesMonitor />}

            {currentPage === "settings" && <Settings />}
          </ErrorBoundary>
        </main>
      </div>

      {/* Quick Scan Live Modal */}
      <QuickScanModal
        isOpen={quickScanOpen}
        onClose={() => setQuickScanOpen(false)}
        onInvestigate={handleNavigateToInvestigation}
      />

      {/* Authentication Modal */}
      <LoginModal
        isOpen={!isAuthenticated}
        onLoginSuccess={handleLoginSuccess}
      />
    </div>
  );
};
