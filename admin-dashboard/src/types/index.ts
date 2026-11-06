export interface MetricData {
  total_scans: number;
  threats_detected: number;
  critical_threats: number;
  threats_prevented: number;
  active_alerts: number;
  active_campaigns: number;
  files_analyzed: number;
  affected_devices: number;
}

export interface AttackDistributionItem {
  name: string;
  value: number;
}

export interface TimelineTrendItem {
  date: string;
  scans: number;
  threats: number;
}

export interface MetricsOverviewResponse {
  metrics: MetricData;
  charts: {
    attack_distribution: AttackDistributionItem[];
    timeline: TimelineTrendItem[];
  };
}

export interface FindingItem {
  rule_id: string;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  contribution: number;
}

export interface XAIFactor {
  factor: string;
  weight: number;
  rationale: string;
}

export interface ThreatItem {
  id: string;
  url: string;
  domain: string;
  risk_score: number;
  classification: "SAFE" | "CAUTION" | "CRITICAL";
  first_seen: string;
  last_seen: string;
  attack_types: string[];
  findings?: FindingItem[];
  xai_factors?: XAIFactor[];
}

export interface InfrastructureDetail {
  domain: string;
  observed_ip?: string;
  resolved_ips: string[];
  asn?: string;
  asn_org?: string;
  country?: string;
  reverse_dns?: string;
  dns_records: Record<string, string[]>;
  ssl_info: {
    has_ssl: boolean;
    issuer?: string;
    grade?: string;
  };
  observed_at: string;
  forensic_disclaimer?: string;
}

export interface InvestigationDossier {
  id: string;
  url: string;
  domain: string;
  risk_score: number;
  classification: "SAFE" | "CAUTION" | "CRITICAL";
  attack_types: string[];
  first_seen: string;
  last_seen: string;
  detection_count: number;
  unique_device_count: number;
  findings: FindingItem[];
  xai_factors: XAIFactor[];
  infrastructure?: InfrastructureDetail;
  threat_intelligence: Record<string, any>;
  related_events: Array<{
    id: string;
    device_id: string;
    risk_score: number;
    classification: string;
    detected_at: string;
    page_title?: string;
  }>;
}

export interface FraudCampaignItem {
  id: string;
  domain: string;
  campaign_name: string;
  status: "ACTIVE" | "MITIGATED" | "INVESTIGATING";
  total_detections: number;
  unique_devices_count: number;
  first_seen: string;
  last_seen: string;
  attack_types: string[];
  confidence_score: number;
  observed_ips: string[];
  notes?: string;
}

export interface AdminAlertItem {
  id: string;
  alert_type: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  title: string;
  message: string;
  details: Record<string, any>;
  is_read: boolean;
  is_resolved: boolean;
  campaign_id?: string;
  url_id?: string;
  created_at: string;
}

export interface BlocklistEntryItem {
  id: string;
  target: string;
  target_type: "DOMAIN" | "URL" | "HASH";
  reason: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  added_by: string;
  is_active: boolean;
  created_at: string;
}

export interface DangerousDownloadItem {
  id: string;
  file_name: string;
  file_extension: string;
  mime_type?: string;
  file_hash?: string;
  download_url: string;
  source_domain: string;
  risk_score: number;
  reasons: string[];
  detected_at: string;
}

export interface FileAnalysisItem {
  id: string;
  file_name: string;
  file_type: "PDF" | "DOCX" | "CSV" | "XLSX";
  file_size: number;
  sha256: string;
  risk_score: number;
  classification: "SAFE" | "CAUTION" | "CRITICAL";
  metadata_extracted: Record<string, any>;
  indicators_found: Array<{
    type: string;
    severity: string;
    description: string;
  }>;
  extracted_urls: string[];
  extracted_domains: string[];
  extracted_ips: string[];
  extracted_emails: string[];
  xai_factors: XAIFactor[];
  created_at: string;
}

export interface DeviceItem {
  id: string;
  installation_pseudonym: string;
  extension_version: string;
  user_agent?: string;
  created_at: string;
  last_seen: string;
}

