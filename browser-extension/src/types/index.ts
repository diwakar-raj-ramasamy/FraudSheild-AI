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

export interface RecommendedAction {
  action: string;
  urgency: "IMMEDIATE" | "RECOMMENDED" | "ADVISORY";
  description: string;
}

export interface ScanResponse {
  url: string;
  normalized_url: string;
  domain: string;
  risk_score: number;
  classification: "SAFE" | "CAUTION" | "CRITICAL";
  attack_types: string[];
  hard_override: boolean;
  override_reason?: string;
  findings: FindingItem[];
  xai_factors: XAIFactor[];
  recommended_actions: RecommendedAction[];
  threat_intelligence: Record<string, any>;
  ml_confidence?: number;
  safe_exit_recommended: boolean;
  observed_infrastructure?: Record<string, any>;
}

export interface DomSignals {
  has_password_field: boolean;
  has_otp_field: boolean;
  form_actions: string[];
  claimed_brand: string;
  suspicious_inline_scripts: number;
  unsafe_dom_sinks: number;
  eval_occurrences: number;
  redirect_hops?: string[];
}

