from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime

# --- Auth Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    user_email: str

class LoginRequest(BaseModel):
    email: str
    password: str

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = "analyst"

class UserOut(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Scan Schemas ---
class ScanRequest(BaseModel):
    url: str
    device_pseudonym: Optional[str] = None
    page_title: Optional[str] = None
    referrer: Optional[str] = None
    dom_signals: Optional[Dict[str, Any]] = Field(default_factory=dict)
    # dom_signals can include: has_password_field, has_otp_field, form_actions, claimed_brand,
    # suspicious_scripts, inline_event_handlers, iframes_count, redirect_hops

class FindingItem(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    contribution: int  # +25, +30, etc.

class XAIFactor(BaseModel):
    factor: str
    weight: int
    rationale: str

class RecommendedAction(BaseModel):
    action: str
    urgency: str  # IMMEDIATE, RECOMMENDED, ADVISORY
    description: str

class ScanResponse(BaseModel):
    url: str
    normalized_url: str
    domain: str
    risk_score: int  # 0 to 100
    classification: str  # SAFE, CAUTION, CRITICAL
    attack_types: List[str]  # e.g. ["PHISHING", "FAKE_LOGIN_PAGE"]
    hard_override: bool = False
    override_reason: Optional[str] = None
    findings: List[FindingItem] = Field(default_factory=list)
    xai_factors: List[XAIFactor] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict)
    ml_confidence: Optional[float] = None
    safe_exit_recommended: bool = False
    observed_infrastructure: Optional[Dict[str, Any]] = None

# --- Detection Event Schemas ---
class DetectionEventCreate(BaseModel):
    url: str
    device_pseudonym: Optional[str] = "anonymous-endpoint"
    risk_score: int
    classification: str
    attack_types: List[str] = Field(default_factory=list)
    page_title: Optional[str] = None
    referrer: Optional[str] = None

class DetectionEventOut(BaseModel):
    id: str
    url_id: str
    device_id: str
    risk_score: int
    classification: str
    attack_types: List[str]
    page_title: Optional[str]
    detected_at: datetime
    device_pseudonym: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Campaign Schemas ---
class CampaignOut(BaseModel):
    id: str
    domain: str
    campaign_name: str
    status: str
    total_detections: int
    unique_devices_count: int
    first_seen: datetime
    last_seen: datetime
    attack_types: List[str]
    confidence_score: int
    observed_ips: List[str] = Field(default_factory=list)
    notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

# --- Alert Schemas ---
class AlertOut(BaseModel):
    id: str
    alert_type: str
    severity: str
    title: str
    message: str
    details: Dict[str, Any]
    is_read: bool
    is_resolved: bool
    campaign_id: Optional[str] = None
    url_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AlertUpdate(BaseModel):
    is_read: Optional[bool] = None
    is_resolved: Optional[bool] = None

# --- Blocklist Schemas ---
class BlocklistCreate(BaseModel):
    target: str
    target_type: str = "DOMAIN"  # DOMAIN, URL, HASH
    reason: str
    severity: str = "CRITICAL"

class BlocklistEntryOut(BaseModel):
    id: str
    target: str
    target_type: str
    reason: str
    severity: str
    added_by: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class BlocklistVersionResponse(BaseModel):
    version: int
    last_updated: datetime
    entries_count: int
    entries: List[str]  # quick list of targets for extension caching

# --- Investigation Schemas ---
class InfrastructureDetail(BaseModel):
    domain: str
    observed_ip: Optional[str] = None  # Explicitly observed infrastructure IP
    resolved_ips: List[str] = Field(default_factory=list)
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    reverse_dns: Optional[str] = None
    dns_records: Dict[str, Any] = Field(default_factory=dict)
    ssl_info: Dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime

class InvestigationDetail(BaseModel):
    id: str
    url: str
    domain: str
    risk_score: int
    classification: str
    attack_types: List[str]
    first_seen: datetime
    last_seen: datetime
    detection_count: int
    unique_device_count: int
    findings: List[FindingItem] = Field(default_factory=list)
    xai_factors: List[XAIFactor] = Field(default_factory=list)
    infrastructure: Optional[InfrastructureDetail] = None
    redirect_chain: Optional[Dict[str, Any]] = None
    related_events: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict)

# --- Dangerous Downloads ---
class DangerousDownloadCreate(BaseModel):
    file_name: str
    file_extension: Optional[str] = None
    mime_type: Optional[str] = None
    file_hash: Optional[str] = None
    download_url: str
    source_domain: Optional[str] = None
    device_pseudonym: Optional[str] = None

class DangerousDownloadOut(BaseModel):
    id: str
    file_name: str
    file_extension: str
    mime_type: Optional[str] = None
    file_hash: Optional[str] = None
    download_url: str
    source_domain: str
    risk_score: int
    reasons: List[str]
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- File Analysis Schemas ---
class FileAnalysisOut(BaseModel):
    id: str
    file_name: str
    file_type: str
    file_size: int
    sha256: str
    risk_score: int
    classification: str
    metadata_extracted: Dict[str, Any]
    indicators_found: List[Dict[str, Any]]
    extracted_urls: List[str]
    extracted_domains: List[str]
    extracted_ips: List[str]
    extracted_emails: List[str]
    xai_factors: List[XAIFactor]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

