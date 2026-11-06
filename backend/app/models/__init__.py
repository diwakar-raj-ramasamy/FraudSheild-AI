import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.core.database import Base

def generate_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="analyst")  # admin, analyst, user
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utc_now)

class Device(Base):
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    installation_pseudonym = Column(String(100), unique=True, index=True, nullable=False)
    extension_version = Column(String(50), default="1.0.0")
    user_agent = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    scan_results = relationship("ScanResult", back_populates="device")
    detection_events = relationship("DetectionEvent", back_populates="device")

class URLRecord(Base):
    __tablename__ = "urls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    normalized_url = Column(Text, index=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    url_hash = Column(String(64), index=True, nullable=False)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now, onupdate=utc_now)
    classification = Column(String(50), default="UNVERIFIED")  # SAFE, CAUTION, CRITICAL
    current_risk_score = Column(Integer, default=0)

    # Relationships
    scan_results = relationship("ScanResult", back_populates="url_record")
    detection_events = relationship("DetectionEvent", back_populates="url_record")

class ScanResult(Base):
    __tablename__ = "scan_results"
    __table_args__ = (
        Index("ix_scan_results_url_created", "url_id", "created_at"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    url_id = Column(String(36), ForeignKey("urls.id"), index=True, nullable=False)
    device_id = Column(String(36), ForeignKey("devices.id"), index=True, nullable=True)
    risk_score = Column(Integer, index=True, nullable=False)
    classification = Column(String(50), index=True, nullable=False)
    attack_types = Column(JSON, default=list)  # ["PHISHING", "FAKE_LOGIN_PAGE"]
    findings = Column(JSON, default=list)  # List of findings with contributions
    recommended_actions = Column(JSON, default=list)
    ml_score = Column(Float, nullable=True)
    threat_intel_data = Column(JSON, default=dict)
    xai_factors = Column(JSON, default=list)
    created_at = Column(DateTime, index=True, default=utc_now)

    # Relationships
    url_record = relationship("URLRecord", back_populates="scan_results")
    device = relationship("Device", back_populates="scan_results")

class DetectionEvent(Base):
    __tablename__ = "detection_events"
    __table_args__ = (
        Index("ix_detection_events_url_detected", "url_id", "detected_at"),
        Index("ix_detection_events_device_detected", "device_id", "detected_at"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    url_id = Column(String(36), ForeignKey("urls.id"), index=True, nullable=False)
    device_id = Column(String(36), ForeignKey("devices.id"), index=True, nullable=False)
    risk_score = Column(Integer, index=True, nullable=False)
    classification = Column(String(50), index=True, nullable=False)
    attack_types = Column(JSON, default=list)
    page_title = Column(String(255), nullable=True)
    referrer = Column(Text, nullable=True)
    detected_at = Column(DateTime, index=True, default=utc_now)

    # Relationships
    url_record = relationship("URLRecord", back_populates="detection_events")
    device = relationship("Device", back_populates="detection_events")

class FraudCampaign(Base):
    __tablename__ = "fraud_campaigns"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain = Column(String(255), index=True, nullable=False)
    campaign_name = Column(String(255), nullable=False)
    status = Column(String(50), default="ACTIVE", index=True)  # ACTIVE, MITIGATED, INVESTIGATING
    total_detections = Column(Integer, default=1)
    unique_devices_count = Column(Integer, default=1)
    first_seen = Column(DateTime, default=utc_now, index=True)
    last_seen = Column(DateTime, default=utc_now, onupdate=utc_now, index=True)
    attack_types = Column(JSON, default=list)
    confidence_score = Column(Integer, default=85)
    observed_ips = Column(JSON, default=list)
    notes = Column(Text, nullable=True)

    def __init__(self, **kwargs):
        if "detection_count" in kwargs and "total_detections" not in kwargs:
            kwargs["total_detections"] = kwargs.pop("detection_count")
        if "affected_devices_count" in kwargs and "unique_devices_count" not in kwargs:
            kwargs["unique_devices_count"] = kwargs.pop("affected_devices_count")
        super().__init__(**kwargs)

    @property
    def detection_count(self):
        return self.total_detections

    @detection_count.setter
    def detection_count(self, val):
        self.total_detections = val

    @property
    def affected_devices_count(self):
        return self.unique_devices_count

    @affected_devices_count.setter
    def affected_devices_count(self, val):
        self.unique_devices_count = val

class AdminAlert(Base):
    __tablename__ = "admin_alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    alert_type = Column(String(100), index=True, nullable=False)  # CAMPAIGN_DETECTED, HIGH_RISK_SPIKE, BLOCKLIST_SYNC
    severity = Column(String(50), default="HIGH", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    details = Column(JSON, default=dict)
    is_read = Column(Boolean, default=False, index=True)
    is_resolved = Column(Boolean, default=False, index=True)
    campaign_id = Column(String(36), ForeignKey("fraud_campaigns.id"), index=True, nullable=True)
    url_id = Column(String(36), ForeignKey("urls.id"), index=True, nullable=True)
    created_at = Column(DateTime, default=utc_now, index=True)

    def __init__(self, **kwargs):
        if "description" in kwargs and "message" not in kwargs:
            kwargs["message"] = kwargs.pop("description")
        if "event_type" in kwargs and "alert_type" not in kwargs:
            kwargs["alert_type"] = kwargs.pop("event_type")
        super().__init__(**kwargs)

    @property
    def description(self):
        return self.message

    @description.setter
    def description(self, val):
        self.message = val

    @property
    def event_type(self):
        return self.alert_type

    @event_type.setter
    def event_type(self, val):
        self.alert_type = val

class BlocklistEntry(Base):
    __tablename__ = "blocklist_entries"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target = Column(String(255), index=True, nullable=False)  # URL or domain or hash
    target_type = Column(String(50), default="DOMAIN")  # DOMAIN, URL, HASH
    reason = Column(String(255), nullable=False)
    severity = Column(String(50), default="CRITICAL")
    added_by = Column(String(100), default="ADMIN")
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=utc_now)

class BlocklistMeta(Base):
    __tablename__ = "blocklist_meta"

    id = Column(Integer, primary_key=True)
    current_version = Column(Integer, default=1)
    last_updated = Column(DateTime, default=utc_now, onupdate=utc_now)

class InfrastructureRecord(Base):
    __tablename__ = "infrastructure_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain = Column(String(255), index=True, nullable=False)
    observed_ip = Column(String(100), index=True, nullable=True)  # Clearly noted: Observed Infrastructure IP
    resolved_ips = Column(JSON, default=list)
    asn = Column(String(50), nullable=True)
    asn_org = Column(String(255), nullable=True)
    country = Column(String(10), nullable=True)
    reverse_dns = Column(String(255), nullable=True)
    dns_records = Column(JSON, default=dict)
    ssl_info = Column(JSON, default=dict)
    observed_at = Column(DateTime, default=utc_now, index=True)

class RedirectChain(Base):
    __tablename__ = "redirect_chains"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    initial_url = Column(Text, nullable=False)
    final_url = Column(Text, nullable=False)
    hop_count = Column(Integer, default=1)
    hops = Column(JSON, default=list)
    is_suspicious = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)

class DangerousDownload(Base):
    __tablename__ = "dangerous_downloads"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    file_name = Column(String(255), nullable=False)
    file_extension = Column(String(50), nullable=False)
    mime_type = Column(String(100), nullable=True)
    file_hash = Column(String(64), nullable=True)
    download_url = Column(Text, nullable=False)
    source_domain = Column(String(255), index=True, nullable=False)
    risk_score = Column(Integer, default=80)
    reasons = Column(JSON, default=list)
    device_id = Column(String(36), ForeignKey("devices.id"), index=True, nullable=True)
    detected_at = Column(DateTime, default=utc_now, index=True)

class FileAnalysis(Base):
    __tablename__ = "file_analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    file_name = Column(String(255), nullable=False)
    file_type = Column(String(50), nullable=False)  # PDF, DOCX, CSV, XLSX
    file_size = Column(Integer, nullable=False)
    sha256 = Column(String(64), index=True, nullable=False)
    risk_score = Column(Integer, index=True, nullable=False)
    classification = Column(String(50), index=True, nullable=False)
    metadata_extracted = Column(JSON, default=dict)
    indicators_found = Column(JSON, default=list)
    extracted_urls = Column(JSON, default=list)
    extracted_domains = Column(JSON, default=list)
    extracted_ips = Column(JSON, default=list)
    extracted_emails = Column(JSON, default=list)
    xai_factors = Column(JSON, default=list)
    created_at = Column(DateTime, default=utc_now, index=True)
