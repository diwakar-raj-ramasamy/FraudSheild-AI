from sqlalchemy.orm import Session
from app.core.database import engine, Base, SessionLocal
from app.core.security import get_password_hash
from app.models import (
    User, Device, URLRecord, ScanResult, DetectionEvent, FraudCampaign,
    AdminAlert, BlocklistEntry, BlocklistMeta, InfrastructureRecord, DangerousDownload
)
from app.utils.url_utils import compute_url_hash
from datetime import datetime, timedelta, timezone

def init_db():
    print("Creating all database tables...")
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        # 1. Create Default Admin User
        admin_email = "admin@fraudshield.ai"
        existing_admin = db.query(User).filter(User.email == admin_email).first()
        if not existing_admin:
            admin_user = User(
                email=admin_email,
                hashed_password=get_password_hash("Admin@FraudShield2026!"),
                full_name="Chief Security Officer (FraudShield Admin)",
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            print(f"Created default admin account: {admin_email}")

        # 2. Initialize Blocklist Metadata & Seed Entries
        meta = db.query(BlocklistMeta).first()
        if not meta:
            meta = BlocklistMeta(current_version=1)
            db.add(meta)

        seed_blocked = [
            ("phishing-login-paypa1.top", "DOMAIN", "Confirmed credential harvesting targeting PayPal", "CRITICAL"),
            ("g00gle-security-update.xyz", "DOMAIN", "Credential harvesting and OAuth hijack", "CRITICAL"),
            ("update-kyc-binance-portal.work", "DOMAIN", "Financial crypto scam and KYC phishing", "CRITICAL"),
            ("185.220.101.5", "DOMAIN", "Known command-and-control drop server", "CRITICAL")
        ]

        for target, t_type, reason, sev in seed_blocked:
            if not db.query(BlocklistEntry).filter(BlocklistEntry.target == target).first():
                db.add(BlocklistEntry(
                    target=target,
                    target_type=t_type,
                    reason=reason,
                    severity=sev,
                    added_by="SYSTEM_SEED"
                ))

        # 3. Seed Sample Devices
        dev_a = db.query(Device).filter(Device.installation_pseudonym == "endpoint-dev-01a").first()
        if not dev_a:
            dev_a = Device(installation_pseudonym="endpoint-dev-01a", extension_version="1.0.0", user_agent="Chrome 122 Windows")
            dev_b = Device(installation_pseudonym="endpoint-dev-02b", extension_version="1.0.0", user_agent="Chrome 122 MacOS")
            dev_c = Device(installation_pseudonym="endpoint-dev-03c", extension_version="1.0.0", user_agent="Edge 122 Windows")
            db.add_all([dev_a, dev_b, dev_c])
            db.flush()

        # 4. Seed Seeded Active Campaign & Infrastructure Record
        seed_campaign_domain = "secure-login-paypa1.xyz"
        existing_campaign = db.query(FraudCampaign).filter(FraudCampaign.domain == seed_campaign_domain).first()
        if not existing_campaign:
            camp = FraudCampaign(
                domain=seed_campaign_domain,
                campaign_name=f"Emerging Phishing Campaign targeting {seed_campaign_domain}",
                status="ACTIVE",
                total_detections=6,
                unique_devices_count=3,
                attack_types=["PHISHING", "FAKE_LOGIN_PAGE", "TYPOSQUATTING"],
                confidence_score=96,
                observed_ips=["104.21.44.182", "172.67.189.22"],
                notes="Correlated 6 detections across 3 unique browser installations within past 12 hours."
            )
            db.add(camp)
            db.flush()

            # Add alert for this campaign
            db.add(AdminAlert(
                alert_type="CAMPAIGN_DETECTED",
                severity="CRITICAL",
                title="🚨 REPEATED FRAUD URL DETECTED",
                message=f"Multi-device fraud campaign detected on '{seed_campaign_domain}'. 6 detections across 3 endpoints.",
                details={
                    "domain": seed_campaign_domain,
                    "risk_score": 94,
                    "attack_types": ["PHISHING", "FAKE_LOGIN_PAGE"],
                    "total_detections": 6,
                    "unique_devices": 3,
                    "observed_ips": ["104.21.44.182", "172.67.189.22"]
                },
                campaign_id=camp.id
            ))

            # Add Infrastructure record
            db.add(InfrastructureRecord(
                domain=seed_campaign_domain,
                observed_ip="104.21.44.182",
                resolved_ips=["104.21.44.182", "172.67.189.22"],
                asn="AS13335",
                asn_org="Cloudflare Inc.",
                country="US",
                reverse_dns="104.21.44.182.cloudflare.com",
                dns_records={"A": ["104.21.44.182", "172.67.189.22"]},
                ssl_info={"has_ssl": True, "issuer": "Let's Encrypt", "grade": "Active TLS"}
            ))

            # Add URL record and scan result
            norm_u = f"http://{seed_campaign_domain}/auth/login.php"
            url_r = URLRecord(
                normalized_url=norm_u,
                domain=seed_campaign_domain,
                url_hash=compute_url_hash(norm_u),
                classification="CRITICAL",
                current_risk_score=94
            )
            db.add(url_r)
            db.flush()

            db.add(ScanResult(
                url_id=url_r.id,
                device_id=dev_a.id if dev_a else None,
                risk_score=94,
                classification="CRITICAL",
                attack_types=["PHISHING", "FAKE_LOGIN_PAGE", "TYPOSQUATTING"],
                findings=[
                    {"rule_id": "RULE-FL-01", "title": "Suspicious Credential Collection Form", "description": "Form harvests credentials mimicking PayPal on unauthorized domain", "severity": "CRITICAL", "contribution": 35},
                    {"rule_id": "RULE-TS-01", "title": "Homoglyph Character Substitution", "description": "Domain 'paypa1' uses numeral '1' to deceive users visually", "severity": "HIGH", "contribution": 30},
                    {"rule_id": "RULE-URL-01", "title": "Suspicious TLD", "description": "Domain uses abuse-prone .xyz top level domain", "severity": "MEDIUM", "contribution": 15}
                ],
                recommended_actions=[
                    {"action": "LEAVE THIS WEBSITE IMMEDIATELY", "urgency": "IMMEDIATE", "description": "Use FraudShield Safe Exit."},
                    {"action": "DO NOT ENTER CREDENTIALS", "urgency": "IMMEDIATE", "description": "Never provide password or OTP."}
                ],
                ml_score=0.92,
                xai_factors=[
                    {"factor": "Credential Harvesting on Spoofed Domain", "weight": 35, "rationale": "Password inputs found on domain impersonating PayPal"},
                    {"factor": "Typosquatting (paypa1)", "weight": 30, "rationale": "Visual imitation of official domain paypal.com"},
                    {"factor": "Abuse TLD (.xyz)", "weight": 15, "rationale": "High-risk registrar space"}
                ]
            ))

            # Add Dangerous Download sample
            db.add(DangerousDownload(
                file_name="invoice_march_statement.pdf.exe",
                file_extension=".exe",
                mime_type="application/x-msdownload",
                file_hash="9f83a45c6123498f7e2a4b9c1d0e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e",
                download_url=f"http://{seed_campaign_domain}/downloads/invoice_march_statement.pdf.exe",
                source_domain=seed_campaign_domain,
                risk_score=95,
                reasons=["Deceptive double-extension (.pdf.exe) concealing Windows executable binary"],
                device_id=dev_a.id if dev_a else None
            ))

        db.commit()
        print("Database initialization and seed records completed successfully.")
    except Exception as e:
        db.rollback()
        print(f"Database initialization error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    init_db()

