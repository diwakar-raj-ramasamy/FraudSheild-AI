from typing import List, Dict, Any

class SafetyAdvisor:
    """
    Provides context-aware cyber hygiene guidance and urgent post-exposure
    remediation protocols based on identified attack classifications.
    Strict Security Axiom: NEVER asks users for passwords, OTPs, or financial secrets.
    """

    def get_attack_advice(self, attack_types: List[str]) -> List[str]:
        advice = []
        if "PHISHING" in attack_types:
            advice.extend([
                "Do not enter passwords, usernames, or One-Time Passwords (OTPs).",
                "Leave this website immediately and verify the official web address manually.",
                "Ensure your browser address bar displays the legitimate domain."
            ])
        if "FAKE_LOGIN_PAGE" in attack_types:
            advice.extend([
                "Never submit login credentials on unverified third-party domains.",
                "Verify whether the current URL matches the authentic service provider.",
                "Use the FraudShield Safe Exit feature to return to a safe browser state."
            ])
        if "FINANCIAL_SCAM" in attack_types:
            advice.extend([
                "Do not authorize any transactions, payments, or cryptocurrency transfers.",
                "Never share your banking credentials, CVV, or crypto wallet seed phrases.",
                "Contact your financial institution through their verified customer support hotline."
            ])
        if "TYPOSQUATTING" in attack_types:
            advice.extend([
                "This domain looks deceptively similar to a well-known brand.",
                "Close the tab and manually type the correct, verified website domain in your address bar."
            ])
        if "MALICIOUS_REDIRECT" in attack_types:
            advice.extend([
                "This site redirected through multiple intermediary domains.",
                "Do not trust the final destination page or interact with any prompts."
            ])
        if "DANGEROUS_DOWNLOAD" in attack_types:
            advice.extend([
                "Do not open, launch, or extract the downloaded file.",
                "Cancel the download immediately or delete the file from your download folder."
            ])

        if not advice:
            advice.append("Exercise caution and avoid providing personal or financial information.")

        return list(dict.fromkeys(advice))

    def get_post_exposure_guidance(self, exposure_type: str) -> Dict[str, Any]:
        """
        Actionable safety steps for users who already submitted data prior to detection.
        """
        exposure_type = exposure_type.upper()
        
        if "PASSWORD" in exposure_type:
            return {
                "situation": "Password or Login Submitted",
                "urgency": "HIGH",
                "steps": [
                    "Immediately open the official website in a new, clean tab and change your password.",
                    "If you reuse this password on other accounts, change those passwords immediately.",
                    "Enable Multi-Factor Authentication (MFA / Authenticator app) on your official account.",
                    "Review recent account login sessions and sign out of all active devices."
                ]
            }
        elif "BANKING" in exposure_type or "PAYMENT" in exposure_type:
            return {
                "situation": "Banking or Payment Card Details Entered",
                "urgency": "CRITICAL",
                "steps": [
                    "Immediately contact your bank or credit card provider via the official phone number on your card.",
                    "Request a temporary freeze or lock on the affected card/account.",
                    "Monitor your transaction statement closely for any unauthorized or micro-charges.",
                    "File a fraud report with your financial institution's cybersecurity department."
                ]
            }
        elif "OTP" in exposure_type or "2FA" in exposure_type:
            return {
                "situation": "One-Time Password (OTP) or 2FA Code Shared",
                "urgency": "CRITICAL",
                "steps": [
                    "Treat this situation as urgent: The attacker may be attempting to finalize a login or transaction right now.",
                    "Immediately contact the service provider's emergency fraud line.",
                    "Change your primary account password instantly to invalidate active authentication sessions.",
                    "Revoke authorized OAuth apps and check for unauthorized trusted devices."
                ]
            }
        elif "FILE" in exposure_type or "DOWNLOAD" in exposure_type:
            return {
                "situation": "Suspicious File Downloaded or Executed",
                "urgency": "HIGH",
                "steps": [
                    "DO NOT open, double-click, or extract the downloaded file.",
                    "Permanently delete the file from your Downloads folder and empty your Recycle Bin.",
                    "Run a full anti-malware system scan using your operating system's endpoint security solution.",
                    "Disconnect your device from the local network temporarily if you suspect code was executed."
                ]
            }

        return {
            "situation": "General Suspicious Interaction",
            "urgency": "MEDIUM",
            "steps": [
                "Clear your browser cookies and site cache for the suspicious domain.",
                "Never communicate further with the suspicious entity.",
                "Ensure your browser and operating system have the latest security patches installed."
            ]
        }

safety_advisor = SafetyAdvisor()

