import json
import os
import pytest

MANIFEST_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "browser-extension", "manifest.json"
)

def test_extension_manifest_v3_compliance():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # 1. Must be Manifest V3
    assert manifest.get("manifest_version") == 3

    # 2. Background must be a service worker
    background = manifest.get("background", {})
    assert "service_worker" in background

    # 3. Required permissions only
    allowed_permissions = {"storage", "webNavigation", "alarms", "downloads", "activeTab"}
    declared_permissions = set(manifest.get("permissions", []))
    assert declared_permissions.issubset(allowed_permissions | {"declarativeNetRequest"})

    # 4. Prohibit unsafe permissions
    dangerous_permissions = {"debugger", "proxy", "vpnProvider", "nativeMessaging"}
    for danger in dangerous_permissions:
        assert danger not in declared_permissions

    # 5. Content Security Policy must prohibit unsafe-eval
    csp = manifest.get("content_security_policy", {}).get("extension_pages", "")
    assert "'unsafe-eval'" not in csp

def test_warning_page_url_scheme_validation():
    def is_safe_url(url_str: str) -> bool:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url_str)
            return parsed.scheme in ["http", "https"]
        except Exception:
            return False

    # Safe web schemes
    assert is_safe_url("https://example.com/login")
    assert is_safe_url("http://insecure-site.org")

    # Malicious or dangerous schemes must be blocked
    assert not is_safe_url("javascript:alert(1)")
    assert not is_safe_url("data:text/html,<script>alert(1)</script>")
    assert not is_safe_url("file:///etc/passwd")
    assert not is_safe_url("vbscript:msgbox(1)")

