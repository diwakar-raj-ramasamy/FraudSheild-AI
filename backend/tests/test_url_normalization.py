import pytest
from app.utils.url_utils import normalize_url, extract_domain, compute_url_hash, is_ip_address

def test_url_normalization():
    # Test standard lowercase and default port removal
    url = "HTTP://Example.COM:80/path//to///resource/?b=2&a=1#frag"
    normalized = normalize_url(url)
    assert normalized.startswith("http://example.com/path/to/resource?a=1&b=2")
    assert "#frag" not in normalized

    # Test missing scheme defaults to http
    assert normalize_url("google.com/search") == "http://google.com/search"

def test_extract_domain():
    assert extract_domain("https://secure.paypa1.top/login") == "secure.paypa1.top"
    assert extract_domain("http://192.168.1.1:8080/test") == "192.168.1.1"

def test_is_ip_address():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1") is True
    assert is_ip_address("google.com") is False
    assert is_ip_address("paypa1.com") is False

def test_url_hash():
    h1 = compute_url_hash("http://test.com/login")
    h2 = compute_url_hash("http://test.com/login/")
    assert len(h1) == 64
    assert h1 == h2
