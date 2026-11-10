from unittest.mock import Mock
from scanner import headers


def test_public_scan_requires_authorization():
    result = headers.analyze_headers("https://example.com")

    assert result["success"] is False
    assert "authorization" in result["error"].lower()


def test_public_scan_uses_same_validated_ip(monkeypatch):
    validated_ip = "93.184.216.34"

    monkeypatch.setattr(
        headers,
        "validate_target_with_ip",
        lambda url: (True, "Approved", validated_ip)
    )

    def fake_http(url, pinned_ip=None):
        assert pinned_ip == validated_ip
        return {
            "status_code": 200,
            "headers": {},
            "target": url
        }

    def fake_tls(hostname, pinned_ip=None):
        assert hostname == "example.com"
        assert pinned_ip == validated_ip
        return {"success": True, "verification": "Valid"}

    monkeypatch.setattr(headers, "safe_https_headers", fake_http)
    monkeypatch.setattr(headers, "check_certificate", fake_tls)
    monkeypatch.setattr(headers, "calculate_security_score", lambda h, tls: 50)
    monkeypatch.setattr(headers, "generate_recommendations", lambda h, tls, target: [])

    result = headers.analyze_headers(
        "https://example.com",
        authorized=True
    )

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["score"] == 50


def test_public_scan_rejects_unapproved_target(monkeypatch):
    monkeypatch.setattr(
        headers,
        "validate_target_with_ip",
        lambda url: (False, "Target not authorized", None)
    )

    result = headers.analyze_headers(
        "https://example.com",
        authorized=True
    )

    assert result["success"] is False
    assert "authorized" in result["error"].lower()


def test_local_demo_scan(monkeypatch):
    response = Mock()
    response.status_code = 200
    response.headers = {
        "Content-Security-Policy": "default-src 'self'"
    }

    monkeypatch.setattr(
        headers.requests,
        "get",
        lambda *args, **kwargs: response
    )

    monkeypatch.setattr(headers, "calculate_security_score", lambda h, tls: 25)
    monkeypatch.setattr(headers, "generate_recommendations", lambda h, tls, target: [])

    result = headers.analyze_headers("http://localhost:5000")

    assert result["success"] is True
    assert result["status_code"] == 200
    assert result["tls"] is None
    response.close.assert_called_once()
