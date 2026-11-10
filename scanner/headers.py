import http.client
import requests
from urllib.parse import urljoin, urlparse

from scanner.target_policy import validate_target_with_ip
from scanner.safe_http import safe_http_headers, safe_https_headers
from scanner.tls_check import check_certificate
from scanner.scoring import calculate_security_score
from scanner.recommendations import generate_recommendations

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS connections.",
    "Content-Security-Policy": "Helps reduce certain content injection risks.",
    "X-Content-Type-Options": "Helps prevent MIME type sniffing.",
    "X-Frame-Options": "Helps protect against clickjacking.",
    "Referrer-Policy": "Controls referrer information sent by browsers.",
}

def _is_local_demo_target(url):
    try:
        parsed = urlparse(url.strip())
        return (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
                and parsed.port == 5000 and not parsed.username and not parsed.password)
    except ValueError:
        return False

def _request_public_target(url):
    current_url = url
    max_redirects = 3
    for redirect_number in range(max_redirects + 1):
        allowed, message, pinned_ip = validate_target_with_ip(current_url)
        if not allowed:
            raise ValueError(message)
        if not pinned_ip:
            raise ValueError("Could not obtain a validated public IP address.")
        parsed = urlparse(current_url)
        if parsed.scheme == "https":
            result = safe_https_headers(current_url, pinned_ip=pinned_ip, allow_redirects=True)
        else:
            result = safe_http_headers(current_url, pinned_ip=pinned_ip, allow_redirects=True)
        if result["status_code"] not in (301, 302, 303, 307, 308):
            tls_result = check_certificate(parsed.hostname, pinned_ip=pinned_ip) if parsed.scheme == "https" else None
            return result, tls_result
        location = result.get("location")
        if not location:
            raise ValueError("The target returned a redirect without a Location header.")
        if redirect_number == max_redirects:
            raise ValueError("The target exceeded the maximum of 3 redirects.")
        current_url = urljoin(current_url, location)
    raise ValueError("Unable to complete the redirect chain.")

def analyze_headers(url, authorized=False):
    if not isinstance(url, str) or not url.strip():
        return {"success": False, "error": "Enter a valid target URL."}
    url = url.strip()
    try:
        parsed_url = urlparse(url)
        tls_result = None
        if _is_local_demo_target(url):
            response = requests.get(url, timeout=10, allow_redirects=False)
            try:
                status_code = response.status_code
                response_headers = dict(response.headers)
            finally:
                response.close()
        else:
            if not authorized:
                return {"success": False, "error": "Authorization confirmation is required for public targets."}
            http_result, tls_result = _request_public_target(url)
            status_code = http_result["status_code"]
            response_headers = http_result["headers"]

        results = []
        for header, recommendation in SECURITY_HEADERS.items():
            if header == "Strict-Transport-Security" and parsed_url.scheme != "https":
                status = "NOT APPLICABLE"
            elif header in response_headers:
                status = "PRESENT"
            else:
                status = "MISSING"
            results.append({"name": header, "status": status, "recommendation": recommendation})

        score = calculate_security_score(results, tls_result)
        recommendations = generate_recommendations(results, tls_result, target=url)
        return {"success": True, "target": url, "status_code": status_code,
                "headers": results, "tls": tls_result, "score": score,
                "recommendations": recommendations}
    except (requests.RequestException, http.client.HTTPException, OSError, ValueError, KeyError) as error:
        return {"success": False, "error": str(error)}
