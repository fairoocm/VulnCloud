
import requests
from urllib.parse import urlparse

from scanner.target_policy import validate_target_with_ip
from scanner.safe_http import safe_https_headers
from scanner.tls_check import check_certificate
from scanner.scoring import calculate_security_score
from scanner.recommendations import generate_recommendations


SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS connections.",
    "Content-Security-Policy": "Helps reduce certain content injection risks.",
    "X-Content-Type-Options": "Helps prevent MIME type sniffing.",
    "X-Frame-Options": "Helps protect against clickjacking.",
    "Referrer-Policy": "Controls referrer information sent by browsers."
}


def _is_local_demo_target(url):
    try:
        parsed = urlparse(url.strip())

        return (
            parsed.scheme == "http"
            and parsed.hostname in ("localhost", "127.0.0.1")
            and parsed.port == 5000
            and not parsed.username
            and not parsed.password
        )
    except ValueError:
        return False


def analyze_headers(url, authorized=False):

    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "error": "Enter a valid target URL."
        }

    url = url.strip()
    parsed_url = urlparse(url)

    tls_result = None

    try:
        # Local educational demo target
        if _is_local_demo_target(url):

            response = requests.get(
                url,
                timeout=10,
                allow_redirects=False
            )

            status_code = response.status_code
            response_headers = dict(response.headers)
            response.close()

        else:
            # Public targets require explicit dashboard authorization
            if not authorized:
                return {
                    "success": False,
                    "error": "Authorization confirmation is required for public targets."
                }

            allowed, message, pinned_ip = validate_target_with_ip(url)

            if not allowed:
                return {
                    "success": False,
                    "error": message
                }

            if not pinned_ip:
                return {
                    "success": False,
                    "error": "Could not obtain a validated public IP address."
                }

            # Connect using the same validated IP
            http_result = safe_https_headers(
                url,
                pinned_ip=pinned_ip
            )

            status_code = http_result["status_code"]
            response_headers = http_result["headers"]

            # Check TLS using the same validated IP
            tls_result = check_certificate(
                parsed_url.hostname,
                pinned_ip=pinned_ip
            )

        results = []

        for header, recommendation in SECURITY_HEADERS.items():

            if (
                header == "Strict-Transport-Security"
                and parsed_url.scheme != "https"
            ):
                status = "NOT APPLICABLE"

            elif header in response_headers:
                status = "PRESENT"

            else:
                status = "MISSING"

            results.append({
                "name": header,
                "status": status,
                "recommendation": recommendation
            })

        score = calculate_security_score(
            results,
            tls_result
        )

        recommendations = generate_recommendations(
            results,
            tls_result,
            target=url
        )

        return {
            "success": True,
            "target": url,
            "status_code": status_code,
            "headers": results,
            "tls": tls_result,
            "score": score,
            "recommendations": recommendations
        }

    except (
        requests.RequestException,
        OSError,
        ValueError,
        KeyError
    ) as error:

        return {
            "success": False,
            "error": str(error)
        }
