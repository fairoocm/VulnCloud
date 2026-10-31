
import requests
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "Helps enforce HTTPS connections.",

    "Content-Security-Policy":
        "Helps reduce certain content injection risks.",

    "X-Content-Type-Options":
        "Helps prevent MIME type sniffing.",

    "X-Frame-Options":
        "Helps protect against clickjacking.",

    "Referrer-Policy":
        "Controls referrer information sent by browsers."
}


def analyze_headers(url):

    parsed_url = urlparse(url)

    if parsed_url.scheme not in ("http", "https") or parsed_url.hostname not in (
        "localhost", "127.0.0.1"
    ):
        return {
            "success": False,
            "error": "Only localhost targets are allowed."
        }

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=False
        )

        results = []

        for header, recommendation in SECURITY_HEADERS.items():

            if header == "Strict-Transport-Security" and parsed_url.scheme != "https":
                status = "NOT APPLICABLE"

            elif header in response.headers:
                status = "PRESENT"

            else:
                status = "MISSING"

            results.append({
                "name": header,
                "status": status,
                "recommendation": recommendation
            })

        return {
            "success": True,
            "target": url,
            "status_code": response.status_code,
            "headers": results
        }

    except requests.RequestException as error:

        return {
            "success": False,
            "error": str(error)
        }
