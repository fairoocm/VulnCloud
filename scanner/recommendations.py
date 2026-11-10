"""Generate practical recommendations from VulnCloud scan findings."""
from urllib.parse import urlsplit
import ipaddress


HEADER_GUIDANCE = {
    "Strict-Transport-Security": {
        "title": "Enable HTTP Strict Transport Security (HSTS)",
        "why": "Helps browsers use HTTPS for future visits and reduces downgrade risks.",
        "fix": "After confirming the site works fully over HTTPS, configure the web server to send a Strict-Transport-Security header. Start with a short max-age and increase it after testing.",
    },
    "Content-Security-Policy": {
        "title": "Add a Content Security Policy (CSP)",
        "why": "Restricts which sources the browser may load content from and can reduce the impact of some injection attacks.",
        "fix": "Create a policy for the site's actual scripts, styles, images, fonts, and other resources. Test it with Content-Security-Policy-Report-Only before enforcing it.",
    },
    "X-Content-Type-Options": {
        "title": "Set X-Content-Type-Options",
        "why": "Helps prevent browsers from interpreting a response as a different content type.",
        "fix": "Configure the server to send X-Content-Type-Options: nosniff.",
    },
    "X-Frame-Options": {
        "title": "Protect pages against unwanted framing",
        "why": "Can reduce clickjacking risk by controlling whether pages may be embedded in frames.",
        "fix": "Set X-Frame-Options: DENY or SAMEORIGIN as appropriate, or use the frame-ancestors directive in Content-Security-Policy.",
    },
    "Referrer-Policy": {
        "title": "Set a Referrer-Policy",
        "why": "Controls how much referrer information browsers send when navigating away from a page.",
        "fix": "Choose a policy appropriate for the application, commonly strict-origin-when-cross-origin, and configure the Referrer-Policy response header.",
    },
}


def _is_local_development_target(target):
    """Identify localhost/loopback targets used for local development."""
    if not target:
        return False
    try:
        hostname = (urlsplit(target).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def generate_recommendations(headers, tls=None, target=None):
    """Return actionable recommendations, omitting HTTPS advice for localhost."""
    recommendations = []

    for item in headers or []:
        if str(item.get("status", "")).upper() != "MISSING":
            continue
        name = item.get("name") or item.get("header")
        guidance = HEADER_GUIDANCE.get(name)
        if guidance:
            recommendations.append({
                "category": "HTTP Security Header",
                "finding": f"{name} is missing",
                **guidance,
            })

    if tls is None and not _is_local_development_target(target):
        recommendations.append({
            "category": "TLS / SSL",
            "finding": "TLS analysis was not performed",
            "title": "Use HTTPS for the website",
            "why": "HTTPS protects data in transit and enables certificate-based server authentication.",
            "fix": "Configure a valid TLS certificate and redirect HTTP traffic to HTTPS. Re-run the assessment over HTTPS.",
        })
    elif tls is not None:
        verification = str(tls.get("verification", "")).upper()
        if not tls.get("success") or verification != "VALID":
            recommendations.append({
                "category": "TLS / SSL",
                "finding": "TLS certificate verification did not pass",
                "title": "Fix the TLS certificate configuration",
                "why": "Browsers may warn users or refuse secure connections when certificate validation fails.",
                "fix": "Check the certificate validity dates, hostname coverage, certificate chain, and server configuration. Install a valid certificate for the assessed hostname.",
            })
        else:
            days = tls.get("days_remaining")
            try:
                days = int(days)
            except (TypeError, ValueError):
                days = None
            if days is not None and days <= 30:
                recommendations.append({
                    "category": "TLS / SSL",
                    "finding": f"TLS certificate expires in {days} days",
                    "title": "Renew the TLS certificate soon",
                    "why": "An expired certificate can cause browser security warnings and connection failures.",
                    "fix": "Renew the certificate before its expiry date and verify that automated renewal is working.",
                })

    return recommendations
