import ipaddress
import re
import socket
from urllib.parse import urlparse

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

def validate_target_with_ip(url):
    try:
        if not isinstance(url, str) or not url.strip():
            return False, "Enter a valid HTTP or HTTPS URL.", None
        parsed = urlparse(url.strip())
        hostname = parsed.hostname
        if parsed.scheme not in ("http", "https") or not hostname:
            return False, "Enter a valid HTTP or HTTPS URL.", None
        if parsed.username or parsed.password:
            return False, "URLs containing login credentials are not allowed.", None
        try:
            port = parsed.port
        except ValueError:
            return False, "The target URL contains an invalid port.", None
        hostname = hostname.rstrip(".").lower()

        # Local demo exception: http://localhost:5000 or 127.0.0.1:5000.
        if (parsed.scheme == "http" and hostname in ("localhost", "127.0.0.1")
                and port == 5000):
            return True, "Local testing target approved.", None

        expected_port = 80 if parsed.scheme == "http" else 443
        if port not in (None, expected_port):
            return False, f"Only the standard {parsed.scheme.upper()} port {expected_port} is allowed.", None

        try:
            literal_ip = ipaddress.ip_address(hostname)
        except ValueError:
            literal_ip = None
        if literal_ip is not None:
            if not literal_ip.is_global:
                return False, "Target IP must be public.", None
            return True, "Public target approved after authorization confirmation.", str(literal_ip)

        if not DOMAIN_PATTERN.fullmatch(hostname):
            return False, "Enter a valid public domain name.", None
        try:
            records = socket.getaddrinfo(hostname, expected_port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False, "Could not resolve the target domain.", None

        public_ips = []
        for record in records:
            ip = ipaddress.ip_address(record[4][0])
            if not ip.is_global:
                return False, "Domain resolves to a non-public IP address.", None
            if str(ip) not in public_ips:
                public_ips.append(str(ip))
        if not public_ips:
            return False, "No public IP address was found for this domain.", None
        return True, "Public target approved after authorization confirmation.", public_ips[0]
    except (ValueError, OSError):
        return False, "Target validation failed. Check the URL and DNS configuration.", None

def validate_target(url):
    allowed, message, _ = validate_target_with_ip(url)
    return allowed, message
