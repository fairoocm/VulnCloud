import json
import re
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

CONFIG_FILE = Path(__file__).resolve().parent.parent / "authorized_targets.json"


def validate_target_with_ip(url):
    try:
        parsed = urlparse(url.strip())
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            return False, "Enter a valid HTTP or HTTPS URL.", None

        if parsed.username or parsed.password:
            return False, "URLs containing login credentials are not allowed.", None

        # Local testing mode
        if hostname in ("localhost", "127.0.0.1"):
            return True, "Local testing target approved.", None

        # Public targets must use HTTPS on port 443
        if parsed.scheme != "https":
            return False, "Public targets must use HTTPS.", None

        if parsed.port not in (None, 443):
            return False, "Only the standard HTTPS port 443 is allowed.", None

        # Validate domain name format
        hostname = hostname.lower().rstrip(".")

        if len(hostname) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+",
            hostname
        ):
            return False, "Enter a valid domain name.", None

        # Resolve DNS once and reject any non-public address
        try:
            addresses = socket.getaddrinfo(
                hostname, 443, type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            return False, "Could not resolve the target domain.", None

        public_ips = []

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return False, "Domain resolves to a non-public IP address.", None

            if str(ip) not in public_ips:
                public_ips.append(str(ip))

        if not public_ips:
            return False, "No valid public IP address found.", None

        # Check explicit authorization list
        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            config = json.load(file)

        approved_targets = [
            target.lower().strip().rstrip(".")
            for target in config.get("authorized_targets", [])
        ]

        if hostname not in approved_targets:
            return False, "This domain is not in your authorized-target list.", None

        return True, "Authorized public target approved.", public_ips[0]

    except (ValueError, OSError, json.JSONDecodeError):
        return False, "Target validation failed. Check your URL and configuration.", None


def validate_target(url):
    allowed, message, _ = validate_target_with_ip(url)
    return allowed, message
