import json
import re
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

CONFIG_FILE = Path(__file__).resolve().parent.parent / "authorized_targets.json"


def validate_target(url):
    try:
        parsed = urlparse(url.strip())
        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https") or not hostname:
            return False, "Enter a valid HTTP or HTTPS URL."

        if parsed.username or parsed.password:
            return False, "URLs containing login credentials are not allowed."

        # Local testing mode
        if hostname in ("localhost", "127.0.0.1"):
            return True, "Local testing target approved."

        # Public targets must use HTTPS
        if parsed.scheme != "https":
            return False, "Public targets must use HTTPS."

        if parsed.port not in (None, 443):
            return False, "Only the standard HTTPS port 443 is allowed."

        # Only explicitly approved domain names are accepted
        # DNS safety check
        try:
            addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)

            for address in addresses:
                ip = ipaddress.ip_address(address[4][0])

                if not ip.is_global:
                    return False, "Domain resolves to a non-public IP address."

        except socket.gaierror:
            return False, "Could not resolve the target domain."
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+",
            hostname
        ):
            return False, "Enter a valid domain name."

        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            config = json.load(file)

        approved_targets = [
            target.lower().strip().rstrip(".")
            for target in config.get("authorized_targets", [])
        ]

        if hostname.lower().rstrip(".") not in approved_targets:
            return False, "This domain is not in your authorized-target list."

        return True, "Authorized public target approved."

    except (ValueError, OSError, json.JSONDecodeError):
        return False, "Target validation failed. Check your URL and configuration."