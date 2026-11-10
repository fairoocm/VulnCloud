import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlparse
import certifi

def _verified_context():
    return ssl.create_default_context(cafile=certifi.where())

class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, pinned_ip, timeout=10):
        super().__init__(hostname, port=80, timeout=timeout)
        self.pinned_ip = pinned_ip
    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, 80), timeout=self.timeout)

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, pinned_ip, timeout=10):
        super().__init__(hostname, port=443, timeout=timeout, context=_verified_context())
        self.pinned_ip = pinned_ip
    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, 443), timeout=self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

def _request_headers(url, pinned_ip, allow_redirects=False):
    parsed = urlparse(url)
    hostname = parsed.hostname
    if parsed.scheme not in ("http", "https") or not hostname:
        raise ValueError("Only valid HTTP or HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The target URL contains an invalid port.")
    expected_port = 80 if parsed.scheme == "http" else 443
    if port not in (None, expected_port):
        raise ValueError(f"Only port {expected_port} is allowed for {parsed.scheme.upper()}.")
    ip = ipaddress.ip_address(pinned_ip)
    if not ip.is_global:
        raise ValueError("Target IP must be public.")
    connection = (PinnedHTTPSConnection(hostname, str(ip), 10) if parsed.scheme == "https"
                  else PinnedHTTPConnection(hostname, str(ip), 10))
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        connection.request("GET", path, headers={
            "Host": hostname, "User-Agent": "VulnCloud-Security-Scanner/1.0",
            "Connection": "close",
        })
        response = connection.getresponse()
        if 300 <= response.status < 400 and not allow_redirects:
            raise ValueError("Redirect responses are not followed.")
        return {"status_code": response.status, "headers": dict(response.getheaders()),
                "location": response.getheader("Location"), "target": url}
    finally:
        connection.close()

def _resolve_public_ip(hostname, port):
    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise ValueError("No IP addresses found.")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Target resolves to a non-public IP.")
    return addresses[0]

def safe_https_headers(url, pinned_ip=None, allow_redirects=False):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Only valid HTTPS URLs are supported.")
    if pinned_ip is None:
        pinned_ip = _resolve_public_ip(parsed.hostname, 443)
    return _request_headers(url, pinned_ip, allow_redirects)

def safe_http_headers(url, pinned_ip, allow_redirects=False):
    parsed = urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("Only valid HTTP URLs are supported.")
    return _request_headers(url, pinned_ip, allow_redirects)
