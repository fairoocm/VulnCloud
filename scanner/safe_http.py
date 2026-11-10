import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlparse


class PinnedHTTPSConnection(http.client.HTTPSConnection):

    def __init__(self, hostname, pinned_ip, timeout=10):
        super().__init__(
            hostname,
            port=443,
            timeout=timeout,
            context=ssl.create_default_context()
        )
        self.pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self.pinned_ip, 443),
            timeout=self.timeout
        )

        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=self.host
        )


def safe_https_headers(url, pinned_ip=None):

    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme != "https" or not hostname:
        raise ValueError("Only valid HTTPS URLs are supported.")

    if parsed.port not in (None, 443):
        raise ValueError("Only HTTPS port 443 is allowed.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")

    if pinned_ip is not None:

        ip = ipaddress.ip_address(pinned_ip)

        if not ip.is_global:
            raise ValueError("Target IP must be public.")

        selected_ip = str(ip)

    else:
        records = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM
        )

        addresses = list({
            record[4][0] for record in records
        })

        if not addresses:
            raise ValueError("No IP addresses found.")

        for address in addresses:
            ip = ipaddress.ip_address(address)

            if not ip.is_global:
                raise ValueError("Target resolves to a non-public IP.")

        selected_ip = addresses[0]

    connection = PinnedHTTPSConnection(
        hostname,
        selected_ip,
        timeout=10
    )

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": hostname,
                "User-Agent": "VulnCloud-Security-Scanner/1.0",
                "Connection": "close"
            }
        )

        response = connection.getresponse()

        # Reject all 3xx responses. Never follow redirects.
        if 300 <= response.status < 400:
            raise ValueError("Redirect responses are not followed.")

        return {
            "status_code": response.status,
            "headers": dict(response.getheaders()),
            "target": url
        }

    finally:
        connection.close()