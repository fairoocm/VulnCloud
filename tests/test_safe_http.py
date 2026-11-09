import socket
import unittest
from unittest.mock import patch

from scanner.safe_http import safe_https_headers


class TestSafeHTTP(unittest.TestCase):

    @patch("scanner.safe_http.socket.getaddrinfo")
    def test_private_ip_is_rejected(self, mock_dns):
        mock_dns.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.168.1.10", 443)
            )
        ]

        with self.assertRaisesRegex(
            ValueError, "non-public IP"
        ):
            safe_https_headers("https://example.com")


if __name__ == "__main__":
    unittest.main()