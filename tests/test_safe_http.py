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
    @patch("scanner.safe_http.PinnedHTTPSConnection")
    def test_redirect_response_is_rejected(self, mock_connection):
        mock_response = mock_connection.return_value.getresponse.return_value
        mock_response.status = 302

        with self.assertRaisesRegex(
            ValueError, "Redirect responses are not followed"
        ):
            safe_https_headers(
                "https://example.com",
                pinned_ip="93.184.216.34"
            )

        mock_connection.return_value.close.assert_called_once()



if __name__ == "__main__":
    unittest.main()