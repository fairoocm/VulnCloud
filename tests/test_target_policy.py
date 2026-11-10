import unittest
from unittest.mock import patch
from scanner.target_policy import validate_target


class TestTargetPolicy(unittest.TestCase):

    def test_localhost_is_allowed(self):
        allowed, message = validate_target("http://127.0.0.1:5000")
        self.assertTrue(allowed)

    def test_public_http_is_rejected(self):
        allowed, message = validate_target("http://example.com")
        self.assertFalse(allowed)

    def test_unapproved_domain_is_rejected(self):
        allowed, message = validate_target("https://example.com")
        self.assertFalse(allowed)

    @patch("scanner.target_policy.socket.getaddrinfo")
    def test_private_ip_resolution_is_rejected(self, mock_dns):
        mock_dns.return_value = [
            (2, 1, 6, "", ("192.168.1.10", 443))
        ]

        with patch(
            "builtins.open",
            side_effect=AssertionError("Configuration should not be read")
        ):
            allowed, message = validate_target("https://example.com")

        self.assertFalse(allowed)
        self.assertIn("non-public IP", message)


if __name__ == "__main__":
    unittest.main()