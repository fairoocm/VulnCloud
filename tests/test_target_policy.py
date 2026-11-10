import unittest
from unittest.mock import patch
from scanner.target_policy import validate_target, validate_target_with_ip

class TestTargetPolicy(unittest.TestCase):
    def test_local_demo_is_allowed(self):
        allowed, message = validate_target("http://127.0.0.1:5000")
        self.assertTrue(allowed, message)

    @patch("scanner.target_policy.socket.getaddrinfo")
    def test_public_http_allowed_without_allowlist(self, mock_dns):
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        allowed, message, pinned_ip = validate_target_with_ip("http://example.com")
        self.assertTrue(allowed, message)
        self.assertEqual(pinned_ip, "93.184.216.34")

    @patch("scanner.target_policy.socket.getaddrinfo")
    def test_unlisted_public_https_allowed(self, mock_dns):
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        allowed, message, pinned_ip = validate_target_with_ip("https://example.com")
        self.assertTrue(allowed, message)
        self.assertEqual(pinned_ip, "93.184.216.34")

    @patch("scanner.target_policy.socket.getaddrinfo")
    def test_private_dns_rejected(self, mock_dns):
        mock_dns.return_value = [(2, 1, 6, "", ("192.168.1.10", 443))]
        allowed, message = validate_target("https://example.com")
        self.assertFalse(allowed)
        self.assertIn("non-public IP", message)

    def test_nonstandard_port_rejected(self):
        allowed, message = validate_target("https://example.com:8443")
        self.assertFalse(allowed)
        self.assertIn("standard HTTPS port 443", message)

    def test_credentials_rejected(self):
        allowed, message = validate_target("https://user:pass@example.com")
        self.assertFalse(allowed)
        self.assertIn("credentials", message)

if __name__ == "__main__":
    unittest.main()
