import ssl
from unittest.mock import MagicMock, patch

from scanner.tls_check import check_certificate


def test_certificate_verification_failure_returns_structured_result():
    mock_socket = MagicMock()

    # Make the context manager return the same socket mock.
    mock_socket.__enter__.return_value = mock_socket

    mock_context = MagicMock()
    mock_context.wrap_socket.side_effect = (
        ssl.SSLCertVerificationError("certificate verify failed")
    )

    with patch(
        "scanner.tls_check.socket.create_connection",
        return_value=mock_socket
    ) as mock_connect, patch(
        "scanner.tls_check.ssl.create_default_context",
        return_value=mock_context
    ):
        result = check_certificate(
            "example.com",
            pinned_ip="93.184.216.34"
        )

    mock_connect.assert_called_once_with(
        ("93.184.216.34", 443),
        timeout=10
    )

    mock_context.wrap_socket.assert_called_once_with(
        mock_socket,
        server_hostname="example.com"
    )

    assert result["success"] is False
    assert result["verification"] == "Failed"
    assert "certificate verify failed" in result["error"].lower()