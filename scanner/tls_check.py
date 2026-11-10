import socket
import ssl
import ipaddress
import certifi
from datetime import datetime, timezone


def check_certificate(hostname, pinned_ip=None):

    context = ssl.create_default_context(cafile=certifi.where())

    try:
        if not hostname:
            raise ValueError("A valid hostname is required.")

        # Connect to the previously validated IP when supplied.
        connection_host = hostname

        if pinned_ip is not None:
            ip = ipaddress.ip_address(pinned_ip)

            if not ip.is_global:
                raise ValueError("Target IP must be public.")

            connection_host = str(ip)

        with socket.create_connection(
            (connection_host, 443), timeout=10
        ) as sock:

            # Keep hostname verification and SNI enabled.
            with context.wrap_socket(
                sock, server_hostname=hostname
            ) as tls:

                certificate = tls.getpeercert()

                issuer = certificate.get("issuer", ())
                issuer_names = [
                    value
                    for rdn in issuer
                    for key, value in rdn
                ]

                expiry_text = certificate.get("notAfter")
                expiry_date = None
                days_remaining = None

                if expiry_text:
                    expiry_date = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(expiry_text),
                        tz=timezone.utc
                    )

                    remaining = expiry_date - datetime.now(timezone.utc)
                    days_remaining = remaining.days

                return {
                    "success": True,
                    "hostname": hostname,
                    "tls_version": tls.version(),
                    "issuer": ", ".join(issuer_names),
                    "expiry_date": (
                        expiry_date.isoformat() if expiry_date else None
                    ),
                    "days_remaining": days_remaining,
                    "verification": "Valid",
                    "error": None
                }

    except (OSError, ssl.SSLError, ValueError) as error:
        return {
            "success": False,
            "hostname": hostname,
            "tls_version": None,
            "issuer": None,
            "expiry_date": None,
            "days_remaining": None,
            "verification": "Failed",
            "error": str(error)
        }


if __name__ == "__main__":
    target = input("Enter authorized website hostname: ").strip()
    result = check_certificate(target)

    for key, value in result.items():
        print(f"{key}: {value}")
