import socket
import ssl
import certifi
from datetime import datetime, timezone


def check_certificate(hostname):

    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:

                certificate = tls.getpeercert()

                print("\n[*] VulnCloud TLS Certificate Analysis")
                print("[+] Hostname:", hostname)
                print("[+] TLS Version:", tls.version())

                # Extract certificate issuer
                issuer = certificate.get("issuer", ())
                issuer_names = [
                    value
                    for rdn in issuer
                    for key, value in rdn
                ]

                print("[+] Certificate Issuer:", ", ".join(issuer_names))

                # Extract certificate expiry date
                expiry_text = certificate.get("notAfter")

                if expiry_text:
                    expiry_date = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(expiry_text),
                        tz=timezone.utc
                    )

                    remaining = expiry_date - datetime.now(timezone.utc)

                    print("[+] Expiry Date:", expiry_date)
                    print("[+] Days Remaining:", remaining.days)

                print("\n[*] Analysis completed.")

    except (OSError, ssl.SSLError) as error:
        print("[-] Connection failed:", error)


if __name__ == "__main__":
    target = input("Enter authorized website hostname: ").strip()
    check_certificate(target)