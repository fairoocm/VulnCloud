
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "Helps enforce HTTPS connections.",

    "Content-Security-Policy":
        "Helps protect against certain injection attacks.",

    "X-Content-Type-Options":
        "Helps prevent MIME type sniffing.",

    "X-Frame-Options":
        "Helps protect against clickjacking.",

    "Referrer-Policy":
        "Controls referrer information sent by browsers."
}


def analyze_headers(url):

    print("\n[*] VulnCloud HTTP Security Analyzer")
    print("[*] Target:", url)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        print("\n[+] HTTP Status:", response.status_code)

        print("\n--- Security Header Analysis ---")

        for header, recommendation in SECURITY_HEADERS.items():

            if header in response.headers:
                print(f"[+] PRESENT: {header}")
            else:
                print(f"[-] MISSING: {header}")
                print("    Recommendation:", recommendation)

        print("\n[*] Analysis completed.")

    except requests.RequestException as error:
        print("\n[!] Connection error:", error)


if __name__ == "__main__":

    target = input("Enter authorized HTTPS website URL: ").strip()

    if not target.startswith("https://"):
        print("[!] Please enter an HTTPS URL.")
    else:
        analyze_headers(target)
