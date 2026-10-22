
import os
import ipaddress
import requests

def check_ip_reputation(ip):
    # Validate the IP address
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid IP address.")
        return

    # Read API key from environment variable
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        print("Error: Set the VT_API_KEY environment variable.")
        return

    # VirusTotal IP report endpoint
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url, headers=headers, timeout=15
        )
        response.raise_for_status()

        data = response.json()
        attributes = data["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        print(f"\nIP Address: {ip}")
        print(f"Malicious detections: {malicious}")
        print(f"Suspicious detections: {suspicious}")
        print(f"Harmless detections: {harmless}")
        print(f"Undetected: {undetected}")
        print(f"Community reputation: "
              f"{attributes.get('reputation', 'Unavailable')}")

        if malicious > 0:
            print("Assessment: Flagged as malicious by at least one engine.")
        elif suspicious > 0:
            print("Assessment: Flagged as suspicious by at least one engine.")
        elif stats:
            print("Assessment: No malicious or suspicious detections in these statistics.")
        else:
            print("Assessment: No usable analysis statistics available.")

    except requests.exceptions.HTTPError as e:
        print(f"API error: {e}")
        if response.status_code == 401:
            print("Check your API key.")
        elif response.status_code == 403:
            print("Access denied or API quota/permission restriction.")
        elif response.status_code == 429:
            print("API rate limit exceeded.")
    except requests.exceptions.RequestException as e:
        print(f"Network error: {e}")
    except (KeyError, TypeError, ValueError):
        print("Could not parse the IP report.")

if __name__ == "__main__":
    ip = input("Enter an IP address to check: ").strip()
    check_ip_reputation(ip)
