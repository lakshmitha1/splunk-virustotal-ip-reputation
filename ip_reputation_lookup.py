
import csv
import ipaddress
import os
import sys
import requests

API_KEY = os.getenv("VT_API_KEY")

def get_reputation(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid_ip"

    if not address.is_global:
        return "private_or_reserved"

    if not API_KEY:
        return "api_key_missing"

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(
            url, headers=headers, timeout=15
        )

        if response.status_code == 404:
            return "no_report"
        if response.status_code == 429:
            return "rate_limited"
        if response.status_code in (401, 403):
            return "api_access_error"

        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})

        if stats.get("malicious", 0) > 0:
            return "malicious"
        if stats.get("suspicious", 0) > 0:
            return "suspicious"
        if stats:
            return "no_detections"

        return "no_analysis"

    except requests.RequestException:
        return "lookup_error"
    except (KeyError, TypeError, ValueError):
        return "invalid_response"


def main():
    reader = csv.DictReader(sys.stdin)
    writer = csv.DictWriter(
        sys.stdout,
        fieldnames=["srcip", "reputation"]
    )

    writer.writeheader()

    for row in reader:
        ip = (row.get("srcip") or "").strip()
        reputation = get_reputation(ip)

        writer.writerow({
            "srcip": ip,
            "reputation": reputation
        })
        sys.stdout.flush()


if __name__ == "__main__":
    main()
