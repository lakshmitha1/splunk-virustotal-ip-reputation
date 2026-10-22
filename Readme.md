# Splunk External Lookup Using Python and VirusTotal

## Project Overview
This project integrates Splunk Enterprise with the VirusTotal API using a Python external lookup to enrich IP addresses with threat intelligence.

## Technologies
- Splunk Enterprise
- Python
- VirusTotal API
- SPL
- CSV input/output

## Architecture
Splunk Search → External Lookup → Python Script → VirusTotal API → Reputation Result in Splunk

## Features
- Validates IP addresses.
- Retrieves IP analysis statistics from VirusTotal.
- Classifies results as malicious, suspicious, or no detections.
- Returns reputation data to Splunk through CSV input/output.

## Setup
1. Install Python and the `requests` package.
2. Configure the `VT_API_KEY` environment variable securely.
3. Copy `ip_reputation_lookup.py` into the Splunk Search app's `bin` directory.
4. Create an external lookup definition in Splunk Web.
5. Test the lookup using SPL.

## Example SPL Query
```spl
| makeresults
| eval srcip="8.8.8.8"
| lookup ip_reputation_lookup srcip OUTPUT reputation
| table srcip reputation
```

## Limitations
- VirusTotal results can change over time.
- API quotas and rate limits apply.
- `no_detections` does not guarantee that an IP is safe.
- Sample SPL events are for testing and do not represent actual firewall traffic.

## Security
Keep API keys out of source code, screenshots, and Git history.
