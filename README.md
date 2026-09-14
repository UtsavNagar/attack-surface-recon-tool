# Attack Surface Recon & Exposure Reporting Tool

A small local web app that demonstrates an end-to-end Attack Surface Management
(ASM) workflow: **discover → assess → report**.

Given a domain or IP address, it:
- Passively enumerates subdomains via certificate transparency logs (crt.sh)
- Resolves hosts and scans a curated list of common TCP ports
- Checks TLS certificate validity/expiry
- Checks for missing HTTP security headers
- Pulls WHOIS (domains) or IP geolocation/ASN intelligence (IPs) — the
  "threat hunting" style overview
- Rolls everything into a severity-ranked risk summary, rendered as a report
  in your browser

## ⚠️ Authorized use only

This tool makes live network connections (port scans, HTTP requests, TLS
handshakes) to whatever target you enter. **Only scan domains/IPs you own or
have explicit written permission to test.** Scanning systems without
authorization may be illegal depending on your jurisdiction. The web form
requires you to confirm authorization before it will run a scan — that
checkbox is not a formality, take it seriously.

Good, safe targets to try:
- A domain you personally own/control
- `scanme.nmap.org` (explicitly set up by the Nmap project to be scanned)
- Your own home router's public IP (check first — some ISPs discourage even
  scanning your own WAN IP; when in doubt, scan a domain you own instead)

## Setup

Requires Python 3.9+.

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## Notes

- The port scanner is pure Python (no nmap install required) — it checks a
  curated list of ~25 common ports using TCP connect scans. This keeps it
  portable across Windows/Mac/Linux.
- Subdomain scanning is capped (default: 10 hosts) to keep scan time
  reasonable — change `MAX_SUBDOMAINS` in `app.py` if you want more.
- IP intelligence uses the free tier of `ip-api.com` (no API key needed, but
  rate-limited to ~45 requests/minute — fine for personal/demo use).
- WHOIS lookups depend on the `python-whois` package and the registrar's
  WHOIS server; some TLDs or registrars may return incomplete data or time
  out — this is handled gracefully and shown as "Unavailable" in the report.
- All external calls (crt.sh, ip-api, WHOIS, TLS/HTTP checks) are wrapped in
  try/except, so a missing internet connection or an unresponsive service
  won't crash the app — the report will just show that section as
  unavailable.

## Project structure

```
asm-tool/
├── app.py                  # Flask app + orchestration logic
├── modules/
│   ├── subdomain_enum.py   # crt.sh-based subdomain discovery
│   ├── dns_resolve.py      # DNS / reverse DNS
│   ├── port_scan.py        # TCP connect port scanner
│   ├── tls_check.py        # TLS certificate expiry check
│   ├── http_headers.py     # HTTP security header check
│   ├── whois_lookup.py     # WHOIS lookup (domains)
│   ├── ip_intel.py         # Geolocation/ASN lookup (IPs)
│   └── risk_summary.py     # Aggregates findings into High/Medium/Info
├── templates/
│   ├── index.html
│   └── report.html
├── static/
│   └── style.css
└── requirements.txt
```

## Resume framing

> **Attack Surface Recon & Exposure Reporting Tool**
> Technologies: Python, Flask, Nmap-style TCP scanning, crt.sh API, TLS, DNS
> - Built a tool to enumerate subdomains via certificate transparency logs and
>   DNS resolution, then scanned discovered hosts for open ports and service
>   exposure.
> - Implemented rule-based exposure checks (expiring TLS certificates,
>   unexpected open ports, missing HTTP security headers) and generated a
>   severity-flagged exposure report with domain/IP intelligence.
> - Demonstrated an end-to-end asset discovery → assessment → reporting
>   workflow aligned with Attack Surface Management practices.
