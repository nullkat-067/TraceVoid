# TraceVoid

**NullKat Development** — a Python CLI OSINT toolkit for Termux on Android.

TraceVoid focuses on reasonable public-source checks, local analysis, and honest results. It does not attempt to obtain passwords, leaked data, chat contents, WhatsApp account status, GPS coordinates, home addresses, profile photos, or phone-number ownership.

## Features

The main menu contains exactly 25 modules:

1. Username Lookup
2. Domain Intelligence
3. DNS Lookup
4. WHOIS Lookup
5. IP Intelligence
6. ASN Lookup
7. HTTP Header Inspector
8. TLS Certificate Check
9. Subdomain Discovery
10. Robots.txt Viewer
11. Sitemap Inspector
12. URL Analyzer
13. Redirect Inspector
14. Email Format Check
15. Username Pattern Analyzer
16. Metadata Inspector
17. File Hash Calculator
18. Image Metadata
19. Public Breach Resources
20. GitHub Public Recon
21. Public DNS History
22. Website Availability
23. Security Headers Audit
24. Threat Intelligence
25. WhatsApp Phone Intelligence

Additional menu items: **Credit**, **Help**, and **Exit**.

## Termux Installation

```bash
pkg update -y
pkg upgrade -y
pkg install python git -y
mkdir -p ~/TraceVoid
cd ~/TraceVoid
# extract or copy ALL project files, including the tracevoid/ directory
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

Normal use after installation:

```bash
cd ~/TraceVoid
. .venv/bin/activate
python main.py
```

If you need shared storage, run `termux-setup-storage` and use the local Android path. File modules do not upload files.

## APIs and limitations

Some modules use free public sources and may encounter rate limits, format changes, or downtime: `ipwho.is` (IP), `bgpview.io` (ASN), `crt.sh` (certificate/subdomain data), the unauthenticated GitHub API (public recon), AlienVault OTX (public reputation data), and the local/ISP DNS resolver. The program reports failures and never invents results.

`Public DNS History` is optional. To enable it, configure a SecurityTrails API key locally:

```bash
export SECURITYTRAILS_API_KEY='your-key-here'
python main.py
```

Free availability and quotas follow each provider's policy. Do not place keys in source code or share them. Without a key, the module clearly reports that the service is not configured.

`Public Breach Resources` only displays links to official checking services. The toolkit does not automatically submit email addresses or download leaked data.

## WhatsApp Phone Intelligence

Enter a number in international format, for example `+628123456789`. The `phonenumbers` library is used locally to return formatting, country code, region, possible/valid status, number type, and available area/carrier metadata. Numbering metadata does not prove ownership and cannot reveal a person's name, address, GPS location, photo, online status, chat contents, or WhatsApp account status. This module does not send the number to a server.

## Project structure

```text
TraceVoid/
├── main.py
├── requirements.txt
├── README.md
└── tracevoid/
    ├── __init__.py
    └── modules.py
```

## Ethics and legal use

Use the toolkit only on targets you are allowed to inspect. Respect privacy, follow each source's Terms of Service, use reasonable rate limits, and comply with applicable law. Public information can still be sensitive.

## License

Use and modify responsibly. This project does not guarantee the accuracy, availability, or completeness of third-party data.

## If you see `No module named 'tracevoid'`

This means that only `main.py` was copied. Make sure the package directory is present:

```text
TraceVoid/
├── main.py
└── tracevoid/
    ├── __init__.py
    └── modules.py
```

Run from the project root, not from inside the `tracevoid` directory:

```bash
cd ~/TraceVoid
python main.py
```
