"""Implementations for TraceVoid's consent-based OSINT modules.

Network modules use public endpoints only, short timeouts, and never claim data that
was not returned. Local modules do not upload user files or phone numbers.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:
    requests = None

TIMEOUT = 8
UA = "TraceVoid/2.0 (public OSINT; respectful rate limits)"


def _print(title: str, value: Any = "") -> None:
    print(f"\n[+] {title}")
    print(value if value not in (None, "") else "(not available)")


def _need_requests() -> bool:
    if requests is None:
        print("[!] Dependency 'requests' is not installed: pip install -r requirements.txt")
        return False
    return True


def _url(value: str) -> str:
    value = value.strip()
    return value if re.match(r"^https?://", value, re.I) else "https://" + value


def _get(url: str, **kwargs):
    if not _need_requests():
        return None
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", UA)
    try:
        return requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as exc:
        print(f"[!] Request failed: {exc}")
        return None


def _host(value: str) -> str:
    parsed = urllib.parse.urlparse(_url(value))
    return parsed.hostname or value.strip().split("/")[0].split(":")[0]


def username_lookup():
    username = input("Username: ").strip()
    if not username or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
        print("[!] Use 1-64 characters: letters, digits, dots, underscores, or hyphens.")
        return
    sites = {
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}/about.json",
        "X": f"https://x.com/{username}",
        "Keybase": f"https://keybase.io/{username}",
    }
    print("[i] Public HEAD checks; an HTTP status is not proof of identity.")
    for name, url in sites.items():
        if not _need_requests(): return
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=True)
            status = "AVAILABLE" if r.status_code < 400 else f"HTTP {r.status_code}"
            print(f"{name:10} {status:10} {r.url}")
        except requests.RequestException as exc:
            print(f"{name:10} FAILED ({exc})")


def domain_intelligence():
    value = input("Domain/URL: ").strip()
    host = _host(value)
    print(f"Host: {host}")
    try:
        print(f"Resolved IPs: {socket.gethostbyname_ex(host)[2]}")
    except socket.gaierror as exc: print(f"Resolution failed: {exc}")
    r = _get(_url(value), stream=True)
    if r is not None:
        print(f"Final URL: {r.url}\nStatus: {r.status_code}\nServer header: {r.headers.get('server', '(not present)')}")
        r.close()


def dns_lookup():
    host = _host(input("Domain: "))
    try:
        import dns.resolver
    except ImportError:
        print("[!] dnspython is not installed."); return
    resolver = dns.resolver.Resolver(); resolver.lifetime = TIMEOUT
    for record in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = resolver.resolve(host, record)
            print(f"\n{record}:\n" + "\n".join(f"  {a}" for a in answers))
        except Exception as exc:
            print(f"{record}: not available ({type(exc).__name__})")


def whois_lookup():
    host = _host(input("Domain: "))
    try:
        import whois
        data = whois.whois(host)
        if not data: print("WHOIS returned no data."); return
        for key in ("domain_name", "registrar", "creation_date", "expiration_date", "name_servers", "status"):
            _print(key, data.get(key))
    except ImportError: print("[!] python-whois is not installed.")
    except Exception as exc: print(f"[!] WHOIS failed: {exc}")


def ip_intelligence():
    raw = input("Public IP: ").strip()
    try: ipaddress.ip_address(raw)
    except ValueError: print("[!] Invalid IP format."); return
    r = _get(f"https://ipwho.is/{raw}")
    if r is not None:
        try:
            data = r.json(); print(json.dumps({k: data.get(k) for k in ("ip","type","continent","country","region","city","connection","timezone")}, indent=2, ensure_ascii=False))
        except ValueError: print("[!] Response was not JSON.")


def asn_lookup():
    value = input("ASN (for example AS15169) or IP: ").strip().upper()
    query = value[2:] if value.startswith("AS") else value
    r = _get(f"https://api.bgpview.io/{'asn' if value.startswith('AS') else 'ip'}/{query}")
    if r is not None:
        try: print(json.dumps(r.json(), indent=2, ensure_ascii=False)[:12000])
        except ValueError: print("[!] Response could not be read.")


def http_header_inspector():
    r = _get(input("URL: "))
    if r is not None:
        for k, v in r.headers.items(): print(f"{k}: {v}")


def tls_certificate_check():
    host = _host(input("Domain: "))
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(); print("Subject:", cert.get("subject")); print("Issuer:", cert.get("issuer")); print("SAN:", cert.get("subjectAltName")); print("Valid from:", cert.get("notBefore")); print("Valid until:", cert.get("notAfter"))
    except (OSError, ssl.SSLError) as exc: print(f"[!] TLS check failed: {exc}")


def subdomain_discovery():
    host = _host(input("Domain: ")).lower()
    r = _get(f"https://crt.sh/?q=%25.{urllib.parse.quote(host)}&output=json")
    if r is None: return
    try:
        names = set()
        for row in r.json():
            names.update(n.strip().lower() for n in row.get("name_value", "").splitlines())
        names = sorted(n for n in names if n == host or n.endswith("." + host))
        print("\n".join(names) if names else "No names found from crt.sh.")
    except (ValueError, TypeError) as exc: print(f"[!] Invalid crt.sh data: {exc}")


def robots_viewer():
    r = _get(urllib.parse.urljoin(_url(input("Website: ")), "/robots.txt"))
    if r is not None: print(r.text[:20000] or "(empty)")


def sitemap_inspector():
    base = _url(input("Website or sitemap URL: "))
    url = base if base.lower().endswith(('.xml', 'sitemap.xml')) else urllib.parse.urljoin(base, "/sitemap.xml")
    r = _get(url)
    if r is not None: print(f"Status {r.status_code}, Final URL {r.url}\n{r.text[:20000]}")


def url_analyzer():
    raw = input("Full URL: ").strip(); p = urllib.parse.urlparse(raw)
    print(json.dumps({"scheme": p.scheme, "netloc": p.netloc, "hostname": p.hostname, "port": p.port, "path": p.path, "query": urllib.parse.parse_qs(p.query), "fragment": p.fragment}, indent=2, ensure_ascii=False))


def redirect_inspector():
    raw = input("URL: ").strip()
    if not _need_requests(): return
    try:
        r = requests.get(_url(raw), headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=False)
        count = 0
        while r.is_redirect and count < 10:
            print(f"{count+1}. {r.status_code} {r.url} -> {r.headers.get('Location')}")
            target = urllib.parse.urljoin(r.url, r.headers["Location"]); r = requests.get(target, headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=False); count += 1
        print(f"Final: {r.status_code} {r.url}")
        if count == 10: print("[!] The 10-redirect limit was reached.")
    except requests.RequestException as exc: print(f"[!] Failed: {exc}")


def email_format_check():
    email = input("Email: ").strip()
    valid = bool(re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", email))
    print("The syntax appears valid." if valid else "Invalid syntax.")
    print("Note: this is local syntax validation only, not ownership or mailbox-existence verification.")


def username_pattern_analyzer():
    value = input("Username: ").strip()
    print(json.dumps({"length": len(value), "lowercase": value.lower() == value, "uppercase": value.upper() == value, "digit_count": sum(c.isdigit() for c in value), "special_count": sum(not c.isalnum() for c in value), "has_year_like": bool(re.search(r"(?:19|20)\d{2}", value)), "unicode": any(ord(c)>127 for c in value)}, indent=2))


def metadata_inspector():
    path = Path(input("Local file path: ").strip()).expanduser()
    if not path.is_file(): print("[!] File not found."); return
    print(f"Name: {path.name}\nSize: {path.stat().st_size} bytes\nExtension: {path.suffix or '(none)'}\nModified: {datetime.fromtimestamp(path.stat().st_mtime)}")
    try:
        from PIL import Image
        with Image.open(path) as im: print(f"Image format: {im.format}, dimensions: {im.size}, metadata keys: {list(im.getexif().keys())}")
    except Exception: print("Special media metadata is not available; the file was not uploaded.")


def file_hash_calculator():
    path = Path(input("Local file path: ").strip()).expanduser()
    if not path.is_file(): print("[!] File not found."); return
    hashes = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hashes.values(): h.update(chunk)
    for n, h in hashes.items(): print(f"{n.upper()}: {h.hexdigest()}")


def image_metadata():
    path = Path(input("Local image path: ").strip()).expanduser()
    try:
        from PIL import Image
        with Image.open(path) as im:
            print(f"Format: {im.format}\nMode: {im.mode}\nSize: {im.size}")
            exif = im.getexif(); print("EXIF:", json.dumps({str(k): str(v) for k,v in exif.items()}, indent=2, ensure_ascii=False) if exif else "none")
    except ImportError: print("[!] Pillow is not installed.")
    except Exception as exc: print(f"[!] Could not read image: {exc}")


def public_breach_resources():
    print("Legitimate checking resources (open manually; do not submit sensitive data without consent):")
    print("- https://haveibeenpwned.com/ (policy and email verification)")
    print("- https://monitor.mozilla.org/")
    print("TraceVoid does not collect, download, or display passwords/leaked data.")


def github_public_recon():
    user = input("GitHub username: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", user): print("[!] Invalid GitHub username."); return
    r = _get(f"https://api.github.com/users/{user}")
    if r is not None:
        try:
            d=r.json(); print(json.dumps({k:d.get(k) for k in ("login","name","company","blog","location","bio","public_repos","followers","following","created_at","updated_at")}, indent=2, ensure_ascii=False))
        except ValueError: print("[!] Invalid GitHub response.")


def public_dns_history():
    host = _host(input("Domain: "))
    print("[i] No history is claimed when the API is not configured.")
    key = os.getenv("SECURITYTRAILS_API_KEY")
    if not key:
        print("SECURITYTRAILS_API_KEY is not set. Optional configuration is required; free APIs have quota limits."); return
    r = _get(f"https://api.securitytrails.com/v1/history/{host}/dns/a", headers={"APIKEY": key})
    if r is not None: print(r.text[:12000])


def website_availability():
    r = _get(input("URL: "))
    if r is not None: print(f"Responding: YES\nStatus: {r.status_code}\nTime: {r.elapsed.total_seconds():.3f}s\nFinal URL: {r.url}")


def security_headers_audit():
    r = _get(input("URL: "))
    if r is None: return
    expected = ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy")
    for h in expected: print(f"{'OK  ' if h in r.headers else 'MISS'} {h}: {r.headers.get(h, '(not present)')}")
    print("This audit is indicative, not a penetration test.")


def threat_intelligence():
    value = input("Domain or Public IP: ").strip()
    try: target = str(ipaddress.ip_address(value))
    except ValueError: target = _host(value)
    r = _get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general" if "." in target and target.replace(".", "").isdigit() else f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general")
    if r is not None:
        try: print(json.dumps(r.json(), indent=2, ensure_ascii=False)[:16000])
        except ValueError: print("[!] OTX response was not JSON.")


def whatsapp_phone_intelligence():
    raw = input("International number (for example +628123456789): ").strip()
    if not raw.startswith("+"): print("[!] Use international format beginning with +."); return
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier
        n = phonenumbers.parse(raw, None)
        print("Original number:", raw); print("International format:", phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL)); print("E.164 format:", phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)); print("Country calling code:", n.country_code); print("Region name:", geocoder.description_for_number(n, "en") or "not available"); print("Region code:", phonenumbers.region_code_for_number(n) or "not available"); print("Possible:", phonenumbers.is_possible_number(n)); print("Valid according to numbering rules:", phonenumbers.is_valid_number(n)); print("Type:", phonenumbers.number_type(n)); print("Carrier/area metadata:", carrier.name_for_number(n, "en") or "not available"); print("Limitations: numbering metadata does not reveal ownership, address, GPS, photos, online status, chat contents, or WhatsApp account status; the number is not sent to a server.")
    except ImportError: print("[!] phonenumbers is not installed.")
    except Exception as exc: print(f"[!] Number could not be analyzed: {exc}")


MODULES = [
    ("Username Lookup", username_lookup), ("Domain Intelligence", domain_intelligence), ("DNS Lookup", dns_lookup),
    ("WHOIS Lookup", whois_lookup), ("IP Intelligence", ip_intelligence), ("ASN Lookup", asn_lookup),
    ("HTTP Header Inspector", http_header_inspector), ("TLS Certificate Check", tls_certificate_check),
    ("Subdomain Discovery", subdomain_discovery), ("Robots.txt Viewer", robots_viewer), ("Sitemap Inspector", sitemap_inspector),
    ("URL Analyzer", url_analyzer), ("Redirect Inspector", redirect_inspector), ("Email Format Check", email_format_check),
    ("Username Pattern Analyzer", username_pattern_analyzer), ("Metadata Inspector", metadata_inspector),
    ("File Hash Calculator", file_hash_calculator), ("Image Metadata", image_metadata),
    ("Public Breach Resources", public_breach_resources), ("GitHub Public Recon", github_public_recon),
    ("Public DNS History", public_dns_history), ("Website Availability", website_availability),
    ("Security Headers Audit", security_headers_audit), ("Threat Intelligence", threat_intelligence),
    ("WhatsApp Phone Intelligence", whatsapp_phone_intelligence),
]
