#!/usr/bin/env python3
"""
PhishScope - Phishing URL Triage Engine
-----------------------------------------
Combines weighted heuristic checks with a live Google Safe Browsing lookup
to score a URL and produce a clear, severity-grouped verdict.

Usage:
    export GSB_API_KEY="your_api_key"        # optional but recommended
    python phishing_detector.py              # then enter a URL when prompted
    python phishing_detector.py --url <url>  # or pass it directly
"""

import os
import sys
import argparse
import ipaddress
from datetime import datetime
from urllib.parse import unquote, urlparse

import requests

# --- detection data ---------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update",
    "signin", "password", "secure", "access",
]
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]


# --- google safe browsing ---------------------------------------------------

def check_google_safe_browsing(url, api_key):
    """
    Query the Google Safe Browsing API.
    Returns:
        list  -> matches found (empty list means the URL is clean)
        None  -> lookup was skipped or failed (no key / network error)
    """
    if not api_key:
        return None

    api_url = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key
    )
    payload = {
        "client": {"clientId": "phishscope", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(api_url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json().get("matches", [])
    except requests.RequestException as err:
        print(f"  [warn] Safe Browsing lookup failed: {err}")
        return None


# --- heuristic engine -------------------------------------------------------

def analyze_url(url):
    """Run all heuristic checks. Returns (score, high, medium, low, passed)."""
    score = 0
    high, medium, low, passed = [], [], [], []

    decoded = unquote(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""

    # 1. transport security
    if url.startswith("https://"):
        passed.append("HTTPS is enabled")
    else:
        medium.append("HTTP used instead of HTTPS")
        score += 2

    # 2. @ obfuscation
    if "@" in url:
        high.append("'@' symbol detected: may hide the real destination")
        score += 3
    else:
        passed.append("No '@' symbol detected")

    # 3. phishing keywords
    keyword_hits = [k for k in SUSPICIOUS_KEYWORDS if k in decoded.lower()]
    if keyword_hits:
        high.append("Phishing keywords: " + ", ".join(keyword_hits))
        score += 2 * len(keyword_hits)
    else:
        passed.append("No phishing keywords detected")

    # 4. suspicious TLDs
    tld_hits = [t for t in SUSPICIOUS_TLDS if t in url]
    if tld_hits:
        medium.append("Suspicious TLD detected: " + ", ".join(tld_hits))
        score += 3 * len(tld_hits)

    # 5. URL length
    if len(url) > 100:
        low.append("URL length is unusually long")
        score += 1
    else:
        passed.append("URL length looks normal")

    # 6. hyphen abuse
    if url.count("-") >= 2:
        low.append("Multiple hyphens detected in URL")
        score += 1
    else:
        passed.append("Hyphen usage is normal")

    # 7. encoded characters
    if "%" in url:
        medium.append("Encoded characters detected: URL may hide readable text")
        score += 2
    else:
        passed.append("No encoded characters detected")

    # 8. lookalike digits
    if any(ch.isdigit() for ch in url):
        low.append("Digits found in URL: possible lookalike")
        score += 1
    else:
        passed.append("No digit mixing detected")

    # 9. raw IP host
    try:
        ipaddress.ip_address(host)
        high.append("Raw IP address used instead of a domain name")
        score += 3
    except ValueError:
        passed.append("Hostname is a domain, not a raw IP")

    # 10. URL shortener
    if host in URL_SHORTENERS:
        medium.append("URL shortener detected: " + host)
        score += 2

    # 11. non-standard port
    if parsed.port and parsed.port not in (80, 443):
        medium.append("Non-standard port detected: " + str(parsed.port))
        score += 2

    return score, high, medium, low, passed


# --- verdict + rendering ----------------------------------------------------

def verdict_for(score):
    if score == 0:
        return "LOW RISK", 1, "No obvious phishing indicators. Verify the sender anyway."
    if score <= 3:
        return "MEDIUM RISK", 4, "Some indicators found. Review the URL carefully before opening."
    if score <= 6:
        return "HIGH RISK", 7, "Multiple suspicious indicators. Avoid clicking unless verified."
    return "VERY HIGH RISK", 10, "Strong phishing indicators. DO NOT CLICK."


def render(url, score, verdict, bar_fill, recommendation,
           high, medium, low, passed, gsb_state):
    bar = "#" * bar_fill + " " * (10 - bar_fill)
    line = "  " + "-" * 55

    print()
    print("  +---------------------------------------------------+")
    print("  |            P H I S H S C O P E   v1                |")
    print("  |        Phishing URL Triage Engine . SOC           |")
    print("  +---------------------------------------------------+")
    print()
    print(f"  [*] Target   : {url}")
    print(f"  [*] Scanned  : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"  [*] Engines  : 11 heuristics + {gsb_state}")
    print()
    print(line)
    print(f"   RISK SCORE   {score}   [{bar}]   {verdict}")
    print(line)
    print()

    for label, tag, items in (
        ("HIGH  ", "[!]", high),
        ("MEDIUM", "[~]", medium),
        ("LOW   ", "[-]", low),
        ("PASSED", "[+]", passed),
    ):
        if items:
            print(f"  {tag} {label}    ({len(items)})")
            for item in items:
                print(f"      - {item}")
            print()

    print(line)
    print(f"   VERDICT: {recommendation}")
    print(line)
    print()


# --- entry point ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PhishScope - phishing URL triage")
    parser.add_argument("--url", help="URL to analyze (otherwise you'll be prompted)")
    args = parser.parse_args()

    url = (args.url or input("Enter the URL: ")).strip()
    if not url:
        print("No URL provided.")
        sys.exit(1)

    api_key = os.environ.get("GSB_API_KEY")

    score, high, medium, low, passed = analyze_url(url)

    matches = check_google_safe_browsing(url, api_key)
    if matches:  # confirmed malicious -> override score
        score = 100
        for match in matches:
            high.insert(0, (
                "Google Safe Browsing: "
                + match.get("threatType", "UNKNOWN")
                + " (" + match.get("platformType", "UNKNOWN") + ")"
            ))
        gsb_state = "Google Safe Browsing"
    elif matches == []:  # checked, came back clean
        passed.append("Google Safe Browsing did not flag this URL")
        gsb_state = "Google Safe Browsing"
    else:  # None -> skipped or failed
        gsb_state = "Google Safe Browsing (skipped: set GSB_API_KEY)"

    verdict, bar_fill, recommendation = verdict_for(score)
    render(url, score, verdict, bar_fill, recommendation,
           high, medium, low, passed, gsb_state)


if __name__ == "__main__":
    main()
