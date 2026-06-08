<div align="center">

# PhishScope

**A phishing-URL triage engine that thinks like a SOC analyst.**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Google Safe Browsing](https://img.shields.io/badge/Google%20Safe%20Browsing-4285F4?style=flat-square&logo=google&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

</div>

---

## Overview

PhishScope analyzes a URL the way an analyst validates an indicator during triage: it runs a
battery of **heuristic checks**, cross-references the URL against the **Google Safe Browsing API**,
and combines both into a weighted risk score with a clear verdict and severity-grouped findings.

It automates the IOC-validation workflow I run in a live SOC — turning "is this link safe?"
into a fast, evidence-backed decision instead of a gut call.

Most beginner phishing detectors stop at regex. PhishScope adds a **live reputation engine** on
top, so a confirmed-malicious URL is caught even when the static heuristics alone wouldn't flag it.

## Detection signals

Each indicator contributes to a weighted score; together they produce the verdict.

| Signal | Severity | Why it matters |
|---|---|---|
| Raw IP address as host | High | Legitimate sites use domains, not bare IPs |
| `@` symbol in URL | High | Classic trick to hide the real destination |
| Phishing keywords (`login`, `verify`, `account`, `signin`, `secure`, …) | High | Common lures in credential-harvesting pages |
| Suspicious TLDs (`.tk`, `.ml`, `.ga`, `.cf`) | Medium | Free TLDs heavily abused for phishing |
| URL shorteners (`bit.ly`, `tinyurl`, …) | Medium | Hide the true landing page |
| Encoded characters (`%`) | Medium | Used to obscure readable text |
| Non-standard ports | Medium | Unusual hosting often signals abuse |
| HTTP instead of HTTPS | Medium | No transport encryption |
| Excessive length / multiple hyphens / digit mixing | Low | Weak signals of lookalike or spoofed domains |
| **Google Safe Browsing match** | Critical | Confirmed malware / social-engineering — forces max score |

Verdict tiers: **Low → Medium → High → Very High Risk.**

## Setup

```bash
git clone https://github.com/harshith-bandameedi/PhishScope.git
cd PhishScope
pip install requests
```

Get a free [Google Safe Browsing API key](https://developers.google.com/safe-browsing) and set it
as an environment variable — **never hardcode keys in source:**

```bash
export GSB_API_KEY="your_api_key_here"
```

## Usage

```bash
python phishing_detector.py
# Enter the URL: http://paypal-account-verify.tk/secure-login@signin
```

## Sample output

**A confirmed phishing URL** — the Google Safe Browsing match forces a maximum score:

```console
  +---------------------------------------------------+
  |            P H I S H S C O P E   v1                |
  |        Phishing URL Triage Engine . SOC           |
  +---------------------------------------------------+

  [*] Target   : http://paypal-account-verify.tk/secure-login@signin
  [*] Scanned  : 2025-06-07 14:32:10
  [*] Engines  : 11 heuristics + Google Safe Browsing

  ---------------------------------------------------------
   RISK SCORE   100 / 100   [##########]   VERY HIGH RISK
  ---------------------------------------------------------

  [!] HIGH      (5)
      - Google Safe Browsing: SOCIAL_ENGINEERING (ANY_PLATFORM)
      - '@' symbol detected: may hide the real destination
      - Phishing keywords: account, verify, secure, login, signin

  [~] MEDIUM    (2)
      - HTTP used instead of HTTPS
      - Suspicious TLD detected: .tk

  [-] LOW       (1)
      - Multiple hyphens detected in URL

  [+] PASSED    (3)
      - URL length looks normal
      - No encoded characters detected
      - Hostname is a domain, not a raw IP

  ---------------------------------------------------------
   VERDICT: Strong phishing indicators. DO NOT CLICK.
  ---------------------------------------------------------
```

**A clean URL** — every check passes and Safe Browsing comes back clear:

```console
  ---------------------------------------------------------
   RISK SCORE   0 / 100   [          ]   LOW RISK
  ---------------------------------------------------------

  [+] PASSED    (7)
      - HTTPS is enabled
      - No '@' symbol detected
      - URL length looks normal
      - Hyphen usage is normal
      - No encoded characters detected
      - Hostname is a domain, not a raw IP
      - Google Safe Browsing did not flag this URL

  ---------------------------------------------------------
   VERDICT: No obvious phishing indicators. Verify the sender anyway.
  ---------------------------------------------------------
```

## How scoring works

Each signal adds points (raw IP / `@` / keywords = high weight; TLD / shortener / encoding =
medium; length / hyphens / digits = low). A **Google Safe Browsing** hit overrides everything and
sets the score to 100, because a confirmed reputation match outweighs any heuristic guess.

## Roadmap

- [ ] Load the API key from environment / `.env` instead of inline
- [ ] Batch mode: score a file of URLs at once
- [ ] Export findings as JSON for SIEM ingestion
- [ ] WHOIS domain-age lookup (newly registered domains are higher risk)
- [ ] Optional VirusTotal cross-reference

---

<div align="center">

Built by **Harshith Bandameedi** · SOC Analyst
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/harshith-b-848957226/)

</div>
