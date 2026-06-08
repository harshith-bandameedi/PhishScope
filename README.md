<div align="center">

# 🎣 PhishScope

**A phishing-URL triage engine that thinks like a SOC analyst.**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Google Safe Browsing](https://img.shields.io/badge/Google%20Safe%20Browsing-4285F4?style=flat-square&logo=google&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

</div>

---

## What it does

PhishScope analyzes a URL the way an analyst validates an indicator during triage: it runs a
battery of **heuristic checks**, cross-references the URL against the **Google Safe Browsing API**,
and combines both into a weighted risk score with a clear verdict and severity-grouped findings.

It mirrors the IOC-validation workflow I run in a live SOC — turning "is this link safe?" into a
fast, evidence-backed decision.

## Detection signals

PhishScope inspects each URL for the following indicators, each contributing to a weighted score:

| Signal | Severity | Why it matters |
|---|---|---|
| Raw IP address as host | High | Legitimate sites use domains, not bare IPs |
| `@` symbol in URL | High | Classic trick to hide the real destination |
| Phishing keywords (`login`, `verify`, `account`, …) | High | Common lures in credential-harvesting pages |
| Suspicious TLDs (`.tk`, `.ml`, `.ga`, `.cf`) | Medium | Free TLDs heavily abused for phishing |
| URL shorteners (`bit.ly`, `tinyurl`, …) | Medium | Hide the true landing page |
| Encoded characters (`%`) | Medium | Used to obscure readable text |
| Non-standard ports | Medium | Unusual hosting often signals abuse |
| HTTP instead of HTTPS | Medium | No transport encryption |
| Excessive length / multiple hyphens / digit mixing | Low | Weak signals of lookalike or spoofed domains |
| **Google Safe Browsing match** | Critical | Confirmed malware / social-engineering — forces max score |

Findings roll up into a verdict: **Low → Medium → High → Very High Risk.**

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
# Enter the URL: http://secure-login-update.tk/account/verify
```

## Sample output

```console
================ PHISHING URL DETECTOR ================
URL     : http://secure-login-update.tk/account/verify
Score   : 12
Verdict : Very High Risk

[High]   Phishing keyword detected: login / verify / account
[Medium] Suspicious TLD detected: .tk
[Medium] HTTP used instead of HTTPS

Recommendation:
  Strong phishing indicators detected. Do not click this URL.
=======================================================
```

## Roadmap

- [ ] Load the API key from environment / `.env` instead of inline
- [ ] Batch mode: score a file of URLs at once
- [ ] Export findings as JSON for SIEM ingestion
- [ ] WHOIS domain-age lookup (newly registered domains are higher risk)

---

<div align="center">

Built by **Harshith Bandameedi** · SOC Analyst
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/harshith-b-848957226/)

</div>
