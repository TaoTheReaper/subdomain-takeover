# subdomain-takeover

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![Async](https://img.shields.io/badge/asyncio-aiohttp-lightgrey?style=for-the-badge)

## Overview

Detects subdomains vulnerable to takeover by checking for dangling CNAME records pointing to unclaimed services (GitHub Pages, Heroku, Netlify, S3, Azure, and 14 more).

## Why this project

Subdomain takeover is a common bug bounty and pentest finding. This tool demonstrates DNS analysis, async HTTP fingerprinting, and service signature matching.

## Features

- Scans 30 common subdomains by default (customizable with `--wordlist`)
- Detects dangling CNAMEs pointing to 18 known takeable services
- Async scanning (15 concurrent) for speed
- Shows all resolving subdomains, not just vulnerable ones
- JSON report output

## Supported Services

GitHub Pages, Heroku, Shopify, Fastly, Ghost, Surge.sh, Tumblr, WordPress.com, Zendesk, Bitbucket, Unbounce, HubSpot, Pantheon, Readme.io, Statuspage, Amazon S3, Azure, Netlify

## Setup

```bash
git clone https://github.com/TaoTheReaper/subdomain-takeover
cd subdomain-takeover
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 subdomain-takeover.py example.com
python3 subdomain-takeover.py example.com --wordlist /path/to/wordlist.txt
python3 subdomain-takeover.py example.com -o report.json
```

## Lessons Learned

- CNAME without A record = dangling DNS = potential takeover
- The fingerprint (error page content) is what confirms exploitability
- Many companies forget subdomains after decommissioning services
