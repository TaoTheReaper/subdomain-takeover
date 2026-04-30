#!/usr/bin/env python3
"""subdomain-takeover — detect dangling DNS records vulnerable to takeover."""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import dns.resolver
    import dns.exception
    import aiohttp
except ImportError as e:
    print(f"[!] Missing: {e}\n    pip install dnspython aiohttp")
    sys.exit(1)

log = logging.getLogger("subdomain-takeover")

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"
}

# Services with known takeover fingerprints
TAKEOVER_SIGNATURES = [
    {"service": "GitHub Pages",      "cname": ["github.io"],           "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "Heroku",            "cname": ["herokuapp.com", "herokudns.com"], "fingerprint": "No such app"},
    {"service": "Shopify",           "cname": ["myshopify.com"],        "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Fastly",            "cname": ["fastly.net"],           "fingerprint": "Fastly error: unknown domain"},
    {"service": "Ghost",             "cname": ["ghost.io"],             "fingerprint": "The thing you were looking for is no longer here"},
    {"service": "Surge.sh",          "cname": ["surge.sh"],             "fingerprint": "project not found"},
    {"service": "Tumblr",            "cname": ["tumblr.com"],           "fingerprint": "There's nothing here"},
    {"service": "WordPress.com",     "cname": ["wordpress.com"],        "fingerprint": "Do you want to register"},
    {"service": "Zendesk",           "cname": ["zendesk.com"],          "fingerprint": "Help Center Closed"},
    {"service": "Bitbucket",         "cname": ["bitbucket.io"],         "fingerprint": "Repository not found"},
    {"service": "Unbounce",          "cname": ["unbouncepages.com"],    "fingerprint": "The requested URL was not found"},
    {"service": "HubSpot",           "cname": ["hubspotpages.com"],     "fingerprint": "Domain not found"},
    {"service": "Pantheon",          "cname": ["pantheonsite.io"],      "fingerprint": "404 error unknown site"},
    {"service": "Readme.io",         "cname": ["readme.io"],            "fingerprint": "Project doesnt exist"},
    {"service": "Statuspage",        "cname": ["statuspage.io"],        "fingerprint": "You are being redirected"},
    {"service": "Amazon S3",         "cname": ["s3.amazonaws.com"],     "fingerprint": "NoSuchBucket"},
    {"service": "Azure",             "cname": ["azurewebsites.net", "cloudapp.net"], "fingerprint": "404 Web Site not found"},
    {"service": "Netlify",           "cname": ["netlify.app", "netlify.com"], "fingerprint": "Not Found - Request ID"},
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "dev", "api", "shop", "portal",
    "beta", "staging", "blog", "smtp", "webmail", "app", "test",
    "demo", "cdn", "static", "assets", "media", "help", "support",
    "docs", "status", "monitor", "vpn", "remote", "old", "new",
]

def setup_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

def resolve_cname(subdomain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=5)
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None

def resolve_a(subdomain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(subdomain, "A", lifetime=5)
        return [str(a) for a in answers]
    except Exception:
        return []

async def fetch_body(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True) as resp:
            return await resp.text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def check_takeover_signature(cname: str, body: str) -> dict | None:
    for sig in TAKEOVER_SIGNATURES:
        if any(s in cname for s in sig["cname"]):
            if sig["fingerprint"].lower() in body.lower():
                return sig
    return None

async def check_subdomain(session: aiohttp.ClientSession, fqdn: str, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        result = {
            "subdomain": fqdn,
            "resolves":  False,
            "cname":     None,
            "ips":       [],
            "vulnerable": False,
            "service":   None,
            "status":    "no_dns",
        }

        cname = resolve_cname(fqdn)
        ips   = resolve_a(fqdn)

        if not cname and not ips:
            return result

        result["resolves"] = True
        result["cname"]    = cname
        result["ips"]      = ips
        result["status"]   = "resolves"

        if cname:
            body = await fetch_body(session, f"http://{fqdn}")
            if not body:
                body = await fetch_body(session, f"https://{fqdn}")

            sig = check_takeover_signature(cname, body)
            if sig:
                result["vulnerable"] = True
                result["service"]    = sig["service"]
                result["status"]     = "VULNERABLE"
                log.info("VULNERABLE: %s → %s (%s)", fqdn, cname, sig["service"])

        return result

async def run_scan(domain: str, wordlist: list[str], custom_subs: list[str]) -> list[dict]:
    subs = list(dict.fromkeys(wordlist + custom_subs))
    fqdns = [f"{s}.{domain}" for s in subs]

    print(f"{C['cyan']}[*] Scanning {len(fqdns)} subdomains on {domain}...{C['reset']}")

    semaphore = asyncio.Semaphore(15)
    async with aiohttp.ClientSession() as session:
        tasks = [check_subdomain(session, fqdn, semaphore) for fqdn in fqdns]
        results = await asyncio.gather(*tasks)

    return list(results)

def print_results(results: list[dict]):
    resolving   = [r for r in results if r["resolves"]]
    vulnerable  = [r for r in results if r["vulnerable"]]
    not_resolve = [r for r in results if not r["resolves"]]

    print(f"\n{C['cyan']}{'='*60}{C['reset']}")

    if vulnerable:
        print(f"\n{C['red']}{C['bold']}⚠ VULNERABLE SUBDOMAINS ({len(vulnerable)}){C['reset']}")
        for r in vulnerable:
            print(f"  {C['red']}[TAKEOVER] {r['subdomain']}{C['reset']}")
            print(f"    CNAME   : {r['cname']}")
            print(f"    Service : {r['service']}")
    else:
        print(f"\n{C['green']}  No vulnerable subdomains found.{C['reset']}")

    print(f"\n{C['green']}Resolving subdomains ({len(resolving)}){C['reset']}")
    for r in resolving:
        vuln_tag = f" {C['red']}[VULNERABLE]{C['reset']}" if r["vulnerable"] else ""
        cname_tag = f" → {r['cname']}" if r["cname"] else ""
        ips_tag = f" [{', '.join(r['ips'])}]" if r["ips"] else ""
        print(f"  {r['subdomain']}{cname_tag}{ips_tag}{vuln_tag}")

    print(f"\n{C['cyan']}Summary{C['reset']}")
    print(f"  Scanned   : {len(results)}")
    print(f"  Resolving : {len(resolving)}")
    print(f"  {C['red']}Vulnerable: {len(vulnerable)}{C['reset']}")
    print(f"{C['cyan']}{'='*60}{C['reset']}")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subdomain-takeover",
        description="Detect subdomains vulnerable to takeover (dangling CNAME records).",
        epilog="Examples:\n  python subdomain-takeover.py example.com\n  python subdomain-takeover.py example.com -o report.json -v",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domain",            help="Target domain (e.g. example.com)")
    p.add_argument("-w", "--wordlist",  metavar="FILE", help="Custom subdomain wordlist (one per line)")
    p.add_argument("-o", "--output",    metavar="FILE", help="Save JSON report")
    p.add_argument("-v", "--verbose",   action="store_true")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    custom = []
    if args.wordlist:
        custom = [l.strip() for l in Path(args.wordlist).read_text().splitlines() if l.strip()]

    results = asyncio.run(run_scan(args.domain, SUBDOMAIN_WORDLIST, custom))
    print_results(results)

    if args.output:
        report = {
            "domain":    args.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results":   results,
        }
        tmp = args.output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, args.output)
        print(f"{C['green']}[+] Report saved: {args.output}{C['reset']}")

if __name__ == "__main__":
    main()
