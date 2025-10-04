#!/usr/bin/env python3
"""
Recon starter script:
- DNS enumeration via dnspython
- Wayback URL collection via waybackurls (if installed) or CDX API fallback
- Async URL liveness checking with aiohttp
- Optional external tool runner (dig/nslookup/amass/waybackurls)
- Outputs structured JSON
"""

import argparse
import asyncio
import json
import subprocess
import sys
from datetime import datetime
from typing import List, Dict, Any

import aiohttp
import dns.resolver
import requests
from bs4 import BeautifulSoup

# --------- Config ----------
USER_AGENT = "ReconStarter/1.0 (+https://example.com/)"
CONCURRENCY = 25
TIMEOUT = 15
CDX_API = "http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
# ---------------------------

def dns_enum(domain: str) -> Dict[str, List[str]]:
    """Perform DNS lookups for common record types."""
    result = {}
    resolver = dns.resolver.Resolver()
    types = ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA"]
    for t in types:
        answers = []
        try:
            answers_raw = resolver.resolve(domain, t, lifetime=5)
            for r in answers_raw:
                answers.append(str(r).strip())
        except Exception as e:
            # No record or other error - capture empty or note
            # Not raising because we want to continue
            answers = []
        result[t] = answers
    return result

def run_external_tool(cmd: List[str], capture_output=True, timeout=60) -> Dict[str, Any]:
    """
    Run an external command safely and return stdout/stderr and returncode.
    Example: run_external_tool(['waybackurls', 'example.com'])
    """
    try:
        proc = subprocess.run(cmd, capture_output=capture_output, text=True, timeout=timeout)
        return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": f"Command not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"rc": -2, "stdout": "", "stderr": "Timeout"}

def get_wayback_urls_via_cdx(domain: str, limit: int = 1000) -> List[str]:
    """Query Wayback CDX API and return unique originals up to limit."""
    try:
        url = CDX_API.format(domain=domain)
        r = requests.get(url, params={"limit": limit}, headers={"User-Agent": USER_AGENT}, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
        # CDX returns array of arrays; first row may be field names
        urls = []
        for i, row in enumerate(data):
            # often first row is header if present; skip if it's a header
            if i == 0 and isinstance(row, list) and "original" in row:
                continue
            # row might be like ["http://example.com/path..."]
            if isinstance(row, list):
                urls.append(row[0])
            elif isinstance(row, str):
                urls.append(row)
        # dedupe while preserving order
        seen = set()
        out = []
        for u in urls:
            if u not in seen:
                out.append(u)
                seen.add(u)
        return out
    except Exception:
        return []

async def check_url(session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
    """Check whether a url is alive and return status code and final url."""
    async with semaphore:
        try:
            async with session.head(url, allow_redirects=True, timeout=TIMEOUT) as resp:
                return {"url": url, "status": resp.status, "final_url": str(resp.url)}
        except aiohttp.ClientResponseError as e:
            return {"url": url, "status": getattr(e, 'status', None), "error": str(e)}
        except Exception as e:
            # fallback to GET if HEAD fails (some servers block HEAD)
            try:
                async with session.get(url, allow_redirects=True, timeout=TIMEOUT) as resp:
                    return {"url": url, "status": resp.status, "final_url": str(resp.url)}
            except Exception as e2:
                return {"url": url, "status": None, "error": str(e2)}

async def bulk_check_urls(urls: List[str]) -> List[Dict[str, Any]]:
    """Check many URLs concurrently with a semaphore and aiohttp."""
    sem = asyncio.Semaphore(CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT + 5)
    headers = {"User-Agent": USER_AGENT}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        tasks = [asyncio.create_task(check_url(session, u, sem)) for u in urls]
        results = await asyncio.gather(*tasks)
    return results

def extract_urls_from_waybackstdout(output: str) -> List[str]:
    """If you called waybackurls binary, parse stdout (one URL per line)."""
    return [line.strip() for line in output.splitlines() if line.strip()]

def basic_html_links(url: str) -> List[str]:
    """Simple example: fetch page and extract anchor hrefs (polite)."""
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=8)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        out = []
        for a in soup.find_all("a", href=True):
            out.append(a["href"])
        return out
    except Exception:
        return []

def main():
    ap = argparse.ArgumentParser(description="Recon starter: DNS, Wayback, async URL checks")
    ap.add_argument("domain", help="Target domain (in-scope only!)")
    ap.add_argument("--use-wayback-bin", action="store_true", help="Use installed waybackurls binary (if available)")
    ap.add_argument("--run-dig", action="store_true", help="Run dig for troubleshooting output (external tool)")
    ap.add_argument("--out", default="recon_result.json", help="Output JSON filename")
    ap.add_argument("--max-wayback", type=int, default=500, help="Max number of wayback URLs to consider")
    args = ap.parse_args()

    domain = args.domain.strip()
    result = {"domain": domain, "timestamp": datetime.utcnow().isoformat(), "dns": {}, "wayback": [], "wayback_check": [], "external": {}}

    print(f"[+] DNS enumeration for {domain} ...")
    result["dns"] = dns_enum(domain)

    if args.run_dig:
        print("[+] Running dig +short A ...")
        out = run_external_tool(["dig", "+short", domain])
        result["external"]["dig_A"] = out

    # Wayback: prefer binary if requested & available
    wayback_urls = []
    if args.use_wayback_bin:
        print("[+] Trying waybackurls binary...")
        wb = run_external_tool(["waybackurls", domain], timeout=120)
        if wb["rc"] >= 0 and wb["stdout"]:
            wayback_urls = extract_urls_from_waybackstdout(wb["stdout"])
            result["external"]["wayback_binary"] = {"rc": wb["rc"], "count": len(wayback_urls)}
        else:
            print("[!] waybackurls binary not found or failed, falling back to CDX API")
    if not wayback_urls:
        print("[+] Querying Wayback CDX API ...")
        wayback_urls = get_wayback_urls_via_cdx(domain, limit=args.max_wayback)
        result["wayback_source"] = "cdx_api"
    # limit & dedupe
    uniq = []
    seen = set()
    for u in wayback_urls:
        if u not in seen:
            uniq.append(u)
            seen.add(u)
        if len(uniq) >= args.max_wayback:
            break
    result["wayback"] = uniq
    print(f"[+] Collected {len(uniq)} wayback URLs")

    # Quick sample: extract only HTTP/HTTPS URLs
    urls_to_check = [u for u in uniq if u.startswith("http://") or u.startswith("https://")]
    print(f"[+] Checking {len(urls_to_check)} URLs for liveness (concurrency {CONCURRENCY}) ...")
    if urls_to_check:
        loop = asyncio.get_event_loop()
        checks = loop.run_until_complete(bulk_check_urls(urls_to_check))
        result["wayback_check"] = checks

    # Example: fetch some HTML links from homepage (be polite)
    print("[+] Fetching basic HTML links from homepage (polite & cached) ...")
    try:
        links = basic_html_links(f"https://{domain}")
        result["basic_links_https"] = links[:200]
    except Exception:
        result["basic_links_https"] = []

    # Save JSON
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"[+] Results written to {args.out}")

if __name__ == "__main__":
    main()
#test push

