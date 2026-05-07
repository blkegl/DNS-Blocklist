#!/usr/bin/env python3

"""
Universal Blocklist Merger

Features:
- Downloads blocklists from urls.txt
- Supports:
    * hosts format
    * dnsmasq format
    * plain domains
- Removes:
    * duplicates
    * comments
    * invalid domains
- Outputs:
    * output.txt in hosts format
- Designed for GitHub Actions automation

Usage:
    python3 build.py
"""

import re
import sys
from pathlib import Path

import requests

# =========================
# CONFIG
# =========================

URL_FILE = "urls.txt"
OUTPUT_FILE = "output.txt"
TEMP_DIR = "tmp"

HEADERS = {
    "User-Agent": "Mozilla/5.0 BlocklistBuilder/1.0"
}

TIMEOUT = 60

# =========================
# DOMAIN VALIDATION
# =========================

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# =========================
# HELPERS
# =========================


def is_valid_domain(domain: str) -> bool:
    domain = domain.strip().lower()

    if not domain:
        return False

    if domain.startswith("."):
        domain = domain[1:]

    return bool(DOMAIN_REGEX.match(domain))


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()

    if domain.startswith("."):
        domain = domain[1:]

    return domain


def extract_domain(line: str):
    line = line.strip()

    if not line:
        return None

    # Remove comments
    if "#" in line:
        line = line.split("#", 1)[0].strip()

    if not line:
        return None

    # Skip comments
    if line.startswith(("!", "#", ";", "//")):
        return None

    # =========================
    # HOSTS FORMAT
    # =========================
    # 0.0.0.0 example.com
    # 127.0.0.1 example.com

    hosts_match = re.match(
        r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s]+)",
        line,
        re.IGNORECASE,
    )

    if hosts_match:
        return normalize_domain(hosts_match.group(1))

    # =========================
    # DNSMASQ FORMAT
    # =========================
    # address=/example.com/0.0.0.0

    dnsmasq_match = re.match(
        r"^address=/([^/]+)/",
        line,
        re.IGNORECASE,
    )

    if dnsmasq_match:
        return normalize_domain(dnsmasq_match.group(1))

    # =========================
    # DOMAIN FORMAT
    # =========================

    candidate = line.split()[0]

    return normalize_domain(candidate)


# =========================
# MAIN
# =========================


def main():
    url_path = Path(URL_FILE)

    if not url_path.exists():
        print(f"[ERROR] {URL_FILE} not found")
        sys.exit(1)

    urls = []

    with open(url_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            urls.append(line)

    if not urls:
        print("[ERROR] No URLs found")
        sys.exit(1)

    domains = set()

    total_downloaded = 0
    total_valid = 0

    for url in urls:
        print(f"[INFO] Downloading: {url}")

        try:
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=TIMEOUT,
            )

            response.raise_for_status()

            total_downloaded += 1

        except Exception as e:
            print(f"[ERROR] Failed: {url}")
            print(f"        {e}")
            continue

        lines = response.text.splitlines()

        for line in lines:
            domain = extract_domain(line)

            if not domain:
                continue

            if not is_valid_domain(domain):
                continue

            domains.add(domain)
            total_valid += 1

    print(f"[INFO] Unique domains: {len(domains)}")

    sorted_domains = sorted(domains)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("# Unified Hosts Blocklist\n")
        f.write("# Generated Automatically\n\n")

        for domain in sorted_domains:
            f.write(f"0.0.0.0 {domain}\n")

    print(f"[INFO] Saved: {OUTPUT_FILE}")
    print(f"[INFO] Downloaded lists: {total_downloaded}")
    print(f"[INFO] Total processed domains: {total_valid}")
    print(f"[INFO] Final unique domains: {len(sorted_domains)}")


if __name__ == "__main__":
    main()
