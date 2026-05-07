#!/usr/bin/env python3

import re
import sys
from pathlib import Path
import requests

# =========================
# CONFIG
# =========================

URL_FILE = "urls.txt"

DNSMASQ_FILE = "dnsmasq.txt"
ADAWAY_FILE = "adaway.txt"

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

    # remove inline comments
    if "#" in line:
        line = line.split("#", 1)[0].strip()

    if not line:
        return None

    # skip comment lines
    if line.startswith(("!", "#", ";", "//")):
        return None

    # hosts format
    hosts_match = re.match(
        r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s]+)",
        line,
        re.IGNORECASE,
    )
    if hosts_match:
        return normalize_domain(hosts_match.group(1))

    # dnsmasq format
    dnsmasq_match = re.match(
        r"^address=/([^/]+)/",
        line,
        re.IGNORECASE,
    )
    if dnsmasq_match:
        return normalize_domain(dnsmasq_match.group(1))

    # fallback raw domain
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

    with open(url_path, "r", encoding="utf-8") as f:
        urls = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    if not urls:
        print("[ERROR] No URLs found")
        sys.exit(1)

    domains = set()

    total_downloaded = 0

    for url in urls:
        print(f"[INFO] Downloading: {url}")

        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            total_downloaded += 1
        except Exception as e:
            print(f"[ERROR] Failed: {url} -> {e}")
            continue

        for line in r.text.splitlines():
            domain = extract_domain(line)

            if not domain:
                continue

            if not is_valid_domain(domain):
                continue

            domains.add(domain)

    print(f"[INFO] Unique domains: {len(domains)}")

    sorted_domains = sorted(domains)

    # =========================
    # dnsmasq.txt (local=/domain/)
    # =========================
    with open(DNSMASQ_FILE, "w", encoding="utf-8") as f:
        f.write("# dnsmasq local override blocklist\n\n")
        for d in sorted_domains:
            f.write(f"local=/{d}/\n")

    # =========================
    # adaway.txt (hosts format)
    # =========================
    with open(ADAWAY_FILE, "w", encoding="utf-8") as f:
        f.write("# AdAway hosts blocklist\n\n")
        for d in sorted_domains:
            f.write(f"127.0.0.1 {d}\n")

    print(f"[INFO] Saved: {DNSMASQ_FILE}")
    print(f"[INFO] Saved: {ADAWAY_FILE}")
    print(f"[INFO] Downloaded sources: {total_downloaded}")
    print(f"[INFO] Final domains: {len(sorted_domains)}")


if __name__ == "__main__":
    main()
