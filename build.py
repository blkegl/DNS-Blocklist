#!/usr/bin/env python3

"""
Unified Blocklist Builder (OpenWrt + Android AdAway)

Input:
    urls.txt → list of blocklist URLs

Output:
    output/hosts.txt      → Android (AdAway)
    output/dnsmasq.conf   → OpenWrt (dnsmasq)

Features:
    - Supports hosts, dnsmasq, and plain domain formats
    - Removes duplicates
    - Normalizes domains
"""

import re
from pathlib import Path
import urllib.request

# =========================
# CONFIG
# =========================

URL_FILE = "urls.txt"
OUTPUT_DIR = Path("output")

HOSTS_FILE = OUTPUT_DIR / "hosts.txt"
DNSMASQ_FILE = OUTPUT_DIR / "dnsmasq.conf"

HEADERS = {
    "User-Agent": "Mozilla/5.0 BlocklistBuilder/1.0"
}

# =========================
# DOMAIN VALIDATION
# =========================

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain))


def normalize(domain: str) -> str:
    return domain.strip().lower().lstrip(".")


# =========================
# PARSER
# =========================

def extract_domain(line: str):
    line = line.strip()

    if not line or line.startswith(("#", "!", ";", "//")):
        return None

    # remove inline comments
    if "#" in line:
        line = line.split("#", 1)[0].strip()

    # hosts format
    m = re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s]+)", line)
    if m:
        return normalize(m.group(2))

    # dnsmasq format
    m = re.match(r"^address=/([^/]+)/", line)
    if m:
        return normalize(m.group(1))

    # plain domain
    return normalize(line.split()[0])


# =========================
# DOWNLOAD
# =========================

def download(url: str) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read().decode(errors="ignore")


# =========================
# MAIN
# =========================

def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    if not Path(URL_FILE).exists():
        print("[ERROR] urls.txt not found")
        return

    urls = [
        line.strip()
        for line in open(URL_FILE, "r", encoding="utf-8")
        if line.strip() and not line.startswith("#")
    ]

    domains = set()

    print(f"[INFO] Loaded {len(urls)} blocklist sources")

    # =========================
    # PROCESS EACH LIST
    # =========================

    for url in urls:
        print(f"[INFO] Downloading: {url}")

        try:
            data = download(url)
        except Exception as e:
            print(f"[ERROR] Failed: {url} → {e}")
            continue

        for line in data.splitlines():
            domain = extract_domain(line)

            if not domain:
                continue

            if not is_valid_domain(domain):
                continue

            domains.add(domain)

    sorted_domains = sorted(domains)

    print(f"[INFO] Unique domains: {len(sorted_domains)}")

    # =========================
    # WRITE: ANDROID (AdAway)
    # =========================

    with open(HOSTS_FILE, "w", encoding="utf-8") as f:
        f.write("# Blocklist for AdAway (Android)\n")
        f.write("# Generated automatically\n\n")

        for d in sorted_domains:
            f.write(f"0.0.0.0 {d}\n")

    # =========================
    # WRITE: OPENWRT (dnsmasq)
    # =========================

    with open(DNSMASQ_FILE, "w", encoding="utf-8") as f:
        f.write("# Blocklist for OpenWrt dnsmasq\n")
        f.write("# Generated automatically\n\n")

        for d in sorted_domains:
            f.write(f"address=/{d}/0.0.0.0\n")

    print("[INFO] Files generated:")
    print(f"       {HOSTS_FILE}")
    print(f"       {DNSMASQ_FILE}")


if __name__ == "__main__":
    main()
