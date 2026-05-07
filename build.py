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

def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def normalize_domain(domain: str) -> str:
    domain = normalize_whitespace(domain.strip().lower())

    if domain.startswith("."):
        domain = domain[1:]

    try:
        # Convert IDN to punycode
        domain = domain.encode("idna").decode("ascii")
    except Exception:
        return ""

    return domain


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False

    return bool(DOMAIN_REGEX.match(domain))


def extract_domain(line: str):
    line = normalize_whitespace(line.strip())

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
    candidate = re.split(r"\s+", line)[0]
    candidate = candidate.strip("/")

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
            if line.strip()
            and not line.strip().startswith("#")
        ]

    # remove duplicate URLs while preserving order
    urls = list(dict.fromkeys(urls))

    if not urls:
        print("[ERROR] No URLs found")
        sys.exit(1)

    domains = set()

    raw_domains = 0

    total_downloaded = 0

    session = requests.Session()

    for i, url in enumerate(urls, start=1):
        print(f"[INFO] ({i}/{len(urls)}) Downloading: {url}")

        try:
            with session.get(
                url,
                headers=HEADERS,
                timeout=TIMEOUT,
                stream=True,
            ) as r:

                r.raise_for_status()

                total_downloaded += 1

                for raw_line in r.iter_lines(decode_unicode=True):
                    if raw_line is None:
                        continue

                    line = raw_line.strip()

                    if not line:
                        continue

                    domain = extract_domain(line)

                    if not domain:
                        continue

                    raw_domains += 1

                    if not is_valid_domain(domain):
                        continue

                    domains.add(domain)

        except Exception as e:
            print(f"[ERROR] Failed: {url} -> {e}")
            continue

    print(f"[INFO] Raw domains found: {raw_domains}")
    print(f"[INFO] Unique valid domains: {len(domains)}")
    print(f"[INFO] Removed duplicates/invalid: {raw_domains - len(domains)}")

    sorted_domains = sorted(domains)

    # =========================
    # dnsmasq.txt
    # =========================

    with open(DNSMASQ_FILE, "w", encoding="utf-8") as f:
        f.write("# dnsmasq blocklist\n\n")

        for d in sorted_domains:
            f.write(f"address=/{d}/\n")

    # =========================
    # adaway.txt
    # =========================

    with open(ADAWAY_FILE, "w", encoding="utf-8") as f:
        f.write("# AdAway hosts blocklist\n\n")

        for d in sorted_domains:
            f.write(f"0.0.0.0 {d}\n")

    print(f"[INFO] Saved: {DNSMASQ_FILE}")
    print(f"[INFO] Saved: {ADAWAY_FILE}")
    print(f"[INFO] Downloaded sources: {total_downloaded}")
    print(f"[INFO] Raw domains: {raw_domains}")
    print(f"[INFO] Optimized unique domains: {len(sorted_domains)}")
    print(f"[INFO] Reduction: {raw_domains - len(sorted_domains)}")


if __name__ == "__main__":
    main()
