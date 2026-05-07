#!/usr/bin/env python3

import re
import sys
from pathlib import Path

import requests

# =========================
# CONFIG
# =========================

URL_FILE = "urls.txt"
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
# NORMALIZATION (STRONG DEDUPE CORE)
# =========================

def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def normalize_domain(domain: str) -> str:
    domain = normalize_whitespace(domain.strip().lower())

    if not domain:
        return ""

    # remove trailing dot (VERY common duplicate source)
    if domain.endswith("."):
        domain = domain[:-1]

    # remove leading dot
    if domain.startswith("."):
        domain = domain[1:]

    try:
        # normalize unicode -> punycode (prevents unicode duplicates)
        domain = domain.encode("idna").decode("ascii")
    except Exception:
        return ""

    return domain


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    return bool(DOMAIN_REGEX.match(domain))


# =========================
# PARSER
# =========================

def extract_domain(line: str):
    line = normalize_whitespace(line.strip())

    if not line:
        return None

    # remove inline comments
    if "#" in line:
        line = line.split("#", 1)[0].strip()

    if not line:
        return None

    # skip full comment lines
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

    # fallback raw token
    candidate = re.split(r"\s+", line)[0].strip("/")

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
            if line.strip() and not line.strip().startswith("#")
        ]

    # remove duplicate URLs (preserve order)
    urls = list(dict.fromkeys(urls))

    if not urls:
        print("[ERROR] No URLs found")
        sys.exit(1)

    session = requests.Session()

    raw_domains = 0
    valid_domains = set()

    total_downloaded = 0

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
                    if not raw_line:
                        continue

                    domain = extract_domain(raw_line)

                    if not domain:
                        continue

                    raw_domains += 1

                    if not is_valid_domain(domain):
                        continue

                    # FINAL STRONG DEDUPE (set already helps, normalization ensures correctness)
                    valid_domains.add(domain)

        except Exception as e:
            print(f"[ERROR] Failed: {url} -> {e}")
            continue

    sorted_domains = sorted(valid_domains)

    # =========================
    # OUTPUT (AdAway only)
    # =========================

    with open(ADAWAY_FILE, "w", encoding="utf-8") as f:
        f.write("# AdAway hosts blocklist\n\n")

        for d in sorted_domains:
            f.write(f"0.0.0.0 {d}\n")

    # =========================
    # STATS
    # =========================

    print(f"[INFO] Downloaded sources: {total_downloaded}")
    print(f"[INFO] Raw domains found: {raw_domains}")
    print(f"[INFO] Unique valid domains: {len(valid_domains)}")
    print(f"[INFO] Duplicates/invalid removed: {raw_domains - len(valid_domains)}")
    print(f"[INFO] Saved: {ADAWAY_FILE}")


if __name__ == "__main__":
    main()
