#!/usr/bin/env python3

import re
import sys
from pathlib import Path

import requests

URL_FILE = "urls.txt"
ADAWAY_FILE = "adaway.txt"
DNSMASQ_FILE = "dnsmasq.txt"

HEADERS = {
    "User-Agent": "Mozilla/5.0 BlocklistBuilder/1.0"
}

TIMEOUT = 60

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())


def normalize_domain(domain: str) -> str:
    domain = normalize_whitespace(domain.strip().lower())

    if not domain:
        return ""

    if domain.endswith("."):
        domain = domain[:-1]

    if domain.startswith("."):
        domain = domain[1:]

    try:
        domain = domain.encode("idna").decode("ascii")
    except Exception:
        return ""

    return domain


def is_valid_domain(domain: str) -> bool:
    return bool(domain and DOMAIN_REGEX.match(domain))


def extract_domain(line: str):
    line = normalize_whitespace(line.strip())

    if not line:
        return None

    if "#" in line:
        line = line.split("#", 1)[0].strip()

    if not line or line.startswith(("!", "#", ";", "//")):
        return None

    m = re.match(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s]+)", line, re.I)
    if m:
        return normalize_domain(m.group(1))

    m = re.match(r"^address=/([^/]+)/", line, re.I)
    if m:
        return normalize_domain(m.group(1))

    return normalize_domain(re.split(r"\s+", line)[0].strip("/"))


def format_size(size_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def main():
    url_path = Path(URL_FILE)

    if not url_path.exists():
        print(f"[ERROR] {URL_FILE} not found")
        sys.exit(1)

    with open(url_path, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]

    urls = list(dict.fromkeys(urls))

    if not urls:
        print("[ERROR] No URLs found")
        sys.exit(1)

    session = requests.Session()

    raw_domains = 0
    valid_domains = set()
    total_downloaded = 0
    source_metrics = []

    for i, url in enumerate(urls, 1):
        print(f"[INFO] ({i}/{len(urls)}) Downloading: {url}")

        try:
            with session.get(url, headers=HEADERS, timeout=TIMEOUT, stream=True) as r:
                r.raise_for_status()
                total_downloaded += 1

                bytes_received = 0
                source_unique = set()
                buffer = ""

                for chunk in r.iter_content(chunk_size=65536, decode_unicode=True):
                    if not chunk:
                        continue

                    bytes_received += len(chunk.encode("utf-8"))
                    buffer += chunk

                    lines = buffer.splitlines(keepends=True)
                    buffer = ""

                    if lines and not lines[-1].endswith(("\n", "\r")):
                        buffer = lines.pop()

                    for raw_line in lines:
                        domain = extract_domain(raw_line)
                        if not domain:
                            continue
                        raw_domains += 1
                        if is_valid_domain(domain):
                            source_unique.add(domain)

                if buffer:
                    domain = extract_domain(buffer)
                    if domain:
                        raw_domains += 1
                        if is_valid_domain(domain):
                            source_unique.add(domain)

                source_metrics.append({
                    "url": url,
                    "size_bytes": bytes_received,
                    "domain_count": len(source_unique)
                })

                valid_domains.update(source_unique)

        except Exception as e:
            print(f"[ERROR] Failed: {url} -> {e}")

    sorted_domains = sorted(valid_domains)

    with open(ADAWAY_FILE, "w", encoding="utf-8") as f:
        f.write("# Plain domain blocklist\n\n")
        for d in sorted_domains:
            f.write(d + "\n")

    with open(DNSMASQ_FILE, "w", encoding="utf-8") as f:
        f.write("# dnsmasq blocklist\n\n")
        for d in sorted_domains:
            f.write(f"address=/{d}/0.0.0.0\n")

    print("\n" + "=" * 50)
    print(" INDIVIDUAL SOURCE METRICS REPORT")
    print("=" * 50)

    source_metrics.sort(key=lambda x: x["domain_count"], reverse=True)

    for m in source_metrics:
        print(f"Source: {m['url']}")
        print(f"  └─ File Size: {format_size(m['size_bytes'])}")
        print(f"  └─ Unique Valid Domains: {m['domain_count']:,}\n")

    print("=" * 50)
    print(f"[INFO] Downloaded sources: {total_downloaded}")
    print(f"[INFO] Raw domains processed: {raw_domains}")
    print(f"[INFO] Global unique valid domains: {len(valid_domains)}")
    print(f"[INFO] Global duplicates/invalid removed: {raw_domains - len(valid_domains)}")
    print(f"[INFO] Saved plain domain list to: {ADAWAY_FILE}")
    print(f"[INFO] Saved dnsmasq blocklist to: {DNSMASQ_FILE}")


if __name__ == "__main__":
    main()
