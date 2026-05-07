import re
import requests
from urllib.parse import urlparse
from collections import defaultdict

SOURCES = [
    # your existing sources here
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (DNS-Blocklist Builder)"
}

DOMAIN_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*"
    r"(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)

ADBLOCK_RE = re.compile(r"^\|\|(?P<domain>[^/^$]+)")


def normalize_domain(line: str) -> str | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    # hosts format: 0.0.0.0 example.com
    m = DOMAIN_RE.match(line)
    if m:
        return clean_domain(m.group("domain"))

    # adblock format: ||example.com^
    m = ADBLOCK_RE.match(line)
    if m:
        return clean_domain(m.group("domain"))

    # raw domain fallback
    if "." in line and " " not in line:
        return clean_domain(line)

    return None


def clean_domain(domain: str) -> str | None:
    domain = domain.strip().lower()

    # remove trailing dot
    if domain.endswith("."):
        domain = domain[:-1]

    # remove adblock artifacts
    domain = domain.replace("^", "")

    # basic validation
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        return None

    return domain


def get_domain_sets():
    return set(), set()


def fetch(url: str) -> list[str]:
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"[ERROR] Failed: {url} → {e}")
        return []


def collapse_domain(domain: str) -> str:
    """
    OPTIONAL: collapses subdomains -> root domain
    Example:
        ads.google.com -> google.com
    """
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


def build_blocklist(collapse_subdomains: bool = False):
    unique = set()
    seen_sources = 0

    for url in SOURCES:
        print(f"[INFO] Downloading: {url}")
        lines = fetch(url)
        seen_sources += 1

        for line in lines:
            domain = normalize_domain(line)
            if not domain:
                continue

            if collapse_subdomains:
                domain = collapse_domain(domain)

            unique.add(domain)

    return unique


def write_hosts(domains, path="output/hosts.txt"):
    with open(path, "w") as f:
        for d in sorted(domains):
            f.write(f"0.0.0.0 {d}\n")


def write_dnsmasq(domains, path="output/dnsmasq.conf"):
    with open(path, "w") as f:
        for d in sorted(domains):
            f.write(f"address=/{d}/0.0.0.0\n")


if __name__ == "__main__":
    print("[INFO] Loaded sources:", len(SOURCES))

    # CHANGE THIS:
    COLLAPSE = False   # set True if you want much smaller list

    domains = build_blocklist(collapse_subdomains=COLLAPSE)

    print("[INFO] Unique domains:", len(domains))

    write_hosts(domains)
    write_dnsmasq(domains)

    print("[INFO] Files generated:")
    print("   output/hosts.txt")
    print("   output/dnsmasq.conf")
