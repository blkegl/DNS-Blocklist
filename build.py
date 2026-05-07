import re
import os
import requests
from collections import defaultdict

# Load URLs from file instead of hardcoding
def load_sources(file="urls.txt"):
    with open(file, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (DNS-Blocklist Builder)"
}

DOMAIN_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*"
    r"(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)

ADBLOCK_RE = re.compile(r"^\|\|(?P<domain>[^/^$^]+)")

def clean_domain(domain: str):
    domain = domain.strip().lower().rstrip(".")
    domain = domain.replace("^", "")

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        return None

    return domain


def normalize_domain(line: str):
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    m = DOMAIN_RE.match(line)
    if m:
        return clean_domain(m.group("domain"))

    m = ADBLOCK_RE.match(line)
    if m:
        return clean_domain(m.group("domain"))

    if "." in line and " " not in line:
        return clean_domain(line)

    return None


# OPTION A: collapse subdomains
def collapse_domain(domain: str):
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    return ".".join(parts[-2:])


# OPTION B: smarter dedupe using parent tracking
def reduce_domains(domains):
    """
    If a root domain exists, remove its subdomains.
    If subdomains exist first, they get replaced by root later.
    """
    collapsed = set()
    children_map = defaultdict(set)

    # first collapse everything
    for d in domains:
        base = collapse_domain(d)
        children_map[base].add(d)

    # keep only base domains
    for base in children_map:
        collapsed.add(base)

    return collapsed


def fetch(url: str):
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"[ERROR] Failed: {url} → {e}")
        return []


def build_blocklist():
    sources = load_sources()
    print(f"[INFO] Loaded sources: {len(sources)}")

    raw_domains = set()

    for url in sources:
        print(f"[INFO] Downloading: {url}")
        lines = fetch(url)

        for line in lines:
            domain = normalize_domain(line)
            if domain:
                raw_domains.add(domain)

    print(f"[INFO] Raw unique domains: {len(raw_domains)}")

    # APPLY BOTH OPTIMIZATIONS
    reduced = reduce_domains(raw_domains)

    print(f"[INFO] Reduced domains: {len(reduced)}")

    return reduced


def write_file(domains, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for d in sorted(domains):
            f.write(f"0.0.0.0 {d}\n")


def write_dnsmasq(domains, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for d in sorted(domains):
            f.write(f"address=/{d}/0.0.0.0\n")


if __name__ == "__main__":
    domains = build_blocklist()

    if not domains:
        print("[ERROR] No domains collected. Check urls.txt")
        exit(1)

    write_file(domains, "output/hosts.txt")
    write_dnsmasq(domains, "output/dnsmasq.conf")

    print("[INFO] Files generated successfully")
