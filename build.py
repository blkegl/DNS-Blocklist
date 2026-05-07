import os
import re
import requests

SOURCES = [
    # your existing sources here
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (DNS-Blocklist Builder)"
}

# Matches hosts-style entries
HOSTS_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)

# Adblock format: ||example.com^
ADBLOCK_RE = re.compile(r"^\|\|(?P<domain>[^/^$]+)")


def clean_domain(domain: str) -> str | None:
    domain = domain.strip().lower().rstrip(".")

    # remove adblock artifacts
    domain = domain.replace("^", "")

    # basic validation
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        return None

    # remove leading dot if any
    domain = domain.lstrip(".")

    return domain


def normalize_domain(line: str) -> str | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    m = HOSTS_RE.match(line)
    if m:
        return clean_domain(m.group("domain"))

    m = ADBLOCK_RE.match(line)
    if m:
        return clean_domain(m.group("domain"))

    # raw domain fallback
    if "." in line and " " not in line:
        return clean_domain(line)

    return None


def fetch(url: str) -> list[str]:
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception as e:
        print(f"[ERROR] Failed: {url} → {e}")
        return []


def collapse_domain(domain: str) -> str:
    parts = domain.split(".")
    return domain if len(parts) <= 2 else ".".join(parts[-2:])


def build_blocklist(collapse_subdomains: bool = False) -> set[str]:
    unique = set()

    print(f"[INFO] Loaded sources: {len(SOURCES)}")

    for url in SOURCES:
        print(f"[INFO] Downloading: {url}")
        lines = fetch(url)

        for line in lines:
            domain = normalize_domain(line)
            if not domain:
                continue

            if collapse_subdomains:
                domain = collapse_domain(domain)

            unique.add(domain)

    return unique


def write_file(path: str, content: list[str]):
    # 🔥 FIX: ensure directory exists
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        for line in content:
            f.write(line + "\n")


def write_hosts(domains: set[str]):
    write_file(
        "output/hosts.txt",
        [f"0.0.0.0 {d}" for d in sorted(domains)]
    )


def write_dnsmasq(domains: set[str]):
    write_file(
        "output/dnsmasq.conf",
        [f"address=/{d}/0.0.0.0" for d in sorted(domains)]
    )


if __name__ == "__main__":
    COLLAPSE = False  # set True to reduce size heavily

    domains = build_blocklist(collapse_subdomains=COLLAPSE)

    print("[INFO] Unique domains:", len(domains))

    if not domains:
        print("[WARNING] No domains collected. Check SOURCES.")
        exit(1)

    write_hosts(domains)
    write_dnsmasq(domains)

    print("[INFO] Files generated:")
    print(" - output/hosts.txt")
    print(" - output/dnsmasq.conf")
