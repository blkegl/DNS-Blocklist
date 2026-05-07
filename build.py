import os
import re
import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0 (DNS-Blocklist Builder)"
}

HOSTS_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)?\s*(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)

ADBLOCK_RE = re.compile(r"^\|\|(?P<domain>[^/^$]+)")


# ----------------------------
# Load sources from urls.txt
# ----------------------------
def load_sources(file_path="urls.txt"):
    if not os.path.exists(file_path):
        print(f"[ERROR] {file_path} not found!")
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        sources = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    return sources


def clean_domain(domain: str) -> str | None:
    domain = domain.strip().lower().rstrip(".")
    domain = domain.replace("^", "")

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        return None

    return domain


def normalize_domain(line: str) -> str | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    # hosts format
    m = HOSTS_RE.match(line)
    if m:
        return clean_domain(m.group("domain"))

    # adblock format
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
    sources = load_sources("urls.txt")

    print("[INFO] Loaded sources:", len(sources))

    unique = set()

    for url in sources:
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


# ----------------------------
# File writers (FIXED)
# ----------------------------
def write_file(path: str, lines: list[str]):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


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


# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    COLLAPSE = False  # set True to reduce size

    domains = build_blocklist(collapse_subdomains=COLLAPSE)

    print("[INFO] Unique domains:", len(domains))

    if not domains:
        print("[WARNING] No domains collected. Check urls.txt content.")
        exit(1)

    write_hosts(domains)
    write_dnsmasq(domains)

    print("[INFO] Files generated:")
    print(" - output/hosts.txt")
    print(" - output/dnsmasq.conf")
