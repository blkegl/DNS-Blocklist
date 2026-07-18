#!/usr/bin/env python3
# Domain Aggregator - Optimized for plain domain lists and hosts files.
import os
import re
import requests

INPUT_FILE = "url.txt"
OUTPUT_FILE = "domains.txt"
TIMEOUT = 30
USER_AGENT = "Mozilla/5.0"

DOMAIN_REGEX = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
SKIP = {"localhost", "localhost.localdomain", "broadcasthost", "local"}
HOSTS = {"0.0.0.0", "127.0.0.1", "::1", "::", "255.255.255.255"}

def fmt(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024 or unit == "GB":
            return f"{int(n)} B" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024

def valid(d):
    if not d: 
        return None
    d = d.strip(".").lower()
    if d in SKIP: 
        return None
    try:
        if any(ord(c) > 127 for c in d): 
            d = d.encode("idna").decode("ascii")
    except Exception: 
        return None
    return d if DOMAIN_REGEX.fullmatch(d) else None

def extract(line):
    # Strip BOM, whitespace, and lowercase early
    line = line.lstrip("\ufeff").strip().lower()
    # Fast drop for comment lines or empty space before execution splits
    if not line or line.startswith("#"):
        return None
    
    line = line.split("#", 1)[0].strip()
    p = line.split()
    if not p: 
        return None
    
    # Process hosts structure vs plain domain format cleanly
    if p[0] in HOSTS:
        if len(p) < 2:
            return None
        return p[1].strip(".")
    return p[0].strip(".")

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: Configuration file '{INPUT_FILE}' not found.")
        return

    with open(INPUT_FILE, encoding="utf-8") as f:
        # Keeps original list ordering intact via insertion-ordered deduplication
        urls = list(dict.fromkeys(l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")))

    g, metrics, raw, ok = set(), [], 0, 0

    with requests.Session() as sess:
        sess.headers.update({"User-Agent": USER_AGENT})

        for i, u in enumerate(urls, 1):
            print(f"[{i}/{len(urls)}] Fetching: {u}")
            try:
                with sess.get(u, stream=True, timeout=TIMEOUT) as r:
                    r.raise_for_status()
                    sz = int(r.headers.get("Content-Length", "0") or 0)
                    fb, uniq, cnt = 0, set(), 0
                    
                    for b in r.iter_lines():
                        if b is None: 
                            continue
                        if not sz: 
                            fb += len(b) + 1
                        
                        extracted = extract(b.decode("utf-8", "ignore"))
                        validated = valid(extracted)
                        if validated:
                            cnt += 1  # Accurately counts actual valid domains before deduplication
                            uniq.add(validated)
                            g.add(validated)
                                
                    metrics.append((u, sz or fb, len(uniq)))
                    raw += cnt
                    ok += 1
                    print(f"  └─ {len(uniq):,} unique valid domains")
            except requests.RequestException as e: 
                print("  └─ HTTP ERROR:", e)

    metrics.sort(key=lambda x: x[2], reverse=True)
    clean = sorted(list(g))

    # Single-pass massive I/O block write to maximize disk throughput
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        if clean:
            f.write("\n".join(clean))
            f.write("\n")

    print("\n" + "=" * 50)
    print(" INDIVIDUAL SOURCE METRICS REPORT")
    print("=" * 50)
    for u, s, c in metrics:
        print(f"Source: {u}\n  └─ File Size: {fmt(s)}\n  └─ Unique Valid Domains: {c:,}\n")

    print("=" * 50)
    print(f"[INFO] Downloaded sources: {ok}")
    print(f"[INFO] Raw valid domains encountered: {raw:,}")
    print(f"[INFO] Global unique valid domains written: {len(clean):,}")
    print(f"[INFO] Total duplicate entries dropped: {raw - len(clean):,}")
    print("=" * 50)

if __name__ == "__main__":
    main()
