#!/usr/bin/env python
"""Detect and apply PSL overrides for clustered reverse-DNS patterns.

Scans `unknown_base_reverse_dns.csv` for entries that contain a full IPv4
address (four dotted or dashed octets) and share a common brand suffix.
Any suffix repeated by N+ distinct domains is added to `psl_overrides.txt`,
and every affected entry across the unknown / known-unknown / map files is
folded to the suffix's base. Any remaining full-IP entries — whether they
clustered or not — are then removed for privacy. After running, the newly
exposed base domains still need to be researched and classified via the
normal `collect_domain_info.py` + classifier workflow.

Usage (run from `parsedmarc/resources/maps/`):

    python detect_psl_overrides.py [--threshold N] [--dry-run]

Defaults: threshold 3, operates on the project's standard file paths.
"""

import argparse
import csv
import os
import re
import sys
from collections import defaultdict

FULL_IP_RE = re.compile(
    r"(?<![\d])(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?![\d])"
)
# Minimum length of the non-IP tail to be considered a PSL-override candidate.
# Rejects generic TLDs (`.com` = 4) but accepts specific brands (`.cprapid.com` = 12).
MIN_TAIL_LEN = 8


def has_full_ip(s: str) -> bool:
    for m in FULL_IP_RE.finditer(s):
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return True
    return False


def extract_brand_tail(domain: str) -> str | None:
    """Return the non-IP tail of a domain that contains a full IPv4 address.

    The returned string starts at the first byte after the IP match, so it
    includes any leading separator (`.`, `-`, or nothing). That is the exact
    form accepted by `psl_overrides.txt`.
    """
    for m in FULL_IP_RE.finditer(domain):
        octets = [int(g) for g in m.groups()]
        if not all(0 <= o <= 255 for o in octets):
            continue
        tail = domain[m.end() :]
        if len(tail) >= MIN_TAIL_LEN:
            return tail
    return None


def load_overrides(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]


def apply_override(domain: str, overrides: list[str]) -> str:
    for ov in overrides:
        if domain.endswith(ov):
            return ov.strip(".").strip("-")
    return domain


def load_unknown(path: str) -> list[tuple[str, int]]:
    rows = []
    with open(path, encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if not row or not row[0].strip():
                continue
            d = row[0].strip().lower()
            try:
                mc = int(row[1]) if len(row) > 1 and row[1].strip() else 0
            except ValueError:
                mc = 0
            rows.append((d, mc))
    return rows


def load_known_unknown(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def load_map(path: str):
    with open(path, "rb") as f:
        data = f.read().decode("utf-8").split("\r\n")
    header = data[0]
    rows = [line for line in data[1:] if line]
    entries = {}
    for line in rows:
        r = next(csv.reader([line]))
        entries[r[0].lower()] = line
    return header, entries


def write_map(path: str, header: str, entries: dict):
    all_rows = sorted(
        entries.values(), key=lambda line: next(csv.reader([line]))[0].lower()
    )
    out = header + "\r\n" + "\r\n".join(all_rows) + "\r\n"
    with open(path, "wb") as f:
        f.write(out.encode("utf-8"))


def detect_clusters(domains: list[str], threshold: int, known_overrides: set[str]):
    """Return {tail: [member_domains]} for tails shared by `threshold`+ domains."""
    tails = defaultdict(list)
    for d in domains:
        tail = extract_brand_tail(d)
        if not tail:
            continue
        if tail in known_overrides:
            continue
        tails[tail].append(d)
    return {t: ms for t, ms in tails.items() if len(ms) >= threshold}


def main():
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--unknown", default="unknown_base_reverse_dns.csv")
    p.add_argument("--known-unknown", default="known_unknown_base_reverse_dns.txt")
    p.add_argument("--map", default="base_reverse_dns_map.csv")
    p.add_argument("--overrides", default="psl_overrides.txt")
    p.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="minimum distinct domains sharing a tail before auto-adding (default 3)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change without writing files",
    )
    args = p.parse_args()

    overrides = load_overrides(args.overrides)
    overrides_set = set(overrides)

    unknown_rows = load_unknown(args.unknown)
    unknown_domains = [d for d, _ in unknown_rows]

    clusters = detect_clusters(unknown_domains, args.threshold, overrides_set)
    if clusters:
        print(f"Detected {len(clusters)} new cluster(s) (threshold={args.threshold}):")
        for tail, members in sorted(clusters.items()):
            print(f"  +{tail}  ({len(members)} members, e.g. {members[0]})")
    else:
        print("No new clusters detected above threshold.")

    # Build the enlarged override list (don't churn existing order).
    new_overrides = overrides + [t for t in sorted(clusters) if t not in overrides_set]

    def fold(d: str) -> str:
        return apply_override(d, new_overrides)

    # Load other lists
    known_unknowns = load_known_unknown(args.known_unknown)
    header, map_entries = load_map(args.map)

    # === Determine new bases exposed by clustering (not yet in any list) ===
    new_bases = set()
    for tail in clusters:
        base = tail.strip(".").strip("-")
        if base not in map_entries and base not in known_unknowns:
            new_bases.add(base)

    # === Rewrite the map: fold folded keys away, drop full-IP entries ===
    new_map = {}
    map_folded_away = []
    map_ip_removed = []
    for k, line in map_entries.items():
        folded = fold(k)
        if folded != k:
            map_folded_away.append((k, folded))
            # Keep the entry only if the folded form is the one in the map;
            # if we're dropping a specific IP-containing entry whose folded
            # base is elsewhere, discard it
            continue
        if has_full_ip(k):
            map_ip_removed.append(k)
            continue
        new_map[k] = line

    # === Rewrite known_unknown: fold, dedupe, drop full-IP, drop now-mapped ===
    new_ku = set()
    ku_folded = 0
    ku_ip_removed = []
    for d in known_unknowns:
        folded = fold(d)
        if folded != d:
            ku_folded += 1
            continue
        if has_full_ip(d):
            ku_ip_removed.append(d)
            continue
        if d in new_map:
            continue
        new_ku.add(d)

    # === Rewrite unknown.csv: fold, aggregate message counts, drop full-IP, drop mapped/ku ===
    new_unknown = defaultdict(int)
    uk_folded = 0
    uk_ip_removed = []
    for d, mc in unknown_rows:
        folded = fold(d)
        if folded != d:
            uk_folded += 1
        if has_full_ip(folded):
            uk_ip_removed.append(folded)
            continue
        if folded in new_map or folded in new_ku:
            continue
        new_unknown[folded] += mc

    print()
    print("Summary:")
    print(
        f"  map: {len(map_entries)} -> {len(new_map)} "
        f"(folded {len(map_folded_away)}, full-IP removed {len(map_ip_removed)})"
    )
    print(
        f"  known_unknown: {len(known_unknowns)} -> {len(new_ku)} "
        f"(folded {ku_folded}, full-IP removed {len(ku_ip_removed)})"
    )
    print(
        f"  unknown.csv: {len(unknown_rows)} -> {len(new_unknown)} "
        f"(folded {uk_folded}, full-IP removed {len(uk_ip_removed)})"
    )
    print(f"  new overrides added: {len(new_overrides) - len(overrides)}")
    if new_bases:
        print("  new bases exposed (still unclassified, need collector + classifier):")
        for b in sorted(new_bases):
            print(f"    {b}")

    if args.dry_run:
        print("\n(dry-run: no files written)")
        return 0

    # Write files
    if len(new_overrides) != len(overrides):
        with open(args.overrides, "w", encoding="utf-8") as f:
            f.write("\n".join(new_overrides) + "\n")
    write_map(args.map, header, new_map)
    with open(args.known_unknown, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(new_ku)) + "\n")
    with open(args.unknown, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source_name", "message_count"])
        for d, mc in sorted(new_unknown.items(), key=lambda x: (-x[1], x[0])):
            w.writerow([d, mc])

    if new_bases:
        print()
        print("Next: run the normal collect + classify workflow on the new bases.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
