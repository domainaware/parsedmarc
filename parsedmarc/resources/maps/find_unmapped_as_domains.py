#!/usr/bin/env python
"""Find ASN domains in the bundled MMDB that aren't in base_reverse_dns_map.csv.

Walks every IPv4 record in the bundled IPinfo Lite MMDB
(``../ipinfo/ipinfo_lite.mmdb``), aggregates the routed IPv4 footprint per
``as_domain``, and subtracts domains already present in
``base_reverse_dns_map.csv`` or ``known_unknown_base_reverse_dns.txt``. The
remaining candidates are ASN-fallback lookup keys with no map coverage yet.

Candidates below ``--min-ips`` (default 4096, i.e. a /20) are dropped. This
floor exists because ASN registration data is self-declared to the RIRs and
``as_domain`` is derived from registrant-controlled WHOIS, so a tiny ASN is
cheap for an adversary to register under an impersonating domain — a large
routed footprint is at least some evidence of a real, long-lived operator.

Output feeds ``collect_domain_info.py -i`` directly (its ``domain`` header is
read by ``_load_input_domains``), which in turn feeds
``classify_unknown_domains.py``. See AGENTS.md's "Checking ASN-domain
coverage of the MMDB" section for the full workflow.
"""

import argparse
import csv
import os
import re
import sys
from collections import defaultdict


# Privacy filter: an as_domain containing a full IPv4 address (four dotted
# or dashed octets) reveals a specific customer IP. Such entries are dropped
# here so they never enter the map or the known-unknown list. Mirrors
# find_unknown_base_reverse_dns.py's _FULL_IP_RE/_has_full_ip.
_FULL_IP_RE = re.compile(
    r"(?<![\d])(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?![\d])"
)


def _has_full_ip(s: str) -> bool:
    for m in _FULL_IP_RE.finditer(s):
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return True
    return False


def _load_as_domain_footprints(mmdb_path: str) -> dict[str, tuple[int, str]]:
    """Return {as_domain.lower(): (ipv4_count, as_name)}.

    Aggregates ``net.num_addresses`` per lowercased/stripped ``as_domain``
    across every IPv4 record. When an as_domain appears under more than one
    as_name (uncommon), the as_name carrying the largest aggregate footprint
    wins.
    """
    try:
        import maxminddb
    except ImportError:
        print(
            "Error: maxminddb is required to walk the MMDB; "
            "install parsedmarc's runtime dependencies (pip install maxminddb)",
            file=sys.stderr,
        )
        sys.exit(1)

    counts: dict[tuple[str, str], int] = defaultdict(int)
    with maxminddb.open_database(mmdb_path) as reader:
        for net, rec in reader:
            if net.version != 4 or not isinstance(rec, dict):
                continue
            as_domain = rec.get("as_domain")
            if not as_domain:
                continue
            as_domain = as_domain.lower().strip()
            as_name = (rec.get("as_name") or "").strip()
            counts[(as_domain, as_name)] += net.num_addresses

    totals: dict[str, int] = defaultdict(int)
    for (as_domain, _as_name), count in counts.items():
        totals[as_domain] += count

    best_name: dict[str, tuple[str, int]] = {}
    for (as_domain, as_name), count in counts.items():
        existing = best_name.get(as_domain)
        if existing is None or count > existing[1]:
            best_name[as_domain] = (as_name, count)

    return {d: (totals[d], best_name[d][0]) for d in totals}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find ASN domains in the bundled MMDB with no "
            "base_reverse_dns_map.csv coverage yet, ranked by routed IPv4 "
            "footprint. Output feeds collect_domain_info.py -i."
        )
    )
    parser.add_argument(
        "--mmdb",
        default="../ipinfo/ipinfo_lite.mmdb",
        help="Path to ipinfo_lite.mmdb (default: %(default)s)",
    )
    parser.add_argument(
        "--min-ips",
        type=int,
        default=4096,
        help=(
            "Minimum aggregate IPv4 footprint (default: %(default)s, a "
            "/20) below which a candidate is dropped as anti-poisoning "
            "protection against self-declared ASN registration data"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default="unmapped_as_domains.csv",
        help="Path to write the output CSV to (default: %(default)s)",
    )
    return parser.parse_args()


def _main():
    args = _parse_args()

    base_reverse_dns_map_file_path = "base_reverse_dns_map.csv"
    known_unknown_list_file_path = "known_unknown_base_reverse_dns.txt"
    psl_overrides_file_path = "psl_overrides.txt"

    known_domains: set[str] = set()
    known_unknown_domains: set[str] = set()
    psl_overrides: list[str] = []

    def load_list(file_path, list_var):
        if not os.path.exists(file_path):
            print(f"Error: {file_path} does not exist")
            sys.exit(1)
        print(f"Loading {file_path}")
        with open(file_path) as f:
            for line in f.readlines():
                domain = line.lower().strip()
                if domain != "":
                    list_var.append(domain)

    if not os.path.exists(base_reverse_dns_map_file_path):
        print(f"Error: {base_reverse_dns_map_file_path} does not exist")
        sys.exit(1)
    print(f"Loading {base_reverse_dns_map_file_path}")
    with open(base_reverse_dns_map_file_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            known_domains.add(row["base_reverse_dns"].lower().strip())

    known_unknown_list: list[str] = []
    load_list(known_unknown_list_file_path, known_unknown_list)
    known_unknown_domains.update(known_unknown_list)

    load_list(psl_overrides_file_path, psl_overrides)

    if not os.path.exists(args.mmdb):
        print(f"Error: {args.mmdb} does not exist")
        sys.exit(1)
    print(f"Loading {args.mmdb}")
    footprints = _load_as_domain_footprints(args.mmdb)
    print(f"Indexed {len(footprints)} as_domains from the MMDB")

    below_floor = 0
    output_rows = []
    for domain, (count, as_name) in footprints.items():
        for psl_domain in psl_overrides:
            if domain.endswith(psl_domain):
                domain = psl_domain.strip(".").strip("-")
                break
        if _has_full_ip(domain):
            continue
        if domain in known_domains or domain in known_unknown_domains:
            continue
        if count < args.min_ips:
            below_floor += 1
            continue
        output_rows.append((domain, count, as_name))

    # A PSL fold can merge multiple as_domains onto the same base domain;
    # keep the row with the larger footprint for each resulting key.
    merged: dict[str, tuple[int, str]] = {}
    for domain, count, as_name in output_rows:
        existing = merged.get(domain)
        if existing is None or count > existing[0]:
            merged[domain] = (count, as_name)

    output_rows = sorted(
        ((d, c, n) for d, (c, n) in merged.items()),
        key=lambda r: -r[1],
    )

    print(
        f"{len(output_rows)} candidate(s) at or above the {args.min_ips:,} "
        f"IPv4 floor; {below_floor} below-floor candidate(s) dropped"
    )
    print(f"Writing {args.output}")
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "ipv4_count", "as_name"])
        for domain, count, as_name in output_rows:
            writer.writerow([domain, count, as_name])


if __name__ == "__main__":
    _main()
