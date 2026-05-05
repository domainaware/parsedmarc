#!/usr/bin/env python

import os
import csv
import re
import sys
from collections import defaultdict


# Privacy filter: a reverse DNS entry containing a full IPv4 address (four
# dotted or dashed octets) reveals a specific customer IP. Such entries are
# dropped here so they never enter unknown_base_reverse_dns.csv and therefore
# never make it into the map or the known-unknown list.
_FULL_IP_RE = re.compile(
    r"(?<![\d])(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?![\d])"
)

# A source_name can fail this match when parsedmarc's ASN-fallback path in
# utils.py:get_ip_address_info surfaces the raw MMDB ``as_name`` (e.g. "VODAFONE
# GROUP PLC") because the IP had no PTR and the as_domain wasn't in the map.
_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$"
)


def _has_full_ip(s: str) -> bool:
    for m in _FULL_IP_RE.finditer(s):
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return True
    return False


def _looks_like_domain(s: str) -> bool:
    return bool(_DOMAIN_RE.match(s))


def _normalize_as_name(s: str) -> str:
    # NBSP (U+00A0) appears in both MMDB as_names and CSV source_names but
    # not always on the same side, so an exact match misses pairs that are
    # otherwise identical. Fold NBSP to a regular space and collapse runs
    # of whitespace before comparing.
    return re.sub(r"\s+", " ", s.replace("\xa0", " ")).lower().strip()


def _load_as_name_index(mmdb_path: str) -> dict[str, str]:
    """Build a normalized as_name -> as_domain index from the bundled MMDB.

    When a single as_name maps to multiple as_domains (about 1% of records),
    the as_domain with the largest aggregate IPv4 footprint wins.
    """
    try:
        import maxminddb
    except ImportError:
        print(
            "Error: maxminddb is required to translate AS-name source rows; "
            "install parsedmarc's runtime dependencies (pip install maxminddb)",
            file=sys.stderr,
        )
        sys.exit(1)

    counts: dict[tuple[str, str], int] = defaultdict(int)
    with maxminddb.open_database(mmdb_path) as reader:
        for net, rec in reader:
            if net.version != 4 or not isinstance(rec, dict):
                continue
            as_name = rec.get("as_name")
            as_domain = rec.get("as_domain")
            if not as_name or not as_domain:
                continue
            counts[(_normalize_as_name(as_name), as_domain.lower().strip())] += (
                net.num_addresses
            )

    best: dict[str, tuple[str, int]] = {}
    for (as_name_lower, as_domain_lower), count in counts.items():
        existing = best.get(as_name_lower)
        if existing is None or count > existing[1]:
            best[as_name_lower] = (as_domain_lower, count)
    return {k: v[0] for k, v in best.items()}


def _main():
    input_csv_file_path = "base_reverse_dns.csv"
    base_reverse_dns_map_file_path = "base_reverse_dns_map.csv"
    known_unknown_list_file_path = "known_unknown_base_reverse_dns.txt"
    psl_overrides_file_path = "psl_overrides.txt"
    mmdb_file_path = "../ipinfo/ipinfo_lite.mmdb"
    output_csv_file_path = "unknown_base_reverse_dns.csv"

    csv_headers = ["source_name", "message_count"]

    known_unknown_domains = []
    psl_overrides = []
    known_domains = []
    output_rows = []

    def load_list(file_path, list_var):
        if not os.path.exists(file_path):
            print(f"Error: {file_path} does not exist")
        print(f"Loading {file_path}")
        with open(file_path) as f:
            for line in f.readlines():
                domain = line.lower().strip()
                if domain in list_var:
                    print(f"Error: {domain} is in {file_path} multiple times")
                    exit(1)
                elif domain != "":
                    list_var.append(domain)

    load_list(known_unknown_list_file_path, known_unknown_domains)
    load_list(psl_overrides_file_path, psl_overrides)
    if not os.path.exists(mmdb_file_path):
        print(f"Error: {mmdb_file_path} does not exist")
        exit(1)
    print(f"Loading {mmdb_file_path}")
    as_name_index = _load_as_name_index(mmdb_file_path)
    print(f"Indexed {len(as_name_index)} as_names from the MMDB")
    if not os.path.exists(base_reverse_dns_map_file_path):
        print(f"Error: {base_reverse_dns_map_file_path} does not exist")
    print(f"Loading {base_reverse_dns_map_file_path}")
    with open(base_reverse_dns_map_file_path) as f:
        for row in csv.DictReader(f):
            domain = row["base_reverse_dns"].lower().strip()
            if domain in known_domains:
                print(
                    f"Error: {domain} is in {base_reverse_dns_map_file_path} multiple times"
                )
                exit()
            else:
                known_domains.append(domain)
            if domain in known_unknown_domains and known_domains:
                print(
                    f"Error:{domain} is in {known_unknown_list_file_path} and \
                        {base_reverse_dns_map_file_path}"
                )
                exit(1)
    if not os.path.exists(input_csv_file_path):
        print(f"Error: {base_reverse_dns_map_file_path} does not exist")
        exit(1)
    with open(input_csv_file_path) as f:
        for row in csv.DictReader(f):
            domain = row["source_name"].lower().strip()
            if domain == "":
                continue
            # If source_name is not domain-shaped, parsedmarc's ASN-fallback
            # path (utils.py:get_ip_address_info) surfaced the raw MMDB
            # ``as_name`` because the IP had no PTR and the as_domain wasn't
            # in the map. Translate to the corresponding as_domain so the
            # row enters the pipeline as a researchable domain. If the
            # as_domain is already in the map, the row drops out below as a
            # known domain — exactly what we want.
            if not _looks_like_domain(domain):
                translated = as_name_index.get(_normalize_as_name(domain))
                if translated is None:
                    print(
                        f"Skipping AS-name source with no MMDB match: "
                        f"{row['source_name']!r}"
                    )
                    continue
                print(f"Translating AS-name {row['source_name']!r} -> {translated}")
                row["source_name"] = translated
                domain = translated
            for psl_domain in psl_overrides:
                if domain.endswith(psl_domain):
                    domain = psl_domain.strip(".").strip("-")
                    break
            # Privacy: never emit an entry containing a full IPv4 address.
            # If no psl_override folded it away, drop it entirely.
            if _has_full_ip(domain):
                continue
            if domain not in known_domains and domain not in known_unknown_domains:
                print(f"New unknown domain found: {domain}")
                output_rows.append(row)
    print(f"Writing {output_csv_file_path}")
    with open(output_csv_file_path, "w") as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        writer.writerows(output_rows)


if __name__ == "__main__":
    _main()
