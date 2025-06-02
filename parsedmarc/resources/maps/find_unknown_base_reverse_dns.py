#!/usr/bin/env python

import logging
import os
import csv


def _main():
    input_csv_file_path = "base_reverse_dns.csv"
    base_reverse_dns_map_file_path = "base_reverse_dns_map.csv"
    known_unknown_list_file_path = "known_unknown_base_reverse_dns.txt"
    output_csv_file_path = "unknown_base_reverse_dns.csv"

    csv_headers = ["source_name", "message_count"]

    output_rows = []

    logging.basicConfig()
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    for p in [
        input_csv_file_path,
        base_reverse_dns_map_file_path,
        known_unknown_list_file_path,
    ]:
        if not os.path.exists(p):
            logger.error(f"{p} does not exist")
            exit(1)
    logger.info(f"Loading {known_unknown_list_file_path}")
    known_unknown_domains = []
    with open(known_unknown_list_file_path) as f:
        for line in f.readlines():
            domain = line.lower().strip()
            if domain in known_unknown_domains:
                logger.warning(
                    f"{domain} is in {known_unknown_list_file_path} multiple times"
                )
            else:
                known_unknown_domains.append(domain)
    logger.info(f"Loading {base_reverse_dns_map_file_path}")
    known_domains = []
    with open(base_reverse_dns_map_file_path) as f:
        for row in csv.DictReader(f):
            domain = row["base_reverse_dns"].lower().strip()
            if domain in known_domains:
                logger.warning(
                    f"{domain} is in {base_reverse_dns_map_file_path} multiple times"
                )
            else:
                known_domains.append(domain)
            if domain in known_unknown_domains and known_domains:
                pass
                logger.warning(
                    f"{domain} is in {known_unknown_list_file_path} and {base_reverse_dns_map_file_path}"
                )

    logger.info(f"Checking domains against {base_reverse_dns_map_file_path}")
    with open(input_csv_file_path) as f:
        for row in csv.DictReader(f):
            domain = row["source_name"].lower().strip()
            if domain not in known_domains and domain not in known_unknown_domains:
                logger.info(f"New unknown domain found: {domain}")
                output_rows.append(row)
    logger.info(f"Writing {output_csv_file_path}")
    with open(output_csv_file_path, "w") as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()
        writer.writerows(output_rows)


if __name__ == "__main__":
    _main()
