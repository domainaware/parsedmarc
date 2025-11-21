#!/usr/bin/env python

import os
import csv


def _main():
    input_csv_file_path = "base_reverse_dns.csv"
    base_reverse_dns_map_file_path = "base_reverse_dns_map.csv"
    known_unknown_list_file_path = "known_unknown_base_reverse_dns.txt"
    psl_overrides_file_path = "psl_overrides.txt"
    output_csv_file_path = "unknown_base_reverse_dns.csv"

    csv_headers = ["source_name", "message_count"]

    output_rows = []

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
            for psl_domain in psl_overrides:
                if domain.endswith(psl_domain):
                    domain = psl_domain.strip(".").strip("-")
                    break
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
