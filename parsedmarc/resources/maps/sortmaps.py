#!/usr/bin/env python3

import os
import csv

maps_dir = os.path.join(".")
map_files = ["base_reverse_dns_map.csv"]
list_files = ["known_unknown_base_reverse_dns.txt", "psl_overrides.txt"]


def sort_csv(filepath, column=0):
    with open(filepath, mode="r", newline="") as infile:
        reader = csv.reader(infile)
        header = next(reader)
        sorted_rows = sorted(reader, key=lambda row: row[column])
        existing_values = []
        for row in sorted_rows:
            if row[column] in existing_values:
                print(f"Warning: {row[column]} is in {filepath} multiple times")

    with open(filepath, mode="w", newline="\n") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(header)
        writer.writerows(sorted_rows)


def sort_list_file(
    filepath,
    lowercase=True,
    strip=True,
    deduplicate=True,
    remove_blank_lines=True,
    ending_newline=True,
    newline="\n",
):
    with open(filepath, mode="r", newline=newline) as infile:
        lines = infile.readlines()
        for i in range(len(lines)):
            if lowercase:
                lines[i] = lines[i].lower()
            if strip:
                lines[i] = lines[i].strip()
        if deduplicate:
            lines = list(set(lines))
        if remove_blank_lines:
            while "" in lines:
                lines.remove("")
        lines = sorted(lines)
        if ending_newline:
            if lines[-1] != "":
                lines.append("")
    with open(filepath, mode="w", newline=newline) as outfile:
        outfile.write("\n".join(lines))


for csv_file in map_files:
    sort_csv(os.path.join(maps_dir, csv_file))
for list_file in list_files:
    sort_list_file(os.path.join(maps_dir, list_file))
