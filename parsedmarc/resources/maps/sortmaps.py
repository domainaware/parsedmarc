#!/usr/bin/env python3

import os
import pandas as pd

maps_dir = os.path.join(".")
map_files = ["base_reverse_dns_map.csv"]
list_files = ["known_unknown_base_reverse_dns.txt", "psl_overrides.txt"]


def sort_csv(
    filepath, column=0, column_name=None, strip_whitespace=True, duplicates_warning=True
):
    # Load CSV into a DataFrame
    df = pd.read_csv(filepath)

    if strip_whitespace:
        df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)

    if column_name is None:
        column_name = df.columns[column]

    # Check for duplicates
    duplicates = df[df.duplicated(subset=[column_name], keep=False)]
    if duplicates_warning and not duplicates.empty:
        print(f"⚠️ Warning: Duplicate values found in column '{column_name}':")
        print(duplicates[[column_name]])

    # Sort by the first column
    df = df.sort_values(by=column_name)

    # Save back to the same file (overwrite, no index column)
    df.to_csv(filepath, index=False)


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
