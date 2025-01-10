#!/usr/bin/env python3

import os
import sys
import glob
import csv


maps_dir = os.path.join("parsedmarc","resources", "maps")
csv_files = glob.glob(os.path.join(maps_dir, "*.csv"))


def sort_csv(filepath, column=0):
    with open(filepath, mode="r", newline="") as infile:
        reader = csv.reader(infile)
        header = next(reader)
        sorted_rows = sorted(reader, key=lambda row: row[column])

    with open(filepath, mode="w", newline="\n") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(header)
        writer.writerows(sorted_rows)


for csv_file in csv_files:
    sort_csv(csv_file)
