#!/usr/bin/env python3

from __future__ import annotations

import os
import csv
from pathlib import Path
from typing import Mapping, Iterable, Optional, Collection, Union, List, Dict


class CSVValidationError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


def sort_csv(
    filepath: Union[str, Path],
    field: str,
    *,
    sort_field_value_must_be_unique: bool = True,
    strip_whitespace: bool = True,
    fields_to_lowercase: Optional[Iterable[str]] = None,
    case_insensitive_sort: bool = False,
    required_fields: Optional[Iterable[str]] = None,
    allowed_values: Optional[Mapping[str, Collection[str]]] = None,
) -> List[Dict[str, str]]:
    """
    Read a CSV, optionally normalize rows (strip whitespace, lowercase certain fields),
    validate field values, and write the sorted CSV back to the same path.

    - filepath: Path to the CSV to sort.
    - field: The field name to sort by.
    - fields_to_lowercase: Permanently lowercases these field(s) in the data.
    - strip_whitespace: Remove all whitespace at the beginning and of field values.
    - case_insensitive_sort: Ignore case when sorting without changing values.
    - required_fields: A list of fields that must have data in all rows.
    - allowed_values: A mapping of allowed values for fields.
    """
    path = Path(filepath)
    required_fields = set(required_fields or [])
    lower_set = set(fields_to_lowercase or [])
    allowed_sets = {k: set(v) for k, v in (allowed_values or {}).items()}
    if sort_field_value_must_be_unique:
        seen_sort_field_values = []

    with path.open("r", newline="") as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames or []
        if field not in fieldnames:
            raise CSVValidationError([f"Missing sort column: {field!r}"])
        missing_headers = required_fields - set(fieldnames)
        if missing_headers:
            raise CSVValidationError(
                [f"Missing required header(s): {sorted(missing_headers)}"]
            )
        rows = list(reader)

    def normalize_row(row: Dict[str, str]) -> None:
        if strip_whitespace:
            for k, v in row.items():
                if isinstance(v, str):
                    row[k] = v.strip()
        for fld in lower_set:
            if fld in row and isinstance(row[fld], str):
                row[fld] = row[fld].lower()

    def validate_row(
        row: Dict[str, str], sort_field: str, line_no: int, errors: list[str]
    ) -> None:
        if sort_field_value_must_be_unique:
            if row[sort_field] in seen_sort_field_values:
                errors.append(f"Line {line_no}: Duplicate row for '{row[sort_field]}'")
            else:
                seen_sort_field_values.append(row[sort_field])
        for rf in required_fields:
            val = row.get(rf)
            if val is None or val == "":
                errors.append(
                    f"Line {line_no}: Missing value for required field '{rf}'"
                )
        for field, allowed_values in allowed_sets.items():
            if field in row:
                val = row[field]
                if val not in allowed_values:
                    errors.append(
                        f"Line {line_no}: '{val}' is not an allowed value for '{field}' "
                        f"(allowed: {sorted(allowed_values)})"
                    )

    errors: list[str] = []
    for idx, row in enumerate(rows, start=2):  # header is line 1
        normalize_row(row)
        validate_row(row, field, idx, errors)

    if errors:
        raise CSVValidationError(errors)

    def sort_key(r: Dict[str, str]):
        v = r.get(field, "")
        if isinstance(v, str) and case_insensitive_sort:
            return v.casefold()
        return v

    rows.sort(key=sort_key)

    with open(filepath, "w", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def sort_list_file(
    filepath: Union[str, Path],
    *,
    lowercase: bool = True,
    strip: bool = True,
    deduplicate: bool = True,
    remove_blank_lines: bool = True,
    ending_newline: bool = True,
    newline: Optional[str] = "\n",
):
    """Read a list from a file, sort it, optionally strip and deduplicate the values,
    then write that list back to the file.

    - Filepath: The path to the file.
    - lowercase: Lowercase all values prior to sorting.
    - remove_blank_lines: Remove any plank lines.
    - ending_newline: End the file with a newline, even if remove_blank_lines is true.
    - newline: The newline character to use.
    """
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


def _main():
    map_file = "base_reverse_dns_map.csv"
    map_key = "base_reverse_dns"
    list_files = ["known_unknown_base_reverse_dns.txt", "psl_overrides.txt"]
    types_file = "base_reverse_dns_types.txt"

    with open(types_file) as f:
        types = f.readlines()
        while "" in types:
            types.remove("")

    map_allowed_values = {"Type": types}

    for list_file in list_files:
        if not os.path.exists(list_file):
            print(f"Error: {list_file} does not exist")
            exit(1)
        sort_list_file(list_file)
    if not os.path.exists(types_file):
        print(f"Error: {types_file} does not exist")
        exit(1)
    sort_list_file(types_file, lowercase=False)
    if not os.path.exists(map_file):
        print(f"Error: {map_file} does not exist")
        exit(1)
    try:
        sort_csv(map_file, map_key, allowed_values=map_allowed_values)
    except CSVValidationError as e:
        print(f"{map_file} did not validate: {e}")


if __name__ == "__main__":
    _main()
