#!/usr/bin/env bash

sort -o "parsedmarc/resources/maps/known_unknown_base_reverse_dns.txt" "parsedmarc/resources/maps/known_unknown_base_reverse_dns.txt"
sort -o "parsedmarc/resources/maps/public_suffix_overrides.txt" "parsedmarc/resources/maps/public_suffix_overrides.txt"
./sortmaps.py
