#!/usr/bin/env bash

set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install .[build]
ruff check .
cd docs
make clean 
make html
touch build/html/.nojekyll
if [  -d "../../parsedmarc-docs" ]; then
  cp -rf build/html/* ../../parsedmarc-docs/
fi
cd ..
cd parsedmarc/resources/maps
python3 sortlists.py
echo "Checking for invalid UTF-8 bytes in base_reverse_dns_map.csv"
python3 find_bad_utf8.py base_reverse_dns_map.csv
cd ../../..
python3 tests.py
rm -rf dist/ build/
hatch build
