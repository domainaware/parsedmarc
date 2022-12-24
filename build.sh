#!/usr/bin/env bash

set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install -U -r requirements.txt
cd docs
make clean 
make html
touch build/html/.nojekyll
cp -rf build/html/* ../../parsedmarc-docs/
cd ..
flake8 parsedmarc
python3 tests.py
rm -rf dist/ build/
hatch build