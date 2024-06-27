#!/usr/bin/env bash

set -e

if [ ! -d "venv" ]; then
  virtualenv venv || exit
fi

. venv/bin/activate
pip install -U -r requirements.txt
flake8 parsedmarc
cd docs
make clean 
make html
touch build/html/.nojekyll
cp -rf build/html/* ../../parsedmarc-docs/
cd ..
python3 tests.py
rm -rf dist/ build/
hatch build