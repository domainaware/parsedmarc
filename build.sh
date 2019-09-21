#!/usr/bin/env bash

set -e

. venv/bin/activate

pip install -U -r requirements.txt
rstcheck --report warning README.rst
cd docs
make html
touch _build/html/.nojekyll
mkdir -p ../../parsedmarc-docs/
cp -rf _build/html/* ../../parsedmarc-docs/
cd ..
flake8 parsedmarc
flake8 tests.py
rm -rf dist/ build/
python3 setup.py sdist
python3 setup.py bdist_wheel
