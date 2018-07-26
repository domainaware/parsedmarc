#!/usr/bin/env bash

. ~/venv/domainaware/bin/activate
pip install -U -r requirements.txt
rstcheck README.rst
cd docs && make html && cp -r _build/html/* ../../parsedmarc-docs/
cd ..
rm -rf dist/ build/
flake8 parsedmarc.py
flake8 tests.py
python3 setup.py sdist
python3 setup.py bdist_wheel
