#!/usr/bin/env bash

. ~/venv/domainaware/bin/activate
pip install -U -r requirements.txt
cd docs && make html && cp -r _build/html/* ../../parsedmarc-docs/
cd ..
rm -rf dist/ build/
python setup.py bdist_wheel

