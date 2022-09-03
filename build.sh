#!/usr/bin/env bash

. venv/bin/activate
pip3 install -U -r requirements.txt && cd docs && make html && cp -r _build/html/* ../../parsedmarc-docs/ && cd .. && flake8 parsedmarc && flake8 tests.py && python3 tests.py && rm -rf dist/ build/ && python3 setup.py sdist && python3 setup.py bdist_wheel
