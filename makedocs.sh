#!/usr/bin/env bash

. ~/venv/domainaware/bin/activate
cd docs && make html && cp -r build/html/* ../../parsedmarc-docs/
