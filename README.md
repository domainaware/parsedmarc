# parsedmarc

[![Build
Status](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml/badge.svg)](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml)
[![Code
Coverage](https://codecov.io/gh/domainaware/parsedmarc/branch/master/graph/badge.svg)](https://codecov.io/gh/domainaware/parsedmarc)
[![PyPI
Package](https://img.shields.io/pypi/v/parsedmarc.svg)](https://pypi.org/project/parsedmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/parsedmarc?color=blue)](https://pypistats.org/packages/parsedmarc)

<p align="center">
  <img src="https://github.com/domainaware/parsedmarc/raw/master/docs/source/_static/screenshots/dmarc-summary-charts.png?raw=true" alt="A screenshot of DMARC summary charts in Kibana"/>
</p>

`parsedmarc` is a Python module and CLI utility for parsing DMARC
reports. When used with Elasticsearch and Kibana (or Splunk), it works
as a self-hosted open-source alternative to commercial DMARC report
processing services such as Agari Brand Protection, Dmarcian, OnDMARC,
ProofPoint Email Fraud Defense, and Valimail.

> [!NOTE]
> __Domain-based Message Authentication, Reporting, and Conformance__ (DMARC) is an email authentication protocol.

## Help Wanted

This project is maintained by one developer. Please consider
reviewing the open
[issues](https://github.com/domainaware/parsedmarc/issues) to see how
you can contribute code, documentation, or user support. Assistance on
the pinned issues would be particularly helpful.

Thanks to all
[contributors](https://github.com/domainaware/parsedmarc/graphs/contributors)!

## Features

- Parses draft and 1.0 standard aggregate/rua reports
- Parses forensic/failure/ruf reports
- Can parse reports from an inbox over IMAP, Microsoft Graph, or Gmail
    API
- Transparently handles gzip or zip compressed reports
- Consistent data structures
- Simple JSON and/or CSV output
- Optionally email the results
- Optionally send the results to Elasticsearch, Opensearch, and/or Splunk, for use
    with premade dashboards
- Optionally send reports to Apache Kafka
