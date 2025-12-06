# parsedmarc

[![Build
Status](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml/badge.svg)](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml)
[![Code
Coverage](https://codecov.io/gh/domainaware/parsedmarc/branch/master/graph/badge.svg)](https://codecov.io/gh/domainaware/parsedmarc)
[![PyPI
Package](https://img.shields.io/pypi/v/parsedmarc.svg)](https://pypi.org/project/parsedmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/parsedmarc?color=blue)](https://pypistats.org/packages/parsedmarc)

<p align="center">
  <img src="https://raw.githubusercontent.com/domainaware/parsedmarc/refs/heads/master/docs/source/_static/screenshots/dmarc-summary-charts.png?raw=true" alt="A screenshot of DMARC summary charts in Kibana"/>
</p>

`parsedmarc` is a Python module and CLI utility for parsing DMARC
reports. When used with Elasticsearch and Kibana (or Splunk), it works
as a self-hosted open-source alternative to commercial DMARC report
processing services such as Agari Brand Protection, Dmarcian, OnDMARC,
ProofPoint Email Fraud Defense, and Valimail.

> [!NOTE]
> __Domain-based Message Authentication, Reporting, and Conformance__ (DMARC) is an email authentication protocol.

## Help Wanted

This project is maintained by one developer. Please consider reviewing the open
[issues](https://github.com/domainaware/parsedmarc/issues) to see how you can
contribute code, documentation, or user support. Assistance on the pinned
issues would be particularly helpful.

Thanks to all
[contributors](https://github.com/domainaware/parsedmarc/graphs/contributors)!

## Features

- Parses draft and 1.0 standard aggregate/rua DMARC reports
- Parses forensic/failure/ruf DMARC reports
- Parses reports from SMTP TLS Reporting
- Can parse reports from an inbox over IMAP, Microsoft Graph, or Gmail API
- Transparently handles gzip or zip compressed reports
- Consistent data structures
- Simple JSON and/or CSV output
- Optionally email the results
- Optionally send the results to Elasticsearch, Opensearch, and/or Splunk, for
  use with premade dashboards
- Optionally send reports to Apache Kafka

## Python Compatibility

This project supports the following Python versions, which are either actively maintained or are the default versions
for RHEL or Debian.

| Version | Supported | Reason                                                     |
|---------|-----------|------------------------------------------------------------|
| < 3.6   | ❌         | End of Life (EOL)                                          |
| 3.6     | ❌         | Used in RHEL 8, but not supported by project dependencies |
| 3.7     | ❌         | End of Life (EOL)                                          |
| 3.8     | ❌         | End of Life (EOL)                                          |
| 3.9     | ✅         | Supported until August 2026 (Debian 11); May 2032 (RHEL 9) |
| 3.10    | ✅         | Actively maintained                                        |
| 3.11    | ✅         | Actively maintained; supported until June 2028 (Debian 12) |
| 3.12    | ✅         | Actively maintained; supported until May 2035 (RHEL 10)    |
| 3.13    | ✅         | Actively maintained; supported until June 2030 (Debian 13) |
| 3.14    | ❌         | Not currently supported due to Not currently supported due to [this imapclient bug](https://github.com/mjs/imapclient/issues/618)|
