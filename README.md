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

## Sponsors

This is a project is maintained by one developer.
Please consider [sponsoring my work](https://github.com/sponsors/seanthegeek) if you or your organization benefit from it.

## Features

- Parses aggregate/rua DMARC reports: the legacy draft and 1.0 schemas
  (RFC 7489) and the new RFC 9990 schema for the final DMARC standard
  (RFC 9989)
- Parses failure/ruf DMARC reports (RFC 6591 and RFC 9991; formerly called
  forensic reports)
- Parses reports from SMTP TLS Reporting (TLS-RPT, RFC 8460)
- Can parse reports from an inbox over IMAP, Microsoft Graph, or Gmail API
- Transparently handles gzip or zip compressed reports
- Consistent data structures
- Simple JSON and/or CSV output
- Optionally email the results
- Optionally send the results to Elasticsearch, OpenSearch, or Splunk, for use
  with premade dashboards
- Optionally send the results to PostgreSQL, Apache Kafka, Amazon S3, Azure Log
  Analytics (Microsoft Sentinel), a Graylog (GELF) endpoint, a syslog server,
  or an HTTP webhook

## Python Compatibility

This project supports the following Python versions, which are either actively maintained or are the default versions
for RHEL or Debian.

| Version | Supported | Reason                                                                  |
|---------|-----------|-------------------------------------------------------------------------|
| < 3.6   | ❌        | End of Life (EOL)                                                       |
| 3.6     | ❌        | Used in RHEL 8, but not supported by project dependencies               |
| 3.7     | ❌        | End of Life (EOL)                                                       |
| 3.8     | ❌        | End of Life (EOL)                                                       |
| 3.9     | ❌        | Used in Debian 11 and RHEL 9, but not supported by project dependencies |
| 3.10    | ✅        | Actively maintained                                                     |
| 3.11    | ✅        | Actively maintained; supported until June 2028 (Debian 12)              |
| 3.12    | ✅        | Actively maintained; supported until May 2035 (RHEL 10)                 |
| 3.13    | ✅        | Actively maintained; supported until June 2030 (Debian 13)              |
| 3.14    | ✅        | Supported (requires `imapclient>=3.1.0`)                                |
