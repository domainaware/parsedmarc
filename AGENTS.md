# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Project Overview

parsedmarc is a Python module and CLI utility for parsing DMARC aggregate (RUA), failure/forensic (RUF), and SMTP TLS reports. It supports both RFC 7489 and DMARCbis (draft-ietf-dmarc-dmarcbis-41, draft-ietf-dmarc-aggregate-reporting-32, draft-ietf-dmarc-failure-reporting-24) report formats. It reads reports from IMAP, Microsoft Graph, Gmail API, Maildir, mbox files, or direct file paths, and outputs to JSON/CSV, Elasticsearch, OpenSearch, Splunk, Kafka, S3, Azure Log Analytics, syslog, or webhooks.

## Common Commands

```bash
# Install with dev/build dependencies
pip install .[build]

# Run all tests with coverage
pytest --cov --cov-report=xml tests.py

# Run a single test
pytest tests.py::Test::testAggregateSamples

# Lint and format
ruff check .
ruff format .

# Test CLI with sample reports
parsedmarc --debug -c ci.ini samples/aggregate/*
parsedmarc --debug -c ci.ini samples/failure/*

# Build docs
cd docs && make html

# Build distribution
hatch build
```

To skip DNS lookups during testing, set `GITHUB_ACTIONS=true`.

## Architecture

**Data flow:** Input sources → CLI (`cli.py:_main`) → Parse (`__init__.py`) → Enrich (DNS/GeoIP via `utils.py`) → Output integrations

### Key modules

- `parsedmarc/__init__.py` — Core parsing logic. Main functions: `parse_report_file()`, `parse_report_email()`, `parse_aggregate_report_xml()`, `parse_failure_report()`, `parse_smtp_tls_report_json()`, `get_dmarc_reports_from_mailbox()`, `watch_inbox()`. Legacy aliases (`parse_forensic_report`, etc.) are preserved for backward compatibility.
- `parsedmarc/cli.py` — CLI entry point (`_main`), config file parsing, output orchestration. Accepts both old (`save_forensic`, `forensic_topic`) and new (`save_failure`, `failure_topic`) config keys.
- `parsedmarc/types.py` — TypedDict definitions for all report types (`AggregateReport`, `FailureReport`, `SMTPTLSReport`, `ParsingResults`). Legacy alias `ForensicReport = FailureReport` preserved.
- `parsedmarc/utils.py` — IP/DNS/GeoIP enrichment, base64 decoding, compression handling
- `parsedmarc/mail/` — Polymorphic mail connections: `IMAPConnection`, `GmailConnection`, `MSGraphConnection`, `MaildirConnection`
- `parsedmarc/{elastic,opensearch,splunk,kafkaclient,loganalytics,syslog,s3,webhook,gelf}.py` — Output integrations

### Report type system

`ReportType = Literal["aggregate", "failure", "smtp_tls"]`. Exception hierarchy: `ParserError` → `InvalidDMARCReport` → `InvalidAggregateReport`/`InvalidFailureReport`, and `InvalidSMTPTLSReport`. Legacy alias `InvalidForensicReport = InvalidFailureReport` preserved.

### DMARCbis support

Aggregate reports support both RFC 7489 and DMARCbis formats. DMARCbis adds fields: `np` (non-existent subdomain policy), `testing` (replaces `pct`), `discovery_method` (`psl`/`treewalk`), `generator` (report metadata), and `human_result` (DKIM/SPF auth results). `pct` and `fo` default to `None` when absent (DMARCbis drops these). Namespaced XML is handled automatically.

### Caching

IP address info cached for 4 hours, seen aggregate report IDs cached for 1 hour (via `ExpiringDict`).

## Code Style

- Ruff for formatting and linting (configured in `.vscode/settings.json`)
- TypedDict for structured data, type hints throughout
- Python ≥3.10 required
- Tests are in a single `tests.py` file using unittest; sample reports live in `samples/`
