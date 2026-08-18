---
name: verify
description: Launch and drive parsedmarc's CLI to verify parser/output changes end-to-end against the bundled sample reports.
---

# Verifying parsedmarc changes

The runtime surface is the `parsedmarc` CLI; the library's stream APIs are
drivable via `python -c` through the public `parsedmarc` package.

## Launch

```bash
# No config file → results print as JSON to stdout. --offline skips DNS/downloads.
GITHUB_ACTIONS=true .venv/bin/python -m parsedmarc.cli --offline <sample files>
```

- Do **not** use `-c ci.ini` locally: it points at `http://localhost:9200`
  Elasticsearch (a CI service container) and retries for ~75s before failing.
- `GITHUB_ACTIONS=true` skips live DNS lookups.
- `--debug` surfaces per-file parse warnings/errors (invalid reports are
  otherwise dropped silently from the JSON).

## Good sample inputs (all under `samples/`)

- `aggregate/rfc9990-sample.xml` — RFC 9990 aggregate report
- `aggregate/*.xml.zip`, `aggregate/*.xml.gz` — archive extraction paths
- `failure/dmarc_ruf_report_linkedin.eml` — failure (RUF) report with an
  embedded rfc822 sample (exercises `utils.parse_email`)
- `aggregate/invalid_xml.xml` — recovered via lxml, parses with `errors` set

## Stream API (stdin is genuinely non-seekable when piped)

```bash
cat samples/aggregate/*.xml.gz | .venv/bin/python -c \
  "import sys, parsedmarc; print(parsedmarc.extract_report(sys.stdin.buffer)[:80])"
# Text-mode stdin must raise ParserError ("binary (rb) mode"):
cat samples/extract_report/nice-input.xml | .venv/bin/python -c \
  "import sys, parsedmarc; parsedmarc.extract_report(sys.stdin)"
```

## Gotchas

- Parse failures are WARNING-level log lines, not stderr errors — grep the
  `--debug` output; the JSON just omits the report.
- To compare against unfixed code: `git stash push -- <file>`, run, `git stash pop`.
