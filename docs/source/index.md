# parsedmarc documentation - Open source DMARC report analyzer and visualizer

[![Build
Status](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml/badge.svg)](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml)
[![Code
Coverage](https://codecov.io/gh/domainaware/parsedmarc/branch/master/graph/badge.svg)](https://codecov.io/gh/domainaware/parsedmarc)
[![PyPI
Package](https://img.shields.io/pypi/v/parsedmarc.svg)](https://pypi.org/project/parsedmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/parsedmarc?color=blue)](https://pypistats.org/packages/parsedmarc)

:::{note}
**Help Wanted**

This is a project is maintained by one developer.
Please consider reviewing the open [issues] to see how you can contribute code, documentation, or user support.
Assistance on the pinned issues would be particularly helpful.

Thanks to all [contributors]!
:::

```{image} _static/screenshots/dmarc-summary-charts.png
:align: center
:alt: A screenshot of DMARC summary charts in Kibana
:scale: 50 %
:target: _static/screenshots/dmarc-summary-charts.png
```

`parsedmarc` is a Python module and CLI utility for parsing DMARC reports.
When used with Elasticsearch and Kibana (or Splunk), or with OpenSearch and Grafana, it works as a self-hosted
open source alternative to commercial DMARC report processing services such
as Agari Brand Protection, Dmarcian, OnDMARC, ProofPoint Email Fraud Defense,
and Valimail.

## Features

- Parses draft and 1.0 standard aggregate/rua reports
- Parses forensic/failure/ruf reports
- Can parse reports from an inbox over IMAP, Microsoft Graph, or Gmail API
- Transparently handles gzip or zip compressed reports
- Consistent data structures
- Simple JSON and/or CSV output
- Optionally email the results
- Optionally send the results to Elasticsearch/OpenSearch and/or Splunk, for use with
  premade dashboards
- Optionally send reports to Apache Kafka

```{toctree}
:caption: 'Contents'
:maxdepth: 2

installation
usage
output
elasticsearch
opensearch
kibana
splunk
davmail
dmarc
contributing
api
```

[contributors]: https://github.com/domainaware/parsedmarc/graphs/contributors
[issues]: https://github.com/domainaware/parsedmarc/issues
