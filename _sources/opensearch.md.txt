# OpenSearch and Grafana

To set up visual dashboards of DMARC data, install OpenSearch and Grafana.

## Installation

OpenSearch: https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/
Grafana: https://grafana.com/docs/grafana/latest/setup-grafana/installation/

## Records retention

Starting in version 5.0.0, `parsedmarc` stores data in a separate
index for each day to make it easy to comply with records
retention regulations such as GDPR.
