# Dashboard development

This directory holds the dashboard sources that ship with parsedmarc:

- [opensearch/opensearch_dashboards.ndjson](opensearch/opensearch_dashboards.ndjson) — the source-of-truth saved-objects export. It is imported into both **OpenSearch Dashboards** and **Kibana** (the file format is compatible with both).
- [grafana/Grafana-DMARC_Reports.json](grafana/Grafana-DMARC_Reports.json) — the Grafana dashboard, with two Elasticsearch datasources (`dmarc-ag`, `dmarc-fo`).
- [grafana/Grafana-DMARC_Reports-PostgreSQL.json](grafana/Grafana-DMARC_Reports-PostgreSQL.json) — the Grafana dashboard for the PostgreSQL backend.
- [splunk/](splunk/) — three Splunk dashboard XML views (`dmarc_aggregate`, `dmarc_failure`, `smtp_tls`).

Edits to any of these files should be exported from a running instance after authoring the change in the UI, not hand-edited (with the occasional exception of small XML tweaks for Splunk).

## The dev stack

[docker-compose.dashboard-dev.yml](../docker-compose.dashboard-dev.yml) brings up every viz target at once so a single dashboard change can be authored and re-exported across all four UIs in one session. It `include:`s [docker-compose.yml](../docker-compose.yml) for the Elasticsearch and OpenSearch backends, then layers on Kibana, OpenSearch Dashboards, Grafana, and Splunk.

| Service               | URL                                              | Credentials                                            |
| --------------------- | ------------------------------------------------ | ------------------------------------------------------ |
| Elasticsearch         | http://localhost:9200                            | (security disabled)                                    |
| OpenSearch            | https://localhost:9201                           | `admin` / `$OPENSEARCH_INITIAL_ADMIN_PASSWORD`         |
| Kibana                | http://localhost:5601                            | (security disabled)                                    |
| OpenSearch Dashboards | http://localhost:5602                            | `admin` / `$OPENSEARCH_INITIAL_ADMIN_PASSWORD`         |
| Grafana               | http://localhost:3000                            | `admin` / `$GRAFANA_PASSWORD`                          |
| Splunk Web / HEC      | http://localhost:8000 / https://localhost:8088   | `admin` / `$SPLUNK_PASSWORD`, HEC token `$SPLUNK_HEC_TOKEN` |

All ports bind to `127.0.0.1` only.

## Prerequisites

1. Docker with the Compose v2 plugin.
2. A repo-root `.env` defining the secrets the compose file references:

   ```ini
   OPENSEARCH_INITIAL_ADMIN_PASSWORD=...
   SPLUNK_PASSWORD=...
   SPLUNK_HEC_TOKEN=...
   GRAFANA_PASSWORD=...
   ```

   Pick any values you like — these are local-only dev secrets. Both `.env` and `parsedmarc*.ini` are gitignored. The matching values must also appear in [parsedmarc-dev.ini](../parsedmarc-dev.ini), which the bootstrap script feeds to the parsedmarc CLI for sample-data ingestion.
3. The parsedmarc CLI on `PATH` (or in `./venv/bin/`) — `pip install -e .[build]` from the repo root works. Override the lookup with `PARSEDMARC_BIN=/path/to/parsedmarc` if needed.

## One-shot bootstrap

[dashboard-dev-bootstrap.sh](../dashboard-dev-bootstrap.sh) is the normal entry point. It is idempotent — re-run it any time:

```bash
./dashboard-dev-bootstrap.sh
```

It does, in order:

1. `docker compose -f docker-compose.dashboard-dev.yml up -d` and waits for every service's health endpoint.
2. Provisions Splunk: creates the `email` index, creates the `DMARC` app, configures the auto-created HEC token to allow the `email` index, and scopes the search-app's "scheduled export" announcement view away from `global` so it stops appearing in the DMARC app's dashboard list.
3. Seeds Elasticsearch, OpenSearch, and Splunk with parsedmarc-parsed sample reports (from [samples/](../samples/)) so the dashboards render against real data. Skipped when ES already has aggregate docs — pass `RESEED=1` to wipe and re-seed all three backends.
4. Imports the dashboard files from this directory into the running services. This step always runs, so the typical edit loop is **edit in the UI → export → save into this directory → re-run the bootstrap script** to verify the file imports cleanly into a fresh service.

VS Code users can run this via the **Dev Dashboard: Bootstrap** task in [.vscode/tasks.json](../.vscode/tasks.json). **Dev Dashboard: Up** brings the stack up without importing or seeding.

## Editing a dashboard

After running the bootstrap script once, the round trip for each platform is:

### OpenSearch Dashboards (and Kibana)

1. Edit the dashboard at http://localhost:5602/ (OpenSearch Dashboards) — this is the canonical authoring surface.
2. **Stack Management → Saved Objects → Export**, select the DMARC dashboard, include related objects, and save the resulting `.ndjson` over [opensearch/opensearch_dashboards.ndjson](opensearch/opensearch_dashboards.ndjson).
3. Re-run `./dashboard-dev-bootstrap.sh` to confirm it re-imports cleanly into both OSD and Kibana. The Kibana CI workflow ([.github/workflows/dashboards.yml](../.github/workflows/dashboards.yml)) also imports the same file on every PR that touches it.

OSD imports default to the `global_tenant` so other admins on the instance can see the result. Set `OSD_TENANT=...` to import elsewhere.

### Grafana

1. Edit the dashboard at http://localhost:3000/.
2. **Dashboard settings → JSON Model**, copy the JSON, save it to [grafana/Grafana-DMARC_Reports.json](grafana/Grafana-DMARC_Reports.json).
3. Re-run the bootstrap script.

The bootstrap script provisions two `elasticsearch` datasources (`dmarc-ag` for `dmarc_aggregate*`, `dmarc-fo` for `dmarc_f*`, which matches both pre-rename `dmarc_forensic*` and post-rename `dmarc_failure*`) on first run; existing datasources are left alone.

### Splunk

1. Edit the dashboard at http://localhost:8000/ inside the **DMARC** app.
2. Open the dashboard's **Source** view, copy the XML, and paste it over the matching file in [splunk/](splunk/) (`dmarc_aggregate_dashboard.xml`, `dmarc_failure_dashboard.xml`, or `smtp_tls_dashboard.xml`).
3. Re-run the bootstrap script. It re-imports each view via `DELETE` + `POST` to the splunkd management API.

## Reseeding sample data

```bash
RESEED=1 ./dashboard-dev-bootstrap.sh
```

Wipes every `dmarc_aggregate*` / `dmarc_failure*` / `dmarc_forensic*` / `smtp_tls*` index from ES and OS, drops and recreates the Splunk `email` index, then re-runs the parsedmarc CLI against the curated sample list. Use this after changing parsedmarc's enrichment or output schemas.

## Tearing the stack down

```bash
docker compose -f docker-compose.dashboard-dev.yml down          # stop containers, keep volumes
docker compose -f docker-compose.dashboard-dev.yml down -v       # also drop volumes (full reset)
```
