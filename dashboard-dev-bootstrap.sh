#!/usr/bin/env bash
# Bring up docker-compose.dashboard-dev.yml, import the latest parsedmarc
# dashboards into each viz system, and seed each backend with sample data so
# the dashboards have something to render. Idempotent — safe to re-run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

COMPOSE=(docker compose -f docker-compose.dashboard-dev.yml --env-file .env)

# Load .env so this script can use the same secrets compose injects.
set -a
# shellcheck disable=SC1091
. .env
set +a

GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin}"

# PostgreSQL dev credentials. Defaults match docker-compose.dashboard-dev.yml's
# ${POSTGRESQL_*:-parsedmarc} fallbacks; override all four in lockstep via .env.
PG_USER="${POSTGRESQL_USER:-parsedmarc}"
PG_PASSWORD="${POSTGRESQL_PASSWORD:-parsedmarc}"
PG_DB="${POSTGRESQL_DB:-parsedmarc}"

log() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

wait_for() {
    local name="$1"; shift
    local max="${WAIT_TIMEOUT:-180}"
    local i=0
    printf 'Waiting for %s' "$name"
    while ! "$@" >/dev/null 2>&1; do
        printf '.'
        i=$((i + 1))
        if [ "$i" -ge "$max" ]; then
            printf '\n'
            echo "ERROR: $name not ready after ${max}s" >&2
            return 1
        fi
        sleep 1
    done
    printf ' ready\n'
}

# ---------------------------------------------------------------------------
# 1. Bring up the stack
# ---------------------------------------------------------------------------
log "Starting docker compose dashboard-dev stack"
"${COMPOSE[@]}" up -d

# ---------------------------------------------------------------------------
# 2. Wait for each service
# ---------------------------------------------------------------------------
log "Waiting for backends and UIs"
wait_for "Elasticsearch" \
    curl -sf 'http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=1s'
wait_for "OpenSearch" \
    curl -ksf -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
    'https://localhost:9201/_cluster/health?wait_for_status=yellow&timeout=1s'
wait_for "Kibana" curl -sf http://localhost:5601/api/status
wait_for "OpenSearch Dashboards" \
    curl -ksf -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
    http://localhost:5602/api/status
wait_for "Grafana" curl -sf http://localhost:3000/api/health
wait_for "PostgreSQL" \
    "${COMPOSE[@]}" exec -T postgresql pg_isready -U "$PG_USER" -d "$PG_DB"
# Splunk's HEC port is healthy once management API is up too.
wait_for "Splunk HEC" curl -ksf https://localhost:8088/services/collector/health
# Splunkd management API (used for dashboard imports) lives inside the container.
wait_for "Splunk management API" \
    "${COMPOSE[@]}" exec -T splunk \
    curl -ksf -u "admin:${SPLUNK_PASSWORD}" https://localhost:8089/services/server/info

# ---------------------------------------------------------------------------
# 3. Provision Splunk: index, app, HEC token allow-list
#    Must run before sample-data ingestion. The Splunk image auto-creates a
#    HEC token from SPLUNK_HEC_TOKEN, but with `indexes=[]` and
#    `index=default` — writes to the parsedmarc-dev.ini `email` index will
#    silently drop until both the index exists and the token allows it.
# ---------------------------------------------------------------------------
log "Provisioning Splunk index, app, and HEC token"
splunk_curl() {
    "${COMPOSE[@]}" exec -T splunk \
        curl -ksS -u "admin:${SPLUNK_PASSWORD}" "$@"
}
splunk_exists() {
    # 200 if the named entity exists, 404 if not.
    local code
    code=$(splunk_curl -o /dev/null -w "%{http_code}" -X GET "$1") || true
    [ "$code" = "200" ]
}

if splunk_exists https://localhost:8089/services/data/indexes/email; then
    echo "  index 'email' already exists — skipping"
else
    splunk_curl -X POST https://localhost:8089/services/data/indexes \
        -d name=email -d datatype=event >/dev/null
    echo "  created index 'email'"
fi

if splunk_exists https://localhost:8089/services/apps/local/DMARC; then
    echo "  app 'DMARC' already exists — skipping"
else
    splunk_curl -X POST https://localhost:8089/services/apps/local \
        -d name=DMARC -d label=DMARC -d visible=true >/dev/null
    echo "  created app 'DMARC'"
fi

# The auto-created HEC token is named "splunk_hec_token". Allow the email
# index and set it as the token default so parsedmarc-dev.ini's `index = email`
# is honoured. Skip the rewrite if the token already allows email and
# defaults to it.
HEC_STATE=$(splunk_curl -X GET \
    "https://localhost:8089/servicesNS/admin/splunk_httpinput/data/inputs/http/splunk_hec_token?output_mode=json" \
    2>/dev/null \
    | python3 -c '
import json, sys
e = json.load(sys.stdin)["entry"][0]["content"]
indexes = e.get("indexes") or []
disabled = "1" if e.get("disabled") else "0"
print("|".join([e.get("index") or "", disabled, ",".join(indexes)]))
' 2>/dev/null || echo "||")
HEC_DEFAULT_INDEX="${HEC_STATE%%|*}"
HEC_REST="${HEC_STATE#*|}"
HEC_DISABLED="${HEC_REST%%|*}"
HEC_INDEXES=",${HEC_REST#*|},"
if [ "$HEC_DEFAULT_INDEX" = "email" ] && [ "$HEC_DISABLED" = "0" ] && [[ "$HEC_INDEXES" == *,email,* ]]; then
    echo "  HEC token 'splunk_hec_token' already configured — skipping"
else
    splunk_curl -X POST \
        "https://localhost:8089/servicesNS/admin/splunk_httpinput/data/inputs/http/splunk_hec_token" \
        -d "indexes=email,main" \
        -d "index=email" \
        -d "disabled=0" \
        >/dev/null
    echo "  reconfigured HEC token 'splunk_hec_token' (index=email, indexes=email,main)"
fi

# Make sure the HEC listener itself is enabled. Splunk treats this as a no-op
# if it's already enabled, so just send it once each run — no point checking.
splunk_curl -X POST \
    "https://localhost:8089/servicesNS/admin/splunk_httpinput/data/inputs/http/http" \
    -d "disabled=0" \
    >/dev/null 2>&1 || true

# Splunk ships an in-product announcement view ("Scheduled export is now
# available for Dashboard Studio") in the search app with sharing=global, so
# it appears in the dashboards list of every app — including DMARC. Views
# don't support a `disabled` flag, but narrowing the sharing from `global` to
# `app` keeps it scoped to the search app only.
SCHED_SHARING=$(splunk_curl -X GET \
    "https://localhost:8089/servicesNS/-/search/data/ui/views/scheduled_export_dashboard?output_mode=json" \
    2>/dev/null \
    | python3 -c '
import json, sys
print(json.load(sys.stdin)["entry"][0]["acl"].get("sharing", ""))
' 2>/dev/null || echo "")
if [ "$SCHED_SHARING" = "global" ]; then
    splunk_curl -X POST \
        "https://localhost:8089/servicesNS/nobody/search/data/ui/views/scheduled_export_dashboard/acl" \
        -d "sharing=app" -d "owner=nobody" \
        >/dev/null
    echo "  scoped 'scheduled_export_dashboard' to search app (was global)"
elif [ -n "$SCHED_SHARING" ]; then
    echo "  'scheduled_export_dashboard' already scoped (sharing=${SCHED_SHARING}) — skipping"
fi

# ---------------------------------------------------------------------------
# 4. Seed sample data via parsedmarc -> ES, OS, Splunk HEC
#    Skipped when ES already has aggregate docs from a prior run. Set
#    RESEED=1 to wipe ES/OS/Splunk parsedmarc data first and re-seed.
# ---------------------------------------------------------------------------
log "Seeding sample data with parsedmarc-dev.ini"
ES_AGG_COUNT=$(curl -sf 'http://localhost:9200/dmarc_aggregate*/_count' 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count", 0))' 2>/dev/null \
    || echo 0)
if [ "${RESEED:-0}" != "1" ] && [ "$ES_AGG_COUNT" -gt 0 ]; then
    echo "  ES already has $ES_AGG_COUNT aggregate docs — skipping seed (RESEED=1 to force)"
else
    if [ "${RESEED:-0}" = "1" ] && [ "$ES_AGG_COUNT" -gt 0 ]; then
        echo "  RESEED=1: wiping existing parsedmarc data from all backends"
        # ES 8.x rejects wildcard DELETEs by default
        # (action.destructive_requires_name=true). Enumerate the daily indexes
        # parsedmarc rolls (dmarc_aggregate-YYYY-MM-DD, dmarc_failure-...,
        # smtp_tls-...) and DELETE each one explicitly. dmarc_forensic-* is the
        # pre-rename failure index family, kept here so RESEED clears old data.
        for prefix in dmarc_aggregate dmarc_failure dmarc_forensic smtp_tls; do
            for idx in $(curl -sf "http://localhost:9200/_cat/indices/${prefix}*?h=index" 2>/dev/null); do
                curl -sS -X DELETE "http://localhost:9200/${idx}" >/dev/null 2>&1 || true
            done
            for idx in $(curl -ksf -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" "https://localhost:9201/_cat/indices/${prefix}*?h=index" 2>/dev/null); do
                curl -ksS -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
                    -X DELETE "https://localhost:9201/${idx}" >/dev/null 2>&1 || true
            done
        done
        # Splunk has no clean-in-place REST endpoint for live indexes. The
        # standard pattern is to delete and recreate. Settings carry over from
        # the recreate POST below — datatype=event is what parsedmarc HEC needs.
        splunk_curl -X DELETE \
            "https://localhost:8089/services/data/indexes/email" >/dev/null 2>&1 || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            splunk_exists https://localhost:8089/services/data/indexes/email || break
            sleep 1
        done
        splunk_curl -X POST https://localhost:8089/services/data/indexes \
            -d name=email -d datatype=event >/dev/null
        # Recreate forces the HEC token allow-list to re-resolve against the
        # new index. Re-apply the token config so the next seed lands.
        splunk_curl -X POST \
            "https://localhost:8089/servicesNS/admin/splunk_httpinput/data/inputs/http/splunk_hec_token" \
            -d "indexes=email,main" -d "index=email" -d "disabled=0" >/dev/null
        # PostgreSQL: drop and recreate the public schema. parsedmarc recreates
        # its tables on the next seed run, so this is a clean wipe.
        "${COMPOSE[@]}" exec -T -e PGPASSWORD="$PG_PASSWORD" postgresql \
            psql -U "$PG_USER" -d "$PG_DB" \
            -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null 2>&1 || true
    fi

    # Resolve a Python environment for the seed and make sure parsedmarc plus
    # the PostgreSQL extra (psycopg) are installed in it, so the same run can
    # populate Postgres. Precedence:
    #   1. An explicit PARSEDMARC_BIN — used as-is, nothing installed.
    #   2. An already-activated virtualenv ($VIRTUAL_ENV).
    #   3. An existing repo venv/ or .venv/.
    #   4. Otherwise a freshly created $REPO_ROOT/venv.
    # Cases 2-4 run `pip install -e .[postgresql]` only when the CLI or psycopg
    # is missing, so it's a no-op once the environment is set up.
    if [ -n "${PARSEDMARC_BIN:-}" ]; then
        if [ ! -x "$PARSEDMARC_BIN" ]; then
            echo "ERROR: PARSEDMARC_BIN is set but not executable: $PARSEDMARC_BIN" >&2
            exit 1
        fi
        echo "  using PARSEDMARC_BIN: $PARSEDMARC_BIN"
    else
        if [ -n "${VIRTUAL_ENV:-}" ]; then
            seed_venv="$VIRTUAL_ENV"
            echo "  using active virtualenv: $seed_venv"
        elif [ -d "$REPO_ROOT/venv" ]; then
            seed_venv="$REPO_ROOT/venv"
            echo "  using existing venv: $seed_venv"
        elif [ -d "$REPO_ROOT/.venv" ]; then
            seed_venv="$REPO_ROOT/.venv"
            echo "  using existing .venv: $seed_venv"
        else
            seed_venv="$REPO_ROOT/venv"
            echo "  creating virtualenv: $seed_venv"
            python3 -m venv "$seed_venv"
        fi
        PARSEDMARC_BIN="$seed_venv/bin/parsedmarc"
        if [ ! -x "$PARSEDMARC_BIN" ] ||
            ! "$seed_venv/bin/python" -c 'import psycopg' >/dev/null 2>&1; then
            echo "  installing parsedmarc[postgresql] into $seed_venv"
            "$seed_venv/bin/python" -m pip install -q -e "${REPO_ROOT}[postgresql]"
        fi
    fi
    if [ ! -x "$PARSEDMARC_BIN" ]; then
        echo "ERROR: parsedmarc CLI not found at $PARSEDMARC_BIN" >&2
        exit 1
    fi

    # Live DNS lookups (no --offline) so source_reverse_dns / source_base_domain
    # are populated. Many samples carry synthetic IPs (10.x, 198.51.100.x,
    # 2001:db8::, etc.) that won't resolve, so cap retries/timeout to bound
    # the cost of those NXDOMAIN-bound lookups. Intentionally invalid samples
    # (empty_reason.xml, invalid_xml.xml, etc.) are skipped from the list.
    SAMPLE_FILES=(
        samples/aggregate/!example.com!1538204542!1538463818.xml
        samples/aggregate/!large-example.com!1711897200!1711983600.xml
        'samples/aggregate/Report domain- borschow.com Submitter- google.com Report-ID- 949348866075514174.eml'
        samples/aggregate/addisonfoods.com!example.com!1536105600!1536191999.xml
        samples/aggregate/estadocuenta1.infonacot.gob.mx!example.com!1536853302!1536939702!2940.xml.zip
        samples/aggregate/example.net!example.com!1529366400!1529452799.xml
        samples/aggregate/fastmail.com!example.com!1516060800!1516147199!102675056.xml.gz
        samples/aggregate/ikea.com!example.de!1538690400!1538776800.xml
        samples/aggregate/protection.outlook.com!example.com!1711756800!1711843200.xml
        samples/aggregate/usssa.com!example.com!1538784000!1538870399.xml
        samples/aggregate/veeam.com!example.com!1530133200!1530219600.xml
        samples/aggregate/rfc9990-sample.xml
        samples/aggregate/rfc9990-example.net!example.com!1700000000!1700086399.xml
        samples/failure/*.eml
        samples/smtp_tls/*.json
        samples/smtp_tls/google.com_smtp_tls_report.eml
    )
    # PostgreSQL config is injected via env vars (parsedmarc synthesizes the
    # [postgresql] section from PARSEDMARC_POSTGRESQL_*), so the same seed run
    # also populates Postgres without touching the gitignored parsedmarc-dev.ini.
    # Only wire it in when psycopg is importable: parsedmarc aborts the whole
    # run (exit 1, nothing written to *any* backend) if a configured output
    # backend can't initialize, so a missing optional extra must not be added.
    pg_seed_env=()
    seed_python="$(dirname "$PARSEDMARC_BIN")/python"
    if [ -x "$seed_python" ] && "$seed_python" -c 'import psycopg' >/dev/null 2>&1; then
        pg_seed_env=(
            PARSEDMARC_POSTGRESQL_HOST=localhost
            PARSEDMARC_POSTGRESQL_PORT=5432
            PARSEDMARC_POSTGRESQL_USER="$PG_USER"
            PARSEDMARC_POSTGRESQL_PASSWORD="$PG_PASSWORD"
            PARSEDMARC_POSTGRESQL_DATABASE="$PG_DB"
        )
    else
        # Reached only for an explicit PARSEDMARC_BIN whose env lacks psycopg
        # (the auto-resolved venv path installs the extra above).
        echo "  NOTE: 'psycopg' is not available to ${PARSEDMARC_BIN} — skipping the"
        echo "        PostgreSQL seed. Enable it with: pip install -e '.[postgresql]'"
    fi
    env "${pg_seed_env[@]}" \
        "$PARSEDMARC_BIN" -t 2.0 --dns-retries 1 -c parsedmarc-dev.ini "${SAMPLE_FILES[@]}" || true
fi

# ---------------------------------------------------------------------------
# 5. Import dashboards. Always re-imported on every run — that's the point of
#    invoking this script after editing a dashboard. Datasources are checked
#    first and skipped when already present.
# ---------------------------------------------------------------------------
log "Importing Kibana dashboards"
curl -sS -X POST 'http://localhost:5601/api/saved_objects/_import?overwrite=true' \
    -H 'kbn-xsrf: true' \
    --form file=@dashboards/opensearch/opensearch_dashboards.ndjson | sed 's/^/  /'

log "Importing OpenSearch Dashboards saved objects"
# OSD with the security plugin enabled stores saved objects per tenant. Without
# a securitytenant header the import lands in the API user's *private* tenant,
# which is invisible to anyone else (and to the same user when their browser
# session is on a different tenant). Target the Global tenant — the shared
# workspace every user has access to and where public dashboards conventionally
# live. Its securitytenant token is the literal "global"; any *other* string is
# treated as a custom tenant name, so "global_tenant" would silently create a
# separate "global_tenant" tenant rather than hit Global. (An empty/omitted
# header is *not* equivalent — it falls back to the user's configured default
# tenant, not Global.) To send the import elsewhere set OSD_TENANT=admin_tenant
# (or any other tenant name) before running.
OSD_TENANT="${OSD_TENANT:-global}"
curl -sS -X POST 'http://localhost:5602/api/saved_objects/_import?overwrite=true' \
    -H 'osd-xsrf: true' \
    -H "securitytenant: ${OSD_TENANT}" \
    -u "admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}" \
    --form file=@dashboards/opensearch/opensearch_dashboards.ndjson | sed 's/^/  /'
echo "  (imported into OSD tenant: ${OSD_TENANT})"

log "Ensuring Grafana Elasticsearch datasource plugin is installed"
# Grafana >= 13 no longer bundles the Elasticsearch datasource plugin, and
# GF_INSTALL_PLUGINS cannot install it (the image ships a root-owned
# plugins-bundled/elasticsearch remnant its background installer fails to
# replace). `grafana cli` installs into /var/lib/grafana/plugins, which works;
# a restart is needed for Grafana to load it.
code=$(curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
    -o /dev/null -w "%{http_code}" \
    "http://localhost:3000/api/plugins/elasticsearch/settings")
if [ "$code" != "200" ]; then
    "${COMPOSE[@]}" exec -T grafana grafana cli plugins install elasticsearch \
        | sed 's/^/  /'
    "${COMPOSE[@]}" restart grafana >/dev/null
    wait_for "Grafana (after plugin install)" \
        curl -sf http://localhost:3000/api/health
    code=$(curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -o /dev/null -w "%{http_code}" \
        "http://localhost:3000/api/plugins/elasticsearch/settings")
    if [ "$code" != "200" ]; then
        echo "ERROR: elasticsearch datasource plugin failed to install" >&2
        exit 1
    fi
    echo "  installed elasticsearch datasource plugin"
else
    echo "  elasticsearch datasource plugin already installed"
fi

log "Configuring Grafana datasources"
# Two Elasticsearch datasources, one per index family, matching the dashboard's
# template variables (dmarc-ag and dmarc-fo). Skipped when already present.
declare -a GF_DS_NAMES=("dmarc-ag" "dmarc-fo")
# dmarc_f* matches both pre-rename dmarc_forensic* and post-rename
# dmarc_failure* indices, mirroring the OpenSearch/Kibana dashboards.
declare -a GF_DS_INDEX=("dmarc_aggregate*" "dmarc_f*")
declare -a GF_DS_TIME=("date_begin" "arrival_date")
for i in 0 1; do
    name="${GF_DS_NAMES[$i]}"
    code=$(curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -o /dev/null -w "%{http_code}" \
        "http://localhost:3000/api/datasources/name/${name}")
    if [ "$code" = "200" ]; then
        echo "  datasource '${name}' already exists — skipping"
        continue
    fi
    body=$(cat <<EOF
{
  "name": "${name}",
  "type": "elasticsearch",
  "url": "http://elasticsearch:9200",
  "access": "proxy",
  "database": "${GF_DS_INDEX[$i]}",
  "isDefault": false,
  "jsonData": {
    "esVersion": "8.0.0",
    "timeField": "${GF_DS_TIME[$i]}",
    "maxConcurrentShardRequests": 5
  }
}
EOF
    )
    curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -H 'Content-Type: application/json' \
        -X POST "http://localhost:3000/api/datasources" \
        -d "$body" | sed 's/^/  /'
    echo
    echo "  created datasource '${name}'"
done

# PostgreSQL datasource for the PostgreSQL DMARC dashboard. Fixed uid dmarc-pg
# so the dashboard import below can resolve its ${DS_POSTGRESQL} input. Skipped
# when already present.
pg_ds_code=$(curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
    -o /dev/null -w "%{http_code}" \
    "http://localhost:3000/api/datasources/name/PostgreSQL")
if [ "$pg_ds_code" = "200" ]; then
    echo "  datasource 'PostgreSQL' already exists — skipping"
else
    pg_ds_body=$(cat <<EOF
{
  "name": "PostgreSQL",
  "uid": "dmarc-pg",
  "type": "grafana-postgresql-datasource",
  "url": "postgresql:5432",
  "access": "proxy",
  "user": "${PG_USER}",
  "database": "${PG_DB}",
  "isDefault": false,
  "jsonData": { "sslmode": "disable" },
  "secureJsonData": { "password": "${PG_PASSWORD}" }
}
EOF
    )
    curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
        -H 'Content-Type: application/json' \
        -X POST "http://localhost:3000/api/datasources" \
        -d "$pg_ds_body" | sed 's/^/  /'
    echo
    echo "  created datasource 'PostgreSQL'"
fi

log "Importing Grafana dashboard"
GF_BODY=$(python3 -c '
import json, sys
with open("dashboards/grafana/Grafana-DMARC_Reports.json") as f:
    d = json.load(f)
# Setting id=None lets Grafana create or replace by uid+overwrite.
d["id"] = None
print(json.dumps({"dashboard": d, "overwrite": True, "folderUid": ""}))
')
curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X POST "http://localhost:3000/api/dashboards/db" \
    -d "$GF_BODY" | sed 's/^/  /'

log "Importing Grafana PostgreSQL dashboard"
# Resolve the dashboard's ${DS_POSTGRESQL} input to the dmarc-pg datasource uid
# created above, drop the export-only __inputs/__requires keys, and let
# id=None create-or-replace by uid+overwrite.
GF_PG_BODY=$(python3 -c '
import json
with open("dashboards/grafana/Grafana-DMARC_Reports-PostgreSQL.json") as f:
    text = f.read()
text = text.replace("${DS_POSTGRESQL}", "dmarc-pg")
d = json.loads(text)
d.pop("__inputs", None)
d.pop("__requires", None)
d["id"] = None
print(json.dumps({"dashboard": d, "overwrite": True, "folderUid": ""}))
')
curl -sS -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X POST "http://localhost:3000/api/dashboards/db" \
    -d "$GF_PG_BODY" | sed 's/^/  /'

log "Importing Splunk dashboard views into the DMARC app"
splunk_import_view() {
    local name="$1"
    local file="$2"
    # DELETE-then-POST is the only path that survives both first-run and
    # re-run; POST to an existing view returns 409.
    splunk_curl -X DELETE \
        "https://localhost:8089/servicesNS/admin/DMARC/data/ui/views/${name}" \
        >/dev/null 2>&1 || true
    splunk_curl -X POST \
        "https://localhost:8089/servicesNS/admin/DMARC/data/ui/views" \
        -d "name=${name}" \
        --data-urlencode "eai:data@-" \
        < "$file" >/dev/null
    echo "  imported splunk view: ${name}"
}

splunk_import_view dmarc_aggregate dashboards/splunk/dmarc_aggregate_dashboard.xml
splunk_import_view dmarc_failure   dashboards/splunk/dmarc_failure_dashboard.xml
splunk_import_view smtp_tls        dashboards/splunk/smtp_tls_dashboard.xml

cat <<EOF

== Done. UIs available at:
  Kibana                  http://localhost:5601/
  OpenSearch Dashboards   http://localhost:5602/   (admin / ${OPENSEARCH_INITIAL_ADMIN_PASSWORD})
  Grafana                 http://localhost:3000/   (${GRAFANA_USER} / ${GRAFANA_PASSWORD})
  Splunk                  http://localhost:8000/   (admin / ${SPLUNK_PASSWORD})
  PostgreSQL              localhost:5432           (${PG_USER} / ${PG_PASSWORD}, db ${PG_DB})
EOF
