"""Tests for the Grafana dashboard for the Loki output"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from typing import Any, cast
from unittest.mock import patch

import parsedmarc
from parsedmarc.loki import LokiClient

ROOT = os.path.join(os.path.dirname(__file__), "..")
GRAFANA = os.path.join(ROOT, "dashboards", "grafana")
SAMPLES = os.path.join(ROOT, "samples")
LOKI_DASHBOARD = os.path.join(GRAFANA, "Grafana-DMARC_Reports-Loki.json")
PG_DASHBOARD = os.path.join(GRAFANA, "Grafana-DMARC_Reports-PostgreSQL.json")
DATASOURCE = {"type": "loki", "uid": "${DS_LOKI}"}

SELECTOR = re.compile(r"\{([^{}]*report_type=\"(\w+)\"[^{}]*)\}")
JSON_STAGE = re.compile(r"\|\s*json\b([^|\[)]*)")
LABEL_FORMAT = re.compile(r"label_format\s+(\w+)=")


def _load(path: str) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def _panels(dashboard: dict[str, Any]):
    for panel in dashboard["panels"]:
        yield panel
        yield from panel.get("panels", [])


def _targets(dashboard: dict[str, Any]):
    for panel in _panels(dashboard):
        for target in panel.get("targets", []):
            yield panel, target


def _lines(report_type: str, path: str) -> list[dict[str, Any]]:
    """Log lines the Loki output writes for one sample report."""
    parsed = parsedmarc.parse_report_file(path, offline=True)
    client = LokiClient("http://loki:3100")
    pushed: list = []
    with patch.object(client, "_push", side_effect=pushed.extend):
        save = getattr(client, f"save_{report_type}_report_to_loki")
        save(cast(Any, parsed["report"]))
    return [line for _, _, line in pushed]


def _sample_fields() -> dict[str, set[str]]:
    samples = {
        "aggregate": os.path.join(
            SAMPLES, "aggregate", "!example.com!1538204542!1538463818.xml"
        ),
        "failure": os.path.join(SAMPLES, "failure", "dmarc_ruf_report_linkedin.eml"),
        "smtp_tls": os.path.join(SAMPLES, "smtp_tls", "google.com_smtp_tls_report.eml"),
    }
    fields = {}
    for report_type, path in samples.items():
        fields[report_type] = {k for line in _lines(report_type, path) for k in line}
    # Columns the CSV rows only carry when the report has them.
    fields["aggregate"] |= {"org_extra_contact_info", "fo", "np"}
    fields["failure"] |= {"sample_headers_only"}
    fields["smtp_tls"] |= {
        "result_type",
        "sending_mta_ip",
        "receiving_ip",
        "receiving_mx_hostname",
        "failure_reason_code",
        "additional_info_uri",
        "policy_strings",
        "mx_host_patterns",
    }
    return fields


class TestGrafanaLokiDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dashboard = _load(LOKI_DASHBOARD)
        cls.postgres = _load(PG_DASHBOARD)

    def test_opens_on_the_last_seven_days(self):
        self.assertEqual(self.dashboard["time"], {"from": "now-7d", "to": "now"})

    def test_declares_the_loki_datasource_input(self):
        [entry] = self.dashboard["__inputs"]
        self.assertEqual(entry["name"], "DS_LOKI")
        self.assertEqual(entry["pluginId"], "loki")

    def test_same_layout_as_the_postgresql_dashboard(self):
        def layout(d):
            return [(p["type"], p.get("title"), p["gridPos"]) for p in _panels(d)]

        self.assertEqual(layout(self.dashboard), layout(self.postgres))

    def test_every_query_uses_the_loki_input(self):
        for panel, target in _targets(self.dashboard):
            with self.subTest(panel=panel["title"]):
                self.assertEqual(panel["datasource"], DATASOURCE)
                self.assertEqual(target["datasource"], DATASOURCE)

    def test_every_query_selects_parsedmarc_streams(self):
        for panel, target in _targets(self.dashboard):
            with self.subTest(panel=panel["title"], ref=target["refId"]):
                match = SELECTOR.search(target["expr"])
                self.assertIsNotNone(match, target["expr"])
                assert match is not None
                self.assertIn('job="parsedmarc"', match.group(1))
                self.assertIn(match.group(2), ("aggregate", "failure", "smtp_tls"))

    def test_aggregate_queries_follow_the_domain_variable(self):
        for panel, target in _targets(self.dashboard):
            match = SELECTOR.search(target["expr"])
            if match and match.group(2) == "aggregate":
                with self.subTest(panel=panel["title"]):
                    self.assertIn('domain=~"$domain"', match.group(1))

    def test_json_stages_name_their_fields(self):
        """A bare `| json` turns every field into a label and hits max_query_series."""
        for panel, target in _targets(self.dashboard):
            for stage in JSON_STAGE.findall(target["expr"]):
                with self.subTest(panel=panel["title"], ref=target["refId"]):
                    self.assertTrue(stage.strip(), target["expr"])

    def test_fields_exist_in_the_lines_the_loki_output_writes(self):
        fields = _sample_fields()
        for panel, target in _targets(self.dashboard):
            expr = target["expr"]
            match = SELECTOR.search(expr)
            assert match is not None
            known = fields[match.group(2)] | set(LABEL_FORMAT.findall(expr))
            used = {
                f.strip()
                for stage in JSON_STAGE.findall(expr)
                for f in stage.split(",")
            }
            with self.subTest(panel=panel["title"], ref=target["refId"]):
                self.assertEqual(used - known, set())

    def test_extracted_columns_exist_in_the_log_lines(self):
        fields = _sample_fields()
        for panel in _panels(self.dashboard):
            for t in panel.get("transformations", []):
                if t["id"] != "extractFields":
                    continue
                match = SELECTOR.search(panel["targets"][0]["expr"])
                assert match is not None
                report_type = match.group(2)
                paths = {p["path"] for p in t["options"]["jsonPaths"]}
                with self.subTest(panel=panel["title"]):
                    self.assertEqual(paths - fields[report_type], set())

    def test_range_queries_keep_their_buckets_inside_the_time_range(self):
        """A fixed 1d step stamps the current bucket after `now`, so the chart is empty."""
        for panel, target in _targets(self.dashboard):
            if target.get("queryType") == "range" and "unwrap" in target["expr"]:
                with self.subTest(panel=panel["title"], ref=target["refId"]):
                    self.assertNotIn("step", target)
                    self.assertNotIn("$interval", target["expr"])

    def test_report_dedup_groups_by_reporter_too(self):
        """report_id is only unique per reporter, so every `by (...)` that
        groups on it must group on org_name as well."""
        for panel, target in _targets(self.dashboard):
            for clause in re.findall(r"\bby \(([^)]*)\)", target["expr"]):
                names = [n.strip() for n in clause.split(",")]
                if "report_id" in names:
                    with self.subTest(panel=panel["title"], ref=target["refId"]):
                        self.assertIn("org_name", names)

    def test_fixed_lookback_series_have_no_additive_legend_calcs(self):
        """A fixed range such as [1d] with the automatic step yields
        overlapping rolling totals, so summing them counts each value many times."""
        for panel in _panels(self.dashboard):
            fixed = False
            for target in panel.get("targets", []):
                if target.get("queryType") != "range":
                    continue
                for dur in re.findall(r"\[([^\]]+)\]", target["expr"]):
                    if dur not in ("$__interval", "$__auto"):
                        fixed = True
            if fixed and panel.get("type") == "timeseries":
                calcs = panel["options"]["legend"].get("calcs", [])
                with self.subTest(panel=panel["title"]):
                    self.assertFalse({"sum", "count"} & set(calcs))

    def test_pies_use_one_slice_per_row(self):
        for panel in _panels(self.dashboard):
            if panel["type"] == "piechart":
                with self.subTest(panel=panel["title"]):
                    self.assertTrue(panel["options"]["reduceOptions"]["values"])

    def test_table_counts_are_named_after_what_they_count(self):
        """Grafana shows the value field as "Value #A" unless a display name says otherwise."""
        for panel in _panels(self.dashboard):
            if panel["type"] != "table":
                continue
            names = set()
            for t in panel.get("transformations", []):
                if t["id"] == "organize":
                    names.update(
                        dst
                        for src, dst in t["options"].get("renameByName", {}).items()
                        if src.startswith("Value")
                    )
            if not names:
                continue
            shown = {
                prop["value"]
                for o in panel.get("fieldConfig", {}).get("overrides", [])
                for prop in o["properties"]
                if prop["id"] == "displayName"
            }
            with self.subTest(panel=panel["title"]):
                self.assertEqual(names - shown, set())

    def test_summary_tables_combine_one_frame_per_series(self):
        for panel in _panels(self.dashboard):
            ids = [t["id"] for t in panel.get("transformations", [])]
            if "labelsToFields" in ids:
                with self.subTest(panel=panel["title"]):
                    self.assertTrue({"merge", "joinByField"} & set(ids))

    def test_tls_session_counts_only_sum_policy_rows(self):
        """Failure-detail rows repeat failed_session_count; summing them double counts."""
        for panel, target in _targets(self.dashboard):
            if re.search(r"unwrap\s+\w+_session_count", target["expr"]):
                with self.subTest(panel=panel["title"], ref=target["refId"]):
                    self.assertIn('policy_type!=""', target["expr"])


BOOTSTRAP = os.path.join(ROOT, "dashboard-dev-bootstrap.sh")

# Stands in for the Grafana HTTP API: the Loki datasource lookup answers from
# FAKE_LOKI_UID (404 when unset) and every request body is appended to
# FAKE_POSTS, one per line.
FAKE_CURL = r"""#!/bin/bash
url="" data="" write=""
while [ $# -gt 0 ]; do
    case "$1" in
        -w) write="$2"; shift ;;
        -d) data="$2"; shift ;;
        -u|-H|-X|-o) shift ;;
        -*) ;;
        *) url="$1" ;;
    esac
    shift
done
if [ -n "$data" ]; then
    printf '%s\n' "$data" >> "$FAKE_POSTS"
fi
if [[ "$url" == */api/datasources/name/Loki ]]; then
    if [ -n "${FAKE_LOKI_UID:-}" ]; then
        printf '{"name": "Loki", "uid": "%s"}' "$FAKE_LOKI_UID"
        code=200
    else
        printf '{"message": "Data source not found"}'
        code=404
    fi
    [ -n "$write" ] && printf '\n%s' "$code"
fi
exit 0
"""


class TestBootstrapLokiDatasourceUid(unittest.TestCase):
    """The dev bootstrap must bind the imported dashboard to whichever uid the
    'Loki' datasource really has, not assume the uid it creates."""

    def _import(self, existing_uid: str | None) -> tuple[str, list[str]]:
        """Run the bootstrap's Loki datasource and dashboard import steps
        against a fake curl. Returns the datasource uid the imported
        dashboard uses and the POSTed request bodies."""
        with open(BOOTSTRAP) as f:
            script = f.read()
        start = script.index("# Loki datasource for the Loki DMARC dashboard")
        end = script.index('log "Importing Splunk dashboard views')
        with tempfile.TemporaryDirectory() as tmp:
            curl = os.path.join(tmp, "curl")
            with open(curl, "w") as f:
                f.write(FAKE_CURL)
            os.chmod(curl, 0o755)
            posts = os.path.join(tmp, "posts")
            env = {
                **os.environ,
                "PATH": tmp + os.pathsep + os.environ["PATH"],
                "FAKE_POSTS": posts,
                "GRAFANA_USER": "admin",
                "GRAFANA_PASSWORD": "pw",
            }
            env.pop("FAKE_LOKI_UID", None)
            if existing_uid:
                env["FAKE_LOKI_UID"] = existing_uid
            prelude = "set -euo pipefail\nlog() { :; }\n"
            subprocess.run(
                ["bash", "-c", prelude + script[start:end]],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            with open(posts) as f:
                bodies = f.read().splitlines()
        imported = [b for b in bodies if '"dashboard"' in b]
        loki = [
            b
            for b in imported
            if json.loads(b)["dashboard"]["uid"] == self._loki_dashboard_uid()
        ]
        self.assertEqual(len(loki), 1)
        uids = {
            t["datasource"]["uid"]
            for _, t in _targets(json.loads(loki[0])["dashboard"])
        }
        self.assertEqual(len(uids), 1)
        return uids.pop(), bodies

    @staticmethod
    def _created(bodies: list[str]) -> list[dict[str, Any]]:
        """Loki datasources the script POSTed (dashboard imports excluded)."""
        parsed = [json.loads(b) for b in bodies]
        return [d for d in parsed if d.get("type") == "loki"]

    def _loki_dashboard_uid(self) -> str:
        return _load(LOKI_DASHBOARD)["uid"]

    def test_existing_datasource_uid_is_used(self):
        uid, bodies = self._import("custom-loki-uid")
        self.assertEqual(uid, "custom-loki-uid")
        # An existing datasource is not created again.
        self.assertEqual(self._created(bodies), [])

    def test_created_datasource_uses_dmarc_loki(self):
        uid, bodies = self._import(None)
        self.assertEqual(uid, "dmarc-loki")
        self.assertEqual([d["uid"] for d in self._created(bodies)], ["dmarc-loki"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
