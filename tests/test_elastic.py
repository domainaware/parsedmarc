"""Tests for parsedmarc.elastic

Mocks at the elasticsearch.dsl SDK boundary (connections.create_connection,
Index, Search, Document.save) so the tests verify the parsedmarc-side
transformation logic — document construction, index naming, deduplication
queries, error wrapping — without needing a running Elasticsearch cluster.
"""

import time
import unittest
from unittest.mock import MagicMock, call, patch

import parsedmarc.elastic as elastic_module
from parsedmarc import InvalidFailureReport
from parsedmarc.elastic import (
    AlreadySaved,
    ElasticsearchError,
    create_indexes,
    save_aggregate_report_to_elasticsearch,
    save_failure_report_to_elasticsearch,
    save_smtp_tls_report_to_elasticsearch,
    set_hosts,
)
from tests.tzutil import force_tz


# ---------------------------------------------------------------------------
# Sample report fixtures
# ---------------------------------------------------------------------------


def _aggregate_report(**overrides):
    base = {
        "xml_schema": "draft",
        "xml_namespace": None,
        "report_metadata": {
            "org_name": "TestOrg",
            "org_email": "dmarc@example.com",
            "org_extra_contact_info": None,
            "report_id": "agg-1",
            "begin_date": "2024-01-15 00:00:00",
            "end_date": "2024-01-16 00:00:00",
            "timespan_requires_normalization": False,
            "original_timespan_seconds": 86400,
            "errors": [],
            "generator": "TestGen/1.0",
        },
        "policy_published": {
            "domain": "example.com",
            "adkim": "r",
            "aspf": "r",
            "p": "none",
            "sp": "none",
            "pct": None,
            "fo": None,
            "np": "reject",
            "testing": "n",
            "discovery_method": "treewalk",
        },
        "records": [
            {
                "interval_begin": "2024-01-15 00:00:00",
                "interval_end": "2024-01-16 00:00:00",
                "normalized_timespan": False,
                "source": {
                    "ip_address": "192.0.2.1",
                    "country": "US",
                    "reverse_dns": None,
                    "base_domain": None,
                    "name": None,
                    "type": None,
                    "asn": 64496,
                    "as_name": "Example AS",
                    "as_domain": "example.net",
                },
                "count": 4,
                "alignment": {"spf": True, "dkim": True, "dmarc": True},
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                    "policy_override_reasons": [
                        {"type": "local_policy", "comment": "approved"}
                    ],
                },
                "identifiers": {
                    "header_from": "example.com",
                    "envelope_from": "example.com",
                    "envelope_to": "rcpt@example.com",
                },
                "auth_results": {
                    "dkim": [
                        {
                            "domain": "example.com",
                            "selector": "s",
                            "result": "pass",
                            "human_result": None,
                        }
                    ],
                    "spf": [
                        {
                            "domain": "example.com",
                            "scope": "mfrom",
                            "result": "pass",
                            "human_result": None,
                        }
                    ],
                },
            }
        ],
    }
    base.update(overrides)
    return base


def _failure_report(**overrides):
    base = {
        "feedback_type": "auth-failure",
        "user_agent": "test/1.0",
        "version": "1",
        "original_envelope_id": None,
        "original_mail_from": "x@example.com",
        "original_rcpt_to": None,
        "arrival_date": "Thu, 1 Jan 2024 00:00:00 +0000",
        "arrival_date_utc": "2024-01-01 00:00:00",
        "authentication_results": None,
        "delivery_result": "other",
        "auth_failure": ["dmarc"],
        "authentication_mechanisms": [],
        "dkim_domain": None,
        "reported_domain": "example.com",
        "sample_headers_only": True,
        "source": {
            "ip_address": "192.0.2.5",
            "country": "US",
            "reverse_dns": None,
            "base_domain": None,
            "name": None,
            "type": None,
            "asn": 64496,
            "as_name": "Example AS",
            "as_domain": "example.net",
        },
        "sample": "raw",
        "parsed_sample": {
            "headers": {
                # mailparser emits headers as [[display_name, address]]
                # lists; an empty display becomes [["", address]].
                "From": [["Sender Name", "sender@example.com"]],
                "To": [["", "rcpt@example.com"]],
                "Subject": "Test",
            },
            "subject": "Test",
            "filename_safe_subject": "Test",
            "body": "body",
            "date": "Thu, 1 Jan 2024 00:00:00 +0000",
            "to": [{"display_name": None, "address": "rcpt@example.com"}],
            "reply_to": [],
            "cc": [],
            "bcc": [],
            "attachments": [],
        },
    }
    base.update(overrides)
    return base


def _smtp_tls_report(**overrides):
    base = {
        "organization_name": "TestOrg",
        "begin_date": "2024-02-03T00:00:00Z",
        "end_date": "2024-02-04T00:00:00Z",
        "contact_info": "tls@example.com",
        "report_id": "tls-1",
        "policies": [
            {
                "policy_domain": "example.com",
                "policy_type": "sts",
                "successful_session_count": 100,
                "failed_session_count": 1,
                "policy_strings": ["version: STSv1"],
                "mx_host_patterns": ["*.example.com"],
                "failure_details": [
                    {
                        "result_type": "certificate-expired",
                        "failed_session_count": 1,
                        "receiving_mx_hostname": "mx.example.com",
                        "sending_mta_ip": "10.0.0.1",
                    }
                ],
            }
        ],
    }
    base.update(overrides)
    return base


def _empty_search():
    """A Search() mock whose .execute() returns an empty hit list."""
    search = MagicMock()
    search.execute.return_value = []
    return search


def _populated_search():
    """A Search() mock whose .execute() returns a non-empty hit list."""
    search = MagicMock()
    search.execute.return_value = [MagicMock()]
    return search


# ---------------------------------------------------------------------------
# set_hosts: connection-parameter assembly
# ---------------------------------------------------------------------------


class TestSetHosts(unittest.TestCase):
    """Verify the conn_params dict handed to the elasticsearch-py 8.x client
    matches each documented option. Each branch corresponds to a
    real-world deployment shape (TLS, basic auth, API key, custom CA).

    The 8.x client dropped the ``use_ssl`` / ``http_auth`` / ``timeout``
    connection kwargs: the scheme now has to be baked into each host URL,
    ``basic_auth`` replaces ``http_auth``, and ``request_timeout`` replaces
    ``timeout``.
    """

    def test_single_host_url_passed_through_unchanged(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("https://es:9200")
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["https://es:9200"])

    def test_host_list_preserved(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts(["http://es1:9200", "http://es2:9200"])
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["http://es1:9200", "http://es2:9200"])

    def test_bare_host_use_ssl_false_gets_http_prefix(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("localhost", use_ssl=False)
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["http://localhost"])
        self.assertNotIn("use_ssl", kwargs)

    def test_bare_host_use_ssl_true_gets_https_prefix(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("localhost", use_ssl=True)
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["https://localhost"])
        self.assertEqual(kwargs["verify_certs"], True)
        self.assertNotIn("use_ssl", kwargs)
        self.assertNotIn("ca_certs", kwargs)

    def test_explicit_url_passes_through_even_with_use_ssl_true(self):
        """A host that already carries a scheme is never re-prefixed,
        even when it disagrees with use_ssl."""
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("http://example.com:9200", use_ssl=True)
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["http://example.com:9200"])

    def test_timeout_default_60s_becomes_request_timeout(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("es:9200")
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["request_timeout"], 60.0)
        self.assertNotIn("timeout", kwargs)

    def test_timeout_custom(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("es:9200", timeout=30.0)
        self.assertEqual(mock_conn.call_args.kwargs["request_timeout"], 30.0)

    def test_use_ssl_with_custom_ca(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("es:9200", use_ssl=True, ssl_cert_path="/etc/ca.pem")
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["ca_certs"], "/etc/ca.pem")

    def test_skip_certificate_verification_sets_verify_false(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("es:9200", use_ssl=True, skip_certificate_verification=True)
        self.assertEqual(mock_conn.call_args.kwargs["verify_certs"], False)

    def test_username_password_sets_basic_auth(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("es:9200", username="u", password="p")
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["basic_auth"], ("u", "p"))
        self.assertNotIn("http_auth", kwargs)

    def test_username_without_password_not_set(self):
        """Half-configured auth is suspicious enough not to send."""
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("es:9200", username="u")
        self.assertNotIn("basic_auth", mock_conn.call_args.kwargs)

    def test_api_key_set(self):
        with patch("parsedmarc.elastic.connections.create_connection") as mock_conn:
            set_hosts("es:9200", api_key="base64key==")
        self.assertEqual(mock_conn.call_args.kwargs["api_key"], "base64key==")


# ---------------------------------------------------------------------------
# create_indexes
# ---------------------------------------------------------------------------


class TestCreateIndexes(unittest.TestCase):
    def test_creates_missing_index_with_default_settings(self):
        with patch("parsedmarc.elastic.Index") as mock_index_cls:
            mock_index = mock_index_cls.return_value
            mock_index.exists.return_value = False
            create_indexes(["dmarc_aggregate-2024-01-15"])
        mock_index.settings.assert_called_once_with(
            number_of_shards=1, number_of_replicas=0
        )
        mock_index.create.assert_called_once()

    def test_creates_with_custom_settings(self):
        with patch("parsedmarc.elastic.Index") as mock_index_cls:
            mock_index = mock_index_cls.return_value
            mock_index.exists.return_value = False
            create_indexes(
                ["idx"], settings={"number_of_shards": 3, "refresh_interval": "5s"}
            )
        mock_index.settings.assert_called_once_with(
            number_of_shards=3, refresh_interval="5s"
        )

    def test_skips_existing_index(self):
        with patch("parsedmarc.elastic.Index") as mock_index_cls:
            mock_index = mock_index_cls.return_value
            mock_index.exists.return_value = True
            create_indexes(["idx"])
        mock_index.create.assert_not_called()

    def test_wraps_sdk_error(self):
        with patch("parsedmarc.elastic.Index") as mock_index_cls:
            mock_index_cls.return_value.exists.side_effect = RuntimeError(
                "cluster down"
            )
            with self.assertRaises(ElasticsearchError) as ctx:
                create_indexes(["idx"])
        self.assertIn("cluster down", str(ctx.exception))


class TestCreateIndexesServerless(unittest.TestCase):
    """Serverless mode strips shard/replica keys but keeps everything else.

    Elastic Cloud Serverless rejects ``number_of_shards`` and
    ``number_of_replicas`` with HTTP 400. Other settings like
    ``refresh_interval`` are accepted and must pass through unchanged.
    """

    def setUp(self):
        self._original = elastic_module._SERVERLESS
        elastic_module._SERVERLESS = True

    def tearDown(self):
        elastic_module._SERVERLESS = self._original

    def test_serverless_default_skips_settings_entirely(self):
        with patch("parsedmarc.elastic.Index") as mock_index_cls:
            mock_index = mock_index_cls.return_value
            mock_index.exists.return_value = False
            create_indexes(["idx"])
        mock_index.settings.assert_not_called()
        mock_index.create.assert_called_once()

    def test_serverless_filters_rejected_keys_and_passes_others_through(self):
        with patch("parsedmarc.elastic.Index") as mock_index_cls:
            mock_index = mock_index_cls.return_value
            mock_index.exists.return_value = False
            create_indexes(
                ["idx"],
                settings={
                    "number_of_shards": 3,
                    "number_of_replicas": 2,
                    "refresh_interval": "5s",
                },
            )
        mock_index.settings.assert_called_once_with(refresh_interval="5s")

    def test_serverless_skips_settings_when_only_rejected_keys(self):
        with patch("parsedmarc.elastic.Index") as mock_index_cls:
            mock_index = mock_index_cls.return_value
            mock_index.exists.return_value = False
            create_indexes(
                ["idx"], settings={"number_of_shards": 3, "number_of_replicas": 2}
            )
        mock_index.settings.assert_not_called()
        mock_index.create.assert_called_once()


# ---------------------------------------------------------------------------
# save_aggregate_report_to_elasticsearch
# ---------------------------------------------------------------------------


class TestSaveAggregateReport(unittest.TestCase):
    """The aggregate-report save fans out across multiple SDK calls:
    Search (for dedup), Index.create (for the daily/monthly index),
    Document.save. Each test patches the boundary it needs and
    leaves the rest alone."""

    def _patches(self, search_factory=_empty_search):
        return [
            patch("parsedmarc.elastic.Search", return_value=search_factory()),
            patch(
                "parsedmarc.elastic.Index",
                return_value=MagicMock(exists=MagicMock(return_value=True)),
            ),
            patch.object(elastic_module._AggregateReportDoc, "save"),
        ]

    def test_save_emits_one_document_per_record(self):
        report = _aggregate_report()
        report["records"].append(report["records"][0].copy())
        patches = self._patches()
        with patches[0], patches[1], patches[2] as mock_save:
            save_aggregate_report_to_elasticsearch(report)
        # Two records → two saves.
        self.assertEqual(mock_save.call_count, 2)

    def test_already_saved_raises_when_search_returns_hit(self):
        """The dedup query is the only thing preventing
        double-indexing on re-run. A regression would silently
        re-save reports, inflating Kibana counts."""
        with (
            patch("parsedmarc.elastic.Search", return_value=_populated_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._AggregateReportDoc, "save") as mock_save,
        ):
            with self.assertRaises(AlreadySaved):
                save_aggregate_report_to_elasticsearch(_aggregate_report())
        mock_save.assert_not_called()

    def test_search_exception_wraps_to_elasticsearch_error(self):
        bad_search = MagicMock()
        bad_search.execute.side_effect = RuntimeError("network")
        with (
            patch("parsedmarc.elastic.Search", return_value=bad_search),
            patch("parsedmarc.elastic.Index"),
        ):
            with self.assertRaises(ElasticsearchError) as ctx:
                save_aggregate_report_to_elasticsearch(_aggregate_report())
        self.assertIn("network", str(ctx.exception))

    def test_save_exception_wraps_to_elasticsearch_error(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(
                elastic_module._AggregateReportDoc,
                "save",
                side_effect=RuntimeError("disk"),
            ),
        ):
            with self.assertRaises(ElasticsearchError) as ctx:
                save_aggregate_report_to_elasticsearch(_aggregate_report())
        self.assertIn("disk", str(ctx.exception))

    def test_index_name_uses_daily_format_by_default(self):
        """Index naming: dmarc_aggregate-YYYY-MM-DD by default."""
        index_calls = []
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch.object(elastic_module._AggregateReportDoc, "save"),
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_elasticsearch(_aggregate_report())
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("dmarc_aggregate-2024-01-15", index_calls)

    def test_index_name_uses_monthly_format_when_flag_set(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch.object(elastic_module._AggregateReportDoc, "save"),
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_elasticsearch(
                _aggregate_report(), monthly_indexes=True
            )
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("dmarc_aggregate-2024-01", index_calls)

    def test_index_name_honours_suffix_and_prefix(self):
        """Prefix/suffix support multi-tenant setups where one ES
        cluster serves several DMARC owners."""
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch.object(elastic_module._AggregateReportDoc, "save"),
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_elasticsearch(
                _aggregate_report(),
                index_suffix="tenant_a",
                index_prefix="customer1_",
            )
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("customer1_dmarc_aggregate_tenant_a-2024-01-15", index_calls)

    def test_dedup_search_pattern_uses_suffix_wildcard(self):
        """Existing-report search uses '*' so it matches both
        daily and monthly index buckets."""
        with (
            patch("parsedmarc.elastic.Search") as mock_search_cls,
            patch(
                "parsedmarc.elastic.Index",
                return_value=MagicMock(exists=MagicMock(return_value=True)),
            ),
            patch.object(elastic_module._AggregateReportDoc, "save"),
        ):
            mock_search_cls.return_value.execute.return_value = []
            save_aggregate_report_to_elasticsearch(
                _aggregate_report(), index_suffix="tenant_a", index_prefix="cust_"
            )
        # Search index pattern wraps prefix+name+suffix with trailing wildcard.
        search_index = mock_search_cls.call_args.kwargs["index"]
        self.assertIn("cust_dmarc_aggregate_tenant_a*", search_index)

    @unittest.skipUnless(hasattr(time, "tzset"), "requires POSIX time.tzset()")
    def test_interval_dates_are_utc_regardless_of_host_timezone(self):
        """interval_begin/interval_end are UTC wall-clock strings (already
        converted to UTC at parse time in __init__.py); the index-date
        bucketing and stored date_begin/date_end must use their true UTC
        epoch on any host. Regression test for
        https://github.com/domainaware/parsedmarc/issues/819: the naive
        parse used to shift the stored epoch (and therefore the index
        date) by the host's UTC offset."""
        force_tz(self)
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch("parsedmarc.elastic._AggregateReportDoc") as mock_doc_cls,
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_elasticsearch(_aggregate_report())
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("dmarc_aggregate-2024-01-15", index_calls)
        # Fixture begin_date/interval_begin is 2024-01-15 00:00:00 UTC.
        self.assertEqual(
            mock_doc_cls.call_args.kwargs["date_begin"].timestamp(), 1705276800
        )

    def test_save_populates_combined_dkim_and_spf_fields(self):
        """Regression guard for issue #169: two DKIM signatures on one
        record must yield exactly two combined entries, not a 4-way
        cross-product. autospec=True is required on the save patch so
        mock_save.call_args captures the doc instance as ``self``."""
        report = _aggregate_report()
        report["records"][0]["auth_results"] = {
            "dkim": [
                {
                    "domain": "example.net",
                    "selector": "net1",
                    "result": "fail",
                    "human_result": None,
                },
                {
                    "domain": "example.org",
                    "selector": "org1",
                    "result": "pass",
                    "human_result": None,
                },
            ],
            "spf": [
                {
                    "domain": "example.org",
                    "scope": "mfrom",
                    "result": "pass",
                    "human_result": None,
                },
            ],
        }
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch(
                "parsedmarc.elastic.Index",
                return_value=MagicMock(exists=MagicMock(return_value=True)),
            ),
            patch.object(
                elastic_module._AggregateReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_aggregate_report_to_elasticsearch(report)
        doc = mock_save.call_args[0][0]
        self.assertEqual(
            list(doc.dkim_results_combined),
            ["net1 / example.net / fail", "org1 / example.org / pass"],
        )
        self.assertEqual(list(doc.spf_results_combined), ["mfrom / example.org / pass"])


class TestAggregateDocPassedDmarc(unittest.TestCase):
    """The _AggregateReportDoc.save() override derives passed_dmarc — the
    field dashboards filter on for DMARC pass/fail — from SPF/DKIM
    alignment. The SDK parent (elasticsearch.dsl.Document.save) is mocked so
    no cluster is needed."""

    def test_passed_dmarc_derived_from_alignment(self):
        cases = [
            (True, False, True),
            (False, True, True),
            (True, True, True),
            (False, False, False),
        ]
        for spf_aligned, dkim_aligned, expected in cases:
            with self.subTest(spf=spf_aligned, dkim=dkim_aligned):
                with patch.object(
                    elastic_module.Document, "save", return_value=None
                ) as mock_super_save:
                    doc = elastic_module._AggregateReportDoc(
                        spf_aligned=spf_aligned, dkim_aligned=dkim_aligned
                    )
                    doc.save()
                mock_super_save.assert_called_once()
                self.assertEqual(bool(doc.passed_dmarc), expected)


class TestAggregateDocCombinedResults(unittest.TestCase):
    """add_dkim_result/add_spf_result never touch the network, so these
    construct _AggregateReportDoc directly rather than going through the
    save_* entry point."""

    def test_add_dkim_result_appends_combined_string(self):
        """Regression guard for issue #169: dkim_results/spf_results are
        stored as nested object arrays, which Kibana/Grafana tables cannot
        terms-aggregate without producing a cross-product of selector/
        domain/result values. The composed "selector / domain / result"
        string preserves per-signature pairing that the object-mapped
        array loses."""
        doc = elastic_module._AggregateReportDoc()
        doc.add_dkim_result(
            domain="example.net", selector="net1", result="fail", human_result=None
        )
        doc.add_dkim_result(
            domain="example.org", selector="org1", result="pass", human_result=None
        )
        expected = ["net1 / example.net / fail", "org1 / example.org / pass"]
        # dkim_results_combined is declared as Text(multi=True, ...); the SDK
        # stub types the class attribute as Text (no Iterable protocol),
        # even though the runtime value is an AttrList once multi=True is
        # set. Same category of stub gap as the Q()/meta.index ignores in
        # elastic.py.
        self.assertEqual(list(doc.dkim_results_combined), expected)  # pyright: ignore[reportArgumentType]
        self.assertEqual(doc.to_dict()["dkim_results_combined"], expected)

    def test_add_spf_result_appends_combined_string(self):
        doc = elastic_module._AggregateReportDoc()
        doc.add_spf_result(
            domain="example.org", scope="mfrom", result="pass", human_result=None
        )
        expected = ["mfrom / example.org / pass"]
        self.assertEqual(list(doc.spf_results_combined), expected)  # pyright: ignore[reportArgumentType]
        self.assertEqual(doc.to_dict()["spf_results_combined"], expected)

    def test_spf_result_serializes_under_singular_result_key(self):
        """The _SPFResult class previously declared a dead ``results``
        (plural) field while the save path wrote ``result``; verify the
        serialized nested doc actually uses the singular key."""
        doc = elastic_module._AggregateReportDoc()
        doc.add_spf_result(
            domain="example.org", scope="mfrom", result="pass", human_result=None
        )
        d = doc.to_dict()["spf_results"][0]
        self.assertEqual(d["result"], "pass")
        self.assertNotIn("results", d)


# ---------------------------------------------------------------------------
# save_failure_report_to_elasticsearch
# ---------------------------------------------------------------------------


class TestSaveFailureReport(unittest.TestCase):
    def test_save_emits_one_document(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save") as mock_save,
        ):
            save_failure_report_to_elasticsearch(_failure_report())
        mock_save.assert_called_once()

    def test_already_saved_raises_on_dedup_hit(self):
        """Failure-report dedup uses arrival_date + From/To/Subject
        from the parsed sample. A hit means we've already indexed
        this exact failure sample."""
        with (
            patch("parsedmarc.elastic.Search", return_value=_populated_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save") as mock_save,
        ):
            with self.assertRaises(AlreadySaved):
                save_failure_report_to_elasticsearch(_failure_report())
        mock_save.assert_not_called()

    def test_save_exception_wraps_to_elasticsearch_error(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(
                elastic_module._FailureReportDoc,
                "save",
                side_effect=RuntimeError("disk"),
            ),
        ):
            with self.assertRaises(ElasticsearchError) as ctx:
                save_failure_report_to_elasticsearch(_failure_report())
        self.assertIn("disk", str(ctx.exception))

    def test_keyerror_wraps_to_invalid_failure_report(self):
        """A malformed failure report (missing a required field) is
        surfaced as InvalidFailureReport so the caller can route it
        differently from infra errors."""
        report = _failure_report()
        del report["feedback_type"]
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save"),
        ):
            with self.assertRaises(InvalidFailureReport):
                save_failure_report_to_elasticsearch(report)

    def test_index_dedup_pattern_searches_both_old_and_new_names(self):
        """The split-PR rename forensic→failure left existing data
        in dmarc_forensic*; the dedup search must check both names
        so re-runs don't double-index."""
        with (
            patch("parsedmarc.elastic.Search") as mock_search_cls,
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save"),
        ):
            mock_search_cls.return_value.execute.return_value = []
            save_failure_report_to_elasticsearch(_failure_report())
        search_index = mock_search_cls.call_args.kwargs["index"]
        self.assertIn("dmarc_failure*", search_index)
        self.assertIn("dmarc_forensic*", search_index)

    def test_index_name_uses_arrival_date_for_monthly_partition(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch.object(elastic_module._FailureReportDoc, "save"),
        ):
            save_failure_report_to_elasticsearch(
                _failure_report(), monthly_indexes=True
            )
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("dmarc_failure-2024-01", index_calls)

    @unittest.skipUnless(hasattr(time, "tzset"), "requires POSIX time.tzset()")
    def test_arrival_date_epoch_is_utc_regardless_of_host_timezone(self):
        """arrival_date_utc is a UTC wall-clock string; the epoch-ms
        value stored in the document (and used in the dedup query) must
        be its true UTC epoch on any host. Regression test for
        https://github.com/domainaware/parsedmarc/issues/811 (bug 1):
        the naive parse used to shift the stored epoch by the host's
        UTC offset."""
        force_tz(self)

        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch("parsedmarc.elastic._FailureReportDoc") as mock_doc_cls,
        ):
            save_failure_report_to_elasticsearch(_failure_report())
        # Fixture arrival_date_utc is 2024-01-01 00:00:00 UTC.
        self.assertEqual(mock_doc_cls.call_args.kwargs["arrival_date"], 1704067200000)

    def test_failure_search_index_with_suffix_and_prefix(self):
        """When both suffix and prefix are set, the dedup search
        pattern joins them onto BOTH dmarc_failure* and
        dmarc_forensic* (the rename back-compat)."""
        with (
            patch("parsedmarc.elastic.Search") as mock_search_cls,
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save"),
        ):
            mock_search_cls.return_value.execute.return_value = []
            save_failure_report_to_elasticsearch(
                _failure_report(),
                index_suffix="tenant_a",
                index_prefix="cust_",
            )
        search_index = mock_search_cls.call_args.kwargs["index"]
        self.assertIn("cust_dmarc_failure_tenant_a*", search_index)
        self.assertIn("cust_dmarc_forensic_tenant_a*", search_index)

    def test_failure_index_honours_suffix_and_prefix(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch.object(elastic_module._FailureReportDoc, "save"),
        ):
            save_failure_report_to_elasticsearch(
                _failure_report(),
                index_suffix="tenant_a",
                index_prefix="cust_",
            )
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("cust_dmarc_failure_tenant_a-2024-01-01", index_calls)

    def test_from_header_with_empty_display_name(self):
        """When the From display name is empty, the code uses the
        address alone (covers the early-return branch in the
        display-name handling)."""
        report = _failure_report()
        report["parsed_sample"]["headers"]["From"] = [["", "sender@example.com"]]
        report["parsed_sample"]["headers"]["To"] = [["", "rcpt@example.com"]]
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save") as mock_save,
        ):
            save_failure_report_to_elasticsearch(report)
        mock_save.assert_called_once()

    def test_to_header_with_non_empty_display_joins_with_brackets(self):
        """The other branch: non-empty display joins display+addr
        with " <" and appends ">", e.g. 'RT <rcpt@example.com>'."""
        report = _failure_report()
        report["parsed_sample"]["headers"]["To"] = [["RT", "rcpt@example.com"]]
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save") as mock_save,
        ):
            save_failure_report_to_elasticsearch(report)
        mock_save.assert_called_once()

    def test_sample_address_lists_indexed_for_reply_to_cc_bcc_attachments(self):
        """A failure report sample can carry reply_to / cc / bcc /
        attachments. Each populates a nested InnerDoc on the sample —
        if the add_* helpers regress, those nested docs would be
        silently empty in Elasticsearch."""
        report = _failure_report()
        report["parsed_sample"]["reply_to"] = [
            {"display_name": "RT", "address": "rt@example.com"}
        ]
        report["parsed_sample"]["cc"] = [
            {"display_name": "CC", "address": "cc@example.com"}
        ]
        report["parsed_sample"]["bcc"] = [
            {"display_name": "", "address": "bcc@example.com"}
        ]
        report["parsed_sample"]["attachments"] = [
            {
                "filename": "a.pdf",
                "mail_content_type": "application/pdf",
                "sha256": "deadbeef",
            }
        ]
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._FailureReportDoc, "save") as mock_save,
        ):
            save_failure_report_to_elasticsearch(report)
        mock_save.assert_called_once()

    def test_reply_to_header_flattened_and_indexed(self):
        """A Reply-To header is flattened to a display string on
        ``sample.headers["reply-to"]`` — so the failure dashboard's
        ``sample.headers.reply-to.keyword`` column resolves — and each
        Reply-To address also populates the nested ``sample.reply_to``
        docs. Asserts on the document handed to .save(), not merely
        that save ran."""
        report = _failure_report()
        report["parsed_sample"]["headers"]["Reply-To"] = [
            ["Real One", "real@phish.example"]
        ]
        report["parsed_sample"]["reply_to"] = [
            {"display_name": "Real One", "address": "real@phish.example"}
        ]
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(
                elastic_module._FailureReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_failure_report_to_elasticsearch(report)
        doc = mock_save.call_args.args[0]
        self.assertEqual(
            doc.sample.headers["reply-to"], "Real One <real@phish.example>"
        )
        self.assertEqual(
            [a.address for a in doc.sample.reply_to], ["real@phish.example"]
        )

    def test_reply_to_header_without_display_name_flattens_to_address(self):
        """A Reply-To header with no display name flattens to the bare
        address — the empty-display branch of the header flattening,
        matching the From/To handling."""
        report = _failure_report()
        report["parsed_sample"]["headers"]["Reply-To"] = [["", "noname@phish.example"]]
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(
                elastic_module._FailureReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_failure_report_to_elasticsearch(report)
        doc = mock_save.call_args.args[0]
        self.assertEqual(doc.sample.headers["reply-to"], "noname@phish.example")


# ---------------------------------------------------------------------------
# save_smtp_tls_report_to_elasticsearch
# ---------------------------------------------------------------------------


class TestSaveSmtpTlsReport(unittest.TestCase):
    def test_save_emits_one_document(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            save_smtp_tls_report_to_elasticsearch(_smtp_tls_report())
        mock_save.assert_called_once()

    def test_already_saved_raises_on_dedup_hit(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_populated_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            with self.assertRaises(AlreadySaved):
                save_smtp_tls_report_to_elasticsearch(_smtp_tls_report())
        mock_save.assert_not_called()

    def test_search_exception_wraps_to_elasticsearch_error(self):
        bad = MagicMock()
        bad.execute.side_effect = RuntimeError("network")
        with (
            patch("parsedmarc.elastic.Search", return_value=bad),
            patch("parsedmarc.elastic.Index"),
        ):
            with self.assertRaises(ElasticsearchError):
                save_smtp_tls_report_to_elasticsearch(_smtp_tls_report())

    def test_save_exception_wraps_to_elasticsearch_error(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(
                elastic_module._SMTPTLSReportDoc,
                "save",
                side_effect=RuntimeError("disk"),
            ),
        ):
            with self.assertRaises(ElasticsearchError):
                save_smtp_tls_report_to_elasticsearch(_smtp_tls_report())

    def test_index_name_uses_begin_date_for_monthly_partition(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch.object(elastic_module._SMTPTLSReportDoc, "save"),
        ):
            save_smtp_tls_report_to_elasticsearch(
                _smtp_tls_report(), monthly_indexes=True
            )
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("smtp_tls-2024-02", index_calls)

    def test_index_name_honours_suffix_and_prefix(self):
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index") as mock_index_cls,
            patch.object(elastic_module._SMTPTLSReportDoc, "save"),
        ):
            save_smtp_tls_report_to_elasticsearch(
                _smtp_tls_report(), index_suffix="t1", index_prefix="cust_"
            )
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("cust_smtp_tls_t1-2024-02-03", index_calls)

    def test_policy_without_strings_or_mx_patterns(self):
        """policy_strings / mx_host_patterns are optional in the
        report shape — verify the branch where they're absent."""
        report = _smtp_tls_report()
        for policy in report["policies"]:
            policy.pop("policy_strings", None)
            policy.pop("mx_host_patterns", None)
            policy.pop("failure_details", None)
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            save_smtp_tls_report_to_elasticsearch(report)
        mock_save.assert_called_once()

    def test_failure_details_all_optional_fields_populated(self):
        """Exercise every optional field in failure_details so the
        full set of `if "x" in failure_detail` branches runs."""
        report = _smtp_tls_report()
        report["policies"][0]["failure_details"] = [
            {
                "result_type": "certificate-expired",
                "failed_session_count": 1,
                "receiving_mx_hostname": "mx.example.com",
                "additional_information_uri": "https://example.com/why",
                "failure_reason_code": "ERR_CERT",
                "ip_address": "10.0.0.5",
                "receiving_ip": "10.0.0.2",
                "receiving_mx_helo": "mx.helo.example.com",
                "sending_mta_ip": "10.0.0.1",
            }
        ]
        with (
            patch("parsedmarc.elastic.Search", return_value=_empty_search()),
            patch("parsedmarc.elastic.Index"),
            patch.object(elastic_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            save_smtp_tls_report_to_elasticsearch(report)
        mock_save.assert_called_once()


class TestBackwardCompatAlias(unittest.TestCase):
    def test_save_forensic_alias_points_to_save_failure(self):
        self.assertIs(
            elastic_module.save_forensic_report_to_elasticsearch,
            elastic_module.save_failure_report_to_elasticsearch,
        )

    def test_forensic_doc_alias_points_to_failure_doc(self):
        self.assertIs(
            elastic_module._ForensicReportDoc, elastic_module._FailureReportDoc
        )
        self.assertIs(
            elastic_module._ForensicSampleDoc, elastic_module._FailureSampleDoc
        )


# Silence unused-import lint in the test module preamble.
_ = call


if __name__ == "__main__":
    unittest.main(verbosity=2)
