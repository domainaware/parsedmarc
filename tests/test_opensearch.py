"""Tests for parsedmarc.opensearch

Mocks at the opensearch-dsl SDK boundary (connections.create_connection,
Index, Search, Document.save, or a mock client registered as the
``default`` connection so the real Document.save runs) so the tests
verify the parsedmarc-side transformation logic — document
construction, index naming, deduplication queries, error wrapping —
without needing a running OpenSearch cluster.
"""

import copy
import json
import re
import time
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, call, patch

from opensearchpy import NotFoundError

import parsedmarc.opensearch as opensearch_module
from parsedmarc import (
    InvalidFailureReport,
    parse_aggregate_report_xml,
    parse_report_email,
    parse_report_file,
)
from parsedmarc.opensearch import (
    AlreadySaved,
    OpenSearchError,
    create_data_streams,
    create_indexes,
    migrate_indexes,
    save_aggregate_report_to_opensearch,
    save_failure_report_to_opensearch,
    save_smtp_tls_report_to_opensearch,
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
    """Verify the conn_params dict handed to opensearch-dsl
    matches each documented option. Each branch corresponds to a
    real-world deployment shape (TLS, basic auth, API key, custom CA)."""

    def test_single_host_string_normalized_to_list(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("https://es:9200")
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["https://es:9200"])

    def test_host_list_preserved(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts(["es1:9200", "es2:9200"])
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["hosts"], ["es1:9200", "es2:9200"])

    def test_debug_log_masks_credentials_but_connects_with_them(self):
        """GHSA-hjr3-rx4c-24cv: the "Connecting to OpenSearch" debug line
        must not carry the URL password, while the client still gets the
        real URL."""
        url = "https://admin:s3cretPW@es.example:9200"
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            with self.assertLogs("parsedmarc.log", level="DEBUG") as logs:
                set_hosts(url)
        output = "\n".join(logs.output)
        self.assertNotIn("s3cretPW", output)
        self.assertIn("https://admin:***@es.example:9200", output)
        self.assertEqual(mock_conn.call_args.kwargs["hosts"], [url])

    def test_debug_log_masks_schemeless_host_list(self):
        hosts = ["admin:s3cretPW@es1:9200", "es2:9200"]
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            with self.assertLogs("parsedmarc.log", level="DEBUG") as logs:
                set_hosts(hosts)
        output = "\n".join(logs.output)
        self.assertNotIn("s3cretPW", output)
        self.assertIn("admin:***@es1:9200", output)
        self.assertIn("es2:9200", output)
        self.assertEqual(mock_conn.call_args.kwargs["hosts"], hosts)

    def test_timeout_default_60s(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200")
        self.assertEqual(mock_conn.call_args.kwargs["timeout"], 60.0)

    def test_timeout_custom(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200", timeout=30.0)
        self.assertEqual(mock_conn.call_args.kwargs["timeout"], 30.0)

    def test_use_ssl_enables_verify_by_default(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200", use_ssl=True)
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["use_ssl"], True)
        self.assertEqual(kwargs["verify_certs"], True)
        self.assertNotIn("ca_certs", kwargs)

    def test_use_ssl_with_custom_ca(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200", use_ssl=True, ssl_cert_path="/etc/ca.pem")
        kwargs = mock_conn.call_args.kwargs
        self.assertEqual(kwargs["ca_certs"], "/etc/ca.pem")

    def test_skip_certificate_verification_sets_verify_false(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200", use_ssl=True, skip_certificate_verification=True)
        self.assertEqual(mock_conn.call_args.kwargs["verify_certs"], False)

    def test_username_password_sets_http_auth(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200", username="u", password="p")
        self.assertEqual(mock_conn.call_args.kwargs["http_auth"], ("u", "p"))

    def test_username_without_password_not_set(self):
        """Half-configured auth is suspicious enough not to send."""
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200", username="u")
        self.assertNotIn("http_auth", mock_conn.call_args.kwargs)

    def test_api_key_set(self):
        with patch("parsedmarc.opensearch.connections.create_connection") as mock_conn:
            set_hosts("es:9200", api_key="base64key==")
        self.assertEqual(mock_conn.call_args.kwargs["api_key"], "base64key==")

    def test_awssigv4_requires_aws_region(self):
        """SigV4 needs an AWS region to sign requests; missing it
        must fail loudly, not silently fall back to unsigned auth."""
        with self.assertRaises(OpenSearchError) as ctx:
            set_hosts("es.amazonaws.com:443", auth_type="awssigv4")
        self.assertIn("aws_region", str(ctx.exception))

    def test_awssigv4_uses_boto3_credentials_and_signer(self):
        """SigV4 path resolves AWS credentials via boto3 and wires
        an AWSV4SignerAuth into the connection params, plus the
        RequestsHttpConnection class required by the signer."""
        with (
            patch("parsedmarc.opensearch.boto3.Session") as mock_session,
            patch("parsedmarc.opensearch.AWSV4SignerAuth") as mock_signer,
            patch("parsedmarc.opensearch.connections.create_connection") as mock_conn,
        ):
            mock_session.return_value.get_credentials.return_value = MagicMock()
            set_hosts(
                "es.amazonaws.com:443",
                auth_type="awssigv4",
                aws_region="us-west-2",
            )
        kwargs = mock_conn.call_args.kwargs
        self.assertIs(kwargs["http_auth"], mock_signer.return_value)
        mock_signer.assert_called_once()
        # connection_class must be set so opensearch-py uses the
        # requests-based transport AWSV4SignerAuth requires.
        self.assertIn("connection_class", kwargs)

    def test_awssigv4_no_credentials_raises(self):
        """If boto3 can't find credentials, fail with a clear error
        rather than letting OpenSearch raise an opaque auth error later."""
        with patch("parsedmarc.opensearch.boto3.Session") as mock_session:
            mock_session.return_value.get_credentials.return_value = None
            with self.assertRaises(OpenSearchError) as ctx:
                set_hosts(
                    "es.amazonaws.com:443",
                    auth_type="awssigv4",
                    aws_region="us-west-2",
                )
        self.assertIn("credentials", str(ctx.exception).lower())

    def test_unsupported_auth_type_raises(self):
        with self.assertRaises(OpenSearchError) as ctx:
            set_hosts("es:9200", auth_type="kerberos")
        self.assertIn("Unsupported", str(ctx.exception))
        self.assertIn("kerberos", str(ctx.exception))


# ---------------------------------------------------------------------------
# create_indexes
# ---------------------------------------------------------------------------


class TestCreateIndexes(unittest.TestCase):
    def test_creates_missing_index_with_default_settings(self):
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_index_cls.return_value.exists.return_value = False
            create_indexes(["dmarc_aggregate-2024-01-15"])
        mock_get_conn.return_value.indices.create.assert_called_once_with(
            index="dmarc_aggregate-2024-01-15",
            body={"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
        )

    def test_creates_with_custom_settings(self):
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_index_cls.return_value.exists.return_value = False
            create_indexes(
                ["idx"], settings={"number_of_shards": 3, "refresh_interval": "5s"}
            )
        body = mock_get_conn.return_value.indices.create.call_args.kwargs["body"]
        self.assertEqual(
            body, {"settings": {"number_of_shards": 3, "refresh_interval": "5s"}}
        )

    def test_empty_settings_send_mappings_only(self):
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_index_cls.return_value.exists.return_value = False
            create_indexes(["idx"], settings={}, mappings={"date_detection": False})
        body = mock_get_conn.return_value.indices.create.call_args.kwargs["body"]
        self.assertEqual(body, {"mappings": {"date_detection": False}})

    def test_skips_existing_index(self):
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_index_cls.return_value.exists.return_value = True
            create_indexes(["idx"], mappings={"date_detection": False})
        mock_get_conn.return_value.indices.create.assert_not_called()
        mock_get_conn.return_value.indices.put_mapping.assert_not_called()

    def test_wraps_sdk_error(self):
        with patch("parsedmarc.opensearch.Index") as mock_index_cls:
            mock_index_cls.return_value.exists.side_effect = RuntimeError(
                "cluster down"
            )
            with self.assertRaises(OpenSearchError) as ctx:
                create_indexes(["idx"])
        self.assertIn("cluster down", str(ctx.exception))


# ---------------------------------------------------------------------------
# migrate_indexes
# ---------------------------------------------------------------------------


class TestMigrateIndexes(unittest.TestCase):
    """migrate_indexes backfills dkim_results_combined/spf_results_combined
    (issue #169) on pre-existing aggregate documents as a non-blocking
    background task. It is guarded by a cheap count() query so repeated
    startups against an already-backfilled index are a no-op, and any SDK
    error is caught and logged rather than raised, so it never blocks
    parsedmarc startup."""

    def test_backfill_submitted_when_old_docs_exist(self):
        with (
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = MagicMock()
            mock_client.count.return_value = {"count": 42}
            mock_get_conn.return_value = mock_client
            migrate_indexes(aggregate_indexes=["dmarc_aggregate"])

        mock_client.update_by_query.assert_called_once()
        kwargs = mock_client.update_by_query.call_args.kwargs
        self.assertEqual(kwargs["index"], "dmarc_aggregate*")
        self.assertEqual(kwargs["conflicts"], "proceed")
        self.assertFalse(kwargs["wait_for_completion"])
        self.assertEqual(
            kwargs["body"]["query"], opensearch_module._COMBINED_BACKFILL_QUERY
        )
        script_source = kwargs["body"]["script"]["source"]
        self.assertIn("ctx._source.dkim_results_combined", script_source)
        self.assertIn("ctx._source.spf_results_combined", script_source)

        # The count() guard query also targets the date-suffixed pattern.
        count_kwargs = mock_client.count.call_args.kwargs
        self.assertEqual(count_kwargs["index"], "dmarc_aggregate*")
        self.assertEqual(
            count_kwargs["body"]["query"], opensearch_module._COMBINED_BACKFILL_QUERY
        )

    def test_backfill_skipped_when_no_old_docs(self):
        with (
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = MagicMock()
            mock_client.count.return_value = {"count": 0}
            mock_get_conn.return_value = mock_client
            migrate_indexes(aggregate_indexes=["dmarc_aggregate"])

        mock_client.update_by_query.assert_not_called()

    def test_backfill_skipped_when_no_aggregate_indexes(self):
        with patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn:
            migrate_indexes()
            migrate_indexes(aggregate_indexes=None)

        mock_get_conn.assert_not_called()

    def test_backfill_failure_does_not_raise(self):
        with (
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = MagicMock()
            mock_client.count.side_effect = RuntimeError("cluster unreachable")
            mock_get_conn.return_value = mock_client
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                migrate_indexes(aggregate_indexes=["dmarc_aggregate"])

        self.assertTrue(any("cluster unreachable" in msg for msg in cm.output))
        mock_client.update_by_query.assert_not_called()

    def test_get_connection_failure_does_not_raise(self):
        """connections.get_connection() itself sits outside the per-index
        try/except for the combined-field backfill; if it raises (e.g. no
        OpenSearch connection has been configured yet), migrate_indexes must
        still not propagate the exception, per its docstring's promise that
        any cluster error is caught and logged."""
        with (
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_get_conn.side_effect = RuntimeError("no connection")
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                migrate_indexes(aggregate_indexes=["dmarc_aggregate"])

        self.assertTrue(
            any("Skipping the dkim_results_combined" in msg for msg in cm.output)
        )
        self.assertTrue(any("no connection" in msg for msg in cm.output))

    def test_smtp_tls_backfill_submitted_when_old_docs_exist(self):
        """SMTP TLS analogue of test_backfill_submitted_when_old_docs_exist:
        policies_combined/failure_details_combined backfill (also issue
        #169) is submitted with its own guard query and painless script."""
        with (
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = MagicMock()
            mock_client.count.return_value = {"count": 7}
            mock_get_conn.return_value = mock_client
            migrate_indexes(smtp_tls_indexes=["smtp_tls"])

        mock_client.update_by_query.assert_called_once()
        kwargs = mock_client.update_by_query.call_args.kwargs
        self.assertEqual(kwargs["index"], "smtp_tls*")
        self.assertEqual(kwargs["conflicts"], "proceed")
        self.assertFalse(kwargs["wait_for_completion"])
        self.assertEqual(
            kwargs["body"]["query"], opensearch_module._SMTP_TLS_COMBINED_BACKFILL_QUERY
        )
        script_source = kwargs["body"]["script"]["source"]
        self.assertIn("ctx._source.policies_combined", script_source)
        self.assertIn("ctx._source.failure_details_combined", script_source)

        count_kwargs = mock_client.count.call_args.kwargs
        self.assertEqual(count_kwargs["index"], "smtp_tls*")
        self.assertEqual(
            count_kwargs["body"]["query"],
            opensearch_module._SMTP_TLS_COMBINED_BACKFILL_QUERY,
        )

    def test_smtp_tls_backfill_skipped_when_no_old_docs(self):
        with (
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = MagicMock()
            mock_client.count.return_value = {"count": 0}
            mock_get_conn.return_value = mock_client
            migrate_indexes(smtp_tls_indexes=["smtp_tls"])

        mock_client.update_by_query.assert_not_called()

    def test_smtp_tls_backfill_skipped_when_no_smtp_tls_indexes_or_aggregate(self):
        with patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn:
            migrate_indexes()
            migrate_indexes(smtp_tls_indexes=None)

        mock_get_conn.assert_not_called()

    def test_smtp_tls_backfill_failure_does_not_raise(self):
        """SMTP TLS analogue of test_backfill_failure_does_not_raise: an
        error from the cluster during the smtp_tls_indexes loop is caught
        and logged rather than raised."""
        with (
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = MagicMock()
            mock_client.count.side_effect = RuntimeError("cluster unreachable")
            mock_get_conn.return_value = mock_client
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                migrate_indexes(smtp_tls_indexes=["smtp_tls"])

        self.assertTrue(any("cluster unreachable" in msg for msg in cm.output))
        mock_client.update_by_query.assert_not_called()


def _typeless_fo_mapping(index_name, fo_type):
    """An indices.get_field_mapping response in the modern, typeless shape.

    OpenSearch has no mapping types, so the field sits directly under
    ``mappings``. This is the only shape a real cluster returns; the
    ES 6-era type-keyed shape is covered separately.
    """
    return {
        index_name: {
            "mappings": {
                "published_policy.fo": {
                    "full_name": "published_policy.fo",
                    "mapping": {"fo": {"type": fo_type}},
                }
            }
        }
    }


class TestMigrateIndexesFoMigration(unittest.TestCase):
    """parsedmarc releases before 5.0.0 declared published_policy.fo as an
    integer, so their indexes mapped it as `long`, which cannot hold the
    multi-value `fo` settings reports carry (`0:1`, `d:s`). migrate_indexes
    detects that and rebuilds the index with the text/keyword shape.

    These tests drive the modern typeless get_field_mapping response.
    Until this was fixed, the code read the response in the Elasticsearch
    6-era mapping-type-keyed shape, which no OpenSearch cluster returns —
    so the migration could never run against a real cluster even though
    tests using the old shape passed. Each test stubs the combined-field
    backfill that runs afterwards in the same call (count 0 → no-op)."""

    @staticmethod
    def _noop_backfill_client():
        client = MagicMock()
        client.count.return_value = {"count": 0}
        return client

    @staticmethod
    def _index_mocks(*, v2_exists):
        """Distinct Index() mocks per name, so the original and the -v2
        target can be told apart. A single shared mock cannot express
        "the original exists but its migration target does not", which is
        the ordinary case."""
        original = MagicMock(name="dmarc_aggregate")
        original.exists.return_value = True
        original.get_field_mapping.return_value = _typeless_fo_mapping(
            "dmarc_aggregate", "long"
        )
        v2 = MagicMock(name="dmarc_aggregate-v2")
        v2.exists.return_value = v2_exists
        return original, v2, lambda name: v2 if name.endswith("-v2") else original

    def test_skips_non_existent_index(self):
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_get_conn.return_value = self._noop_backfill_client()
            mock_index_cls.return_value.exists.return_value = False
            migrate_indexes(legacy_fo_indexes=["missing"])
        # exists() returned False — no field_mapping fetch.
        mock_index_cls.return_value.get_field_mapping.assert_not_called()

    def test_skips_when_field_is_unmapped(self):
        """An index that does not map published_policy.fo at all (e.g. an
        empty index with the default mapping) is left alone."""
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
            patch("parsedmarc.opensearch.reindex") as mock_reindex,
        ):
            mock_get_conn.return_value = self._noop_backfill_client()
            idx = mock_index_cls.return_value
            idx.exists.return_value = True
            idx.get_field_mapping.return_value = {"dmarc_aggregate": {"mappings": {}}}
            migrate_indexes(legacy_fo_indexes=["dmarc_aggregate"])
        mock_reindex.assert_not_called()
        idx.create.assert_not_called()
        idx.delete.assert_not_called()

    def test_migrates_when_fo_is_long(self):
        """The actual migration path: when fo is mapped as 'long', a v2
        index is created with the corrected text/keyword mapping, data is
        reindexed into it, and the old index is deleted."""
        original, v2, factory = self._index_mocks(v2_exists=False)
        with (
            patch("parsedmarc.opensearch.Index", side_effect=factory) as mock_index_cls,
            patch("parsedmarc.opensearch.reindex") as mock_reindex,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = self._noop_backfill_client()
            mock_get_conn.return_value = mock_client
            migrate_indexes(legacy_fo_indexes=["dmarc_aggregate"])

        self.assertIn(call("dmarc_aggregate-v2"), mock_index_cls.call_args_list)
        v2.create.assert_called_once_with()
        mapping_kwargs = v2.put_mapping.call_args.kwargs
        self.assertNotIn("doc_type", mapping_kwargs)
        self.assertEqual(
            mapping_kwargs["body"]["properties"]["published_policy"]["properties"][
                "fo"
            ],
            {
                "type": "text",
                "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
            },
        )

        # reindex old -> new (v2) with the connection's client, and only
        # then is the original dropped. The v2 index is never deleted here:
        # nothing was left over to discard.
        mock_reindex.assert_called_once_with(
            mock_client, "dmarc_aggregate", "dmarc_aggregate-v2"
        )
        original.delete.assert_called_once_with()
        v2.delete.assert_not_called()

    def test_retries_after_an_interrupted_earlier_attempt(self):
        """A run that died between create() and delete() leaves a -v2 index
        behind. Reaching this code means the original still holds the data
        -- it is deleted only after the reindex succeeds -- so the leftover
        is debris. Without discarding it, create() raises "resource already
        exists" on every later startup and the index is never migrated;
        confirmed against a live cluster, where the unfixed code left the
        original in place and the debris document in the v2 index."""
        original, v2, factory = self._index_mocks(v2_exists=True)
        with (
            patch("parsedmarc.opensearch.Index", side_effect=factory),
            patch("parsedmarc.opensearch.reindex") as mock_reindex,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_client = self._noop_backfill_client()
            mock_get_conn.return_value = mock_client
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                migrate_indexes(legacy_fo_indexes=["dmarc_aggregate"])

        self.assertTrue(
            any("Discarding dmarc_aggregate-v2" in msg for msg in cm.output)
        )
        # The stale target is dropped, then recreated, and the migration
        # runs to completion instead of aborting on "already exists".
        v2.delete.assert_called_once_with()
        v2.create.assert_called_once_with()
        mock_reindex.assert_called_once_with(
            mock_client, "dmarc_aggregate", "dmarc_aggregate-v2"
        )
        original.delete.assert_called_once_with()

    def test_migrates_when_fo_is_long_under_a_mapping_type(self):
        """The Elasticsearch 6-era response nested the field under the
        mapping type name. No cluster either client can connect to still
        reports mappings that way, so this covers the fallback branch
        rather than a reachable deployment -- but the branch is what lets
        the type check stay a check on the mapped type instead of on the
        response shape, which is what broke this migration before."""
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.reindex") as mock_reindex,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_get_conn.return_value = self._noop_backfill_client()
            idx = mock_index_cls.return_value
            idx.exists.return_value = True
            idx.get_field_mapping.return_value = {
                "dmarc_aggregate": {
                    "mappings": {
                        "doc": {
                            "published_policy.fo": {"mapping": {"fo": {"type": "long"}}}
                        }
                    }
                }
            }
            migrate_indexes(legacy_fo_indexes=["dmarc_aggregate"])
        mock_reindex.assert_called_once()

    def test_skips_when_fo_already_text(self):
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
            patch("parsedmarc.opensearch.reindex") as mock_reindex,
        ):
            mock_get_conn.return_value = self._noop_backfill_client()
            idx = mock_index_cls.return_value
            idx.exists.return_value = True
            idx.get_field_mapping.return_value = _typeless_fo_mapping(
                "dmarc_aggregate", "text"
            )
            migrate_indexes(legacy_fo_indexes=["dmarc_aggregate"])
        mock_reindex.assert_not_called()
        idx.create.assert_not_called()
        idx.delete.assert_not_called()

    def test_index_exists_failure_does_not_raise(self):
        """A cluster error inside the per-index fo-migration loop (e.g.
        Index(...).exists() raising because the cluster is unreachable)
        must not abort startup: it is caught, logged, and the loop moves
        on to the combined-field backfill, which is exercised here with
        its own connection failure so both warnings are asserted."""
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_index_cls.return_value.exists.side_effect = ConnectionError(
                "cluster unreachable"
            )
            mock_get_conn.side_effect = RuntimeError("no connection")
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                migrate_indexes(
                    aggregate_indexes=["dmarc_aggregate"],
                    legacy_fo_indexes=["dmarc_aggregate"],
                )

        self.assertTrue(
            any(
                "legacy published_policy.fo migration" in msg
                and "cluster unreachable" in msg
                for msg in cm.output
            )
        )
        self.assertTrue(
            any("Skipping the dkim_results_combined" in msg for msg in cm.output)
        )
        self.assertTrue(any("no connection" in msg for msg in cm.output))

    def test_no_legacy_indexes_means_no_lookup(self):
        """The combined-field backfill must not drag the fo migration
        along: passing only aggregate_indexes leaves the legacy loop
        untouched, so a modern deployment never probes for it."""
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
        ):
            mock_get_conn.return_value = self._noop_backfill_client()
            migrate_indexes(aggregate_indexes=["dmarc_aggregate"])
        mock_index_cls.return_value.exists.assert_not_called()


# ---------------------------------------------------------------------------
# save_aggregate_report_to_opensearch
# ---------------------------------------------------------------------------


class TestSaveAggregateReport(unittest.TestCase):
    """The aggregate-report save fans out across multiple SDK calls:
    Search (for dedup), Index.create (for the daily/monthly index),
    Document.save. Each test patches the boundary it needs and
    leaves the rest alone."""

    def _patches(self, search_factory=_empty_search):
        return [
            patch("parsedmarc.opensearch.Search", return_value=search_factory()),
            patch(
                "parsedmarc.opensearch.Index",
                return_value=MagicMock(exists=MagicMock(return_value=True)),
            ),
            patch.object(opensearch_module._AggregateReportDoc, "save"),
        ]

    def test_save_emits_one_document_per_record(self):
        report = _aggregate_report()
        report["records"].append(report["records"][0].copy())
        patches = self._patches()
        with patches[0], patches[1], patches[2] as mock_save:
            save_aggregate_report_to_opensearch(report)
        # Two records → two saves.
        self.assertEqual(mock_save.call_count, 2)

    def test_already_saved_raises_when_search_returns_hit(self):
        """The dedup query is the only thing preventing
        double-indexing on re-run. A regression would silently
        re-save reports, inflating dashboard counts."""
        with (
            patch("parsedmarc.opensearch.Search", return_value=_populated_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._AggregateReportDoc, "save") as mock_save,
        ):
            with self.assertRaises(AlreadySaved):
                save_aggregate_report_to_opensearch(_aggregate_report())
        mock_save.assert_not_called()

    def test_search_exception_wraps_to_opensearch_error(self):
        bad_search = MagicMock()
        bad_search.execute.side_effect = RuntimeError("network")
        with (
            patch("parsedmarc.opensearch.Search", return_value=bad_search),
            patch("parsedmarc.opensearch.Index"),
        ):
            with self.assertRaises(OpenSearchError) as ctx:
                save_aggregate_report_to_opensearch(_aggregate_report())
        self.assertIn("network", str(ctx.exception))

    def test_save_exception_wraps_to_opensearch_error(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._AggregateReportDoc,
                "save",
                side_effect=RuntimeError("disk"),
            ),
        ):
            with self.assertRaises(OpenSearchError) as ctx:
                save_aggregate_report_to_opensearch(_aggregate_report())
        self.assertIn("disk", str(ctx.exception))

    def test_index_name_uses_daily_format_by_default(self):
        """Index naming: dmarc_aggregate-YYYY-MM-DD by default."""
        index_calls = []
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch.object(opensearch_module._AggregateReportDoc, "save"),
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_opensearch(_aggregate_report())
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("dmarc_aggregate-2024-01-15", index_calls)

    def test_index_name_uses_monthly_format_when_flag_set(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch.object(opensearch_module._AggregateReportDoc, "save"),
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_opensearch(
                _aggregate_report(), monthly_indexes=True
            )
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("dmarc_aggregate-2024-01", index_calls)

    def test_index_name_honours_suffix_and_prefix(self):
        """Prefix/suffix support multi-tenant setups where one
        OpenSearch cluster serves several DMARC owners."""
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch.object(opensearch_module._AggregateReportDoc, "save"),
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_opensearch(
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
            patch("parsedmarc.opensearch.Search") as mock_search_cls,
            patch(
                "parsedmarc.opensearch.Index",
                return_value=MagicMock(exists=MagicMock(return_value=True)),
            ),
            patch.object(opensearch_module._AggregateReportDoc, "save"),
        ):
            mock_search_cls.return_value.execute.return_value = []
            save_aggregate_report_to_opensearch(
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch._AggregateReportDoc") as mock_doc_cls,
        ):
            mock_index_cls.return_value.exists.return_value = True
            save_aggregate_report_to_opensearch(_aggregate_report())
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch(
                "parsedmarc.opensearch.Index",
                return_value=MagicMock(exists=MagicMock(return_value=True)),
            ),
            patch.object(
                opensearch_module._AggregateReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_aggregate_report_to_opensearch(report)
        doc = mock_save.call_args[0][0]
        self.assertEqual(
            list(doc.dkim_results_combined),
            ["net1 / example.net / fail", "org1 / example.org / pass"],
        )
        self.assertEqual(list(doc.spf_results_combined), ["mfrom / example.org / pass"])


class TestAggregateDocPassedDmarc(unittest.TestCase):
    """The _AggregateReportDoc.save() override derives passed_dmarc — the
    field dashboards filter on for DMARC pass/fail — from SPF/DKIM
    alignment. The SDK parent (opensearchpy.Document.save) is mocked so
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
                    opensearch_module.Document, "save", return_value=None
                ) as mock_super_save:
                    doc = opensearch_module._AggregateReportDoc(
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
        arrays of objects that the engine dynamic-maps as plain ``object``
        (not ``nested``) and flattens, so OpenSearch Dashboards/Grafana
        tables cannot terms-aggregate their subfields without producing a
        cross-product of selector/domain/result values. The composed
        "selector / domain / result" string preserves the per-signature
        pairing that the flattened array loses."""
        doc = opensearch_module._AggregateReportDoc()
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
        # set.
        self.assertEqual(list(doc.dkim_results_combined), expected)  # pyright: ignore[reportArgumentType]
        self.assertEqual(doc.to_dict()["dkim_results_combined"], expected)

    def test_add_spf_result_appends_combined_string(self):
        doc = opensearch_module._AggregateReportDoc()
        doc.add_spf_result(
            domain="example.org", scope="mfrom", result="pass", human_result=None
        )
        expected = ["mfrom / example.org / pass"]
        self.assertEqual(list(doc.spf_results_combined), expected)  # pyright: ignore[reportArgumentType]
        self.assertEqual(doc.to_dict()["spf_results_combined"], expected)

    def test_spf_result_serializes_under_singular_result_key(self):
        """The _SPFResult class previously declared a dead ``results``
        (plural) field while the save path wrote ``result``; verify the
        serialized inner doc actually uses the singular key."""
        doc = opensearch_module._AggregateReportDoc()
        doc.add_spf_result(
            domain="example.org", scope="mfrom", result="pass", human_result=None
        )
        d = doc.to_dict()["spf_results"][0]
        self.assertEqual(d["result"], "pass")
        self.assertNotIn("results", d)


# ---------------------------------------------------------------------------
# save_failure_report_to_opensearch
# ---------------------------------------------------------------------------


class TestSaveFailureReport(unittest.TestCase):
    def test_save_emits_one_document(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save") as mock_save,
        ):
            save_failure_report_to_opensearch(_failure_report())
        mock_save.assert_called_once()

    def test_already_saved_raises_on_dedup_hit(self):
        """Failure-report dedup uses arrival_date + From/To/Subject
        from the parsed sample. A hit means we've already indexed
        this exact failure sample."""
        with (
            patch("parsedmarc.opensearch.Search", return_value=_populated_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save") as mock_save,
        ):
            with self.assertRaises(AlreadySaved):
                save_failure_report_to_opensearch(_failure_report())
        mock_save.assert_not_called()

    def test_save_exception_wraps_to_opensearch_error(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._FailureReportDoc,
                "save",
                side_effect=RuntimeError("disk"),
            ),
        ):
            with self.assertRaises(OpenSearchError) as ctx:
                save_failure_report_to_opensearch(_failure_report())
        self.assertIn("disk", str(ctx.exception))

    def test_search_exception_wraps_to_opensearch_error(self):
        """The duplicate check's search failing is a OpenSearchError, as it is for
        the aggregate and SMTP TLS saves, not the search library's own error."""
        bad_search = MagicMock()
        bad_search.execute.side_effect = RuntimeError("network")
        with (
            patch("parsedmarc.opensearch.Search", return_value=bad_search),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save") as mock_save,
        ):
            with self.assertRaises(OpenSearchError) as ctx:
                save_failure_report_to_opensearch(_failure_report())
        self.assertIn("network", str(ctx.exception))
        mock_save.assert_not_called()

    def test_keyerror_wraps_to_invalid_failure_report(self):
        """A malformed failure report (missing a required field) is
        surfaced as InvalidFailureReport so the caller can route it
        differently from infra errors."""
        report = _failure_report()
        del report["feedback_type"]
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save"),
        ):
            with self.assertRaises(InvalidFailureReport):
                save_failure_report_to_opensearch(report)

    def test_index_dedup_pattern_searches_both_old_and_new_names(self):
        """The split-PR rename forensic→failure left existing data
        in dmarc_forensic*; the dedup search must check both names
        so re-runs don't double-index."""
        with (
            patch("parsedmarc.opensearch.Search") as mock_search_cls,
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save"),
        ):
            mock_search_cls.return_value.execute.return_value = []
            save_failure_report_to_opensearch(_failure_report())
        search_index = mock_search_cls.call_args.kwargs["index"]
        self.assertIn("dmarc_failure*", search_index)
        self.assertIn("dmarc_forensic*", search_index)

    def test_index_name_uses_arrival_date_for_monthly_partition(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch.object(opensearch_module._FailureReportDoc, "save"),
        ):
            save_failure_report_to_opensearch(_failure_report(), monthly_indexes=True)
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch("parsedmarc.opensearch._FailureReportDoc") as mock_doc_cls,
        ):
            save_failure_report_to_opensearch(_failure_report())
        # Fixture arrival_date_utc is 2024-01-01 00:00:00 UTC.
        self.assertEqual(mock_doc_cls.call_args.kwargs["arrival_date"], 1704067200000)

    def test_failure_search_index_with_suffix_and_prefix(self):
        """When both suffix and prefix are set, the dedup search
        pattern joins them onto BOTH dmarc_failure* and
        dmarc_forensic* (the rename back-compat)."""
        with (
            patch("parsedmarc.opensearch.Search") as mock_search_cls,
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save"),
        ):
            mock_search_cls.return_value.execute.return_value = []
            save_failure_report_to_opensearch(
                _failure_report(),
                index_suffix="tenant_a",
                index_prefix="cust_",
            )
        search_index = mock_search_cls.call_args.kwargs["index"]
        self.assertIn("cust_dmarc_failure_tenant_a*", search_index)
        self.assertIn("cust_dmarc_forensic_tenant_a*", search_index)

    def test_failure_index_honours_suffix_and_prefix(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch.object(opensearch_module._FailureReportDoc, "save"),
        ):
            save_failure_report_to_opensearch(
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save") as mock_save,
        ):
            save_failure_report_to_opensearch(report)
        mock_save.assert_called_once()

    def test_to_header_with_non_empty_display_joins_with_brackets(self):
        """The other branch: non-empty display joins display+addr
        with " <" and appends ">", e.g. 'RT <rcpt@example.com>'.
        Asserts the joined string actually reaches the saved document
        (see test_reply_to_header_flattened_and_indexed for the
        autospec-save pattern), not merely that save ran."""
        report = _failure_report()
        report["parsed_sample"]["headers"]["To"] = [["RT", "rcpt@example.com"]]
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._FailureReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_failure_report_to_opensearch(report)
        mock_save.assert_called_once()
        doc = mock_save.call_args.args[0]
        self.assertEqual(doc.sample.headers["to"], "RT <rcpt@example.com>")

    def test_sample_address_lists_indexed_for_reply_to_cc_bcc_attachments(self):
        """A failure report sample can carry reply_to / cc / bcc /
        attachments. Each populates a nested InnerDoc on the sample;
        this drives all four add_* helper paths (nested-doc contents
        are asserted separately in
        test_reply_to_header_flattened_and_indexed)."""
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._FailureReportDoc, "save") as mock_save,
        ):
            save_failure_report_to_opensearch(report)
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._FailureReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_failure_report_to_opensearch(report)
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._FailureReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_failure_report_to_opensearch(report)
        doc = mock_save.call_args.args[0]
        self.assertEqual(doc.sample.headers["reply-to"], "noname@phish.example")


# ---------------------------------------------------------------------------
# save_smtp_tls_report_to_opensearch
# ---------------------------------------------------------------------------


class TestSaveSmtpTlsReport(unittest.TestCase):
    def test_save_emits_one_document(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            save_smtp_tls_report_to_opensearch(_smtp_tls_report())
        mock_save.assert_called_once()

    def test_already_saved_raises_on_dedup_hit(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_populated_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            with self.assertRaises(AlreadySaved):
                save_smtp_tls_report_to_opensearch(_smtp_tls_report())
        mock_save.assert_not_called()

    def test_search_exception_wraps_to_opensearch_error(self):
        bad = MagicMock()
        bad.execute.side_effect = RuntimeError("network")
        with (
            patch("parsedmarc.opensearch.Search", return_value=bad),
            patch("parsedmarc.opensearch.Index"),
        ):
            with self.assertRaises(OpenSearchError):
                save_smtp_tls_report_to_opensearch(_smtp_tls_report())

    def test_save_exception_wraps_to_opensearch_error(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._SMTPTLSReportDoc,
                "save",
                side_effect=RuntimeError("disk"),
            ),
        ):
            with self.assertRaises(OpenSearchError):
                save_smtp_tls_report_to_opensearch(_smtp_tls_report())

    def test_index_name_uses_begin_date_for_monthly_partition(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch.object(opensearch_module._SMTPTLSReportDoc, "save"),
        ):
            save_smtp_tls_report_to_opensearch(_smtp_tls_report(), monthly_indexes=True)
            index_calls = [c.args[0] for c in mock_index_cls.call_args_list]
        self.assertIn("smtp_tls-2024-02", index_calls)

    def test_index_name_honours_suffix_and_prefix(self):
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch.object(opensearch_module._SMTPTLSReportDoc, "save"),
        ):
            save_smtp_tls_report_to_opensearch(
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            save_smtp_tls_report_to_opensearch(report)
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
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(opensearch_module._SMTPTLSReportDoc, "save") as mock_save,
        ):
            save_smtp_tls_report_to_opensearch(report)
        mock_save.assert_called_once()

    def test_save_populates_combined_policy_and_failure_detail_fields(self):
        """Regression guard for the SMTP TLS analogue of issue #169:
        policies and their failure_details are object arrays, so stacked
        terms aggregations on their subfields cross-product just like
        dkim_results/spf_results did. Two policies (one with two failure
        details, one with none) must yield exactly two policies_combined
        entries and two failure_details_combined entries, not a
        cross-product. autospec=True is required on the save patch so
        mock_save.call_args captures the doc instance as ``self``."""
        report = _smtp_tls_report(
            policies=[
                {
                    "policy_domain": "example.com",
                    "policy_type": "sts",
                    "successful_session_count": 100,
                    "failed_session_count": 2,
                    "failure_details": [
                        {
                            "result_type": "certificate-expired",
                            "failed_session_count": 1,
                            "sending_mta_ip": "192.0.2.1",
                            "receiving_ip": "203.0.113.1",
                            "receiving_mx_hostname": "mx1.example.com",
                            "additional_info_uri": (
                                "https://reports.example.com/tls-help"
                            ),
                        },
                        {
                            "result_type": "starttls-not-supported",
                            "failed_session_count": 1,
                            "sending_mta_ip": "192.0.2.2",
                            "receiving_ip": "203.0.113.2",
                            "receiving_mx_hostname": "mx2.example.com",
                        },
                    ],
                },
                {
                    "policy_domain": "example.net",
                    "policy_type": "tlsa",
                    "successful_session_count": 50,
                    "failed_session_count": 0,
                },
            ]
        )
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._SMTPTLSReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_smtp_tls_report_to_opensearch(report)
        doc = mock_save.call_args[0][0]
        self.assertEqual(
            list(doc.policies_combined), ["example.com / sts", "example.net / tlsa"]
        )
        expected_detail_expired = (
            "example.com / sts / certificate-expired / 192.0.2.1 / "
            "203.0.113.1 / mx1.example.com"
        )
        expected_detail_starttls = (
            "example.com / sts / starttls-not-supported / 192.0.2.2 / "
            "203.0.113.2 / mx2.example.com"
        )
        self.assertEqual(
            list(doc.failure_details_combined),
            [expected_detail_expired, expected_detail_starttls],
        )
        # The parser emits additional_info_uri (SMTPTLSFailureDetailsOptional
        # in types.py); the saver must persist it on the declared
        # additional_information_uri field rather than dropping it.
        self.assertEqual(
            doc.policies[0].failure_details[0].additional_information_uri,
            "https://reports.example.com/tls-help",
        )

    def test_save_blank_failure_detail_fields_omitted_from_ip_fields(self):
        """Blank optional failure-detail fields must not reach the Ip()
        fields (issue #915).

        samples/smtp_tls/empty_failure_detail_fields.json reproduces a
        real reporter's shape: sending-mta-ip/receiving-ip sent as "" on
        an sts-policy-fetch-error. Verified directly against opensearchpy:
        Document.save() validates by calling full_clean() before any
        network call, and an Ip() field's
        validation calls Python's ipaddress.ip_address(""), which raises
        a bare ValueError ("'' does not appear to be an IPv4 or IPv6
        address") rather than a caught ValidationException -- so an empty
        string here previously discarded the whole report instead of
        indexing it with a blank IP.

        save() is mocked (per this module's convention, so no real
        cluster is needed), which also means it never runs full_clean()
        itself; call it explicitly on the captured document so this test
        exercises the same validation a real save() would, and fails with
        that ValueError on unfixed parsedmarc/__init__.py.
        """
        result = parse_report_file(
            "samples/smtp_tls/empty_failure_detail_fields.json", offline=True
        )
        report = cast(dict, result["report"])
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._SMTPTLSReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_smtp_tls_report_to_opensearch(report)
        doc = mock_save.call_args[0][0]
        doc.full_clean()
        failure_detail = doc.policies[0].failure_details[0]
        self.assertIsNone(failure_detail.sending_mta_ip)
        self.assertIsNone(failure_detail.receiving_ip)
        self.assertEqual(failure_detail.failure_reason_code, "no-policy-served")


# ---------------------------------------------------------------------------
# Data streams (issue #842)
# ---------------------------------------------------------------------------


def _not_found() -> NotFoundError:
    """The exception opensearch-py raises for an HTTP 404."""
    return NotFoundError(404, "index_not_found_exception", {})


def _stream_listing(*names: str) -> dict:
    """A GET _data_stream/<name> response body listing *names*."""
    return {"data_streams": [{"name": name} for name in names]}


@contextmanager
def _registered_client() -> Iterator[MagicMock]:
    """Register a mock client as the ``default`` connection.

    Both ``create_data_streams`` and ``Document.save`` resolve the client
    through the connection registry, so registering the mock there (rather
    than patching either function) lets the real save path run and the test
    read what reached the transport. The previous registration is put back
    afterwards.
    """
    client = MagicMock()
    client.index.return_value = {"_index": "x", "_id": "1", "result": "created"}
    try:
        previous = opensearch_module.connections.get_connection("default")
    except KeyError:
        previous = None
    opensearch_module.connections.add_connection("default", client)
    try:
        yield client
    finally:
        if previous is None:
            opensearch_module.connections.remove_connection("default")
        else:
            opensearch_module.connections.add_connection("default", previous)


class _DataStreamTestCase(unittest.TestCase):
    """Isolates each test from the module's data stream memo."""

    def setUp(self):
        opensearch_module._READY_DATA_STREAMS.clear()

    def tearDown(self):
        opensearch_module._READY_DATA_STREAMS.clear()


class TestCreateDataStreams(_DataStreamTestCase):
    def test_creates_template_and_stream_when_missing(self):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = False
            create_data_streams(
                ["dmarc_aggregate"],
                {"number_of_shards": 2, "number_of_replicas": 1},
            )
        template_call = client.indices.put_index_template.call_args.kwargs
        self.assertEqual(template_call["name"], "dmarc_aggregate")
        body = template_call["body"]
        # Exact name, no wildcard: the template must never claim the
        # date-suffixed indexes written without data streams.
        self.assertEqual(body["index_patterns"], ["dmarc_aggregate"])
        self.assertEqual(body["data_stream"], {})
        self.assertEqual(body["priority"], 501)
        self.assertNotIn("composed_of", body)
        self.assertEqual(
            body["template"],
            {
                "settings": {"number_of_shards": 2, "number_of_replicas": 1},
                "mappings": {"properties": {"@timestamp": {"type": "date"}}},
            },
        )
        self.assertIn("ism_template", body["_meta"]["description"])
        client.indices.create_data_stream.assert_called_once_with(
            name="dmarc_aggregate"
        )
        # No concrete index is created for a stream.
        client.indices.create.assert_not_called()
        self.assertIn("dmarc_aggregate", opensearch_module._READY_DATA_STREAMS)

    def test_default_settings_are_one_shard_no_replicas(self):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = False
            create_data_streams(["smtp_tls"])
        settings = client.indices.put_index_template.call_args.kwargs["body"][
            "template"
        ]["settings"]
        self.assertEqual(settings, {"number_of_shards": 1, "number_of_replicas": 0})

    def test_existing_stream_gets_template_but_is_not_recreated(self):
        """The template is put again so that settings changes reach the
        next backing index; the stream itself already exists."""
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.return_value = _stream_listing(
                "dmarc_failure"
            )
            create_data_streams(["dmarc_failure"])
        client.indices.put_index_template.assert_called_once()
        client.indices.create_data_stream.assert_not_called()
        mock_index_cls.return_value.exists.assert_not_called()
        self.assertIn("dmarc_failure", opensearch_module._READY_DATA_STREAMS)

    def test_concrete_index_holding_the_name_raises_without_writing(self):
        """OpenSearch 3 answers GET _data_stream/<name> for a name held by
        a concrete index with a 404, so the Index.exists() check is what
        catches it, before anything is written. Writing to that name would
        otherwise go into the old undated index, such as one left by a
        pre-5.0.0 release."""
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = True
            with self.assertRaises(OpenSearchError) as ctx:
                create_data_streams(["dmarc_aggregate"])
        mock_index_cls.assert_called_with("dmarc_aggregate")
        self.assertIn("already exists", str(ctx.exception))
        self.assertIn("dmarc_aggregate", str(ctx.exception))
        client.indices.put_index_template.assert_not_called()
        client.indices.create_data_stream.assert_not_called()
        self.assertNotIn("dmarc_aggregate", opensearch_module._READY_DATA_STREAMS)

    def test_empty_listing_is_not_taken_as_an_existing_stream(self):
        """Elasticsearch answers a name held by a concrete index with 200
        and an empty list; the shared logic must not read that as "the
        stream exists" if an OpenSearch release ever does the same."""
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.return_value = _stream_listing()
            mock_index_cls.return_value.exists.return_value = True
            with self.assertRaises(OpenSearchError):
                create_data_streams(["smtp_tls"])
        client.indices.put_index_template.assert_not_called()
        client.indices.create_data_stream.assert_not_called()

    def test_ready_stream_is_not_set_up_again(self):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = False
            create_data_streams(["dmarc_aggregate"])
            create_data_streams(["dmarc_aggregate"])
        self.assertEqual(client.indices.get_data_stream.call_count, 1)
        self.assertEqual(client.indices.put_index_template.call_count, 1)
        self.assertEqual(client.indices.create_data_stream.call_count, 1)

    def test_set_hosts_forgets_ready_streams(self):
        """A new connection may be a different cluster or carry new index
        settings, so the template has to be put again."""
        opensearch_module._READY_DATA_STREAMS.add("dmarc_aggregate")
        with patch("parsedmarc.opensearch.connections.create_connection"):
            set_hosts("os:9200")
        self.assertEqual(opensearch_module._READY_DATA_STREAMS, set())

    def test_sdk_error_is_wrapped_and_retried_next_time(self):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = False
            client.indices.put_index_template.side_effect = RuntimeError("cluster down")
            with self.assertRaises(OpenSearchError) as ctx:
                create_data_streams(["dmarc_aggregate"])
            self.assertIn("cluster down", str(ctx.exception))
            self.assertNotIn("dmarc_aggregate", opensearch_module._READY_DATA_STREAMS)
            client.indices.create_data_stream.assert_not_called()

            client.indices.put_index_template.side_effect = None
            create_data_streams(["dmarc_aggregate"])
        client.indices.create_data_stream.assert_called_once_with(
            name="dmarc_aggregate"
        )
        self.assertIn("dmarc_aggregate", opensearch_module._READY_DATA_STREAMS)


class TestSaveToDataStreams(_DataStreamTestCase):
    """Each save function, run through the real Document.save() into a
    mock client: in stream mode the document goes to the undated name
    with op_type=create and an @timestamp; in the default mode it goes to
    the dated index as before, with the same op_type and @timestamp."""

    def _save(self, save_function, report, **kwargs):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Search") as mock_search_cls,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            mock_search_cls.return_value.execute.return_value = []
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = False
            save_function(report, **kwargs)
        return client, mock_search_cls, mock_index_cls

    def test_aggregate_report_goes_to_the_stream(self):
        client, mock_search_cls, mock_index_cls = self._save(
            save_aggregate_report_to_opensearch,
            _aggregate_report(),
            index_prefix="cust_",
            index_suffix="tenant_a",
            # Ignored in stream mode.
            monthly_indexes=True,
            use_data_streams=True,
        )
        index_call = client.index.call_args.kwargs
        self.assertEqual(index_call["index"], "cust_dmarc_aggregate_tenant_a")
        self.assertEqual(index_call["op_type"], "create")
        self.assertEqual(
            index_call["body"]["@timestamp"],
            datetime(2024, 1, 15, tzinfo=timezone.utc),
        )
        self.assertEqual(index_call["body"]["report_id"], "agg-1")
        self.assertEqual(
            client.indices.put_index_template.call_args.kwargs["body"][
                "index_patterns"
            ],
            ["cust_dmarc_aggregate_tenant_a"],
        )
        client.indices.create_data_stream.assert_called_once_with(
            name="cust_dmarc_aggregate_tenant_a"
        )
        client.indices.create.assert_not_called()
        # The dedup search still uses the wildcard, which matches the
        # stream as well as dated indexes written before the switch.
        self.assertEqual(
            mock_search_cls.call_args.kwargs["index"],
            "cust_dmarc_aggregate_tenant_a*",
        )

    def test_aggregate_report_dated_mode_unchanged_apart_from_timestamp_and_op_type(
        self,
    ):
        client, _, mock_index_cls = self._save(
            save_aggregate_report_to_opensearch, _aggregate_report()
        )
        index_call = client.index.call_args.kwargs
        self.assertEqual(index_call["index"], "dmarc_aggregate-2024-01-15")
        self.assertEqual(index_call["op_type"], "create")
        self.assertEqual(
            index_call["body"]["@timestamp"],
            datetime(2024, 1, 15, tzinfo=timezone.utc),
        )
        client.indices.create.assert_called_once()
        client.indices.put_index_template.assert_not_called()
        client.indices.create_data_stream.assert_not_called()

    def test_failure_report_goes_to_the_stream(self):
        client, mock_search_cls, mock_index_cls = self._save(
            save_failure_report_to_opensearch,
            _failure_report(),
            monthly_indexes=True,
            use_data_streams=True,
        )
        index_call = client.index.call_args.kwargs
        self.assertEqual(index_call["index"], "dmarc_failure")
        self.assertEqual(index_call["op_type"], "create")
        self.assertEqual(
            index_call["body"]["@timestamp"],
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        client.indices.create_data_stream.assert_called_once_with(name="dmarc_failure")
        client.indices.create.assert_not_called()
        self.assertEqual(
            mock_search_cls.call_args.kwargs["index"],
            "dmarc_failure*,dmarc_forensic*",
        )

    def test_failure_report_dated_mode_unchanged_apart_from_timestamp_and_op_type(self):
        client, _, _ = self._save(save_failure_report_to_opensearch, _failure_report())
        index_call = client.index.call_args.kwargs
        self.assertEqual(index_call["index"], "dmarc_failure-2024-01-01")
        self.assertEqual(index_call["op_type"], "create")
        self.assertEqual(
            index_call["body"]["@timestamp"],
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        client.indices.create_data_stream.assert_not_called()

    def test_smtp_tls_report_goes_to_the_stream(self):
        client, mock_search_cls, mock_index_cls = self._save(
            save_smtp_tls_report_to_opensearch,
            _smtp_tls_report(),
            index_prefix="cust_",
            use_data_streams=True,
        )
        index_call = client.index.call_args.kwargs
        self.assertEqual(index_call["index"], "cust_smtp_tls")
        self.assertEqual(index_call["op_type"], "create")
        self.assertEqual(
            index_call["body"]["@timestamp"],
            datetime(2024, 2, 3, tzinfo=timezone.utc),
        )
        client.indices.create_data_stream.assert_called_once_with(name="cust_smtp_tls")
        client.indices.create.assert_not_called()
        self.assertEqual(mock_search_cls.call_args.kwargs["index"], "cust_smtp_tls*")

    def test_smtp_tls_report_dated_mode_unchanged_apart_from_timestamp_and_op_type(
        self,
    ):
        client, _, _ = self._save(
            save_smtp_tls_report_to_opensearch, _smtp_tls_report()
        )
        index_call = client.index.call_args.kwargs
        self.assertEqual(index_call["index"], "smtp_tls-2024-02-03")
        self.assertEqual(index_call["op_type"], "create")
        self.assertEqual(
            index_call["body"]["@timestamp"],
            datetime(2024, 2, 3, tzinfo=timezone.utc),
        )
        client.indices.create_data_stream.assert_not_called()

    def test_stream_set_up_once_for_a_multi_record_report(self):
        report = _aggregate_report()
        report["records"].append(report["records"][0].copy())
        client, _, _ = self._save(
            save_aggregate_report_to_opensearch, report, use_data_streams=True
        )
        self.assertEqual(client.index.call_count, 2)
        self.assertEqual(client.indices.put_index_template.call_count, 1)

    def test_name_collision_saves_nothing(self):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Search") as mock_search_cls,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            mock_search_cls.return_value.execute.return_value = []
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = True
            with self.assertRaises(OpenSearchError):
                save_smtp_tls_report_to_opensearch(
                    _smtp_tls_report(), use_data_streams=True
                )
        client.index.assert_not_called()


class TestMigrateIndexesWithDataStream(unittest.TestCase):
    def test_legacy_fo_migration_skips_a_stream_with_the_name(self):
        """With use_data_streams the undated legacy name is the stream
        itself. Index.exists() is true for it, and the field mapping comes
        back keyed by a backing index; its fo is text, so nothing is
        migrated or deleted."""
        with (
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.reindex") as mock_reindex,
        ):
            index = mock_index_cls.return_value
            index.exists.return_value = True
            index.get_field_mapping.return_value = {
                ".ds-dmarc_aggregate-000001": {
                    "mappings": {
                        "published_policy.fo": {
                            "full_name": "published_policy.fo",
                            "mapping": {"fo": {"type": "text"}},
                        }
                    }
                }
            }
            migrate_indexes(legacy_fo_indexes=["dmarc_aggregate"])
        mock_reindex.assert_not_called()
        index.create.assert_not_called()
        index.delete.assert_not_called()


class TestBackwardCompatAlias(unittest.TestCase):
    def test_save_forensic_alias_points_to_save_failure(self):
        self.assertIs(
            opensearch_module.save_forensic_report_to_opensearch,
            opensearch_module.save_failure_report_to_opensearch,
        )

    def test_forensic_doc_alias_points_to_failure_doc(self):
        self.assertIs(
            opensearch_module._ForensicReportDoc, opensearch_module._FailureReportDoc
        )
        self.assertIs(
            opensearch_module._ForensicSampleDoc, opensearch_module._FailureSampleDoc
        )


class TestMappingGuards(_DataStreamTestCase):
    """New indexes and data stream templates carry explicit mappings
    (GHSA-qpcg-29vr-jwm3).

    Before 11.2.2 they were created with settings only, so the cluster
    inferred every field's type from the first document, with
    ``date_detection`` on: an aggregate report with ``report_id``
    ``2026-11-09`` mapped ``report_id`` as a date for its day, a failure
    sample header ``Subject.x`` mapped ``sample.headers.subject`` as an
    object, and invented header names used up the 1,000-field limit, after
    which legitimate reports for that index were rejected.
    """

    def _save_dated(self, save_function, report):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Search") as mock_search_cls,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            mock_search_cls.return_value.execute.return_value = []
            mock_index_cls.return_value.exists.return_value = False
            save_function(report)
        client.indices.create.assert_called_once()
        return client

    def _created_mappings(self, save_function, report):
        client = self._save_dated(save_function, report)
        return client.indices.create.call_args.kwargs["body"]["mappings"]

    def _template_mappings(self, save_function, report):
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Search") as mock_search_cls,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            mock_search_cls.return_value.execute.return_value = []
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = False
            save_function(report, use_data_streams=True)
        template = client.indices.put_index_template.call_args.kwargs["body"]
        return template["template"]["mappings"]

    def _assert_dates_declared(self, mappings, names):
        for name in names:
            self.assertEqual(mappings["properties"][name], {"type": "date"}, name)

    def test_aggregate_index_turns_date_detection_off(self):
        mappings = self._created_mappings(
            save_aggregate_report_to_opensearch, _aggregate_report()
        )
        self.assertIs(mappings["date_detection"], False)
        self._assert_dates_declared(
            mappings, ["@timestamp", "date_range", "date_begin", "date_end"]
        )
        self.assertNotIn("sample", mappings["properties"])
        # report_id stays dynamic: with date detection off a date-shaped
        # value maps it as a string, not a date.
        self.assertNotIn("report_id", mappings["properties"])

    def test_smtp_tls_index_turns_date_detection_off(self):
        mappings = self._created_mappings(
            save_smtp_tls_report_to_opensearch, _smtp_tls_report()
        )
        self.assertIs(mappings["date_detection"], False)
        self._assert_dates_declared(
            mappings, ["@timestamp", "date_range", "date_begin", "date_end"]
        )
        self.assertNotIn("sample", mappings["properties"])

    def test_failure_index_maps_sample_headers_without_dynamic_fields(self):
        mappings = self._created_mappings(
            save_failure_report_to_opensearch, _failure_report()
        )
        self.assertIs(mappings["date_detection"], False)
        self._assert_dates_declared(mappings, ["@timestamp", "arrival_date"])
        sample = mappings["properties"]["sample"]["properties"]
        self.assertEqual(sample["date"], {"type": "date"})
        headers = sample["headers"]
        self.assertEqual(headers["type"], "object")
        self.assertIs(headers["dynamic"], False)
        string_field = {
            "type": "text",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
        }
        for name in ("from", "to", "subject", "date", "message-id", "cc"):
            self.assertEqual(headers["properties"][name], string_field, name)
        for name in headers["properties"]:
            # Stored names are lower-cased with "." replaced, so a declared
            # name must be in that form or no stored header can match it.
            self.assertEqual(name, name.lower().replace(".", "_"), name)

    def test_failure_mapping_declares_every_header_the_dashboards_query(self):
        dashboards = Path(__file__).resolve().parent.parent / "dashboards"
        referenced = set()
        for path in dashboards.rglob("*"):
            if path.is_file() and path.suffix in (".json", ".ndjson", ".xml"):
                text = path.read_text(encoding="utf-8")
                for match in re.finditer(r"sample\.headers\.([A-Za-z0-9_-]+)", text):
                    referenced.add(match.group(1).lower())
        self.assertIn("x-mailer", referenced)
        mappings = self._created_mappings(
            save_failure_report_to_opensearch, _failure_report()
        )
        declared = mappings["properties"]["sample"]["properties"]["headers"][
            "properties"
        ]
        self.assertLessEqual(referenced, set(declared))

    def test_data_stream_templates_carry_the_mappings(self):
        for save_function, report, has_sample in (
            (save_aggregate_report_to_opensearch, _aggregate_report(), False),
            (save_failure_report_to_opensearch, _failure_report(), True),
            (save_smtp_tls_report_to_opensearch, _smtp_tls_report(), False),
        ):
            case = save_function.__name__
            opensearch_module._READY_DATA_STREAMS.clear()
            mappings = self._template_mappings(save_function, report)
            self.assertIs(mappings["date_detection"], False, case)
            self.assertEqual(
                mappings["properties"]["@timestamp"], {"type": "date"}, case
            )
            self.assertEqual("sample" in mappings["properties"], has_sample, case)
            if has_sample:
                headers = mappings["properties"]["sample"]["properties"]["headers"]
                self.assertIs(headers["dynamic"], False, case)
                self.assertIn("subject", headers["properties"], case)

    def test_data_stream_template_adds_timestamp_without_changing_the_argument(
        self,
    ):
        mappings = {"date_detection": False, "properties": {"x": {"type": "long"}}}
        with (
            _registered_client() as client,
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
        ):
            client.indices.get_data_stream.side_effect = _not_found()
            mock_index_cls.return_value.exists.return_value = False
            create_data_streams(["s"], mappings=mappings)
        template = client.indices.put_index_template.call_args.kwargs["body"]
        self.assertEqual(
            template["template"]["mappings"],
            {
                "date_detection": False,
                "properties": {"x": {"type": "long"}, "@timestamp": {"type": "date"}},
            },
        )
        self.assertEqual(
            mappings, {"date_detection": False, "properties": {"x": {"type": "long"}}}
        )

    def test_dotted_header_name_is_stored_with_an_underscore(self):
        report = _failure_report()
        report["parsed_sample"] = dict(report["parsed_sample"])
        report["parsed_sample"]["headers"] = {
            "From": [["", "sender@example.com"]],
            "Subject.x": "v",
            "X.Y.Z": "w",
        }
        client = self._save_dated(save_failure_report_to_opensearch, report)
        headers = client.index.call_args.kwargs["body"]["sample"]["headers"]
        self.assertEqual(headers["subject_x"], "v")
        self.assertEqual(headers["x_y_z"], "w")
        self.assertNotIn("subject.x", headers)
        self.assertNotIn("subject", headers)
        # The address headers are still flattened under their usual keys.
        self.assertEqual(headers["from"], "sender@example.com")


# Silence unused-import lint in the test module preamble.
_ = call


class TestAggregateIndexCap(unittest.TestCase):
    """One report may create at most MAX_INDEXES_PER_REPORT dated indexes;
    the overflow records are saved to the report's first index."""

    DAYS = 40

    def _report(self):
        report = _aggregate_report()
        template = report["records"][0]
        report["records"] = []
        for day in range(self.DAYS):
            record = copy.deepcopy(template)
            begin = datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)
            end = begin + timedelta(days=1)
            record["interval_begin"] = begin.strftime("%Y-%m-%d %H:%M:%S")
            record["interval_end"] = end.strftime("%Y-%m-%d %H:%M:%S")
            report["records"].append(record)
        return report

    def _save(self, **kwargs):
        """Save the report; return created index names, the (index,
        date_begin) of each saved document and the logger mock."""
        saved = []

        def capture(doc, *args, **save_kwargs):
            saved.append((doc.meta.index, doc.date_begin))

        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection") as mock_get_conn,
            patch("parsedmarc.opensearch.logger") as mock_logger,
            patch("parsedmarc.opensearch.create_data_streams") as mock_streams,
            patch.object(
                opensearch_module._AggregateReportDoc,
                "save",
                autospec=True,
                side_effect=capture,
            ),
        ):
            mock_index_cls.return_value.exists.return_value = False
            save_aggregate_report_to_opensearch(self._report(), **kwargs)
            created = [
                c.kwargs["index"]
                for c in mock_get_conn.return_value.indices.create.call_args_list
            ]
        return created, saved, mock_logger, mock_streams

    def test_daily_indexes_are_capped_and_overflow_goes_to_the_first(self):
        created, saved, mock_logger, _ = self._save()
        expected = [f"dmarc_aggregate-2024-01-{d:02d}" for d in range(1, 32)]
        self.assertEqual(sorted(set(created)), expected)
        self.assertEqual(len(saved), self.DAYS)
        self.assertEqual([index for index, _ in saved[:31]], expected)
        self.assertEqual(
            [index for index, _ in saved[31:]], ["dmarc_aggregate-2024-01-01"] * 9
        )
        # The overflow records keep their own dates.
        begins = [begin for _, begin in saved]
        self.assertEqual(begins[31], datetime(2024, 2, 1, tzinfo=timezone.utc))
        self.assertEqual(begins[39], datetime(2024, 2, 9, tzinfo=timezone.utc))
        mock_logger.warning.assert_called_once()
        self.assertIn("9 records", mock_logger.warning.call_args.args[0])

    def test_routing_warning_escapes_the_report_id(self):
        """The report ID is sender-controlled; a CR/LF in it must not forge
        a log line."""
        report = self._report()
        report["report_metadata"]["report_id"] = "poc\r\nforged"
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection"),
            patch("parsedmarc.opensearch.logger") as mock_logger,
            patch.object(opensearch_module._AggregateReportDoc, "save", autospec=True),
        ):
            mock_index_cls.return_value.exists.return_value = False
            save_aggregate_report_to_opensearch(report)
        message = mock_logger.warning.call_args.args[0]
        self.assertIn("poc\\r\\nforged", message)
        self.assertNotIn("\n", message)

    def test_monthly_indexes_are_not_affected(self):
        created, saved, mock_logger, _ = self._save(monthly_indexes=True)
        self.assertEqual(
            sorted(set(created)), ["dmarc_aggregate-2024-01", "dmarc_aggregate-2024-02"]
        )
        self.assertEqual(
            [index for index, _ in saved],
            ["dmarc_aggregate-2024-01"] * 31 + ["dmarc_aggregate-2024-02"] * 9,
        )
        mock_logger.warning.assert_not_called()

    def test_data_streams_are_not_affected(self):
        created, saved, mock_logger, mock_streams = self._save(use_data_streams=True)
        self.assertEqual(created, [])
        self.assertEqual({index for index, _ in saved}, {"dmarc_aggregate"})
        self.assertEqual(len(saved), self.DAYS)
        self.assertEqual(mock_streams.call_count, self.DAYS)
        mock_logger.warning.assert_not_called()


class TestSaveFailureReportEmptyAddressHeaders(unittest.TestCase):
    """GHSA-4272-4r8g-6c5h: a failure sample whose From, To or Reply-To
    header holds no address made the save index ``headers[...][0]`` of
    mail-parser's empty list and raise ``IndexError``, which escaped the
    CLI and stopped the mailbox run. The header is now left out of the
    document and of the duplicate query."""

    # An empty From: and Reply-To:, and To: undisclosed-recipients:; (an
    # RFC 5322 §3.4 group with no members, which legitimate mail uses).
    ARF = (
        "From: dmarc@reporter.example\n"
        "To: ruf@example.com\n"
        "Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
        "Subject: DMARC Failure Report\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/report; report-type=feedback-report; boundary="b"\n'
        "\n"
        "--b\n"
        "Content-Type: text/plain\n"
        "\n"
        "Authentication failure report.\n"
        "--b\n"
        "Content-Type: message/feedback-report\n"
        "\n"
        "Feedback-Type: auth-failure\n"
        "User-Agent: test/1.0\n"
        "Version: 1\n"
        "Original-Mail-From: user@example.com\n"
        "Arrival-Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
        "Source-IP: 192.0.2.1\n"
        "Reported-Domain: example.com\n"
        "Authentication-Results: mx; dmarc=fail\n"
        "\n"
        "--b\n"
        "Content-Type: text/rfc822-headers\n"
        "\n"
        "From:\n"
        "To: undisclosed-recipients:;\n"
        "Reply-To:\n"
        "Subject: spoofed\n"
        "Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
        "--b--\n"
    )

    def test_empty_address_headers_are_left_out(self):
        parsed = parse_report_email(self.ARF, offline=True)
        self.assertEqual(parsed["report_type"], "failure")
        report = cast(dict, parsed["report"])
        headers = report["parsed_sample"]["headers"]
        self.assertEqual(
            (headers["From"], headers["To"], headers["Reply-To"]), ([], [], [])
        )
        search = _empty_search()
        with (
            patch("parsedmarc.opensearch.Search", return_value=search),
            patch("parsedmarc.opensearch.Index"),
            patch.object(
                opensearch_module._FailureReportDoc, "save", autospec=True
            ) as mock_save,
        ):
            save_failure_report_to_opensearch(report)
        doc = mock_save.call_args.args[0]
        self.assertEqual(doc.sample.headers["subject"], "spoofed")
        for header in ("from", "to", "reply-to"):
            self.assertNotIn(header, doc.sample.headers)
        query = json.dumps(search.query.to_dict())
        self.assertIn("sample.headers.subject", query)
        self.assertNotIn("sample.headers.from", query)
        self.assertNotIn("sample.headers.to", query)


class TestAggregateAttributesDoNotReachTheDocument(unittest.TestCase):
    """GHSA-qpcg-29vr-jwm3: an XML attribute on a scalar element reached the
    document as an object and mapped the field as one."""

    def test_document_holds_no_object_for_attributed_fields(self):
        attribute = ' a="1"'
        xml = (
            f"<feedback><version{attribute}>1.0</version><report_metadata>"
            "<org_name>example.net</org_name><email>a@example.net</email>"
            "<report_id>r</report_id><date_range><begin>1704067200</begin>"
            "<end>1704153599</end></date_range></report_metadata>"
            "<policy_published><domain>example.com</domain>"
            f"<p{attribute}>none</p><fo{attribute}>1</fo></policy_published>"
            "<record><row><source_ip>192.0.2.1</source_ip><count>1</count>"
            f"<policy_evaluated><disposition{attribute}>none</disposition>"
            "<dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>"
            "<identifiers><header_from>example.com</header_from>"
            f"<envelope_to{attribute}>example.org</envelope_to></identifiers>"
            "<auth_results><spf><domain>example.com</domain><result>pass</result>"
            "</spf></auth_results></record></feedback>"
        )
        report = parse_aggregate_report_xml(xml, offline=True)
        docs = []
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection"),
            patch.object(
                opensearch_module._AggregateReportDoc,
                "save",
                autospec=True,
                side_effect=lambda doc, *args, **kwargs: docs.append(doc.to_dict()),
            ),
        ):
            mock_index_cls.return_value.exists.return_value = False
            save_aggregate_report_to_opensearch(cast(dict, report))
        doc = docs[0]
        self.assertEqual(doc["xml_schema"], "1.0")
        self.assertEqual(doc["disposition"], "none")
        self.assertEqual(doc["envelope_to"], "example.org")
        self.assertEqual(doc["published_policy"]["p"], "none")
        self.assertEqual(doc["published_policy"]["fo"], "1")


# Every element of an aggregate report that the schema types as a string,
# with its plain value; {name} placeholders take a variant.
_SCALAR_FIELD_VALUES = {
    "version": "1.0",
    "org_name": "reporter.example",
    "email": "dmarc@reporter.example",
    "extra_contact_info": "https://reporter.example/dmarc",
    "report_id": "scalar-test",
    "generator": "reporter/1.0",
    "domain": "example.com",
    "adkim": "r",
    "aspf": "s",
    "p": "none",
    "sp": "quarantine",
    "pct": "100",
    "fo": "1",
    "np": "reject",
    "testing": "n",
    "discovery_method": "psl",
    "source_ip": "192.0.2.1",
    "count": "3",
    "disposition": "none",
    "dkim": "pass",
    "spf": "fail",
    "header_from": "example.com",
    "envelope_from": "bounce.example.com",
    "envelope_to": "example.org",
    "dkim_domain": "example.com",
    "selector": "s1",
    "dkim_result": "pass",
    "dkim_human_result": "good signature",
    "spf_domain": "bounce.example.com",
    "scope": "mfrom",
    "spf_result": "fail",
    "spf_human_result": "not listed",
}
_SCALAR_FIELD_TEMPLATE = (
    "<feedback><version>{version}</version><report_metadata>"
    "<org_name>{org_name}</org_name><email>{email}</email>"
    "<extra_contact_info>{extra_contact_info}</extra_contact_info>"
    "<report_id>{report_id}</report_id><generator>{generator}</generator>"
    "<date_range><begin>1704067200</begin><end>1704153599</end></date_range>"
    "</report_metadata><policy_published><domain>{domain}</domain>"
    "<adkim>{adkim}</adkim><aspf>{aspf}</aspf><p>{p}</p><sp>{sp}</sp>"
    "<pct>{pct}</pct><fo>{fo}</fo><np>{np}</np><testing>{testing}</testing>"
    "<discovery_method>{discovery_method}</discovery_method></policy_published>"
    "<record><row><source_ip>{source_ip}</source_ip><count>{count}</count>"
    "<policy_evaluated><disposition>{disposition}</disposition>"
    "<dkim>{dkim}</dkim><spf>{spf}</spf>"
    "<reason><type>other</type><comment>c</comment></reason>"
    "</policy_evaluated></row><identifiers><header_from>{header_from}</header_from>"
    "<envelope_from>{envelope_from}</envelope_from>"
    "<envelope_to>{envelope_to}</envelope_to></identifiers><auth_results>"
    "<dkim><domain>{dkim_domain}</domain><selector>{selector}</selector>"
    "<result>{dkim_result}</result><human_result>{dkim_human_result}</human_result>"
    "</dkim><spf><domain>{spf_domain}</domain><scope>{scope}</scope>"
    "<result>{spf_result}</result><human_result>{spf_human_result}</human_result>"
    "</spf></auth_results></record></feedback>"
)


def _scalar_field_xml(**variants: str) -> str:
    """The report with each named field's value replaced by its variant."""
    return _SCALAR_FIELD_TEMPLATE.format(**{**_SCALAR_FIELD_VALUES, **variants})


# Fields whose element can hold child elements without the report being
# rejected.
_OPTIONAL_SCALAR_FIELDS = tuple(
    name
    for name in _SCALAR_FIELD_VALUES
    if name
    not in (
        "org_name",
        "report_id",
        "domain",
        "p",
        "source_ip",
        "count",
        "header_from",
        "dkim_domain",
        "spf_domain",
    )
)


# The fields of an aggregate report document that hold objects or lists;
# "[]" stands for a list item. Every other field must be a scalar.
_AGGREGATE_DOC_CONTAINERS = {
    "date_range",
    "published_policy",
    "policy_overrides",
    "policy_overrides[]",
    "dkim_results",
    "dkim_results[]",
    "dkim_results_combined",
    "spf_results",
    "spf_results[]",
    "spf_results_combined",
    "errors",
}


def _container_paths(value, path=""):
    """Yield the path of every dict and list inside ``value``."""
    if isinstance(value, dict):
        if path:
            yield path
        for key, item in value.items():
            yield from _container_paths(item, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        yield path
        for item in value:
            yield from _container_paths(item, f"{path}[]")


# A second <policy_published> makes the field a list; the first one's <p>
# holds a child element.
_REPEATED_POLICY_VARIANTS = {
    "p": "<x>1</x>",
    "discovery_method": (
        "psl</discovery_method></policy_published><policy_published>"
        "<domain>example.com</domain><p>none</p><discovery_method>psl"
    ),
}


class TestAggregateScalarFieldsReachTheDocumentAsScalars(unittest.TestCase):
    """GHSA-qpcg-29vr-jwm3: a child element under a field the schema types
    as a string reached the document as an object and mapped the field as
    one. The walk covers every field, so a scalar field added later is
    checked too."""

    def _document(self, **variants):
        report = parse_aggregate_report_xml(_scalar_field_xml(**variants), offline=True)
        docs = []
        with (
            patch("parsedmarc.opensearch.Search", return_value=_empty_search()),
            patch("parsedmarc.opensearch.Index") as mock_index_cls,
            patch("parsedmarc.opensearch.connections.get_connection"),
            patch.object(
                opensearch_module._AggregateReportDoc,
                "save",
                autospec=True,
                side_effect=lambda doc, *args, **kwargs: docs.append(doc.to_dict()),
            ),
        ):
            mock_index_cls.return_value.exists.return_value = False
            save_aggregate_report_to_opensearch(cast(dict, report))
        return docs[0]

    def test_no_object_outside_the_object_fields(self):
        mixed = {name: f"{value}<x/>" for name, value in _SCALAR_FIELD_VALUES.items()}
        child = {name: "<x>1</x>" for name in _OPTIONAL_SCALAR_FIELDS}
        for label, variants in (
            ("mixed", mixed),
            ("child", child),
            ("repeated policy_published", _REPEATED_POLICY_VARIANTS),
        ):
            paths = set(_container_paths(self._document(**variants)))
            self.assertIn("published_policy", paths, msg=label)
            self.assertLessEqual(paths, _AGGREGATE_DOC_CONTAINERS, msg=label)


if __name__ == "__main__":
    unittest.main(verbosity=2)
