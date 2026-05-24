"""Tests for parsedmarc.postgres — the PostgreSQL output backend.

The pure timestamp/contact-info helpers are tested directly. The
``PostgreSQLClient`` save methods are tested with psycopg mocked at the SDK
boundary (``parsedmarc.postgres.psycopg``); the assertions check the SQL and
the bound parameters that a real PostgreSQL server would receive, plus the
real-sample round trip, so the tests fail if the dict-key mapping regresses.
"""

import os
import unittest
from glob import glob
from unittest.mock import MagicMock, patch

import parsedmarc
from parsedmarc.postgres import (
    AlreadySaved,
    PostgreSQLClient,
    PostgreSQLError,
    _contact_info_to_text,
    _ensure_utc_suffix,
    _naive_local_to_timestamptz,
    _normalize_arrival_date,
)

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

# psycopg is an optional dependency and is not installed in CI (which installs
# only the [build] extra). The save methods mock the connection, but the
# failure path also references ``psycopg_types.json.Jsonb`` at module scope, so
# mock that SDK boundary for the whole module when psycopg is absent.
_types_patcher = None


def setUpModule():
    global _types_patcher
    import parsedmarc.postgres as pg

    if pg.psycopg_types is None:
        _types_patcher = patch("parsedmarc.postgres.psycopg_types", MagicMock())
        _types_patcher.start()


def tearDownModule():
    if _types_patcher is not None:
        _types_patcher.stop()


class TestPostgreSQLHelpers(unittest.TestCase):
    """Unit tests for the pure helper functions in parsedmarc.postgres."""

    # -- _ensure_utc_suffix --------------------------------------------------

    def test_ensure_utc_suffix_none(self):
        """None passes through unchanged."""
        self.assertIsNone(_ensure_utc_suffix(None))

    def test_ensure_utc_suffix_empty_string(self):
        """Empty string passes through unchanged (falsy)."""
        self.assertEqual(_ensure_utc_suffix(""), "")

    def test_ensure_utc_suffix_naive_utc(self):
        """A naive UTC timestamp gets '+00' appended."""
        self.assertEqual(
            _ensure_utc_suffix("2024-01-15 10:30:00"),
            "2024-01-15 10:30:00+00",
        )

    def test_ensure_utc_suffix_already_has_plus(self):
        """A timestamp already containing '+' is left unchanged."""
        val = "2024-01-15 10:30:00+05:30"
        self.assertEqual(_ensure_utc_suffix(val), val)

    def test_ensure_utc_suffix_already_has_z(self):
        """A timestamp ending with 'Z' is left unchanged."""
        val = "2024-01-15T10:30:00Z"
        self.assertEqual(_ensure_utc_suffix(val), val)

    def test_ensure_utc_suffix_negative_offset(self):
        """A timestamp with a negative offset after position 10 is unchanged."""
        val = "2024-01-15 10:30:00-05:00"
        self.assertEqual(_ensure_utc_suffix(val), val)

    def test_ensure_utc_suffix_iso_t_naive(self):
        """Naive ISO 8601 with T separator gets '+00'."""
        self.assertEqual(
            _ensure_utc_suffix("2024-01-15T10:30:00"),
            "2024-01-15T10:30:00+00",
        )

    # -- _naive_local_to_timestamptz -----------------------------------------

    def test_naive_local_to_timestamptz_none(self):
        self.assertIsNone(_naive_local_to_timestamptz(None))

    def test_naive_local_to_timestamptz_empty(self):
        self.assertEqual(_naive_local_to_timestamptz(""), "")

    def test_naive_local_to_timestamptz_valid(self):
        """A valid naive string is returned with a timezone offset."""
        result = _naive_local_to_timestamptz("2024-01-15 10:30:00")
        self.assertIsInstance(result, str)
        self.assertTrue(
            "+" in result or "-" in result[10:],
            f"Expected timezone offset in result: {result}",
        )
        from datetime import datetime as _dt

        parsed = _dt.fromisoformat(result)
        self.assertIsNotNone(parsed.tzinfo)

    def test_naive_local_to_timestamptz_bad_format_raises(self):
        """An unparseable string raises ValueError (from strptime)."""
        with self.assertRaises(ValueError):
            _naive_local_to_timestamptz("not-a-date")

    # -- _normalize_arrival_date ---------------------------------------------

    def test_normalize_arrival_date_none(self):
        self.assertIsNone(_normalize_arrival_date(None))

    def test_normalize_arrival_date_empty(self):
        self.assertEqual(_normalize_arrival_date(""), "")

    def test_normalize_arrival_date_iso_naive_utc(self):
        """A naive ISO string (known UTC) is returned with +00 suffix."""
        result = _normalize_arrival_date("2024-01-15 10:30:00")
        self.assertTrue(result.endswith("+00"), f"Expected +00 suffix: {result}")

    def test_normalize_arrival_date_rfc2822(self):
        """An RFC 2822 date is converted to UTC with +00 suffix."""
        result = _normalize_arrival_date("Fri, 28 Oct 2022 00:34:24 +0800")
        self.assertTrue(result.endswith("+00"), f"Expected +00 suffix: {result}")
        # 00:34:24 +0800 is 16:34:24 UTC on 27 Oct 2022.
        self.assertIn("2022-10-27", result)
        self.assertIn("16:34:24", result)

    def test_normalize_arrival_date_already_utc(self):
        """A string already ending with +00 still works."""
        result = _normalize_arrival_date("2024-01-15 10:30:00+00")
        self.assertTrue(result.endswith("+00"), f"Expected +00 suffix: {result}")

    def test_normalize_arrival_date_unparseable(self):
        """An unparseable string is returned as-is (fallback)."""
        garbage = "not a date at all"
        self.assertEqual(_normalize_arrival_date(garbage), garbage)

    # -- _contact_info_to_text -----------------------------------------------

    def test_contact_info_to_text_none(self):
        self.assertIsNone(_contact_info_to_text(None))

    def test_contact_info_to_text_string(self):
        self.assertEqual(
            _contact_info_to_text("admin@example.com"),
            "admin@example.com",
        )

    def test_contact_info_to_text_list(self):
        self.assertEqual(
            _contact_info_to_text(["admin@example.com", "abuse@example.com"]),
            "admin@example.com, abuse@example.com",
        )

    def test_contact_info_to_text_empty_list(self):
        self.assertEqual(_contact_info_to_text([]), "")

    def test_contact_info_to_text_numeric(self):
        """Non-string scalars are converted via str()."""
        self.assertEqual(_contact_info_to_text(123), "123")


def _make_client():
    """Create a PostgreSQLClient with a fully-mocked psycopg connection."""
    with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
        mock_conn = MagicMock()
        mock_psycopg.connect.return_value = mock_conn
        mock_psycopg.Error = Exception

        client = PostgreSQLClient(
            host="localhost", database="test", user="test", password="test"
        )
    client._conn = mock_conn
    client._conn.closed = False
    return client, mock_conn


def _mock_cursor(mock_conn, fetchone_results):
    """Wire up a mock cursor whose fetchone() yields *fetchone_results*."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = list(fetchone_results)
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.transaction.return_value.__enter__ = MagicMock()
    mock_conn.transaction.return_value.__exit__ = MagicMock(return_value=False)
    return mock_cursor


def _executed_sql(mock_cursor):
    """Return the list of SQL strings passed to cursor.execute()."""
    return [c.args[0] for c in mock_cursor.execute.call_args_list]


def _named_params(call):
    """Map an INSERT's column names to the bound parameter values.

    Lets tests assert by column name instead of fragile positional indices.
    """
    import re

    sql = call.args[0]
    m = re.search(r"\(([^)]*?)\)\s*VALUES", sql, re.S)
    cols = [c.strip() for c in m.group(1).split(",") if c.strip()]
    return dict(zip(cols, call.args[1]))


class TestPostgreSQLConstruction(unittest.TestCase):
    """Construction-time behaviour, including the optional-dependency guard."""

    def test_missing_psycopg_raises_install_hint(self):
        """Without psycopg installed, construction fails with an install hint."""
        with patch("parsedmarc.postgres.psycopg", None):
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(host="localhost")
        self.assertIn("pip install parsedmarc[postgresql]", str(ctx.exception))

    def test_close_closes_open_connection(self):
        """close() closes a live connection and is a no-op once closed."""
        client, mock_conn = _make_client()
        mock_conn.closed = False
        client.close()
        mock_conn.close.assert_called_once()

        mock_conn.close.reset_mock()
        mock_conn.closed = True
        client.close()
        mock_conn.close.assert_not_called()

    def test_ensure_connected_reconnects_on_closed(self):
        """_ensure_connected reconnects when the connection is closed."""
        client, mock_conn = _make_client()
        mock_conn.closed = True
        with patch.object(client, "_connect") as mock_reconnect:
            client._ensure_connected()
            mock_reconnect.assert_called_once()

    def test_connect_uses_connection_string_when_provided(self):
        """A DSN/URI is passed straight to psycopg.connect."""
        with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
            mock_psycopg.Error = Exception
            PostgreSQLClient(connection_string="postgresql://u:p@h/db")
        mock_psycopg.connect.assert_called_once_with("postgresql://u:p@h/db")

    def test_connect_failure_raises_postgresql_error(self):
        """A driver-level connection error is wrapped in PostgreSQLError."""
        with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
            mock_psycopg.Error = Exception
            mock_psycopg.connect.side_effect = mock_psycopg.Error("refused")
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(host="localhost")
        self.assertIn("refused", str(ctx.exception))

    def test_create_tables_executes_all_ddl(self):
        """create_tables issues CREATE TABLE for every table and the indexes."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        client.create_tables()
        executed = " ".join(_executed_sql(cur))
        for table in (
            "dmarc_aggregate_report",
            "dmarc_aggregate_record",
            "dmarc_aggregate_record_dkim",
            "dmarc_aggregate_record_spf",
            "dmarc_aggregate_record_policy_override",
            "dmarc_failure_report",
            "dmarc_failure_sample_address",
            "smtp_tls_report",
            "smtp_tls_policy",
            "smtp_tls_failure_detail",
        ):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", executed)
        self.assertIn("CREATE INDEX IF NOT EXISTS", executed)

    def test_create_tables_wraps_db_error(self):
        """A driver error during DDL is wrapped in PostgreSQLError."""

        class FakeDriverError(Exception):
            pass

        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        cur.execute.side_effect = FakeDriverError("ddl boom")
        with patch("parsedmarc.postgres.psycopg") as mp:
            mp.Error = FakeDriverError
            with self.assertRaises(PostgreSQLError) as ctx:
                client.create_tables()
        self.assertIn("ddl boom", str(ctx.exception))


class TestPostgreSQLClientSave(unittest.TestCase):
    """Save methods with a mocked DB: assert on SQL and bound parameters."""

    # -- aggregate -----------------------------------------------------------

    def test_save_aggregate_report_calls_insert(self):
        """Aggregate save executes INSERTs for report, record, dkim and spf."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,), (10,)])

        report = {
            "xml_schema": "1.0",
            "xml_namespace": "urn:ietf:params:xml:ns:dmarc-2.0",
            "report_metadata": {
                "org_name": "Example Inc.",
                "org_email": "dmarc@example.com",
                "org_extra_contact_info": None,
                "report_id": "rpt-123",
                "begin_date": "2024-01-15 00:00:00",
                "end_date": "2024-01-15 23:59:59",
                "errors": [],
                "generator": "ExampleReporter/2.0",
            },
            "policy_published": {
                "domain": "example.com",
                "adkim": "r",
                "aspf": "r",
                "p": "none",
                "sp": "none",
                "pct": "100",
                "fo": "0",
                "np": "reject",
                "testing": "y",
                "discovery_method": "treewalk",
            },
            "records": [
                {
                    "source": {
                        "ip_address": "203.0.113.1",
                        "country": "US",
                        "reverse_dns": "mail.example.com",
                        "base_domain": "example.com",
                        "name": None,
                        "type": None,
                    },
                    "count": 5,
                    "alignment": {"spf": True, "dkim": True, "dmarc": True},
                    "policy_evaluated": {
                        "disposition": "none",
                        "dkim": "pass",
                        "spf": "pass",
                        "policy_override_reasons": [],
                    },
                    "identifiers": {
                        "header_from": "example.com",
                        "envelope_from": "example.com",
                        "envelope_to": None,
                    },
                    "interval_begin": "2024-01-15 00:00:00",
                    "interval_end": "2024-01-15 23:59:59",
                    "auth_results": {
                        "dkim": [
                            {
                                "domain": "example.com",
                                "selector": "s1",
                                "result": "pass",
                                "human_result": "valid signature",
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

        client.save_aggregate_report_to_postgresql(report)

        sqls = _executed_sql(cur)
        self.assertIn("dmarc_aggregate_report", sqls[0])
        self.assertIn("dmarc_aggregate_record", sqls[1])
        self.assertTrue(any("dmarc_aggregate_record_dkim" in s for s in sqls))
        self.assertTrue(any("dmarc_aggregate_record_spf" in s for s in sqls))

        # The RFC 9990 / DMARCbis fields must reach the report INSERT.
        report_params = _named_params(cur.execute.call_args_list[0])
        self.assertEqual(
            report_params["xml_namespace"], "urn:ietf:params:xml:ns:dmarc-2.0"
        )
        self.assertEqual(report_params["generator"], "ExampleReporter/2.0")
        self.assertEqual(report_params["np"], "reject")
        self.assertEqual(report_params["testing"], "y")
        self.assertEqual(report_params["discovery_method"], "treewalk")

        # DKIM auth-result values, including human_result, reach the INSERT.
        dkim_sql_idx = next(
            i for i, s in enumerate(sqls) if "dmarc_aggregate_record_dkim" in s
        )
        dkim_params = _named_params(cur.execute.call_args_list[dkim_sql_idx])
        self.assertEqual(dkim_params["domain"], "example.com")
        self.assertEqual(dkim_params["selector"], "s1")
        self.assertEqual(dkim_params["result"], "pass")
        self.assertEqual(dkim_params["human_result"], "valid signature")

    def test_save_aggregate_report_already_saved(self):
        """AlreadySaved is raised when ON CONFLICT returns no row."""
        client, mock_conn = _make_client()
        _mock_cursor(mock_conn, [None])

        report = {
            "report_metadata": {
                "org_name": "Dup Inc.",
                "report_id": "dup-001",
                "begin_date": "2024-01-01 00:00:00",
                "end_date": "2024-01-01 23:59:59",
            },
            "policy_published": {"domain": "example.com"},
            "records": [],
        }

        with self.assertRaises(AlreadySaved):
            client.save_aggregate_report_to_postgresql(report)

    def test_aggregate_report_normalizes_timestamps(self):
        """Report dates get a tz offset; record intervals get a +00 suffix."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,), (10,)])

        report = {
            "report_metadata": {
                "org_name": "TZ Test",
                "report_id": "tz-001",
                "begin_date": "2024-01-15 00:00:00",
                "end_date": "2024-01-15 23:59:59",
            },
            "policy_published": {"domain": "example.com"},
            "records": [
                {
                    "source": {},
                    "count": 1,
                    "alignment": {},
                    "policy_evaluated": {},
                    "identifiers": {"header_from": "example.com"},
                    "interval_begin": "2024-01-15 00:00:00",
                    "interval_end": "2024-01-15 23:59:59",
                    "auth_results": {"dkim": [], "spf": []},
                }
            ],
        }

        client.save_aggregate_report_to_postgresql(report)

        report_params = _named_params(cur.execute.call_args_list[0])
        for label in ("begin_date", "end_date"):
            val = report_params[label]
            self.assertIsNotNone(val, f"{label} should not be None")
            self.assertTrue(
                "+" in val or "-" in val[10:],
                f"Report {label} should carry a tz offset: {val}",
            )

        record_params = _named_params(cur.execute.call_args_list[1])
        for label in ("interval_begin", "interval_end"):
            val = record_params[label]
            self.assertIsNotNone(val, f"{label} should not be None")
            self.assertTrue(
                val.endswith("+00"),
                f"Record {label} should end with +00: {val}",
            )

    # -- failure -------------------------------------------------------------

    def test_save_failure_report_calls_insert(self):
        """Failure save dedups, then INSERTs the report and sample addresses."""
        client, mock_conn = _make_client()
        # 1st fetchone = dedup SELECT (None → not a duplicate); 2nd = INSERT id.
        cur = _mock_cursor(mock_conn, [None, (1,)])

        report = {
            "feedback_type": "auth-failure",
            "user_agent": "test/1.0",
            "version": "1",
            "original_envelope_id": None,
            "original_mail_from": "sender@example.com",
            "original_rcpt_to": "receiver@example.com",
            "arrival_date": "Mon, 15 Jan 2024 10:30:00 +0000",
            "arrival_date_utc": "2024-01-15 10:30:00",
            "authentication_results": "spf=pass",
            "delivery_result": None,
            "auth_failure": ["dkim"],
            "authentication_mechanisms": [],
            "dkim_domain": "example.com",
            "reported_domain": "example.com",
            "sample_headers_only": False,
            "source": {
                "ip_address": "203.0.113.1",
                "country": "US",
                "reverse_dns": "mail.example.com",
                "base_domain": "example.com",
                "name": None,
                "type": None,
            },
            "sample": "raw email content",
            "parsed_sample": {
                "date": "2024-01-15",
                "subject": "Test",
                "body": "Hello",
                "has_defects": False,
                "headers": {"From": "sender@example.com"},
                "from": {"display_name": "Sender", "address": "sender@example.com"},
                "to": [{"display_name": "Receiver", "address": "receiver@example.com"}],
                "cc": [],
                "bcc": [],
                "reply_to": [],
            },
        }

        client.save_failure_report_to_postgresql(report)

        sqls = _executed_sql(cur)
        # First statement is the dedup SELECT, then the report INSERT.
        self.assertIn("SELECT", sqls[0])
        self.assertIn("dmarc_failure_report", sqls[0])
        self.assertTrue(
            any("INSERT INTO dmarc_failure_report" in s for s in sqls),
            "expected a failure-report INSERT",
        )
        self.assertTrue(
            any("dmarc_failure_sample_address" in s for s in sqls),
            "expected a sample-address INSERT for the 'to' recipient",
        )

    def test_save_failure_report_already_saved(self):
        """A matching existing failure report raises AlreadySaved."""
        client, mock_conn = _make_client()
        # Dedup SELECT returns a row → duplicate.
        _mock_cursor(mock_conn, [(1,)])

        report = {
            "arrival_date_utc": "2024-01-15 10:30:00",
            "reported_domain": "example.com",
            "source": {"ip_address": "203.0.113.1"},
            "parsed_sample": {"subject": "Test"},
        }

        with self.assertRaises(AlreadySaved):
            client.save_failure_report_to_postgresql(report)

    # -- SMTP TLS ------------------------------------------------------------

    def test_save_smtp_tls_report_calls_insert(self):
        """SMTP TLS save INSERTs report, policy, and failure detail rows."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,), (10,)])

        report = {
            "organization_name": "Example Inc.",
            "begin_date": "2024-01-15T00:00:00Z",
            "end_date": "2024-01-16T00:00:00Z",
            "contact_info": "admin@example.com",
            "report_id": "tls-001",
            "policies": [
                {
                    "policy_domain": "example.com",
                    "policy_type": "sts",
                    "policy_strings": ["version: STSv1"],
                    "mx_host_patterns": ["*.example.com"],
                    "successful_session_count": 100,
                    "failed_session_count": 2,
                    "failure_details": [
                        {
                            "result_type": "certificate-expired",
                            "failed_session_count": 2,
                            "sending_mta_ip": "203.0.113.1",
                            "receiving_ip": "198.51.100.1",
                            "receiving_mx_hostname": "mx.example.com",
                            "receiving_mx_helo": "mx.example.com",
                            "additional_info_uri": None,
                            "failure_reason_code": None,
                        }
                    ],
                }
            ],
        }

        client.save_smtp_tls_report_to_postgresql(report)

        sqls = _executed_sql(cur)
        self.assertIn("smtp_tls_report", sqls[0])
        self.assertIn("smtp_tls_policy", sqls[1])
        self.assertIn("smtp_tls_failure_detail", sqls[2])

        # Policy field mapping must reach the INSERT (regression guard).
        policy_params = cur.execute.call_args_list[1].args[1]
        self.assertIn("example.com", policy_params)
        self.assertIn("sts", policy_params)
        self.assertIn(100, policy_params)
        self.assertIn(2, policy_params)

    def test_save_smtp_tls_report_already_saved(self):
        """AlreadySaved is raised when ON CONFLICT returns no row."""
        client, mock_conn = _make_client()
        _mock_cursor(mock_conn, [None])

        report = {
            "organization_name": "Dup Inc.",
            "begin_date": "2024-01-01T00:00:00Z",
            "end_date": "2024-01-02T00:00:00Z",
            "contact_info": "admin@dup.com",
            "report_id": "dup-tls-001",
            "policies": [],
        }

        with self.assertRaises(AlreadySaved):
            client.save_smtp_tls_report_to_postgresql(report)

    def test_save_smtp_tls_report_contact_info_list(self):
        """A contact_info list is joined to a string before insert."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,)])

        report = {
            "organization_name": "Multi Inc.",
            "begin_date": "2024-01-15T00:00:00Z",
            "end_date": "2024-01-16T00:00:00Z",
            "contact_info": ["admin@multi.com", "abuse@multi.com"],
            "report_id": "multi-001",
            "policies": [],
        }

        client.save_smtp_tls_report_to_postgresql(report)

        insert_params = cur.execute.call_args_list[0].args[1]
        self.assertEqual(insert_params[3], "admin@multi.com, abuse@multi.com")

    def test_save_failure_report_single_address_dict(self):
        """A recipient header parsed as a single dict (not a list) is wrapped."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [None, (1,)])

        report = {
            "arrival_date_utc": "2024-01-15 10:30:00",
            "reported_domain": "example.com",
            "source": {"ip_address": "203.0.113.1"},
            "parsed_sample": {
                "subject": "Single",
                # 'to' as a lone dict rather than a list of dicts.
                "to": {"display_name": "Solo", "address": "solo@example.com"},
            },
        }

        client.save_failure_report_to_postgresql(report)

        addr_sqls = [
            (c.args[0], c.args[1])
            for c in cur.execute.call_args_list
            if "dmarc_failure_sample_address" in c.args[0]
        ]
        self.assertEqual(len(addr_sqls), 1)
        self.assertIn("solo@example.com", addr_sqls[0][1])

    def test_save_failure_report_indexes_reply_to_address(self):
        """A parsed Reply-To address is written to
        dmarc_failure_sample_address with address_type 'reply_to' — the
        rows the Grafana PostgreSQL failure panel aggregates for its
        'Reply To' column. Guards the path that parse_email now
        populates (reply_to was always [] before the hyphen-key fix)."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [None, (1,)])

        report = {
            "arrival_date_utc": "2024-01-15 10:30:00",
            "reported_domain": "example.com",
            "source": {"ip_address": "203.0.113.1"},
            "parsed_sample": {
                "subject": "Test",
                "reply_to": [
                    {"display_name": "Real One", "address": "real@phish.example"}
                ],
            },
        }

        client.save_failure_report_to_postgresql(report)

        reply_to_inserts = [
            _named_params(c)
            for c in cur.execute.call_args_list
            if "dmarc_failure_sample_address" in c.args[0]
            and c.args[1][1] == "reply_to"
        ]
        self.assertEqual(len(reply_to_inserts), 1)
        self.assertEqual(reply_to_inserts[0]["address"], "real@phish.example")
        self.assertEqual(reply_to_inserts[0]["display_name"], "Real One")


class TestPostgreSQLSaveErrors(unittest.TestCase):
    """Driver errors raised mid-save are wrapped in PostgreSQLError."""

    class _FakeDriverError(Exception):
        pass

    def _run(self, method, report):
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        cur.execute.side_effect = self._FakeDriverError("db boom")
        with patch("parsedmarc.postgres.psycopg") as mp:
            mp.Error = self._FakeDriverError
            with self.assertRaises(PostgreSQLError) as ctx:
                getattr(client, method)(report)
        self.assertIn("db boom", str(ctx.exception))

    def test_save_aggregate_wraps_db_error(self):
        self._run(
            "save_aggregate_report_to_postgresql",
            {"report_metadata": {}, "policy_published": {}, "records": []},
        )

    def test_save_failure_wraps_db_error(self):
        self._run(
            "save_failure_report_to_postgresql",
            {"parsed_sample": {}, "source": {}},
        )

    def test_save_smtp_tls_wraps_db_error(self):
        self._run(
            "save_smtp_tls_report_to_postgresql",
            {"policies": []},
        )


class TestPostgreSQLWithSamples(unittest.TestCase):
    """Feed real parsed sample reports through the save methods (DB mocked)."""

    def test_aggregate_samples(self):
        client, mock_conn = _make_client()
        saved = 0
        for sample_path in glob("samples/aggregate/*"):
            if os.path.isdir(sample_path):
                continue
            try:
                parsed = parsedmarc.parse_report_file(
                    sample_path,
                    always_use_local_files=True,
                    offline=OFFLINE_MODE,
                )
            except parsedmarc.ParserError:
                continue
            if parsed.get("report_type") != "aggregate":
                continue

            report = parsed["report"]
            num_records = len(report.get("records", []))
            _mock_cursor(mock_conn, [(rid,) for rid in range(1, 2 + num_records)])
            try:
                client.save_aggregate_report_to_postgresql(report)
                saved += 1
            except Exception as exc:
                self.fail(f"aggregate save failed for {sample_path}: {exc}")

        self.assertGreater(saved, 0, "Expected at least one aggregate sample")

    def test_failure_samples(self):
        client, mock_conn = _make_client()
        saved = 0
        for sample_path in glob("samples/failure/*.eml"):
            try:
                parsed = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
            except parsedmarc.ParserError:
                continue
            if parsed.get("report_type") != "failure":
                continue

            reports = parsed["report"]
            if not isinstance(reports, list):
                reports = [reports]
            for report in reports:
                # Dedup SELECT returns None (not a dup), then the INSERT id.
                _mock_cursor(mock_conn, [None, (1,)])
                try:
                    client.save_failure_report_to_postgresql(report)
                    saved += 1
                except Exception as exc:
                    self.fail(f"failure save failed for {sample_path}: {exc}")

        self.assertGreater(saved, 0, "Expected at least one failure sample")

    def test_smtp_tls_samples(self):
        client, mock_conn = _make_client()
        saved = 0
        for sample_path in glob("samples/smtp_tls/*"):
            if os.path.isdir(sample_path):
                continue
            try:
                parsed = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
            except parsedmarc.ParserError:
                continue
            if parsed.get("report_type") != "smtp_tls":
                continue

            report = parsed["report"]
            num_policies = len(report.get("policies", []))
            _mock_cursor(mock_conn, [(rid,) for rid in range(1, 2 + num_policies)])
            try:
                client.save_smtp_tls_report_to_postgresql(report)
                saved += 1
            except Exception as exc:
                self.fail(f"smtp_tls save failed for {sample_path}: {exc}")

        self.assertGreater(saved, 0, "Expected at least one SMTP TLS sample")


if __name__ == "__main__":
    unittest.main()
