#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import os
import unittest
from glob import glob

from lxml import etree

import parsedmarc
import parsedmarc.utils

# Detect if running in GitHub Actions to skip DNS lookups
OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"


def minify_xml(xml_string):
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.fromstring(xml_string.encode("utf-8"), parser)
    return etree.tostring(tree, pretty_print=False).decode("utf-8")


def compare_xml(xml1, xml2):
    parser = etree.XMLParser(remove_blank_text=True)
    tree1 = etree.fromstring(xml1.encode("utf-8"), parser)
    tree2 = etree.fromstring(xml2.encode("utf-8"), parser)
    return etree.tostring(tree1) == etree.tostring(tree2)


class Test(unittest.TestCase):
    def testBase64Decoding(self):
        """Test base64 decoding"""
        # Example from Wikipedia Base64 article
        b64_str = "YW55IGNhcm5hbCBwbGVhcw"
        decoded_str = parsedmarc.utils.decode_base64(b64_str)
        assert decoded_str == b"any carnal pleas"

    def testPSLDownload(self):
        subdomain = "foo.example.com"
        result = parsedmarc.utils.get_base_domain(subdomain)
        assert result == "example.com"

        # Test newer PSL entries
        subdomain = "e3191.c.akamaiedge.net"
        result = parsedmarc.utils.get_base_domain(subdomain)
        assert result == "c.akamaiedge.net"

    def testExtractReportXMLComparator(self):
        """Test XML comparator function"""
        xmlnice_file = open("samples/extract_report/nice-input.xml")
        xmlnice = xmlnice_file.read()
        xmlnice_file.close()
        xmlchanged_file = open("samples/extract_report/changed-input.xml")
        xmlchanged = minify_xml(xmlchanged_file.read())
        xmlchanged_file.close()
        self.assertTrue(compare_xml(xmlnice, xmlnice))
        self.assertTrue(compare_xml(xmlchanged, xmlchanged))
        self.assertFalse(compare_xml(xmlnice, xmlchanged))
        self.assertFalse(compare_xml(xmlchanged, xmlnice))
        print("Passed!")

    def testExtractReportBytes(self):
        """Test extract report function for bytes string input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        with open(file, "rb") as f:
            data = f.read()
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report(data)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportXML(self):
        """Test extract report function for XML input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportGZip(self):
        """Test extract report function for gzip input"""
        print()
        file = "samples/extract_report/nice-input.xml.gz"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportZip(self):
        """Test extract report function for zip input"""
        print()
        file = "samples/extract_report/nice-input.xml.zip"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = minify_xml(xmlin_file.read())
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        xmlin_file = open("samples/extract_report/changed-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertFalse(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        print()
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            parsed_report = parsedmarc.parse_report_file(
                sample_path, always_use_local_files=True, offline=OFFLINE_MODE
            )["report"]
            parsedmarc.parsed_aggregate_reports_to_csv(parsed_report)
            print("Passed!")

    def testEmptySample(self):
        """Test empty/unparasable report"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_file("samples/empty.xml", offline=OFFLINE_MODE)

    def testForensicSamples(self):
        """Test sample forensic/ruf/failure DMARC reports"""
        print()
        sample_paths = glob("samples/forensic/*.eml")
        for sample_path in sample_paths:
            print("Testing {0}: ".format(sample_path), end="")
            with open(sample_path) as sample_file:
                sample_content = sample_file.read()
                parsed_report = parsedmarc.parse_report_email(
                    sample_content, offline=OFFLINE_MODE
                )["report"]
            parsed_report = parsedmarc.parse_report_file(
                sample_path, offline=OFFLINE_MODE
            )["report"]
            parsedmarc.parsed_forensic_reports_to_csv(parsed_report)
            print("Passed!")

    def testSmtpTlsSamples(self):
        """Test sample SMTP TLS reports"""
        print()
        sample_paths = glob("samples/smtp_tls/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            parsed_report = parsedmarc.parse_report_file(
                sample_path, offline=OFFLINE_MODE
            )["report"]
            parsedmarc.parsed_smtp_tls_reports_to_csv(parsed_report)
            print("Passed!")


# ---------------------------------------------------------------------------
# PostgreSQL backend tests
# ---------------------------------------------------------------------------

from unittest.mock import MagicMock, patch, call
from parsedmarc.postgres import (
    _ensure_utc_suffix,
    _naive_local_to_timestamptz,
    _normalize_arrival_date,
    _contact_info_to_text,
    AlreadySaved,
    PostgreSQLError,
)


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
        # The result must be a valid ISO 8601 datetime with offset.
        self.assertIsInstance(result, str)
        # It should contain either '+' or '-' for the tz offset.
        self.assertTrue(
            "+" in result or "-" in result[10:],
            f"Expected timezone offset in result: {result}",
        )
        # It should be parseable back to a datetime.
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


class TestPostgreSQLClientSave(unittest.TestCase):
    """Integration tests for PostgreSQLClient.save_* using a mocked DB."""

    def _make_client(self):
        """Create a PostgreSQLClient with a fully-mocked psycopg connection."""
        with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
            mock_conn = MagicMock()
            mock_psycopg.connect.return_value = mock_conn
            mock_psycopg.Error = Exception

            from parsedmarc.postgres import PostgreSQLClient

            client = PostgreSQLClient(
                host="localhost", database="test", user="test", password="test"
            )
        # Replace the live connection with our mock.
        client._conn = mock_conn
        client._conn.closed = False
        return client, mock_conn

    # -- save_aggregate_report_to_postgresql ---------------------------------

    def test_save_aggregate_report_calls_insert(self):
        """Aggregate save should execute INSERT statements for report + records."""
        client, mock_conn = self._make_client()

        mock_cursor = MagicMock()
        # First execute returns report id, second returns record id.
        mock_cursor.fetchone.side_effect = [(1,), (10,)]
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )

        report = {
            "xml_schema": "1.0",
            "report_metadata": {
                "org_name": "Example Inc.",
                "org_email": "dmarc@example.com",
                "org_extra_contact_info": None,
                "report_id": "rpt-123",
                "begin_date": "2024-01-15 00:00:00",
                "end_date": "2024-01-15 23:59:59",
                "errors": [],
            },
            "policy_published": {
                "domain": "example.com",
                "adkim": "r",
                "aspf": "r",
                "p": "none",
                "sp": "none",
                "pct": "100",
                "fo": "0",
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
                    "alignment": {
                        "spf": True,
                        "dkim": True,
                        "dmarc": True,
                    },
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
                            }
                        ],
                        "spf": [
                            {
                                "domain": "example.com",
                                "scope": "mfrom",
                                "result": "pass",
                            }
                        ],
                    },
                }
            ],
        }

        client.save_aggregate_report_to_postgresql(report)

        # We expect at least 4 cursor.execute calls:
        # 1) report INSERT  2) record INSERT  3) dkim INSERT  4) spf INSERT
        self.assertGreaterEqual(mock_cursor.execute.call_count, 4)

        # The first INSERT should be the aggregate report.
        first_sql = mock_cursor.execute.call_args_list[0][0][0]
        self.assertIn("dmarc_aggregate_report", first_sql)

        # The second INSERT should be the aggregate record.
        second_sql = mock_cursor.execute.call_args_list[1][0][0]
        self.assertIn("dmarc_aggregate_record", second_sql)

        # Third and fourth are DKIM and SPF auth results.
        third_sql = mock_cursor.execute.call_args_list[2][0][0]
        self.assertIn("dmarc_aggregate_record_dkim", third_sql)
        fourth_sql = mock_cursor.execute.call_args_list[3][0][0]
        self.assertIn("dmarc_aggregate_record_spf", fourth_sql)

    def test_save_aggregate_report_already_saved(self):
        """AlreadySaved is raised when ON CONFLICT returns no row."""
        client, mock_conn = self._make_client()

        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None  # conflict → no RETURNING
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )

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

    # -- save_forensic_report_to_postgresql ----------------------------------

    def test_save_forensic_report_calls_insert(self):
        """Forensic save should INSERT the report and sample addresses."""
        client, mock_conn = self._make_client()

        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )

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
                "to": [
                    {"display_name": "Receiver", "address": "receiver@example.com"}
                ],
                "cc": [],
                "bcc": [],
                "reply_to": [],
            },
        }

        client.save_forensic_report_to_postgresql(report)

        # At least 1 INSERT for the report + 1 for the "to" address.
        self.assertGreaterEqual(mock_cursor.execute.call_count, 2)

        first_sql = mock_cursor.execute.call_args_list[0][0][0]
        self.assertIn("dmarc_forensic_report", first_sql)

        # The second call should be a sample address INSERT for the "to".
        second_sql = mock_cursor.execute.call_args_list[1][0][0]
        self.assertIn("dmarc_forensic_sample_address", second_sql)

    # -- save_smtp_tls_report_to_postgresql ----------------------------------

    def test_save_smtp_tls_report_calls_insert(self):
        """SMTP TLS save should INSERT report, policy, and failure details."""
        client, mock_conn = self._make_client()

        mock_cursor = MagicMock()
        # report id, policy id
        mock_cursor.fetchone.side_effect = [(1,), (10,)]
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )

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

        # 1) report INSERT  2) policy INSERT  3) failure detail INSERT
        self.assertEqual(mock_cursor.execute.call_count, 3)

        first_sql = mock_cursor.execute.call_args_list[0][0][0]
        self.assertIn("smtp_tls_report", first_sql)

        second_sql = mock_cursor.execute.call_args_list[1][0][0]
        self.assertIn("smtp_tls_policy", second_sql)

        third_sql = mock_cursor.execute.call_args_list[2][0][0]
        self.assertIn("smtp_tls_failure_detail", third_sql)

    def test_save_smtp_tls_report_already_saved(self):
        """AlreadySaved is raised when ON CONFLICT returns no row."""
        client, mock_conn = self._make_client()

        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )

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
        """contact_info list is joined to a string before insert."""
        client, mock_conn = self._make_client()

        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )

        report = {
            "organization_name": "Multi Inc.",
            "begin_date": "2024-01-15T00:00:00Z",
            "end_date": "2024-01-16T00:00:00Z",
            "contact_info": ["admin@multi.com", "abuse@multi.com"],
            "report_id": "multi-001",
            "policies": [],
        }

        client.save_smtp_tls_report_to_postgresql(report)

        # Verify the contact_info parameter was joined.
        insert_params = mock_cursor.execute.call_args_list[0][0][1]
        contact_info_param = insert_params[3]  # 4th param in INSERT
        self.assertEqual(contact_info_param, "admin@multi.com, abuse@multi.com")

    # -- Reconnection --------------------------------------------------------

    def test_ensure_connected_reconnects_on_closed(self):
        """_ensure_connected should reconnect when the connection is closed."""
        client, mock_conn = self._make_client()

        # Simulate a closed connection.
        mock_conn.closed = True
        with patch.object(client, "_connect") as mock_reconnect:
            client._ensure_connected()
            mock_reconnect.assert_called_once()

    # -- Timestamp normalization in save methods -----------------------------

    def test_aggregate_report_normalizes_timestamps(self):
        """Verify that aggregate report date fields are normalized."""
        client, mock_conn = self._make_client()

        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [(1,), (10,)]
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )

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

        # Report-level dates use _naive_local_to_timestamptz → should have tz.
        report_params = mock_cursor.execute.call_args_list[0][0][1]
        begin_date = report_params[5]  # 6th param
        end_date = report_params[6]  # 7th param
        for label, val in [("begin_date", begin_date), ("end_date", end_date)]:
            self.assertIsNotNone(val, f"{label} should not be None")
            self.assertTrue(
                "+" in val or "-" in val[10:],
                f"Report {label} should have tz offset: {val}",
            )

        # Record-level dates use _ensure_utc_suffix → should end with +00.
        record_params = mock_cursor.execute.call_args_list[1][0][1]
        interval_begin = record_params[1]  # 2nd param
        interval_end = record_params[2]  # 3rd param
        for label, val in [
            ("interval_begin", interval_begin),
            ("interval_end", interval_end),
        ]:
            self.assertIsNotNone(val, f"{label} should not be None")
            self.assertTrue(
                val.endswith("+00"),
                f"Record {label} should end with +00: {val}",
            )


class TestPostgreSQLWithSamples(unittest.TestCase):
    """Test that real parsed sample data can be fed to the save methods."""

    def _make_client(self):
        """Create a PostgreSQLClient with a fully-mocked psycopg connection."""
        with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
            mock_conn = MagicMock()
            mock_psycopg.connect.return_value = mock_conn
            mock_psycopg.Error = Exception

            from parsedmarc.postgres import PostgreSQLClient

            client = PostgreSQLClient(
                host="localhost", database="test", user="test", password="test"
            )
        client._conn = mock_conn
        client._conn.closed = False
        return client, mock_conn

    def _mock_cursor(self, mock_conn, return_ids):
        """Set up a mock cursor that returns sequential IDs."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [(rid,) for rid in return_ids]
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.transaction.return_value.__enter__ = MagicMock()
        mock_conn.transaction.return_value.__exit__ = MagicMock(
            return_value=False
        )
        return mock_cursor

    def test_aggregate_samples(self):
        """Parse real aggregate samples and feed them through the mock save."""
        sample_paths = glob("samples/aggregate/*")
        client, mock_conn = self._make_client()

        saved = 0
        for sample_path in sample_paths:
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
            # We need enough IDs: 1 report + N records (each needs an id).
            num_records = len(report.get("records", []))
            ids = list(range(1, 2 + num_records))
            self._mock_cursor(mock_conn, ids)

            try:
                client.save_aggregate_report_to_postgresql(report)
                saved += 1
            except Exception as exc:
                self.fail(
                    f"save_aggregate_report_to_postgresql failed for "
                    f"{sample_path}: {exc}"
                )

        self.assertGreater(saved, 0, "Expected at least one aggregate sample")

    def test_forensic_samples(self):
        """Parse real forensic samples and feed them through the mock save."""
        sample_paths = glob("samples/forensic/*.eml")
        client, mock_conn = self._make_client()

        saved = 0
        for sample_path in sample_paths:
            try:
                parsed = parsedmarc.parse_report_file(
                    sample_path, offline=OFFLINE_MODE
                )
            except parsedmarc.ParserError:
                continue

            if parsed.get("report_type") != "forensic":
                continue

            reports = parsed["report"]
            if not isinstance(reports, list):
                reports = [reports]

            for report in reports:
                self._mock_cursor(mock_conn, [1])
                try:
                    client.save_forensic_report_to_postgresql(report)
                    saved += 1
                except Exception as exc:
                    self.fail(
                        f"save_forensic_report_to_postgresql failed for "
                        f"{sample_path}: {exc}"
                    )

        self.assertGreater(saved, 0, "Expected at least one forensic sample")

    def test_smtp_tls_samples(self):
        """Parse real SMTP TLS samples and feed them through the mock save."""
        sample_paths = glob("samples/smtp_tls/*")
        client, mock_conn = self._make_client()

        saved = 0
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            try:
                parsed = parsedmarc.parse_report_file(
                    sample_path, offline=OFFLINE_MODE
                )
            except parsedmarc.ParserError:
                continue

            if parsed.get("report_type") != "smtp_tls":
                continue

            report = parsed["report"]
            num_policies = len(report.get("policies", []))
            ids = list(range(1, 2 + num_policies))
            self._mock_cursor(mock_conn, ids)

            try:
                client.save_smtp_tls_report_to_postgresql(report)
                saved += 1
            except Exception as exc:
                self.fail(
                    f"save_smtp_tls_report_to_postgresql failed for "
                    f"{sample_path}: {exc}"
                )

        self.assertGreater(saved, 0, "Expected at least one SMTP TLS sample")


if __name__ == "__main__":
    unittest.main(verbosity=2)
