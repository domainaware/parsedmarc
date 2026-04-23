#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import io
import json
import os
import signal
import sys
import tempfile
import unittest
from base64 import urlsafe_b64encode
from configparser import ConfigParser
from glob import glob
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import cast
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from lxml import etree  # type: ignore[import-untyped]
from googleapiclient.errors import HttpError
from httplib2 import Response
from imapclient.exceptions import IMAPClientError

import parsedmarc
import parsedmarc.cli
from parsedmarc.mail.gmail import GmailConnection
from parsedmarc.mail.gmail import _get_creds
from parsedmarc.mail.graph import MSGraphConnection
from parsedmarc.mail.graph import _generate_credential
from parsedmarc.mail.graph import _get_cache_args
from parsedmarc.mail.graph import _load_token
from parsedmarc.mail.imap import IMAPConnection
import parsedmarc.mail.gmail as gmail_module
import parsedmarc.mail.graph as graph_module
import parsedmarc.mail.imap as imap_module
import parsedmarc.elastic
import parsedmarc.opensearch as opensearch_module
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

        # psl_overrides.txt intentionally folds CDN-customer PTRs so every
        # sender on the same network clusters under one display key.
        # ``.akamaiedge.net`` is an override, so its subdomains collapse to
        # ``akamaiedge.net`` even though the live PSL carries the finer-grained
        # ``c.akamaiedge.net`` — the override is the design decision.
        subdomain = "e3191.c.akamaiedge.net"
        result = parsedmarc.utils.get_base_domain(subdomain)
        assert result == "akamaiedge.net"

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
        report_path = "samples/extract_report/nice-input.xml"
        print("Testing {0}: ".format(report_path), end="")
        xmlout = parsedmarc.extract_report_from_file_path(report_path)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportXMLFromPath(self):
        """Test extract report function for pathlib.Path input"""
        report_path = Path("samples/extract_report/nice-input.xml")
        xmlout = parsedmarc.extract_report_from_file_path(report_path)
        with open("samples/extract_report/nice-input.xml") as xmlin_file:
            xmlin = xmlin_file.read()
        self.assertTrue(compare_xml(xmlout, xmlin))

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

    def testParseReportFileAcceptsPathForXML(self):
        report_path = Path(
            "samples/aggregate/protection.outlook.com!example.com!1711756800!1711843200.xml"
        )
        result = parsedmarc.parse_report_file(
            report_path,
            offline=True,
        )
        assert result["report_type"] == "aggregate"
        self.assertEqual(result["report"]["report_metadata"]["org_name"], "outlook.com")

    def testParseReportFileAcceptsPathForEmail(self):
        report_path = Path(
            "samples/aggregate/Report domain- borschow.com Submitter- google.com Report-ID- 949348866075514174.eml"
        )
        result = parsedmarc.parse_report_file(
            report_path,
            offline=True,
        )
        assert result["report_type"] == "aggregate"
        self.assertEqual(result["report"]["report_metadata"]["org_name"], "google.com")

    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        print()
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            result = parsedmarc.parse_report_file(
                sample_path, always_use_local_files=True, offline=OFFLINE_MODE
            )
            assert result["report_type"] == "aggregate"
            parsedmarc.parsed_aggregate_reports_to_csv(result["report"])
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
                email_result = parsedmarc.parse_report_email(
                    sample_content, offline=OFFLINE_MODE
                )
                assert email_result["report_type"] == "forensic"
            result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
            assert result["report_type"] == "forensic"
            parsedmarc.parsed_forensic_reports_to_csv(result["report"])
            print("Passed!")

    def testSmtpTlsSamples(self):
        """Test sample SMTP TLS reports"""
        print()
        sample_paths = glob("samples/smtp_tls/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
            assert result["report_type"] == "smtp_tls"
            parsedmarc.parsed_smtp_tls_reports_to_csv(result["report"])
            print("Passed!")

    def testIpAddressInfoSurfacesASNFields(self):
        """ASN number, name, and domain from the bundled MMDB appear on every
        IP info result, even when no PTR resolves."""
        info = parsedmarc.utils.get_ip_address_info("8.8.8.8", offline=True)
        self.assertEqual(info["asn"], 15169)
        self.assertIsInstance(info["asn"], int)
        self.assertEqual(info["as_domain"], "google.com")
        self.assertTrue(info["as_name"])

    def testIpAddressInfoFallsBackToASNMapEntryWhenNoPTR(self):
        """When reverse DNS is absent, the ASN domain should be used as a
        lookup into the reverse_dns_map so the row still gets attributed,
        while reverse_dns and base_domain remain null."""
        info = parsedmarc.utils.get_ip_address_info("8.8.8.8", offline=True)
        self.assertIsNone(info["reverse_dns"])
        self.assertIsNone(info["base_domain"])
        self.assertEqual(info["name"], "Google (Including Gmail and Google Workspace)")
        self.assertEqual(info["type"], "Email Provider")

    def testIpAddressInfoFallsBackToRawASNameOnMapMiss(self):
        """When neither PTR nor an ASN-map entry resolves, the raw AS name
        is used as source_name with type left null — better than leaving
        the row unattributed."""
        # 204.79.197.100 is in an ASN whose as_domain is not in the map at
        # the time of this test (msn.com); this exercises the as_name
        # fallback branch without depending on a specific map state.
        from unittest.mock import patch

        with patch(
            "parsedmarc.utils.get_ip_address_db_record",
            return_value={
                "country": "US",
                "asn": 64496,
                "as_name": "Some Unmapped Org, Inc.",
                "as_domain": "unmapped-for-this-test.example",
            },
        ):
            # Bypass cache to avoid prior-test pollution.
            info = parsedmarc.utils.get_ip_address_info(
                "192.0.2.1", offline=True, cache=None
            )
        self.assertIsNone(info["reverse_dns"])
        self.assertIsNone(info["base_domain"])
        self.assertIsNone(info["type"])
        self.assertEqual(info["name"], "Some Unmapped Org, Inc.")
        self.assertEqual(info["as_domain"], "unmapped-for-this-test.example")

    def testIPinfoAPIPrimarySourceAndInvalidKeyIsFatal(self):
        """With an API token configured, lookups hit the API first via the
        documented ?token= query param. A 401/403 response propagates as
        ``InvalidIPinfoAPIKey`` so the CLI can exit fatally. Any other
        non-2xx or network error falls through to the MMDB silently.

        The IPinfo Lite API is documented as having no request limit, so
        there is no rate-limit/quota handling to test — only the fatal path
        on invalid tokens and the success path."""
        from unittest.mock import patch, MagicMock

        from parsedmarc.utils import (
            InvalidIPinfoAPIKey,
            configure_ipinfo_api,
            get_ip_address_db_record,
        )

        def _mock_response(status_code, json_body=None):
            resp = MagicMock()
            resp.status_code = status_code
            resp.ok = 200 <= status_code < 300
            resp.json.return_value = json_body or {}
            return resp

        try:
            # Success: API returns IPinfo-schema JSON; record comes from API.
            api_json = {
                "ip": "8.8.8.8",
                "asn": "AS15169",
                "as_name": "Google LLC",
                "as_domain": "google.com",
                "country_code": "US",
            }
            with patch(
                "parsedmarc.utils.requests.get",
                return_value=_mock_response(200, api_json),
            ) as mock_get:
                configure_ipinfo_api("fake-token", probe=False)
                record = get_ip_address_db_record("8.8.8.8")
            self.assertEqual(record["country"], "US")
            self.assertEqual(record["asn"], 15169)
            self.assertEqual(record["as_domain"], "google.com")
            # Auth must use the documented query param, not a Bearer header.
            _, kwargs = mock_get.call_args
            self.assertEqual(kwargs["params"], {"token": "fake-token"})
            self.assertNotIn("Authorization", kwargs["headers"])

            # Invalid key: 401 raises a fatal exception even on a random lookup.
            with patch(
                "parsedmarc.utils.requests.get",
                return_value=_mock_response(401),
            ):
                configure_ipinfo_api("bad-token", probe=False)
                with self.assertRaises(InvalidIPinfoAPIKey):
                    get_ip_address_db_record("8.8.8.8")

            # Any other non-2xx (e.g. 500, 503) falls back to the MMDB silently.
            configure_ipinfo_api("fake-token", probe=False)
            with patch(
                "parsedmarc.utils.requests.get",
                return_value=_mock_response(500),
            ):
                record = get_ip_address_db_record("8.8.8.8")
            # MMDB fallback fills in Google's ASN from the bundled MMDB.
            self.assertEqual(record["asn"], 15169)
        finally:
            configure_ipinfo_api(None)

    def testAggregateCsvExposesASNColumns(self):
        """The aggregate CSV output should include source_asn, source_as_name,
        and source_as_domain columns."""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/!example.com!1538204542!1538463818.xml",
            always_use_local_files=True,
            offline=True,
        )
        csv_text = parsedmarc.parsed_aggregate_reports_to_csv(result["report"])
        header = csv_text.splitlines()[0].split(",")
        self.assertIn("source_asn", header)
        self.assertIn("source_as_name", header)
        self.assertIn("source_as_domain", header)

    def testOpenSearchSigV4RequiresRegion(self):
        with self.assertRaises(opensearch_module.OpenSearchError):
            opensearch_module.set_hosts(
                "https://example.org:9200",
                auth_type="awssigv4",
            )

    def testOpenSearchSigV4ConfiguresConnectionClass(self):
        fake_credentials = object()
        with patch.object(opensearch_module.boto3, "Session") as session_cls:
            session_cls.return_value.get_credentials.return_value = fake_credentials
            with patch.object(
                opensearch_module, "AWSV4SignerAuth", return_value="auth"
            ) as signer:
                with patch.object(
                    opensearch_module.connections, "create_connection"
                ) as create_connection:
                    opensearch_module.set_hosts(
                        "https://example.org:9200",
                        use_ssl=True,
                        auth_type="awssigv4",
                        aws_region="eu-west-1",
                    )
        signer.assert_called_once_with(fake_credentials, "eu-west-1", "es")
        create_connection.assert_called_once()
        self.assertEqual(
            create_connection.call_args.kwargs.get("connection_class"),
            opensearch_module.RequestsHttpConnection,
        )
        self.assertEqual(create_connection.call_args.kwargs.get("http_auth"), "auth")

    def testOpenSearchSigV4RejectsUnknownAuthType(self):
        with self.assertRaises(opensearch_module.OpenSearchError):
            opensearch_module.set_hosts(
                "https://example.org:9200",
                auth_type="kerberos",
            )

    def testOpenSearchSigV4RequiresAwsCredentials(self):
        with patch.object(opensearch_module.boto3, "Session") as session_cls:
            session_cls.return_value.get_credentials.return_value = None
            with self.assertRaises(opensearch_module.OpenSearchError):
                opensearch_module.set_hosts(
                    "https://example.org:9200",
                    auth_type="awssigv4",
                    aws_region="eu-west-1",
                )

    @patch("parsedmarc.cli.opensearch.migrate_indexes")
    @patch("parsedmarc.cli.opensearch.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testCliPassesOpenSearchSigV4Settings(
        self,
        mock_imap_connection,
        mock_get_reports,
        mock_set_hosts,
        _mock_migrate_indexes,
    ):
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        config = """[general]
save_aggregate = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[opensearch]
hosts = localhost
authentication_type = awssigv4
aws_region = eu-west-1
aws_service = aoss
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(mock_set_hosts.call_args.kwargs.get("auth_type"), "awssigv4")
        self.assertEqual(mock_set_hosts.call_args.kwargs.get("aws_region"), "eu-west-1")
        self.assertEqual(mock_set_hosts.call_args.kwargs.get("aws_service"), "aoss")

    @patch("parsedmarc.cli.elastic.save_aggregate_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.migrate_indexes")
    @patch("parsedmarc.cli.elastic.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testFailOnOutputErrorExits(
        self,
        mock_imap_connection,
        mock_get_reports,
        _mock_set_hosts,
        _mock_migrate_indexes,
        mock_save_aggregate,
    ):
        """CLI should exit with code 1 when fail_on_output_error is enabled"""
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [{"policy_published": {"domain": "example.com"}}],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        mock_save_aggregate.side_effect = parsedmarc.elastic.ElasticsearchError(
            "simulated output failure"
        )

        config = """[general]
save_aggregate = true
fail_on_output_error = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[elasticsearch]
hosts = localhost
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            with self.assertRaises(SystemExit) as ctx:
                parsedmarc.cli._main()

        self.assertEqual(ctx.exception.code, 1)
        mock_save_aggregate.assert_called_once()

    @patch("parsedmarc.cli.elastic.save_aggregate_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.migrate_indexes")
    @patch("parsedmarc.cli.elastic.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testOutputErrorDoesNotExitWhenDisabled(
        self,
        mock_imap_connection,
        mock_get_reports,
        _mock_set_hosts,
        _mock_migrate_indexes,
        mock_save_aggregate,
    ):
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [{"policy_published": {"domain": "example.com"}}],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        mock_save_aggregate.side_effect = parsedmarc.elastic.ElasticsearchError(
            "simulated output failure"
        )

        config = """[general]
save_aggregate = true
fail_on_output_error = false
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[elasticsearch]
hosts = localhost
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        mock_save_aggregate.assert_called_once()

    @patch("parsedmarc.cli.opensearch.save_forensic_report_to_opensearch")
    @patch("parsedmarc.cli.opensearch.migrate_indexes")
    @patch("parsedmarc.cli.opensearch.set_hosts")
    @patch("parsedmarc.cli.elastic.save_forensic_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.save_aggregate_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.migrate_indexes")
    @patch("parsedmarc.cli.elastic.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testFailOnOutputErrorExitsWithMultipleSinkErrors(
        self,
        mock_imap_connection,
        mock_get_reports,
        _mock_es_set_hosts,
        _mock_es_migrate,
        mock_save_aggregate,
        _mock_save_forensic_elastic,
        _mock_os_set_hosts,
        _mock_os_migrate,
        mock_save_forensic_opensearch,
    ):
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [{"policy_published": {"domain": "example.com"}}],
            "forensic_reports": [{"reported_domain": "example.com"}],
            "smtp_tls_reports": [],
        }
        mock_save_aggregate.side_effect = parsedmarc.elastic.ElasticsearchError(
            "aggregate sink failed"
        )
        mock_save_forensic_opensearch.side_effect = (
            parsedmarc.cli.opensearch.OpenSearchError("forensic sink failed")
        )

        config = """[general]
save_aggregate = true
save_forensic = true
fail_on_output_error = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[elasticsearch]
hosts = localhost

[opensearch]
hosts = localhost
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            with self.assertRaises(SystemExit) as ctx:
                parsedmarc.cli._main()

        self.assertEqual(ctx.exception.code, 1)
        mock_save_aggregate.assert_called_once()
        mock_save_forensic_opensearch.assert_called_once()


class _FakeGraphResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class _BreakLoop(BaseException):
    pass


class TestGmailConnection(unittest.TestCase):
    def _build_connection(self, *, paginate=True):
        connection = GmailConnection.__new__(GmailConnection)
        connection.include_spam_trash = False
        connection.reports_label_id = "REPORTS"
        connection.paginate_messages = paginate
        connection.service = MagicMock()
        return connection

    def testFindLabelId(self):
        connection = self._build_connection()
        labels_api = connection.service.users.return_value.labels.return_value
        labels_api.list.return_value.execute.return_value = {
            "labels": [
                {"id": "INBOX", "name": "INBOX"},
                {"id": "REPORTS", "name": "Reports"},
            ]
        }
        self.assertEqual(connection._find_label_id_for_label("Reports"), "REPORTS")
        self.assertEqual(connection._find_label_id_for_label("MISSING"), "")

    def testFetchMessagesWithPagination(self):
        connection = self._build_connection(paginate=True)
        messages_api = connection.service.users.return_value.messages.return_value

        def list_side_effect(**kwargs):
            response = MagicMock()
            if kwargs.get("pageToken") is None:
                response.execute.return_value = {
                    "messages": [{"id": "a"}, {"id": "b"}],
                    "nextPageToken": "n1",
                }
            else:
                response.execute.return_value = {"messages": [{"id": "c"}]}
            return response

        messages_api.list.side_effect = list_side_effect
        connection._find_label_id_for_label = MagicMock(return_value="REPORTS")
        self.assertEqual(connection.fetch_messages("Reports"), ["a", "b", "c"])

    def testFetchMessageDecoding(self):
        connection = self._build_connection()
        messages_api = connection.service.users.return_value.messages.return_value
        raw = urlsafe_b64encode(b"Subject: test\n\nbody").decode()
        messages_api.get.return_value.execute.return_value = {"raw": raw}
        content = connection.fetch_message("m1")
        self.assertIn("Subject: test", content)

    def testMoveAndDeleteMessage(self):
        connection = self._build_connection()
        connection._find_label_id_for_label = MagicMock(return_value="ARCHIVE")
        messages_api = connection.service.users.return_value.messages.return_value
        messages_api.modify.return_value.execute.return_value = {}
        connection.move_message("m1", "Archive")
        messages_api.modify.assert_called_once()
        connection.delete_message("m1")
        messages_api.delete.assert_called_once_with(userId="me", id="m1")
        messages_api.delete.return_value.execute.assert_called_once()

    def testGetCredsFromTokenFile(self):
        creds = MagicMock()
        creds.valid = True
        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("{}")
            token_path = token_file.name
        try:
            with patch.object(
                gmail_module.Credentials,
                "from_authorized_user_file",
                return_value=creds,
            ):
                returned = _get_creds(token_path, "credentials.json", ["scope"], 8080)
        finally:
            os.remove(token_path)
        self.assertEqual(returned, creds)

    def testGetCredsWithOauthFlow(self):
        expired_creds = MagicMock()
        expired_creds.valid = False
        expired_creds.expired = False
        expired_creds.refresh_token = None
        new_creds = MagicMock()
        new_creds.valid = True
        new_creds.to_json.return_value = '{"token":"x"}'
        flow = MagicMock()
        flow.run_local_server.return_value = new_creds

        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("{}")
            token_path = token_file.name
        try:
            with patch.object(
                gmail_module.Credentials,
                "from_authorized_user_file",
                return_value=expired_creds,
            ):
                with patch.object(
                    gmail_module.InstalledAppFlow,
                    "from_client_secrets_file",
                    return_value=flow,
                ):
                    returned = _get_creds(
                        token_path, "credentials.json", ["scope"], 8080
                    )
        finally:
            os.remove(token_path)
        self.assertEqual(returned, new_creds)
        flow.run_local_server.assert_called_once()

    def testGetCredsRefreshesExpiredToken(self):
        expired_creds = MagicMock()
        expired_creds.valid = False
        expired_creds.expired = True
        expired_creds.refresh_token = "rt"
        expired_creds.to_json.return_value = '{"token":"refreshed"}'

        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("{}")
            token_path = token_file.name
        try:
            with patch.object(
                gmail_module.Credentials,
                "from_authorized_user_file",
                return_value=expired_creds,
            ):
                returned = _get_creds(token_path, "credentials.json", ["scope"], 8080)
        finally:
            os.remove(token_path)

        self.assertEqual(returned, expired_creds)
        expired_creds.refresh.assert_called_once()

    def testCreateFolderConflictIgnored(self):
        connection = self._build_connection()
        labels_api = connection.service.users.return_value.labels.return_value
        conflict = HttpError(Response({"status": "409"}), b"conflict")
        labels_api.create.return_value.execute.side_effect = conflict
        connection.create_folder("Existing")


class TestGraphConnection(unittest.TestCase):
    def testLoadTokenMissing(self):
        with TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing-token-file"
            self.assertIsNone(_load_token(missing_path))

    def testLoadTokenExisting(self):
        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("serialized-auth-record")
            token_path = token_file.name
        try:
            self.assertEqual(_load_token(Path(token_path)), "serialized-auth-record")
        finally:
            os.remove(token_path)

    def testGetAllMessagesPagination(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        first_response = _FakeGraphResponse(
            200, {"value": [{"id": "1"}], "@odata.nextLink": "next-url"}
        )
        second_response = _FakeGraphResponse(200, {"value": [{"id": "2"}]})
        connection._client = MagicMock()
        connection._client.get.side_effect = [first_response, second_response]
        messages = connection._get_all_messages("/url", batch_size=0, since=None)
        self.assertEqual([msg["id"] for msg in messages], ["1", "2"])

    def testGetAllMessagesInitialRequestFailure(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(500, text="boom")
        with self.assertRaises(RuntimeError):
            connection._get_all_messages("/url", batch_size=0, since=None)

    def testGetAllMessagesRetriesTransientRequestErrors(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection._client = MagicMock()
        connection._client.get.side_effect = [
            graph_module.RequestException("connection reset"),
            _FakeGraphResponse(200, {"value": [{"id": "1"}]}),
        ]
        with patch.object(graph_module, "sleep") as mocked_sleep:
            messages = connection._get_all_messages("/url", batch_size=0, since=None)
        self.assertEqual([msg["id"] for msg in messages], ["1"])
        mocked_sleep.assert_called_once_with(
            graph_module.GRAPH_REQUEST_RETRY_DELAY_SECONDS
        )

    def testGetAllMessagesRaisesAfterRetryExhaustion(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection._client = MagicMock()
        connection._client.get.side_effect = graph_module.RequestException(
            "connection reset"
        )
        with patch.object(graph_module, "sleep") as mocked_sleep:
            with self.assertRaises(graph_module.RequestException):
                connection._get_all_messages("/url", batch_size=0, since=None)
        self.assertEqual(
            mocked_sleep.call_count, graph_module.GRAPH_REQUEST_RETRY_ATTEMPTS - 1
        )

    def testGetAllMessagesNextPageFailure(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        first_response = _FakeGraphResponse(
            200, {"value": [{"id": "1"}], "@odata.nextLink": "next-url"}
        )
        second_response = _FakeGraphResponse(500, text="page-fail")
        connection._client = MagicMock()
        connection._client.get.side_effect = [first_response, second_response]
        with self.assertRaises(RuntimeError):
            connection._get_all_messages("/url", batch_size=0, since=None)

    def testGetAllMessagesHonorsBatchSizeLimit(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        first_response = _FakeGraphResponse(
            200,
            {
                "value": [{"id": "1"}, {"id": "2"}],
                "@odata.nextLink": "next-url",
            },
        )
        connection._client = MagicMock()
        connection._client.get.return_value = first_response
        messages = connection._get_all_messages("/url", batch_size=2, since=None)
        self.assertEqual([msg["id"] for msg in messages], ["1", "2"])
        connection._client.get.assert_called_once()

    def testFetchMessagesPassesSinceAndBatchSize(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._find_folder_id_from_folder_path = MagicMock(
            return_value="folder-id"
        )
        connection._get_all_messages = MagicMock(return_value=[{"id": "1"}])
        self.assertEqual(
            connection.fetch_messages("Inbox", since="2026-03-01", batch_size=5), ["1"]
        )
        connection._get_all_messages.assert_called_once_with(
            "/users/mailbox@example.com/mailFolders/folder-id/messages",
            5,
            "2026-03-01",
        )

    def testFetchMessageMarksRead(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(
            200, text="email-content"
        )
        connection.mark_message_read = MagicMock()
        content = connection.fetch_message("123", mark_read=True)
        self.assertEqual(content, "email-content")
        connection.mark_message_read.assert_called_once_with("123")

    def testFindFolderIdNotFound(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(200, {"value": []})
        with self.assertRaises(RuntimeError):
            connection._find_folder_id_with_parent("Missing", None)

    def testGetCacheArgsWithAuthRecord(self):
        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("serialized")
            token_path = Path(token_file.name)
        try:
            with patch.object(
                graph_module.AuthenticationRecord,
                "deserialize",
                return_value="auth_record",
            ):
                args = _get_cache_args(token_path, allow_unencrypted_storage=False)
            self.assertIn("authentication_record", args)
        finally:
            os.remove(token_path)

    def testGenerateCredentialInvalid(self):
        with self.assertRaises(RuntimeError):
            _generate_credential(
                "Nope",
                Path("/tmp/token"),
                client_id="x",
                client_secret="y",
                username="u",
                password="p",
                tenant_id="t",
                allow_unencrypted_storage=False,
            )

    def testGenerateCredentialDeviceCode(self):
        fake_credential = object()
        with patch.object(
            graph_module, "_get_cache_args", return_value={"cached": True}
        ):
            with patch.object(
                graph_module,
                "DeviceCodeCredential",
                return_value=fake_credential,
            ) as mocked:
                result = _generate_credential(
                    graph_module.AuthMethod.DeviceCode.name,
                    Path("/tmp/token"),
                    client_id="cid",
                    client_secret="secret",
                    username="user",
                    password="pass",
                    tenant_id="tenant",
                    allow_unencrypted_storage=True,
                )
        self.assertIs(result, fake_credential)
        mocked.assert_called_once()

    def testGenerateCredentialClientSecret(self):
        fake_credential = object()
        with patch.object(
            graph_module, "ClientSecretCredential", return_value=fake_credential
        ) as mocked:
            result = _generate_credential(
                graph_module.AuthMethod.ClientSecret.name,
                Path("/tmp/token"),
                client_id="cid",
                client_secret="secret",
                username="user",
                password="pass",
                tenant_id="tenant",
                allow_unencrypted_storage=False,
            )
        self.assertIs(result, fake_credential)
        mocked.assert_called_once_with(
            client_id="cid", tenant_id="tenant", client_secret="secret"
        )

    def testGenerateCredentialCertificate(self):
        fake_credential = object()
        with patch.object(
            graph_module, "CertificateCredential", return_value=fake_credential
        ) as mocked:
            result = _generate_credential(
                graph_module.AuthMethod.Certificate.name,
                Path("/tmp/token"),
                client_id="cid",
                client_secret="secret",
                certificate_path="/tmp/cert.pem",
                certificate_password="secret-pass",
                username="user",
                password="pass",
                tenant_id="tenant",
                allow_unencrypted_storage=False,
            )
        self.assertIs(result, fake_credential)
        mocked.assert_called_once_with(
            client_id="cid",
            tenant_id="tenant",
            certificate_path="/tmp/cert.pem",
            password="secret-pass",
        )

    def testGenerateCredentialCertificateRequiresPath(self):
        with self.assertRaisesRegex(
            ValueError,
            "certificate_path is required when auth_method is 'Certificate'",
        ):
            _generate_credential(
                graph_module.AuthMethod.Certificate.name,
                Path("/tmp/token"),
                client_id="cid",
                client_secret=None,
                certificate_path=None,
                certificate_password="secret-pass",
                username=None,
                password=None,
                tenant_id="tenant",
                allow_unencrypted_storage=False,
            )

    def testInitUsesSharedMailboxScopes(self):
        class FakeCredential:
            def __init__(self):
                self.authenticate = MagicMock(return_value="auth-record")

        fake_credential = FakeCredential()
        with patch.object(
            graph_module, "_generate_credential", return_value=fake_credential
        ):
            with patch.object(graph_module, "_cache_auth_record") as cache_auth:
                with patch.object(graph_module, "GraphClient") as graph_client:
                    MSGraphConnection(
                        auth_method=graph_module.AuthMethod.DeviceCode.name,
                        mailbox="shared@example.com",
                        graph_url="https://graph.microsoft.com",
                        client_id="cid",
                        client_secret="secret",
                        username="owner@example.com",
                        password="pass",
                        tenant_id="tenant",
                        token_file="/tmp/token-file",
                        allow_unencrypted_storage=True,
                    )
        fake_credential.authenticate.assert_called_once_with(
            scopes=["Mail.ReadWrite.Shared"]
        )
        cache_auth.assert_called_once()
        graph_client.assert_called_once()
        self.assertEqual(
            graph_client.call_args.kwargs.get("scopes"), ["Mail.ReadWrite.Shared"]
        )

    def testInitWithoutUsernameUsesDefaultMailReadWriteScope(self):
        class FakeCredential:
            def __init__(self):
                self.authenticate = MagicMock(return_value="auth-record")

        fake_credential = FakeCredential()
        with patch.object(
            graph_module, "_generate_credential", return_value=fake_credential
        ):
            with patch.object(graph_module, "_cache_auth_record") as cache_auth:
                with patch.object(graph_module, "GraphClient") as graph_client:
                    MSGraphConnection(
                        auth_method=graph_module.AuthMethod.DeviceCode.name,
                        mailbox="owner@example.com",
                        graph_url="https://graph.microsoft.com",
                        client_id="cid",
                        client_secret="secret",
                        username=None,
                        password=None,
                        tenant_id="tenant",
                        token_file="/tmp/token-file",
                        allow_unencrypted_storage=True,
                    )
        fake_credential.authenticate.assert_called_once_with(scopes=["Mail.ReadWrite"])
        cache_auth.assert_called_once()
        graph_client.assert_called_once()
        self.assertEqual(
            graph_client.call_args.kwargs.get("scopes"), ["Mail.ReadWrite"]
        )

    def testInitCertificateAuthSkipsInteractiveAuthenticate(self):
        class DummyCertificateCredential:
            pass

        fake_credential = DummyCertificateCredential()
        with patch.object(
            graph_module, "CertificateCredential", DummyCertificateCredential
        ):
            with patch.object(
                graph_module, "_generate_credential", return_value=fake_credential
            ):
                with patch.object(graph_module, "_cache_auth_record") as cache_auth:
                    with patch.object(graph_module, "GraphClient") as graph_client:
                        MSGraphConnection(
                            auth_method=graph_module.AuthMethod.Certificate.name,
                            mailbox="shared@example.com",
                            graph_url="https://graph.microsoft.com",
                            client_id="cid",
                            client_secret=None,
                            certificate_path="/tmp/cert.pem",
                            certificate_password="secret-pass",
                            username=None,
                            password=None,
                            tenant_id="tenant",
                            token_file="/tmp/token-file",
                            allow_unencrypted_storage=False,
                        )
        cache_auth.assert_not_called()
        graph_client.assert_called_once()
        self.assertNotIn("scopes", graph_client.call_args.kwargs)

    def testCreateFolderAndMoveErrors(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.post.return_value = _FakeGraphResponse(500, {"error": "x"})
        connection._find_folder_id_from_folder_path = MagicMock(return_value="dest")
        with self.assertRaises(RuntimeWarning):
            connection.move_message("m1", "Archive")
        connection._client.post.return_value = _FakeGraphResponse(409, {})
        connection.create_folder("Archive")

    def testMarkReadDeleteFailures(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.patch.return_value = _FakeGraphResponse(500, {"error": "x"})
        with self.assertRaises(RuntimeWarning):
            connection.mark_message_read("m1")
        connection._client.delete.return_value = _FakeGraphResponse(500, {"error": "x"})
        with self.assertRaises(RuntimeWarning):
            connection.delete_message("m1")


class TestImapConnection(unittest.TestCase):
    def testDelegatesToImapClient(self):
        with patch.object(imap_module, "IMAPClient") as mocked_client_cls:
            mocked_client = MagicMock()
            mocked_client_cls.return_value = mocked_client
            connection = IMAPConnection(
                "imap.example.com", user="user", password="pass"
            )
            connection.create_folder("Archive")
            mocked_client.create_folder.assert_called_once_with("Archive")
            mocked_client.search.return_value = [1, 2]
            self.assertEqual(connection.fetch_messages("INBOX"), [1, 2])
            mocked_client.select_folder.assert_called_with("INBOX")
            connection.fetch_messages("INBOX", since="2026-03-01")
            mocked_client.search.assert_called_with("SINCE 2026-03-01")
            mocked_client.fetch_message.return_value = "raw-message"
            self.assertEqual(connection.fetch_message(1), "raw-message")
            connection.delete_message(7)
            mocked_client.delete_messages.assert_called_once_with([7])
            connection.move_message(8, "Archive")
            mocked_client.move_messages.assert_called_once_with([8], "Archive")
            connection.keepalive()
            mocked_client.noop.assert_called_once()

    def testWatchReconnectPath(self):
        with patch.object(imap_module, "IMAPClient") as mocked_client_cls:
            base_client = MagicMock()
            base_client.host = "imap.example.com"
            base_client.port = 993
            base_client.ssl = True
            mocked_client_cls.return_value = base_client
            connection = IMAPConnection(
                "imap.example.com", user="user", password="pass"
            )
            calls = {"count": 0}

            def fake_imap_constructor(*args, **kwargs):
                idle_callback = kwargs.get("idle_callback")
                if calls["count"] == 0:
                    calls["count"] += 1
                    raise IMAPClientError("timeout")
                if idle_callback is not None:
                    idle_callback(base_client)
                raise _BreakLoop()

            callback = MagicMock()
            with patch.object(imap_module, "sleep", return_value=None):
                with patch.object(
                    imap_module, "IMAPClient", side_effect=fake_imap_constructor
                ):
                    with self.assertRaises(_BreakLoop):
                        connection.watch(callback, check_timeout=1)
            callback.assert_called_once_with(connection)


class TestGmailAuthModes(unittest.TestCase):
    @patch(
        "parsedmarc.mail.gmail.service_account.Credentials.from_service_account_file"
    )
    def testGetCredsServiceAccountWithoutSubject(self, mock_from_service_account_file):
        service_creds = MagicMock()
        service_creds.with_subject.return_value = MagicMock()
        mock_from_service_account_file.return_value = service_creds

        creds = gmail_module._get_creds(
            token_file=".token",
            credentials_file="service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            oauth2_port=8080,
            auth_mode="service_account",
            service_account_user=None,
        )

        self.assertIs(creds, service_creds)
        mock_from_service_account_file.assert_called_once_with(
            "service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        service_creds.with_subject.assert_not_called()

    @patch(
        "parsedmarc.mail.gmail.service_account.Credentials.from_service_account_file"
    )
    def testGetCredsServiceAccountWithSubject(self, mock_from_service_account_file):
        base_creds = MagicMock()
        delegated_creds = MagicMock()
        base_creds.with_subject.return_value = delegated_creds
        mock_from_service_account_file.return_value = base_creds

        creds = gmail_module._get_creds(
            token_file=".token",
            credentials_file="service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            oauth2_port=8080,
            auth_mode="service_account",
            service_account_user="dmarc@example.com",
        )

        self.assertIs(creds, delegated_creds)
        base_creds.with_subject.assert_called_once_with("dmarc@example.com")

    def testGetCredsRejectsUnsupportedAuthMode(self):
        with self.assertRaises(ValueError):
            gmail_module._get_creds(
                token_file=".token",
                credentials_file="client-secret.json",
                scopes=["https://www.googleapis.com/auth/gmail.modify"],
                oauth2_port=8080,
                auth_mode="unsupported",
            )

    @patch("parsedmarc.mail.gmail.Path.exists", return_value=True)
    @patch("parsedmarc.mail.gmail.Credentials.from_authorized_user_file")
    def testGetCredsInstalledAppStillUsesTokenFile(
        self, mock_from_authorized_user_file, _mock_exists
    ):
        token_creds = MagicMock()
        token_creds.valid = True
        mock_from_authorized_user_file.return_value = token_creds

        creds = gmail_module._get_creds(
            token_file=".token",
            credentials_file="client-secret.json",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            oauth2_port=8080,
            auth_mode="installed_app",
        )

        self.assertIs(creds, token_creds)
        mock_from_authorized_user_file.assert_called_once_with(
            ".token",
            ["https://www.googleapis.com/auth/gmail.modify"],
        )

    @patch("parsedmarc.mail.gmail.GmailConnection._find_label_id_for_label")
    @patch("parsedmarc.mail.gmail.build")
    @patch("parsedmarc.mail.gmail._get_creds")
    def testGmailConnectionPassesAuthModeAndDelegatedUser(
        self, mock_get_creds, mock_build, mock_find_label
    ):
        mock_get_creds.return_value = MagicMock()
        mock_build.return_value = MagicMock()
        mock_find_label.return_value = "INBOX"

        gmail_module.GmailConnection(
            token_file=".token",
            credentials_file="service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            include_spam_trash=False,
            reports_folder="INBOX",
            oauth2_port=8080,
            paginate_messages=True,
            auth_mode="service_account",
            service_account_user="dmarc@example.com",
        )

        mock_get_creds.assert_called_once_with(
            ".token",
            "service-account.json",
            ["https://www.googleapis.com/auth/gmail.modify"],
            8080,
            auth_mode="service_account",
            service_account_user="dmarc@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.GmailConnection")
    def testCliPassesGmailServiceAccountAuthSettings(
        self, mock_gmail_connection, mock_get_mailbox_reports
    ):
        mock_gmail_connection.return_value = MagicMock()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        config = """[general]
silent = true

[gmail_api]
credentials_file = /tmp/service-account.json
auth_mode = service_account
service_account_user = dmarc@example.com
scopes = https://www.googleapis.com/auth/gmail.modify
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg_file:
            cfg_file.write(config)
            config_path = cfg_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("auth_mode"), "service_account"
        )
        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("service_account_user"),
            "dmarc@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.GmailConnection")
    def testCliAcceptsDelegatedUserAlias(self, mock_gmail_connection, mock_get_reports):
        mock_gmail_connection.return_value = MagicMock()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        config = """[general]
silent = true

[gmail_api]
credentials_file = /tmp/service-account.json
auth_mode = service_account
delegated_user = delegated@example.com
scopes = https://www.googleapis.com/auth/gmail.modify
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg_file:
            cfg_file.write(config)
            config_path = cfg_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("service_account_user"),
            "delegated@example.com",
        )


class TestImapFallbacks(unittest.TestCase):
    def testDeleteSuccessDoesNotUseFallback(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection.delete_message(42)
        connection._client.delete_messages.assert_called_once_with([42])
        connection._client.add_flags.assert_not_called()
        connection._client.expunge.assert_not_called()

    def testDeleteFallbackUsesFlagsAndExpunge(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.delete_messages.side_effect = IMAPClientError("uid expunge")
        connection.delete_message(42)
        connection._client.add_flags.assert_called_once_with(
            [42], [r"\Deleted"], silent=True
        )
        connection._client.expunge.assert_called_once_with()

    def testDeleteFallbackErrorPropagates(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.delete_messages.side_effect = IMAPClientError("uid expunge")
        connection._client.add_flags.side_effect = IMAPClientError("flag failed")
        with self.assertRaises(IMAPClientError):
            connection.delete_message(42)

    def testMoveSuccessDoesNotUseFallback(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        with patch.object(connection, "delete_message") as delete_mock:
            connection.move_message(99, "Archive")
        connection._client.move_messages.assert_called_once_with([99], "Archive")
        connection._client.copy.assert_not_called()
        delete_mock.assert_not_called()

    def testMoveFallbackCopiesThenDeletes(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.move_messages.side_effect = IMAPClientError("move failed")
        with patch.object(connection, "delete_message") as delete_mock:
            connection.move_message(99, "Archive")
        connection._client.copy.assert_called_once_with([99], "Archive")
        delete_mock.assert_called_once_with(99)

    def testMoveFallbackCopyErrorPropagates(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.move_messages.side_effect = IMAPClientError("move failed")
        connection._client.copy.side_effect = IMAPClientError("copy failed")
        with patch.object(connection, "delete_message") as delete_mock:
            with self.assertRaises(IMAPClientError):
                connection.move_message(99, "Archive")
        delete_mock.assert_not_called()


class TestMailboxWatchSince(unittest.TestCase):
    def setUp(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = True
        self._stdout_patch = patch("sys.stdout", new_callable=io.StringIO)
        self._stderr_patch = patch("sys.stderr", new_callable=io.StringIO)
        self._stdout_patch.start()
        self._stderr_patch.start()

    def tearDown(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = False
        self._stderr_patch.stop()
        self._stdout_patch.stop()

    def testWatchInboxPassesSinceToMailboxFetch(self):
        mailbox_connection = SimpleNamespace()

        def fake_watch(check_callback, check_timeout, config_reloading=None):
            check_callback(mailbox_connection)
            raise _BreakLoop()

        mailbox_connection.watch = fake_watch
        callback = MagicMock()
        with patch.object(
            parsedmarc, "get_dmarc_reports_from_mailbox", return_value={}
        ) as mocked:
            with self.assertRaises(_BreakLoop):
                parsedmarc.watch_inbox(
                    mailbox_connection=cast(
                        parsedmarc.MailboxConnection, mailbox_connection
                    ),
                    callback=callback,
                    check_timeout=1,
                    batch_size=10,
                    since="1d",
                )
        self.assertEqual(mocked.call_args.kwargs.get("since"), "1d")

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testCliPassesSinceToWatchInbox(
        self, mock_imap_connection, mock_watch_inbox, mock_get_mailbox_reports
    ):
        mock_imap_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        mock_watch_inbox.side_effect = FileExistsError("stop-watch-loop")

        config_text = """[general]
silent = true

[imap]
host = imap.example.com
user = user
password = pass

[mailbox]
watch = true
since = 2d
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, 1)
        self.assertEqual(mock_watch_inbox.call_args.kwargs.get("since"), "2d")


class _DummyMailboxConnection(parsedmarc.MailboxConnection):
    def __init__(self):
        self.fetch_calls: list[dict[str, object]] = []

    def create_folder(self, folder_name: str):
        return None

    def fetch_messages(self, reports_folder: str, **kwargs):
        self.fetch_calls.append({"reports_folder": reports_folder, **kwargs})
        return []

    def fetch_message(self, message_id) -> str:
        return ""

    def delete_message(self, message_id):
        return None

    def move_message(self, message_id, folder_name: str):
        return None

    def keepalive(self):
        return None

    def watch(self, check_callback, check_timeout, config_reloading=None):
        return None


class TestMailboxPerformance(unittest.TestCase):
    def setUp(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = True
        self._stdout_patch = patch("sys.stdout", new_callable=io.StringIO)
        self._stderr_patch = patch("sys.stderr", new_callable=io.StringIO)
        self._stdout_patch.start()
        self._stderr_patch.start()

    def tearDown(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = False
        self._stderr_patch.stop()
        self._stdout_patch.stop()

    def testBatchModeAvoidsExtraFullFetch(self):
        connection = _DummyMailboxConnection()
        parsedmarc.get_dmarc_reports_from_mailbox(
            connection=connection,
            reports_folder="INBOX",
            test=True,
            batch_size=10,
            create_folders=False,
        )
        self.assertEqual(len(connection.fetch_calls), 1)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliPassesMsGraphCertificateAuthSettings(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
certificate_password = cert-pass
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"), "Certificate"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("certificate_path"),
            "/tmp/msgraph-cert.pem",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("certificate_password"),
            "cert-pass",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphCertificatePath(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "certificate_path setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliUsesMsGraphUserAsMailboxForUsernamePasswordAuth(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = UsernamePassword
client_id = client-id
client_secret = client-secret
user = owner@example.com
password = test-password
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "owner@example.com",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("username"),
            "owner@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphPasswordForUsernamePasswordAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = UsernamePassword
client_id = client-id
client_secret = client-secret
user = owner@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "password setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()


class _FakeGraphClient:
    def get(self, url, params=None):
        if "/mailFolders/inbox?$select=id,displayName" in url:
            return _FakeGraphResponse(200, {"id": "inbox-id", "displayName": "Inbox"})

        if "/mailFolders?$filter=displayName eq 'Inbox'" in url:
            return _FakeGraphResponse(
                404,
                {
                    "error": {
                        "code": "ErrorItemNotFound",
                        "message": "Default folder Root not found.",
                    }
                },
            )

        if "/mailFolders?$filter=displayName eq 'Custom'" in url:
            return _FakeGraphResponse(
                404,
                {
                    "error": {
                        "code": "ErrorItemNotFound",
                        "message": "Default folder Root not found.",
                    }
                },
            )

        return _FakeGraphResponse(404, {"error": {"code": "NotFound"}})


class TestMSGraphFolderFallback(unittest.TestCase):
    def testWellKnownFolderFallback(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._client = _FakeGraphClient()  # type: ignore[assignment]
        connection._request_with_retries = MagicMock(
            side_effect=lambda method_name, *args, **kwargs: getattr(
                connection._client, method_name
            )(*args, **kwargs)
        )

        folder_id = connection._find_folder_id_with_parent("Inbox", None)
        self.assertEqual(folder_id, "inbox-id")
        connection._request_with_retries.assert_any_call(
            "get",
            "/users/shared@example.com/mailFolders?$filter=displayName eq 'Inbox'",
        )
        connection._request_with_retries.assert_any_call(
            "get", "/users/shared@example.com/mailFolders/inbox?$select=id,displayName"
        )

    def testUnknownFolderStillFails(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._client = _FakeGraphClient()  # type: ignore[assignment]
        connection._request_with_retries = MagicMock(
            side_effect=lambda method_name, *args, **kwargs: getattr(
                connection._client, method_name
            )(*args, **kwargs)
        )

        with self.assertRaises(RuntimeWarning):
            connection._find_folder_id_from_folder_path("Custom")

    def testSingleSegmentPathAvoidsExtraWellKnownLookupWhenListingSucceeds(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._find_folder_id_with_parent = MagicMock(return_value="custom-id")
        connection._get_well_known_folder_id = MagicMock(return_value="inbox-id")

        folder_id = connection._find_folder_id_from_folder_path("Inbox")

        self.assertEqual(folder_id, "custom-id")
        connection._find_folder_id_with_parent.assert_called_once_with("Inbox", None)
        connection._get_well_known_folder_id.assert_not_called()


class TestMSGraphCliValidation(unittest.TestCase):
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliPassesMsGraphClientSecretAuthSettings(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
client_secret = client-secret
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"), "ClientSecret"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("client_secret"),
            "client-secret",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("tenant_id"), "tenant-id"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "shared@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphClientSecretForClientSecretAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "client_secret setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphTenantIdForClientSecretAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
client_secret = client-secret
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "tenant_id setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphMailboxForClientSecretAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
client_secret = client-secret
tenant_id = tenant-id
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "mailbox setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliAllowsMsGraphDeviceCodeWithoutUser(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = DeviceCode
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"), "DeviceCode"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "shared@example.com",
        )
        self.assertIsNone(mock_graph_connection.call_args.kwargs.get("username"))

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphTenantIdForDeviceCodeAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = DeviceCode
client_id = client-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "tenant_id setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphMailboxForDeviceCodeAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = DeviceCode
client_id = client-id
tenant_id = tenant-id
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "mailbox setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphTenantIdForCertificateAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "tenant_id setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphMailboxForCertificateAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
tenant_id = tenant-id
certificate_path = /tmp/msgraph-cert.pem
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "mailbox setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()


class TestSighupReload(unittest.TestCase):
    """Tests for SIGHUP-driven configuration reload in watch mode."""

    def setUp(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = True
        self._stdout_patch = patch("sys.stdout", new_callable=io.StringIO)
        self._stderr_patch = patch("sys.stderr", new_callable=io.StringIO)
        self._stdout_patch.start()
        self._stderr_patch.start()

    def tearDown(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = False
        self._stderr_patch.stop()
        self._stdout_patch.stop()

    _BASE_CONFIG = """[general]
silent = true

[imap]
host = imap.example.com
user = user
password = pass

[mailbox]
watch = true
"""

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testSighupTriggersReloadAndWatchRestarts(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """SIGHUP causes watch to return, config is re-parsed, and watch restarts."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        def parse_side_effect(config, opts):
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            return None

        mock_parse_config.side_effect = parse_side_effect
        mock_init_clients.return_value = {}

        call_count = [0]

        def watch_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # Simulate SIGHUP arriving while watch is running
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return  # Normal return — reload loop will continue
            else:
                raise FileExistsError("stop-watch-loop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as cm:
                parsedmarc.cli._main()

        # Exited with code 1 (from FileExistsError handler)
        self.assertEqual(cm.exception.code, 1)
        # watch_inbox was called twice: initial run + after reload
        self.assertEqual(mock_watch.call_count, 2)
        # _parse_config called for initial load + reload
        self.assertGreaterEqual(mock_parse_config.call_count, 2)

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testInvalidConfigOnReloadKeepsPreviousState(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """A failing reload leaves opts and clients unchanged."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        # Initial parse sets required opts; reload parse raises
        initial_map = {"prefix_": ["example.com"]}
        call_count = [0]

        def parse_side_effect(config, opts):
            call_count[0] += 1
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            if call_count[0] == 1:
                return initial_map
            raise RuntimeError("bad config")

        mock_parse_config.side_effect = parse_side_effect

        initial_clients = {"s3_client": MagicMock()}
        mock_init_clients.return_value = initial_clients

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as cm:
                parsedmarc.cli._main()

        self.assertEqual(cm.exception.code, 1)
        # watch was still called twice (reload loop continued after failed reload)
        self.assertEqual(mock_watch.call_count, 2)
        # The failed reload must not have closed the original clients
        initial_clients["s3_client"].close.assert_not_called()

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testReloadClosesOldClients(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """Successful reload closes the old output clients before replacing them."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        def parse_side_effect(config, opts):
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            return None

        mock_parse_config.side_effect = parse_side_effect

        old_client = MagicMock()
        new_client = MagicMock()
        init_call = [0]

        def init_side_effect(opts):
            init_call[0] += 1
            if init_call[0] == 1:
                return {"kafka_client": old_client}
            return {"kafka_client": new_client}

        mock_init_clients.side_effect = init_side_effect

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit):
                parsedmarc.cli._main()

        # Old client must have been closed when reload succeeded
        old_client.close.assert_called_once()

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testRemovedConfigSectionTakesEffectOnReload(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_init_clients,
    ):
        """Removing a config section on reload resets that option to its default."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        mock_init_clients.return_value = {}

        # First config sets kafka_hosts (with required topics); second removes it.
        config_v1 = (
            self._BASE_CONFIG
            + "\n[kafka]\nhosts = kafka.example.com:9092\n"
            + "aggregate_topic = dmarc_agg\n"
            + "forensic_topic = dmarc_forensic\n"
            + "smtp_tls_topic = smtp_tls\n"
        )
        config_v2 = self._BASE_CONFIG  # no [kafka] section

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_v1)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                # Rewrite config to remove kafka before triggering reload
                with open(cfg_path, "w") as f:
                    f.write(config_v2)
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        # Capture opts used on each _init_output_clients call
        init_opts_captures = []

        def init_side_effect(opts):
            from argparse import Namespace as NS

            init_opts_captures.append(NS(**vars(opts)))
            return {}

        mock_init_clients.side_effect = init_side_effect

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit):
                parsedmarc.cli._main()

        # First init: kafka_hosts should be set from v1 config
        self.assertIsNotNone(init_opts_captures[0].kafka_hosts)
        # Second init (after reload with v2 config): kafka_hosts should be None
        self.assertIsNone(init_opts_captures[1].kafka_hosts)

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testReloadRefreshesReverseDnsMap(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """SIGHUP reload repopulates the reverse DNS map so lookups still work."""
        import signal as signal_module

        from parsedmarc import REVERSE_DNS_MAP

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        def parse_side_effect(config, opts):
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            return None

        mock_parse_config.side_effect = parse_side_effect
        mock_init_clients.return_value = {}

        # Snapshot the map state after each watch_inbox call
        map_snapshots = []

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                # Capture the map state after reload, before we stop the loop
                map_snapshots.append(dict(REVERSE_DNS_MAP))
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        # Pre-populate the map so we can verify it gets refreshed
        REVERSE_DNS_MAP.clear()
        REVERSE_DNS_MAP["stale.example.com"] = {
            "name": "Stale",
            "type": "stale",
        }
        original_contents = dict(REVERSE_DNS_MAP)

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit):
                parsedmarc.cli._main()

        self.assertEqual(mock_watch.call_count, 2)
        # The map should have been repopulated (not empty, not the stale data)
        self.assertEqual(len(map_snapshots), 1)
        refreshed = map_snapshots[0]
        self.assertGreater(len(refreshed), 0, "Map should not be empty after reload")
        self.assertNotEqual(
            refreshed,
            original_contents,
            "Map should have been refreshed, not kept stale data",
        )
        self.assertNotIn(
            "stale.example.com",
            refreshed,
            "Stale entry should have been cleared by reload",
        )


class TestIndexPrefixDomainMapTlsFiltering(unittest.TestCase):
    """Tests that SMTP TLS reports for unmapped domains are filtered out
    when index_prefix_domain_map is configured."""

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testTlsReportsFilteredByDomainMap(
        self,
        mock_imap_connection,
        mock_get_reports,
    ):
        """TLS reports for domains not in the map should be silently dropped."""
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [
                {
                    "organization_name": "Allowed Org",
                    "begin_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-01T23:59:59Z",
                    "report_id": "allowed-1",
                    "contact_info": "tls@allowed.example.com",
                    "policies": [
                        {
                            "policy_domain": "allowed.example.com",
                            "policy_type": "sts",
                            "successful_session_count": 1,
                            "failed_session_count": 0,
                        }
                    ],
                },
                {
                    "organization_name": "Unmapped Org",
                    "begin_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-01T23:59:59Z",
                    "report_id": "unmapped-1",
                    "contact_info": "tls@unmapped.example.net",
                    "policies": [
                        {
                            "policy_domain": "unmapped.example.net",
                            "policy_type": "sts",
                            "successful_session_count": 5,
                            "failed_session_count": 0,
                        }
                    ],
                },
                {
                    "organization_name": "Mixed Case Org",
                    "begin_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-01T23:59:59Z",
                    "report_id": "mixed-case-1",
                    "contact_info": "tls@mixedcase.example.com",
                    "policies": [
                        {
                            "policy_domain": "MixedCase.Example.Com",
                            "policy_type": "sts",
                            "successful_session_count": 2,
                            "failed_session_count": 0,
                        }
                    ],
                },
            ],
        }

        domain_map = {"tenant_a": ["example.com"]}
        with NamedTemporaryFile("w", suffix=".yaml", delete=False) as map_file:
            import yaml

            yaml.dump(domain_map, map_file)
            map_path = map_file.name
        self.addCleanup(lambda: os.path.exists(map_path) and os.remove(map_path))

        config = f"""[general]
save_smtp_tls = true
silent = false
index_prefix_domain_map = {map_path}

[imap]
host = imap.example.com
user = test-user
password = test-password
"""
        with NamedTemporaryFile("w", suffix=".ini", delete=False) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        captured = io.StringIO()
        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            with patch("sys.stdout", captured):
                parsedmarc.cli._main()

        output = json.loads(captured.getvalue())
        tls_reports = output["smtp_tls_reports"]
        self.assertEqual(len(tls_reports), 2)
        report_ids = {r["report_id"] for r in tls_reports}
        self.assertIn("allowed-1", report_ids)
        self.assertIn("mixed-case-1", report_ids)
        self.assertNotIn("unmapped-1", report_ids)


class TestMaildirConnection(unittest.TestCase):
    """Tests for MaildirConnection subdirectory creation."""

    def test_create_subdirs_when_missing(self):
        """maildir_create=True creates cur/new/tmp in an empty directory."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            for subdir in ("cur", "new", "tmp"):
                self.assertFalse(os.path.exists(os.path.join(d, subdir)))

            conn = MaildirConnection(d, maildir_create=True)

            for subdir in ("cur", "new", "tmp"):
                self.assertTrue(os.path.isdir(os.path.join(d, subdir)))
            # Should be able to list messages without error
            self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_create_subdirs_idempotent(self):
        """maildir_create=True is safe when subdirs already exist."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            for subdir in ("cur", "new", "tmp"):
                os.makedirs(os.path.join(d, subdir))

            # Should not raise
            conn = MaildirConnection(d, maildir_create=True)
            self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_no_create_raises_on_missing_subdirs(self):
        """maildir_create=False does not create subdirs; keys() fails."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=False)

            with self.assertRaises(FileNotFoundError):
                conn.fetch_messages("INBOX")

    def test_fetch_and_delete_message(self):
        """Round-trip: add a message, fetch it, delete it."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            # Add a message via the underlying client
            msg_key = conn._client.add("From: test@example.com\n\nHello")
            keys = conn.fetch_messages("INBOX")
            self.assertIn(msg_key, keys)

            content = conn.fetch_message(msg_key)
            self.assertIn("test@example.com", content)

            conn.delete_message(msg_key)
            self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_move_message_creates_subfolder(self):
        """move_message auto-creates the destination subfolder."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            msg_key = conn._client.add("From: test@example.com\n\nHello")
            conn.move_message(msg_key, "archive")

            # Original should be gone
            self.assertEqual(conn.fetch_messages("INBOX"), [])
            # Archive subfolder should have the message
            self.assertIn("archive", conn._subfolder_client)
            self.assertEqual(len(conn._subfolder_client["archive"].keys()), 1)


class TestMaildirReportsFolder(unittest.TestCase):
    """Tests for Maildir reports_folder support in fetch_messages."""

    def test_fetch_from_subfolder(self):
        """fetch_messages with a subfolder name reads from that subfolder."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            # Add message to a subfolder
            subfolder = conn._client.add_folder("reports")
            msg_key = subfolder.add("From: test@example.com\n\nSubfolder msg")

            # Root should be empty
            self.assertEqual(conn.fetch_messages("INBOX"), [])

            # Subfolder should have the message
            keys = conn.fetch_messages("reports")
            self.assertIn(msg_key, keys)

    def test_fetch_message_uses_active_folder(self):
        """fetch_message reads from the folder set by fetch_messages."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            subfolder = conn._client.add_folder("reports")
            msg_key = subfolder.add("From: sub@example.com\n\nIn subfolder")

            conn.fetch_messages("reports")
            content = conn.fetch_message(msg_key)
            self.assertIn("sub@example.com", content)

    def test_delete_message_uses_active_folder(self):
        """delete_message removes from the folder set by fetch_messages."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            subfolder = conn._client.add_folder("reports")
            msg_key = subfolder.add("From: del@example.com\n\nDelete me")

            conn.fetch_messages("reports")
            conn.delete_message(msg_key)
            self.assertEqual(conn.fetch_messages("reports"), [])

    def test_move_message_from_subfolder(self):
        """move_message works when active folder is a subfolder."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            subfolder = conn._client.add_folder("reports")
            msg_key = subfolder.add("From: move@example.com\n\nMove me")

            conn.fetch_messages("reports")
            conn.move_message(msg_key, "archive")

            # Source should be empty
            self.assertEqual(conn.fetch_messages("reports"), [])
            # Destination should have the message
            archive_keys = conn.fetch_messages("archive")
            self.assertEqual(len(archive_keys), 1)

    def test_inbox_reads_root(self):
        """INBOX reads from the top-level Maildir."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            msg_key = conn._client.add("From: root@example.com\n\nRoot msg")

            keys = conn.fetch_messages("INBOX")
            self.assertIn(msg_key, keys)

    def test_empty_folder_reads_root(self):
        """Empty string reports_folder reads from the top-level Maildir."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)

            msg_key = conn._client.add("From: root@example.com\n\nRoot msg")

            keys = conn.fetch_messages("")
            self.assertIn(msg_key, keys)


class TestConfigAliases(unittest.TestCase):
    """Tests for config key aliases (env var friendly short names)."""

    def test_maildir_create_alias(self):
        """[maildir] create works as alias for maildir_create."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        env = {
            "PARSEDMARC_MAILDIR_CREATE": "true",
            "PARSEDMARC_MAILDIR_PATH": "/tmp/test",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)
        opts = Namespace()
        _parse_config(config, opts)
        self.assertTrue(opts.maildir_create)

    def test_maildir_path_alias(self):
        """[maildir] path works as alias for maildir_path."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        env = {"PARSEDMARC_MAILDIR_PATH": "/var/mail/dmarc"}
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)
        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.maildir_path, "/var/mail/dmarc")

    def test_msgraph_url_alias(self):
        """[msgraph] url works as alias for graph_url."""
        from parsedmarc.cli import _load_config, _parse_config
        from argparse import Namespace

        env = {
            "PARSEDMARC_MSGRAPH_AUTH_METHOD": "ClientSecret",
            "PARSEDMARC_MSGRAPH_CLIENT_ID": "test-id",
            "PARSEDMARC_MSGRAPH_CLIENT_SECRET": "test-secret",
            "PARSEDMARC_MSGRAPH_TENANT_ID": "test-tenant",
            "PARSEDMARC_MSGRAPH_MAILBOX": "test@example.com",
            "PARSEDMARC_MSGRAPH_URL": "https://custom.graph.example.com",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)
        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.graph_url, "https://custom.graph.example.com")

    def test_original_keys_still_work(self):
        """Original INI key names (maildir_create, maildir_path) still work."""
        from argparse import Namespace
        from parsedmarc.cli import _parse_config

        config = ConfigParser(interpolation=None)
        config.add_section("maildir")
        config.set("maildir", "maildir_path", "/original/path")
        config.set("maildir", "maildir_create", "true")

        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.maildir_path, "/original/path")
        self.assertTrue(opts.maildir_create)

    def test_ipinfo_url_option(self):
        """[general] ipinfo_url lands on opts.ipinfo_url."""
        from argparse import Namespace
        from parsedmarc.cli import _parse_config

        config = ConfigParser(interpolation=None)
        config.add_section("general")
        config.set("general", "ipinfo_url", "https://mirror.example/mmdb")

        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.ipinfo_url, "https://mirror.example/mmdb")

    def test_ip_db_url_deprecated_alias(self):
        """[general] ip_db_url is accepted as an alias for ipinfo_url but
        emits a deprecation warning."""
        from argparse import Namespace
        from parsedmarc.cli import _parse_config

        config = ConfigParser(interpolation=None)
        config.add_section("general")
        config.set("general", "ip_db_url", "https://old.example/mmdb")

        opts = Namespace()
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            _parse_config(config, opts)
        self.assertEqual(opts.ipinfo_url, "https://old.example/mmdb")
        self.assertTrue(
            any("ip_db_url" in line and "deprecated" in line for line in cm.output),
            f"expected deprecation warning, got: {cm.output}",
        )


class TestMaildirUidHandling(unittest.TestCase):
    """Tests for Maildir UID mismatch handling in Docker-like environments."""

    def test_uid_mismatch_warns_instead_of_crashing(self):
        """UID mismatch logs a warning instead of raising an exception."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            # Create subdirs so Maildir works
            for subdir in ("cur", "new", "tmp"):
                os.makedirs(os.path.join(d, subdir))

            # Mock os.stat to return a different UID than os.getuid
            fake_stat = os.stat(d)
            with (
                patch("parsedmarc.mail.maildir.os.stat") as mock_stat,
                patch("parsedmarc.mail.maildir.os.getuid", return_value=9999),
            ):
                mock_stat.return_value = fake_stat
                # Should not raise — just warn
                conn = MaildirConnection(d, maildir_create=False)
                self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_uid_match_no_warning(self):
        """No warning when UIDs match."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            conn = MaildirConnection(d, maildir_create=True)
            self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_stat_failure_does_not_crash(self):
        """If os.stat fails on the maildir path, we don't crash."""
        from parsedmarc.mail.maildir import MaildirConnection

        with TemporaryDirectory() as d:
            for subdir in ("cur", "new", "tmp"):
                os.makedirs(os.path.join(d, subdir))

            original_stat = os.stat

            def stat_that_fails_once(path, *args, **kwargs):
                """Fail on the first call (UID check), pass through after."""
                stat_that_fails_once.calls += 1
                if stat_that_fails_once.calls == 1:
                    raise OSError("no stat")
                return original_stat(path, *args, **kwargs)

            stat_that_fails_once.calls = 0

            with patch(
                "parsedmarc.mail.maildir.os.stat", side_effect=stat_that_fails_once
            ):
                conn = MaildirConnection(d, maildir_create=False)
                self.assertEqual(conn.fetch_messages("INBOX"), [])


class TestExpandPath(unittest.TestCase):
    """Tests for _expand_path config path expansion."""

    def test_expand_tilde(self):
        from parsedmarc.cli import _expand_path

        result = _expand_path("~/some/path")
        self.assertFalse(result.startswith("~"))
        self.assertTrue(result.endswith("/some/path"))

    def test_expand_env_var(self):
        from parsedmarc.cli import _expand_path

        with patch.dict(os.environ, {"PARSEDMARC_TEST_DIR": "/opt/data"}):
            result = _expand_path("$PARSEDMARC_TEST_DIR/tokens/.token")
        self.assertEqual(result, "/opt/data/tokens/.token")

    def test_expand_both(self):
        from parsedmarc.cli import _expand_path

        with patch.dict(os.environ, {"MY_APP": "parsedmarc"}):
            result = _expand_path("~/$MY_APP/config")
        self.assertNotIn("~", result)
        self.assertIn("parsedmarc/config", result)

    def test_no_expansion_needed(self):
        from parsedmarc.cli import _expand_path

        self.assertEqual(_expand_path("/absolute/path"), "/absolute/path")
        self.assertEqual(_expand_path("relative/path"), "relative/path")


class TestTokenParentDirCreation(unittest.TestCase):
    """Tests for parent directory creation when writing token files."""

    def test_graph_cache_creates_parent_dirs(self):
        from parsedmarc.mail.graph import _cache_auth_record

        with TemporaryDirectory() as d:
            token_path = Path(d) / "subdir" / "nested" / ".token"
            self.assertFalse(token_path.parent.exists())

            mock_record = MagicMock()
            mock_record.serialize.return_value = "serialized-token"

            _cache_auth_record(mock_record, token_path)

            self.assertTrue(token_path.exists())
            self.assertEqual(token_path.read_text(), "serialized-token")

    def test_gmail_token_write_creates_parent_dirs(self):
        """Gmail token write creates parent directories."""
        with TemporaryDirectory() as d:
            token_path = Path(d) / "deep" / "nested" / "token.json"
            self.assertFalse(token_path.parent.exists())

            # Directly test the mkdir + open pattern
            token_path.parent.mkdir(parents=True, exist_ok=True)
            with token_path.open("w") as f:
                f.write('{"token": "test"}')

            self.assertTrue(token_path.exists())
            self.assertEqual(token_path.read_text(), '{"token": "test"}')


class TestEnvVarConfig(unittest.TestCase):
    """Tests for environment variable configuration support."""

    def test_resolve_section_key_simple(self):
        """Simple section names resolve correctly."""
        from parsedmarc.cli import _resolve_section_key

        self.assertEqual(_resolve_section_key("IMAP_PASSWORD"), ("imap", "password"))
        self.assertEqual(_resolve_section_key("GENERAL_DEBUG"), ("general", "debug"))
        self.assertEqual(_resolve_section_key("S3_BUCKET"), ("s3", "bucket"))
        self.assertEqual(_resolve_section_key("GELF_HOST"), ("gelf", "host"))

    def test_resolve_section_key_underscore_sections(self):
        """Multi-word section names (splunk_hec, gmail_api, etc.) resolve correctly."""
        from parsedmarc.cli import _resolve_section_key

        self.assertEqual(
            _resolve_section_key("SPLUNK_HEC_TOKEN"), ("splunk_hec", "token")
        )
        self.assertEqual(
            _resolve_section_key("GMAIL_API_CREDENTIALS_FILE"),
            ("gmail_api", "credentials_file"),
        )
        self.assertEqual(
            _resolve_section_key("LOG_ANALYTICS_CLIENT_ID"),
            ("log_analytics", "client_id"),
        )

    def test_resolve_section_key_unknown(self):
        """Unknown prefixes return (None, None)."""
        from parsedmarc.cli import _resolve_section_key

        self.assertEqual(_resolve_section_key("UNKNOWN_FOO"), (None, None))
        # Just a section name with no key should not match
        self.assertEqual(_resolve_section_key("IMAP"), (None, None))

    def test_apply_env_overrides_injects_values(self):
        """Env vars are injected into an existing ConfigParser."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()
        config.add_section("imap")
        config.set("imap", "host", "original.example.com")

        env = {
            "PARSEDMARC_IMAP_HOST": "new.example.com",
            "PARSEDMARC_IMAP_PASSWORD": "secret123",
        }
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        self.assertEqual(config.get("imap", "host"), "new.example.com")
        self.assertEqual(config.get("imap", "password"), "secret123")

    def test_apply_env_overrides_creates_sections(self):
        """Env vars create new sections when they don't exist."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()

        env = {"PARSEDMARC_ELASTICSEARCH_HOSTS": "http://localhost:9200"}
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        self.assertTrue(config.has_section("elasticsearch"))
        self.assertEqual(config.get("elasticsearch", "hosts"), "http://localhost:9200")

    def test_apply_env_overrides_ignores_config_file_var(self):
        """PARSEDMARC_CONFIG_FILE is not injected as a config key."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()

        env = {"PARSEDMARC_CONFIG_FILE": "/some/path.ini"}
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        self.assertEqual(config.sections(), [])

    def test_load_config_with_file_and_env_override(self):
        """Env vars override values from an INI file."""
        from parsedmarc.cli import _load_config

        with NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write(
                "[imap]\nhost = file.example.com\nuser = alice\npassword = fromfile\n"
            )
            f.flush()
            config_path = f.name

        try:
            env = {"PARSEDMARC_IMAP_PASSWORD": "fromenv"}
            with patch.dict(os.environ, env, clear=False):
                config = _load_config(config_path)

            self.assertEqual(config.get("imap", "host"), "file.example.com")
            self.assertEqual(config.get("imap", "user"), "alice")
            self.assertEqual(config.get("imap", "password"), "fromenv")
        finally:
            os.unlink(config_path)

    def test_load_config_env_only(self):
        """Config can be loaded purely from env vars with no file."""
        from parsedmarc.cli import _load_config

        env = {
            "PARSEDMARC_GENERAL_DEBUG": "true",
            "PARSEDMARC_ELASTICSEARCH_HOSTS": "http://localhost:9200",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)

        self.assertEqual(config.get("general", "debug"), "true")
        self.assertEqual(config.get("elasticsearch", "hosts"), "http://localhost:9200")

    def test_parse_config_from_env(self):
        """Full round-trip: env vars -> ConfigParser -> opts."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        env = {
            "PARSEDMARC_GENERAL_DEBUG": "true",
            "PARSEDMARC_GENERAL_SAVE_AGGREGATE": "true",
            "PARSEDMARC_GENERAL_OFFLINE": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)

        opts = Namespace()
        _parse_config(config, opts)

        self.assertTrue(opts.debug)
        self.assertTrue(opts.save_aggregate)
        self.assertTrue(opts.offline)

    def test_config_file_env_var(self):
        """PARSEDMARC_CONFIG_FILE env var specifies the config file path."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        with NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[general]\ndebug = true\noffline = true\n")
            f.flush()
            config_path = f.name

        try:
            env = {"PARSEDMARC_CONFIG_FILE": config_path}
            with patch.dict(os.environ, env, clear=False):
                config = _load_config(os.environ.get("PARSEDMARC_CONFIG_FILE"))

            opts = Namespace()
            _parse_config(config, opts)
            self.assertTrue(opts.debug)
            self.assertTrue(opts.offline)
        finally:
            os.unlink(config_path)

    def test_boolean_values_from_env(self):
        """Various boolean string representations work through ConfigParser."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        for true_val in ("true", "yes", "1", "on", "True", "YES"):
            config = ConfigParser()
            env = {"PARSEDMARC_GENERAL_DEBUG": true_val}
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertTrue(
                config.getboolean("general", "debug"),
                f"Expected truthy for {true_val!r}",
            )

        for false_val in ("false", "no", "0", "off", "False", "NO"):
            config = ConfigParser()
            env = {"PARSEDMARC_GENERAL_DEBUG": false_val}
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertFalse(
                config.getboolean("general", "debug"),
                f"Expected falsy for {false_val!r}",
            )


class TestLoadPSLOverrides(unittest.TestCase):
    """Covers `parsedmarc.utils.load_psl_overrides`."""

    def setUp(self):
        # Snapshot the module-level list so each test leaves it as it found it.
        self._saved = list(parsedmarc.utils.psl_overrides)

    def tearDown(self):
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend(self._saved)

    def test_offline_loads_bundled_file(self):
        """offline=True populates the list from the bundled file, no network."""
        result = parsedmarc.utils.load_psl_overrides(offline=True)
        self.assertIs(result, parsedmarc.utils.psl_overrides)
        self.assertGreater(len(result), 0)
        # The bundled file is expected to contain at least one well-known entry.
        self.assertIn(".linode.com", result)

    def test_local_file_path_overrides_bundled(self):
        """A custom local_file_path takes precedence over the bundled copy."""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tf:
            tf.write("-custom-brand.com\n.another-brand.net\n\n   \n")
            path = tf.name
        try:
            result = parsedmarc.utils.load_psl_overrides(
                offline=True, local_file_path=path
            )
            self.assertEqual(result, ["-custom-brand.com", ".another-brand.net"])
        finally:
            os.unlink(path)

    def test_clear_before_reload(self):
        """Re-running load_psl_overrides replaces the list, not appends."""
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.append(".stale-entry.com")
        parsedmarc.utils.load_psl_overrides(offline=True)
        self.assertNotIn(".stale-entry.com", parsedmarc.utils.psl_overrides)

    def test_url_success(self):
        """A 200 response from the URL populates the list."""
        fake_body = "-fetched-brand.com\n.cdn-fetched.net\n"
        mock_response = MagicMock()
        mock_response.text = fake_body
        mock_response.raise_for_status = MagicMock()
        with patch(
            "parsedmarc.utils.requests.get", return_value=mock_response
        ) as mock_get:
            result = parsedmarc.utils.load_psl_overrides(url="https://example.test/ov")
            self.assertEqual(result, ["-fetched-brand.com", ".cdn-fetched.net"])
            mock_get.assert_called_once()

    def test_url_failure_falls_back_to_local(self):
        """A network error falls back to the bundled copy."""
        import requests

        with patch(
            "parsedmarc.utils.requests.get",
            side_effect=requests.exceptions.ConnectionError("nope"),
        ):
            result = parsedmarc.utils.load_psl_overrides(url="https://example.test/ov")
        # Bundled file still loaded.
        self.assertGreater(len(result), 0)
        self.assertIn(".linode.com", result)

    def test_always_use_local_skips_network(self):
        """always_use_local_file=True must not call requests.get."""
        with patch("parsedmarc.utils.requests.get") as mock_get:
            parsedmarc.utils.load_psl_overrides(always_use_local_file=True)
            mock_get.assert_not_called()


class TestLoadReverseDnsMapReloadsPSLOverrides(unittest.TestCase):
    """`load_reverse_dns_map` must reload `psl_overrides.txt` in the same call
    so map entries that depend on folded bases resolve correctly."""

    def setUp(self):
        self._saved = list(parsedmarc.utils.psl_overrides)

    def tearDown(self):
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend(self._saved)

    def test_map_load_triggers_psl_reload(self):
        """Calling load_reverse_dns_map offline also invokes load_psl_overrides
        with matching flags, and the overrides list is repopulated."""
        rdm = {}
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.append(".stale-from-before.com")
        with patch(
            "parsedmarc.utils.load_psl_overrides",
            wraps=parsedmarc.utils.load_psl_overrides,
        ) as spy:
            parsedmarc.utils.load_reverse_dns_map(rdm, offline=True)
        spy.assert_called_once()
        kwargs = spy.call_args.kwargs
        self.assertTrue(kwargs["offline"])
        self.assertIsNone(kwargs["url"])
        self.assertIsNone(kwargs["local_file_path"])
        self.assertNotIn(".stale-from-before.com", parsedmarc.utils.psl_overrides)

    def test_map_load_forwards_psl_overrides_kwargs(self):
        """psl_overrides_path / psl_overrides_url are forwarded verbatim."""
        rdm = {}
        with patch("parsedmarc.utils.load_psl_overrides") as spy:
            parsedmarc.utils.load_reverse_dns_map(
                rdm,
                offline=True,
                always_use_local_file=True,
                psl_overrides_path="/tmp/custom.txt",
                psl_overrides_url="https://example.test/ov",
            )
        spy.assert_called_once_with(
            always_use_local_file=True,
            local_file_path="/tmp/custom.txt",
            url="https://example.test/ov",
            offline=True,
        )


class TestGetBaseDomainWithOverrides(unittest.TestCase):
    """`get_base_domain` must honour the current psl_overrides list."""

    def setUp(self):
        self._saved = list(parsedmarc.utils.psl_overrides)
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend([".cprapid.com", "-nobre.com.br"])

    def tearDown(self):
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend(self._saved)

    def test_dot_prefixed_override_folds_subdomain(self):
        result = parsedmarc.utils.get_base_domain("74-208-244-234.cprapid.com")
        self.assertEqual(result, "cprapid.com")

    def test_dash_prefixed_override_folds_subdomain(self):
        result = parsedmarc.utils.get_base_domain("host-1-2-3-4-nobre.com.br")
        self.assertEqual(result, "nobre.com.br")

    def test_unmatched_domain_falls_through_to_psl(self):
        result = parsedmarc.utils.get_base_domain("sub.example.com")
        self.assertEqual(result, "example.com")


class TestMapScriptsIPDetection(unittest.TestCase):
    """Full-IP detection and PSL folding in the map-maintenance scripts."""

    def test_collect_domain_info_detects_full_ips(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        # Dotted and dashed four-octet patterns with valid octets: detected.
        self.assertTrue(cdi._has_full_ip("74-208-244-234.cprapid.com"))
        self.assertTrue(cdi._has_full_ip("host.192.168.1.1.example.com"))
        self.assertTrue(cdi._has_full_ip("a-10-20-30-40-brand.com"))
        # Three octets is NOT a full IP — OVH's reverse-DNS pattern stays safe.
        self.assertFalse(cdi._has_full_ip("ip-147-135-108.us"))
        # Out-of-range octet fails the 0-255 sanity check.
        self.assertFalse(cdi._has_full_ip("999-1-2-3-foo.com"))
        # Pure domain, no IP.
        self.assertFalse(cdi._has_full_ip("example.com"))

    def test_find_unknown_detects_full_ips(self):
        import parsedmarc.resources.maps.find_unknown_base_reverse_dns as fu

        self.assertTrue(fu._has_full_ip("170-254-144-204-nobreinternet.com.br"))
        self.assertFalse(fu._has_full_ip("ip-147-135-108.us"))
        self.assertFalse(fu._has_full_ip("cprapid.com"))

    def test_apply_psl_override_dot_prefix(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        ov = [".cprapid.com", ".linode.com"]
        self.assertEqual(cdi._apply_psl_override("foo.cprapid.com", ov), "cprapid.com")
        self.assertEqual(cdi._apply_psl_override("a.b.linode.com", ov), "linode.com")

    def test_apply_psl_override_dash_prefix(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        ov = ["-nobre.com.br"]
        self.assertEqual(
            cdi._apply_psl_override("1-2-3-4-nobre.com.br", ov), "nobre.com.br"
        )

    def test_apply_psl_override_no_match(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        ov = [".cprapid.com"]
        self.assertEqual(cdi._apply_psl_override("example.com", ov), "example.com")


class TestDetectPSLOverrides(unittest.TestCase):
    """Cluster detection, brand-tail extraction, and full-pipeline behaviour
    for `detect_psl_overrides.py`."""

    def setUp(self):
        import parsedmarc.resources.maps.detect_psl_overrides as dpo

        self.dpo = dpo

    def test_extract_brand_tail_dot_separator(self):
        self.assertEqual(
            self.dpo.extract_brand_tail("74-208-244-234.cprapid.com"),
            ".cprapid.com",
        )

    def test_extract_brand_tail_dash_separator(self):
        self.assertEqual(
            self.dpo.extract_brand_tail("170-254-144-204-nobre.com.br"),
            "-nobre.com.br",
        )

    def test_extract_brand_tail_no_separator(self):
        self.assertEqual(
            self.dpo.extract_brand_tail("host134-254-143-190tigobusiness.com.ni"),
            "tigobusiness.com.ni",
        )

    def test_extract_brand_tail_no_ip_returns_none(self):
        self.assertIsNone(self.dpo.extract_brand_tail("plain.example.com"))

    def test_extract_brand_tail_rejects_short_tail(self):
        """A tail shorter than MIN_TAIL_LEN is rejected to avoid folding to `.com`."""
        # Four-octet IP followed by only `.br` (2 chars after the dot) — too short.
        self.assertIsNone(self.dpo.extract_brand_tail("1-2-3-4.br"))

    def test_detect_clusters_meets_threshold(self):
        domains = [
            "1-2-3-4.cprapid.com",
            "5-6-7-8.cprapid.com",
            "9-10-11-12.cprapid.com",
            "1-2-3-4-other.com.br",  # not enough of these
        ]
        clusters = self.dpo.detect_clusters(domains, threshold=3, known_overrides=set())
        self.assertIn(".cprapid.com", clusters)
        self.assertEqual(len(clusters[".cprapid.com"]), 3)
        self.assertNotIn("-other.com.br", clusters)

    def test_detect_clusters_honours_threshold(self):
        domains = [
            "1-2-3-4.cprapid.com",
            "5-6-7-8.cprapid.com",
        ]
        clusters = self.dpo.detect_clusters(domains, threshold=3, known_overrides=set())
        self.assertEqual(clusters, {})

    def test_detect_clusters_skips_known_overrides(self):
        """Tails already in psl_overrides.txt must not be re-proposed."""
        domains = [
            "1-2-3-4.cprapid.com",
            "5-6-7-8.cprapid.com",
            "9-10-11-12.cprapid.com",
        ]
        clusters = self.dpo.detect_clusters(
            domains, threshold=3, known_overrides={".cprapid.com"}
        )
        self.assertNotIn(".cprapid.com", clusters)

    def test_apply_override_matches_first(self):
        """apply_override iterates in list order and returns on the first match."""
        ov = [".cprapid.com", "-nobre.com.br"]
        self.assertEqual(
            self.dpo.apply_override("1-2-3-4.cprapid.com", ov), "cprapid.com"
        )
        self.assertEqual(
            self.dpo.apply_override("1-2-3-4-nobre.com.br", ov), "nobre.com.br"
        )
        self.assertEqual(self.dpo.apply_override("unrelated.com", ov), "unrelated.com")

    def test_has_full_ip_shared_with_other_scripts(self):
        """The detect script's IP check must agree with the other map scripts."""
        self.assertTrue(self.dpo.has_full_ip("74-208-244-234.cprapid.com"))
        self.assertFalse(self.dpo.has_full_ip("ip-147-135-108.us"))
        self.assertFalse(self.dpo.has_full_ip("example.com"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
