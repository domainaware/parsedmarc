#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import os
import signal
import sys
import tempfile
import unittest
from base64 import urlsafe_b64encode
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

    def testFailureSamples(self):
        """Test sample failure/ruf DMARC reports"""
        print()
        sample_paths = glob("samples/failure/*.eml")
        for sample_path in sample_paths:
            print("Testing {0}: ".format(sample_path), end="")
            with open(sample_path) as sample_file:
                sample_content = sample_file.read()
                email_result = parsedmarc.parse_report_email(
                    sample_content, offline=OFFLINE_MODE
                )
                assert email_result["report_type"] == "failure"
            result = parsedmarc.parse_report_file(
                sample_path, offline=OFFLINE_MODE
            )
            assert result["report_type"] == "failure"
            parsedmarc.parsed_failure_reports_to_csv(result["report"])
            print("Passed!")

    def testFailureReportBackwardCompat(self):
        """Test that old forensic function aliases still work"""
        self.assertIs(
            parsedmarc.parse_forensic_report,
            parsedmarc.parse_failure_report,
        )
        self.assertIs(
            parsedmarc.parsed_forensic_reports_to_csv,
            parsedmarc.parsed_failure_reports_to_csv,
        )
        self.assertIs(
            parsedmarc.parsed_forensic_reports_to_csv_rows,
            parsedmarc.parsed_failure_reports_to_csv_rows,
        )
        self.assertIs(
            parsedmarc.InvalidForensicReport,
            parsedmarc.InvalidFailureReport,
        )

    def testDMARCbisDraftSample(self):
        """Test parsing the sample report from the DMARCbis aggregate draft"""
        print()
        sample_path = (
            "samples/aggregate/dmarcbis-draft-sample.xml"
        )
        print("Testing {0}: ".format(sample_path), end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = result["report"]

        # Verify report_type
        self.assertEqual(result["report_type"], "aggregate")

        # Verify xml_schema
        self.assertEqual(report["xml_schema"], "1.0")

        # Verify report_metadata
        metadata = report["report_metadata"]
        self.assertEqual(metadata["org_name"], "Sample Reporter")
        self.assertEqual(
            metadata["org_email"], "report_sender@example-reporter.com"
        )
        self.assertEqual(
            metadata["org_extra_contact_info"], "..."
        )
        self.assertEqual(
            metadata["report_id"], "3v98abbp8ya9n3va8yr8oa3ya"
        )
        self.assertEqual(
            metadata["generator"],
            "Example DMARC Aggregate Reporter v1.2",
        )

        # Verify DMARCbis policy_published fields
        pp = report["policy_published"]
        self.assertEqual(pp["domain"], "example.com")
        self.assertEqual(pp["p"], "quarantine")
        self.assertEqual(pp["sp"], "none")
        self.assertEqual(pp["np"], "none")
        self.assertEqual(pp["testing"], "n")
        self.assertEqual(pp["discovery_method"], "treewalk")
        # adkim/aspf default when not in XML
        self.assertEqual(pp["adkim"], "r")
        self.assertEqual(pp["aspf"], "r")
        # pct/fo are None on DMARCbis reports (not used)
        self.assertIsNone(pp["pct"])
        self.assertIsNone(pp["fo"])

        # Verify record
        self.assertEqual(len(report["records"]), 1)
        rec = report["records"][0]
        self.assertEqual(rec["source"]["ip_address"], "192.0.2.123")
        self.assertEqual(rec["count"], 123)
        self.assertEqual(
            rec["policy_evaluated"]["disposition"], "pass"
        )
        self.assertEqual(rec["policy_evaluated"]["dkim"], "pass")
        self.assertEqual(rec["policy_evaluated"]["spf"], "fail")

        # Verify DKIM auth result with human_result
        self.assertEqual(len(rec["auth_results"]["dkim"]), 1)
        dkim = rec["auth_results"]["dkim"][0]
        self.assertEqual(dkim["domain"], "example.com")
        self.assertEqual(dkim["selector"], "abc123")
        self.assertEqual(dkim["result"], "pass")
        self.assertIsNone(dkim["human_result"])

        # Verify SPF auth result with human_result
        self.assertEqual(len(rec["auth_results"]["spf"]), 1)
        spf = rec["auth_results"]["spf"][0]
        self.assertEqual(spf["domain"], "example.com")
        self.assertEqual(spf["result"], "fail")
        self.assertIsNone(spf["human_result"])

        # Verify CSV output includes new fields
        csv = parsedmarc.parsed_aggregate_reports_to_csv(report)
        header = csv.split("\n")[0]
        self.assertIn("np", header.split(","))
        self.assertIn("testing", header.split(","))
        self.assertIn("discovery_method", header.split(","))
        print("Passed!")

    def testDMARCbisFieldsWithRFC7489(self):
        """Test that RFC 7489 reports have None for DMARCbis-only fields"""
        print()
        sample_path = (
            "samples/aggregate/"
            "example.net!example.com!1529366400!1529452799.xml"
        )
        print("Testing {0}: ".format(sample_path), end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = result["report"]
        pp = report["policy_published"]

        # RFC 7489 fields present
        self.assertEqual(pp["pct"], "100")
        self.assertEqual(pp["fo"], "0")

        # DMARCbis fields absent (None)
        self.assertIsNone(pp["np"])
        self.assertIsNone(pp["testing"])
        self.assertIsNone(pp["discovery_method"])

        # generator absent (None)
        self.assertIsNone(report["report_metadata"]["generator"])
        print("Passed!")

    def testDMARCbisWithExplicitFields(self):
        """Test DMARCbis report with explicit testing and discovery_method"""
        print()
        sample_path = (
            "samples/aggregate/"
            "dmarcbis-example.net!example.com!1700000000!1700086399.xml"
        )
        print("Testing {0}: ".format(sample_path), end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = result["report"]
        pp = report["policy_published"]

        self.assertEqual(pp["np"], "reject")
        self.assertEqual(pp["testing"], "y")
        self.assertEqual(pp["discovery_method"], "treewalk")
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
            "failure_reports": [],
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
            "failure_reports": [],
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
            "failure_reports": [],
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

    @patch("parsedmarc.cli.opensearch.save_failure_report_to_opensearch")
    @patch("parsedmarc.cli.opensearch.migrate_indexes")
    @patch("parsedmarc.cli.opensearch.set_hosts")
    @patch("parsedmarc.cli.elastic.save_failure_report_to_elasticsearch")
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
        _mock_save_failure_elastic,
        _mock_os_set_hosts,
        _mock_os_migrate,
        mock_save_failure_opensearch,
    ):
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [{"policy_published": {"domain": "example.com"}}],
            "failure_reports": [{"reported_domain": "example.com"}],
            "smtp_tls_reports": [],
        }
        mock_save_aggregate.side_effect = parsedmarc.elastic.ElasticsearchError(
            "aggregate sink failed"
        )
        mock_save_failure_opensearch.side_effect = (
            parsedmarc.cli.opensearch.OpenSearchError("failure sink failed")
        )

        config = """[general]
save_aggregate = true
save_failure = true
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
        mock_save_failure_opensearch.assert_called_once()


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
            "failure_reports": [],
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
            "failure_reports": [],
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
            "failure_reports": [],
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
            "failure_reports": [],
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
            "failure_reports": [],
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
            "failure_reports": [],
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
            "failure_reports": [],
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
    @patch("parsedmarc.cli._parse_config_file")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testSighupTriggersReloadAndWatchRestarts(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_parse_config,
        mock_init_clients,
    ):
        """SIGHUP causes watch to return, config is re-parsed, and watch restarts."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        def parse_side_effect(config_file, opts):
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
        # _parse_config_file called for initial load + reload
        self.assertGreaterEqual(mock_parse_config.call_count, 2)

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config_file")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testInvalidConfigOnReloadKeepsPreviousState(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_parse_config,
        mock_init_clients,
    ):
        """A failing reload leaves opts and clients unchanged."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        # Initial parse sets required opts; reload parse raises
        initial_map = {"prefix_": ["example.com"]}
        call_count = [0]

        def parse_side_effect(config_file, opts):
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
    @patch("parsedmarc.cli._parse_config_file")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testReloadClosesOldClients(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_parse_config,
        mock_init_clients,
    ):
        """Successful reload closes the old output clients before replacing them."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        def parse_side_effect(config_file, opts):
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
            "failure_reports": [],
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

    # ===================================================================
    # New tests for _bucket_interval_by_day
    # ===================================================================

    def testBucketIntervalBeginAfterEnd(self):
        """begin > end should raise ValueError"""
        from datetime import datetime, timezone
        begin = datetime(2024, 1, 2, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalNaiveDatetime(self):
        """Non-timezone-aware datetimes should raise ValueError"""
        from datetime import datetime
        begin = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalDifferentTzinfo(self):
        """Different tzinfo objects should raise ValueError"""
        from datetime import datetime, timezone, timedelta
        tz1 = timezone.utc
        tz2 = timezone(timedelta(hours=5))
        begin = datetime(2024, 1, 1, tzinfo=tz1)
        end = datetime(2024, 1, 2, tzinfo=tz2)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalNegativeCount(self):
        """Negative total_count should raise ValueError"""
        from datetime import datetime, timezone
        begin = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, -1)

    def testBucketIntervalZeroCount(self):
        """Zero total_count should return empty list"""
        from datetime import datetime, timezone
        begin = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 0)
        self.assertEqual(result, [])

    def testBucketIntervalSameBeginEnd(self):
        """Same begin and end (zero interval) should return empty list"""
        from datetime import datetime, timezone
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(dt, dt, 100)
        self.assertEqual(result, [])

    def testBucketIntervalSingleDay(self):
        """Single day interval should return one bucket with total count"""
        from datetime import datetime, timezone
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 23, 59, 59, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 100)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["count"], 100)
        self.assertEqual(result[0]["begin"], begin)

    def testBucketIntervalMultiDay(self):
        """Multi-day interval should distribute counts proportionally"""
        from datetime import datetime, timezone
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 100)
        self.assertEqual(len(result), 2)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 100)
        # Equal days => equal distribution
        self.assertEqual(result[0]["count"], 50)
        self.assertEqual(result[1]["count"], 50)

    def testBucketIntervalRemainderDistribution(self):
        """Odd count across equal days distributes remainder correctly"""
        from datetime import datetime, timezone
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 4, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 10)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 10)
        self.assertEqual(len(result), 3)

    def testBucketIntervalPartialDays(self):
        """Partial days: 12h on day1, 24h on day2 => 1/3 vs 2/3 split"""
        from datetime import datetime, timezone
        begin = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 90)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 90)
        # day1: 12h, day2: 24h => 1/3 vs 2/3
        self.assertEqual(result[0]["count"], 30)
        self.assertEqual(result[1]["count"], 60)

    # ===================================================================
    # Tests for _append_parsed_record
    # ===================================================================

    def testAppendParsedRecordNoNormalize(self):
        """No normalization: record appended as-is with interval fields"""
        from datetime import datetime, timezone
        records = []
        rec = {"count": 10, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, False)
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0]["normalized_timespan"])
        self.assertEqual(records[0]["interval_begin"], "2024-01-01 00:00:00")
        self.assertEqual(records[0]["interval_end"], "2024-01-02 00:00:00")

    def testAppendParsedRecordNormalize(self):
        """Normalization: record split into daily buckets"""
        from datetime import datetime, timezone
        records = []
        rec = {"count": 100, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, True)
        self.assertEqual(len(records), 2)
        total = sum(r["count"] for r in records)
        self.assertEqual(total, 100)
        for r in records:
            self.assertTrue(r["normalized_timespan"])

    def testAppendParsedRecordNormalizeZeroCount(self):
        """Normalization with zero count: nothing appended"""
        from datetime import datetime, timezone
        records = []
        rec = {"count": 0, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, True)
        self.assertEqual(len(records), 0)

    # ===================================================================
    # Tests for _parse_report_record
    # ===================================================================

    def testParseReportRecordNoneSourceIP(self):
        """Record with None source_ip should raise ValueError"""
        record = {
            "row": {
                "source_ip": None,
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "pass"},
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        with self.assertRaises(ValueError):
            parsedmarc._parse_report_record(record, offline=True)

    def testParseReportRecordMissingDkimSpf(self):
        """Record with missing dkim/spf auth results defaults correctly"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "5",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "fail"},
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {},
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertEqual(result["auth_results"]["dkim"], [])
        self.assertEqual(result["auth_results"]["spf"], [])

    def testParseReportRecordReasonHandling(self):
        """Reasons in policy_evaluated get normalized with comment default"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                    "reason": {"type": "forwarded"},
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        reasons = result["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(len(reasons), 1)
        self.assertEqual(reasons[0]["type"], "forwarded")
        self.assertIsNone(reasons[0]["comment"])

    def testParseReportRecordReasonList(self):
        """Multiple reasons as a list are preserved"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                    "reason": [
                        {"type": "forwarded", "comment": "relay"},
                        {"type": "local_policy"},
                    ],
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        reasons = result["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(len(reasons), 2)
        self.assertEqual(reasons[0]["comment"], "relay")
        self.assertIsNone(reasons[1]["comment"])

    def testParseReportRecordIdentities(self):
        """'identities' key is mapped to 'identifiers'"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "pass"},
            },
            "identities": {"header_from": "Example.COM", "envelope_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertIn("identifiers", result)
        self.assertEqual(result["identifiers"]["header_from"], "example.com")

    def testParseReportRecordDkimDefaults(self):
        """DKIM result defaults: selector='none', result='none' when missing"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "fail", "spf": "fail"},
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": {"domain": "example.com"},
                "spf": [],
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        dkim = result["auth_results"]["dkim"][0]
        self.assertEqual(dkim["selector"], "none")
        self.assertEqual(dkim["result"], "none")
        self.assertIsNone(dkim["human_result"])

    def testParseReportRecordSpfDefaults(self):
        """SPF result defaults: scope='mfrom', result='none' when missing"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "fail", "spf": "fail"},
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [],
                "spf": {"domain": "example.com"},
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        spf = result["auth_results"]["spf"][0]
        self.assertEqual(spf["scope"], "mfrom")
        self.assertEqual(spf["result"], "none")
        self.assertIsNone(spf["human_result"])

    def testParseReportRecordHumanResult(self):
        """human_result field is included when present"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "pass"},
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [{"domain": "example.com", "selector": "s1",
                          "result": "pass", "human_result": "good key"}],
                "spf": [{"domain": "example.com", "scope": "mfrom",
                         "result": "pass", "human_result": "sender valid"}],
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertEqual(result["auth_results"]["dkim"][0]["human_result"], "good key")
        self.assertEqual(result["auth_results"]["spf"][0]["human_result"], "sender valid")

    def testParseReportRecordEnvelopeFromFallback(self):
        """envelope_from falls back to last SPF domain when missing"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "pass"},
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [],
                "spf": [{"domain": "Bounce.Example.COM", "scope": "mfrom", "result": "pass"}],
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertEqual(result["identifiers"]["envelope_from"], "bounce.example.com")

    def testParseReportRecordEnvelopeFromNullFallback(self):
        """envelope_from None value falls back to SPF domain"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "pass"},
            },
            "identifiers": {
                "header_from": "example.com",
                "envelope_from": None,
            },
            "auth_results": {
                "dkim": [],
                "spf": [{"domain": "SPF.Example.COM", "scope": "mfrom", "result": "pass"}],
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertEqual(result["identifiers"]["envelope_from"], "spf.example.com")

    def testParseReportRecordEnvelopeTo(self):
        """envelope_to is preserved and moved correctly"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "pass"},
            },
            "identifiers": {
                "header_from": "example.com",
                "envelope_from": "bounce@example.com",
                "envelope_to": "recipient@example.com",
            },
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertEqual(result["identifiers"]["envelope_to"], "recipient@example.com")

    def testParseReportRecordAlignment(self):
        """Alignment fields computed correctly from policy_evaluated"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {"disposition": "none", "dkim": "pass", "spf": "fail"},
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertTrue(result["alignment"]["dkim"])
        self.assertFalse(result["alignment"]["spf"])
        self.assertTrue(result["alignment"]["dmarc"])

    # ===================================================================
    # Tests for _parse_smtp_tls_failure_details
    # ===================================================================

    def testParseSmtpTlsFailureDetailsMinimal(self):
        """Minimal failure details with just required fields"""
        details = {
            "result-type": "certificate-expired",
            "failed-session-count": 5,
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(result["result_type"], "certificate-expired")
        self.assertEqual(result["failed_session_count"], 5)
        self.assertNotIn("sending_mta_ip", result)

    def testParseSmtpTlsFailureDetailsAllOptional(self):
        """All optional fields included"""
        details = {
            "result-type": "starttls-not-supported",
            "failed-session-count": 3,
            "sending-mta-ip": "10.0.0.1",
            "receiving-ip": "10.0.0.2",
            "receiving-mx-hostname": "mx.example.com",
            "receiving-mx-helo": "mx.example.com",
            "additional-info-uri": "https://example.com/info",
            "failure-reason-code": "TLS_ERROR",
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(result["sending_mta_ip"], "10.0.0.1")
        self.assertEqual(result["receiving_ip"], "10.0.0.2")
        self.assertEqual(result["receiving_mx_hostname"], "mx.example.com")
        self.assertEqual(result["receiving_mx_helo"], "mx.example.com")
        self.assertEqual(result["additional_info_uri"], "https://example.com/info")
        self.assertEqual(result["failure_reason_code"], "TLS_ERROR")

    def testParseSmtpTlsFailureDetailsMissingRequired(self):
        """Missing required field raises InvalidSMTPTLSReport"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc._parse_smtp_tls_failure_details({"result-type": "err"})

    # ===================================================================
    # Tests for _parse_smtp_tls_report_policy
    # ===================================================================

    def testParseSmtpTlsReportPolicyValid(self):
        """Valid STS policy parses correctly"""
        policy = {
            "policy": {
                "policy-type": "sts",
                "policy-domain": "example.com",
                "policy-string": ["version: STSv1", "mode: enforce"],
                "mx-host-pattern": ["*.example.com"],
            },
            "summary": {
                "total-successful-session-count": 100,
                "total-failure-session-count": 2,
            },
        }
        result = parsedmarc._parse_smtp_tls_report_policy(policy)
        self.assertEqual(result["policy_type"], "sts")
        self.assertEqual(result["policy_domain"], "example.com")
        self.assertEqual(result["policy_strings"], ["version: STSv1", "mode: enforce"])
        self.assertEqual(result["mx_host_patterns"], ["*.example.com"])
        self.assertEqual(result["successful_session_count"], 100)
        self.assertEqual(result["failed_session_count"], 2)

    def testParseSmtpTlsReportPolicyInvalidType(self):
        """Invalid policy type raises InvalidSMTPTLSReport"""
        policy = {
            "policy": {
                "policy-type": "invalid",
                "policy-domain": "example.com",
            },
            "summary": {
                "total-successful-session-count": 0,
                "total-failure-session-count": 0,
            },
        }
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc._parse_smtp_tls_report_policy(policy)

    def testParseSmtpTlsReportPolicyEmptyPolicyString(self):
        """Empty policy-string list is not included"""
        policy = {
            "policy": {
                "policy-type": "sts",
                "policy-domain": "example.com",
                "policy-string": [],
                "mx-host-pattern": [],
            },
            "summary": {
                "total-successful-session-count": 50,
                "total-failure-session-count": 0,
            },
        }
        result = parsedmarc._parse_smtp_tls_report_policy(policy)
        self.assertNotIn("policy_strings", result)
        self.assertNotIn("mx_host_patterns", result)

    def testParseSmtpTlsReportPolicyWithFailureDetails(self):
        """Policy with failure-details parses nested details"""
        policy = {
            "policy": {
                "policy-type": "sts",
                "policy-domain": "example.com",
            },
            "summary": {
                "total-successful-session-count": 10,
                "total-failure-session-count": 1,
            },
            "failure-details": [
                {
                    "result-type": "certificate-expired",
                    "failed-session-count": 1,
                }
            ],
        }
        result = parsedmarc._parse_smtp_tls_report_policy(policy)
        self.assertEqual(len(result["failure_details"]), 1)
        self.assertEqual(result["failure_details"][0]["result_type"], "certificate-expired")

    def testParseSmtpTlsReportPolicyMissingField(self):
        """Missing required policy field raises InvalidSMTPTLSReport"""
        policy = {"policy": {"policy-type": "sts"}, "summary": {}}
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc._parse_smtp_tls_report_policy(policy)

    # ===================================================================
    # Tests for parse_smtp_tls_report_json
    # ===================================================================

    def testParseSmtpTlsReportJsonValid(self):
        """Valid SMTP TLS JSON report parses correctly"""
        import json
        report = json.dumps({
            "organization-name": "Example Corp",
            "date-range": {
                "start-datetime": "2024-01-01T00:00:00Z",
                "end-datetime": "2024-01-02T00:00:00Z",
            },
            "contact-info": "admin@example.com",
            "report-id": "report-123",
            "policies": [
                {
                    "policy": {
                        "policy-type": "sts",
                        "policy-domain": "example.com",
                    },
                    "summary": {
                        "total-successful-session-count": 50,
                        "total-failure-session-count": 0,
                    },
                }
            ],
        })
        result = parsedmarc.parse_smtp_tls_report_json(report)
        self.assertEqual(result["organization_name"], "Example Corp")
        self.assertEqual(result["report_id"], "report-123")
        self.assertEqual(len(result["policies"]), 1)

    def testParseSmtpTlsReportJsonBytes(self):
        """SMTP TLS report as bytes parses correctly"""
        import json
        report = json.dumps({
            "organization-name": "Org",
            "date-range": {"start-datetime": "2024-01-01", "end-datetime": "2024-01-02"},
            "contact-info": "a@b.com",
            "report-id": "r1",
            "policies": [{
                "policy": {"policy-type": "tlsa", "policy-domain": "a.com"},
                "summary": {"total-successful-session-count": 1, "total-failure-session-count": 0},
            }],
        }).encode("utf-8")
        result = parsedmarc.parse_smtp_tls_report_json(report)
        self.assertEqual(result["organization_name"], "Org")

    def testParseSmtpTlsReportJsonMissingField(self):
        """Missing required field raises InvalidSMTPTLSReport"""
        import json
        report = json.dumps({"organization-name": "Org"})
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(report)

    def testParseSmtpTlsReportJsonPoliciesNotList(self):
        """Non-list policies raises InvalidSMTPTLSReport"""
        import json
        report = json.dumps({
            "organization-name": "Org",
            "date-range": {"start-datetime": "2024-01-01", "end-datetime": "2024-01-02"},
            "contact-info": "a@b.com",
            "report-id": "r1",
            "policies": "not-a-list",
        })
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(report)

    # ===================================================================
    # Tests for aggregate report parsing (validation warnings, etc.)
    # ===================================================================

    def testAggregateReportInvalidNpWarning(self):
        """Invalid np value is preserved but logs warning"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <version>1.0</version>
            <report_metadata>
                <org_name>Test Org</org_name>
                <email>test@example.com</email>
                <report_id>test-np-invalid</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
                <np>banana</np>
                <testing>maybe</testing>
                <discovery_method>magic</discovery_method>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <spf><domain>example.com</domain><result>pass</result></spf>
                </auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        # Invalid values are still stored
        self.assertEqual(report["policy_published"]["np"], "banana")
        self.assertEqual(report["policy_published"]["testing"], "maybe")
        self.assertEqual(report["policy_published"]["discovery_method"], "magic")

    def testAggregateReportPassDisposition(self):
        """'pass' as valid disposition is preserved"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-pass</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>reject</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>pass</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <spf><domain>example.com</domain><result>pass</result></spf>
                </auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["records"][0]["policy_evaluated"]["disposition"], "pass")

    def testAggregateReportMultipleRecords(self):
        """Reports with multiple records are all parsed"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-multi</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>10</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
            <record>
                <row>
                    <source_ip>192.0.2.2</source_ip>
                    <count>5</count>
                    <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>fail</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(len(report["records"]), 2)
        self.assertEqual(report["records"][0]["count"], 10)
        self.assertEqual(report["records"][1]["count"], 5)

    def testAggregateReportInvalidXmlRecovery(self):
        """Badly formed XML is recovered via lxml"""
        xml = '<?xml version="1.0"?><feedback><report_metadata><org_name>Test</org_name><email>t@e.com</email><report_id>r1</report_id><date_range><begin>1704067200</begin><end>1704153599</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>'
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["report_id"], "r1")

    def testAggregateReportCsvRowsContainDMARCbisFields(self):
        """CSV rows include np, testing, discovery_method columns"""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/dmarcbis-draft-sample.xml",
            always_use_local_files=True, offline=True,
        )
        report = result["report"]
        rows = parsedmarc.parsed_aggregate_reports_to_csv_rows(report)
        self.assertTrue(len(rows) > 0)
        row = rows[0]
        self.assertIn("np", row)
        self.assertIn("testing", row)
        self.assertIn("discovery_method", row)
        self.assertIn("source_ip_address", row)
        self.assertIn("dkim_domains", row)
        self.assertIn("spf_domains", row)

    def testAggregateReportSchemaVersion(self):
        """DMARCbis report with <version> returns correct xml_schema"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <version>1.0</version>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-version</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["xml_schema"], "1.0")

    def testAggregateReportDraftSchema(self):
        """Report without <version> defaults to 'draft' schema"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-draft</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["xml_schema"], "draft")

    def testAggregateReportGeneratorField(self):
        """Generator field is correctly extracted"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-gen</report_id>
                <generator>My Reporter v1.0</generator>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["generator"], "My Reporter v1.0")

    def testAggregateReportReportErrors(self):
        """Report errors in metadata are captured"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-err</report_id>
                <error>Some error</error>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIn("Some error", report["report_metadata"]["errors"])

    def testAggregateReportPolicyDefaults(self):
        """Policy defaults: adkim/aspf='r', sp=p, pct/fo=None"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-defaults</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>reject</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        pp = report["policy_published"]
        self.assertEqual(pp["adkim"], "r")
        self.assertEqual(pp["aspf"], "r")
        self.assertEqual(pp["sp"], "reject")  # defaults to p
        self.assertIsNone(pp["pct"])
        self.assertIsNone(pp["fo"])
        self.assertIsNone(pp["np"])
        self.assertIsNone(pp["testing"])
        self.assertIsNone(pp["discovery_method"])

    def testMagicXmlTagDetection(self):
        """XML without declaration (starting with '<') is extracted"""
        xml_no_decl = b"<feedback><report_metadata><org_name>T</org_name><email>a@b.com</email><report_id>r1</report_id><date_range><begin>1704067200</begin><end>1704153599</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>"
        self.assertTrue(xml_no_decl.startswith(parsedmarc.MAGIC_XML_TAG))
        # Ensure it extracts as XML
        result = parsedmarc.extract_report(xml_no_decl)
        self.assertIn("<feedback>", result)

    # ===================================================================
    # Tests for parsedmarc/utils.py
    # ===================================================================

    def testTimestampToDatetime(self):
        """timestamp_to_datetime converts UNIX timestamp to datetime"""
        from datetime import datetime
        dt = parsedmarc.utils.timestamp_to_datetime(0)
        self.assertIsInstance(dt, datetime)
        # Epoch 0 should be Jan 1 1970 in local time
        self.assertEqual(dt.year, 1970)

    def testTimestampToHuman(self):
        """timestamp_to_human returns formatted string"""
        result = parsedmarc.utils.timestamp_to_human(1704067200)
        self.assertRegex(result, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

    def testHumanTimestampToDatetime(self):
        """human_timestamp_to_datetime parses timestamp string"""
        from datetime import datetime
        dt = parsedmarc.utils.human_timestamp_to_datetime("2024-01-01 00:00:00")
        self.assertIsInstance(dt, datetime)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 1)

    def testHumanTimestampToDatetimeUtc(self):
        """human_timestamp_to_datetime with to_utc=True returns UTC"""
        from datetime import timezone
        dt = parsedmarc.utils.human_timestamp_to_datetime(
            "2024-01-01 12:00:00", to_utc=True
        )
        self.assertEqual(dt.tzinfo, timezone.utc)

    def testHumanTimestampToDatetimeParenthesisStripping(self):
        """Parenthesized content is stripped from timestamps"""
        dt = parsedmarc.utils.human_timestamp_to_datetime(
            "Mon, 01 Jan 2024 00:00:00 +0000 (UTC)"
        )
        self.assertEqual(dt.year, 2024)

    def testHumanTimestampToDatetimeNegativeZero(self):
        """-0000 timezone is handled"""
        dt = parsedmarc.utils.human_timestamp_to_datetime(
            "2024-01-01 00:00:00 -0000"
        )
        self.assertEqual(dt.year, 2024)

    def testHumanTimestampToUnixTimestamp(self):
        """human_timestamp_to_unix_timestamp converts to int"""
        ts = parsedmarc.utils.human_timestamp_to_unix_timestamp("2024-01-01 00:00:00")
        self.assertIsInstance(ts, int)

    def testHumanTimestampToUnixTimestampWithT(self):
        """T separator in timestamp is handled"""
        ts = parsedmarc.utils.human_timestamp_to_unix_timestamp("2024-01-01T00:00:00")
        self.assertIsInstance(ts, int)

    def testGetIpAddressCountry(self):
        """get_ip_address_country returns country code using bundled DBIP"""
        # 8.8.8.8 is a well-known Google DNS IP in US
        country = parsedmarc.utils.get_ip_address_country("8.8.8.8")
        self.assertEqual(country, "US")

    def testGetIpAddressCountryNotFound(self):
        """get_ip_address_country returns None for reserved IP"""
        country = parsedmarc.utils.get_ip_address_country("127.0.0.1")
        self.assertIsNone(country)

    def testGetServiceFromReverseDnsBaseDomainOffline(self):
        """get_service_from_reverse_dns_base_domain in offline mode"""
        result = parsedmarc.utils.get_service_from_reverse_dns_base_domain(
            "google.com", offline=True
        )
        self.assertIn("Google", result["name"])
        self.assertIsNotNone(result["type"])

    def testGetServiceFromReverseDnsBaseDomainUnknown(self):
        """Unknown base domain returns domain as name and None as type"""
        result = parsedmarc.utils.get_service_from_reverse_dns_base_domain(
            "unknown-domain-xyz.example", offline=True
        )
        self.assertEqual(result["name"], "unknown-domain-xyz.example")
        self.assertIsNone(result["type"])

    def testGetIpAddressInfoOffline(self):
        """get_ip_address_info in offline mode returns country but no DNS"""
        info = parsedmarc.utils.get_ip_address_info("8.8.8.8", offline=True)
        self.assertEqual(info["ip_address"], "8.8.8.8")
        self.assertEqual(info["country"], "US")
        self.assertIsNone(info["reverse_dns"])

    def testGetIpAddressInfoCache(self):
        """get_ip_address_info uses cache on second call"""
        from expiringdict import ExpiringDict
        cache = ExpiringDict(max_len=100, max_age_seconds=60)
        # offline=True means reverse_dns is None, so cache is not populated
        # Use offline=False with mock to test cache
        from unittest.mock import patch
        with patch("parsedmarc.utils.get_reverse_dns", return_value="dns.google"):
            info1 = parsedmarc.utils.get_ip_address_info(
                "8.8.8.8", offline=False, cache=cache,
                always_use_local_files=True,
            )
        self.assertIn("8.8.8.8", cache)
        info2 = parsedmarc.utils.get_ip_address_info("8.8.8.8", offline=False, cache=cache)
        self.assertEqual(info1["ip_address"], info2["ip_address"])
        self.assertEqual(info2["reverse_dns"], "dns.google")

    def testParseEmailAddressWithDisplayName(self):
        """parse_email_address with display name"""
        result = parsedmarc.utils.parse_email_address(("John Doe", "john@example.com"))
        self.assertEqual(result["display_name"], "John Doe")
        self.assertEqual(result["address"], "john@example.com")
        self.assertEqual(result["local"], "john")
        self.assertEqual(result["domain"], "example.com")

    def testParseEmailAddressWithoutDisplayName(self):
        """parse_email_address with empty display name"""
        result = parsedmarc.utils.parse_email_address(("", "john@example.com"))
        self.assertIsNone(result["display_name"])
        self.assertEqual(result["address"], "john@example.com")

    def testParseEmailAddressNoAt(self):
        """parse_email_address with no @ returns None local/domain"""
        result = parsedmarc.utils.parse_email_address(("", "localonly"))
        self.assertIsNone(result["local"])
        self.assertIsNone(result["domain"])

    def testGetFilenameSafeString(self):
        """get_filename_safe_string removes invalid chars"""
        result = parsedmarc.utils.get_filename_safe_string('file/name:with"bad*chars')
        self.assertNotIn("/", result)
        self.assertNotIn(":", result)
        self.assertNotIn('"', result)
        self.assertNotIn("*", result)

    def testGetFilenameSafeStringNone(self):
        """get_filename_safe_string with None returns 'None'"""
        result = parsedmarc.utils.get_filename_safe_string(None)
        self.assertEqual(result, "None")

    def testGetFilenameSafeStringLong(self):
        """get_filename_safe_string truncates to 100 chars"""
        result = parsedmarc.utils.get_filename_safe_string("a" * 200)
        self.assertEqual(len(result), 100)

    def testGetFilenameSafeStringTrailingDot(self):
        """get_filename_safe_string strips trailing dots"""
        result = parsedmarc.utils.get_filename_safe_string("filename...")
        self.assertFalse(result.endswith("."))

    def testIsMboxNonMbox(self):
        """is_mbox returns False for non-mbox file"""
        result = parsedmarc.utils.is_mbox("samples/empty.xml")
        self.assertFalse(result)

    def testIsOutlookMsgNonMsg(self):
        """is_outlook_msg returns False for non-MSG content"""
        self.assertFalse(parsedmarc.utils.is_outlook_msg(b"not an outlook msg"))
        self.assertFalse(parsedmarc.utils.is_outlook_msg("string content"))

    def testIsOutlookMsgMagic(self):
        """is_outlook_msg returns True for correct magic bytes"""
        magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100
        self.assertTrue(parsedmarc.utils.is_outlook_msg(magic))

    # ===================================================================
    # Tests for output modules (mocked)
    # ===================================================================

    def testWebhookClientInit(self):
        """WebhookClient initializes with correct attributes"""
        from parsedmarc.webhook import WebhookClient
        client = WebhookClient(
            aggregate_url="http://agg.example.com",
            failure_url="http://fail.example.com",
            smtp_tls_url="http://tls.example.com",
        )
        self.assertEqual(client.aggregate_url, "http://agg.example.com")
        self.assertEqual(client.failure_url, "http://fail.example.com")
        self.assertEqual(client.smtp_tls_url, "http://tls.example.com")
        self.assertEqual(client.timeout, 60)

    def testWebhookClientSaveMethods(self):
        """WebhookClient save methods call _send_to_webhook"""
        from unittest.mock import MagicMock
        from parsedmarc.webhook import WebhookClient
        client = WebhookClient("http://a", "http://f", "http://t")
        client.session = MagicMock()
        client.save_aggregate_report_to_webhook('{"test": 1}')
        client.session.post.assert_called_with("http://a", data='{"test": 1}', timeout=60)
        client.save_failure_report_to_webhook('{"fail": 1}')
        client.session.post.assert_called_with("http://f", data='{"fail": 1}', timeout=60)
        client.save_smtp_tls_report_to_webhook('{"tls": 1}')
        client.session.post.assert_called_with("http://t", data='{"tls": 1}', timeout=60)

    def testWebhookBackwardCompatAlias(self):
        """WebhookClient forensic alias points to failure method"""
        from parsedmarc.webhook import WebhookClient
        self.assertIs(
            WebhookClient.save_forensic_report_to_webhook,
            WebhookClient.save_failure_report_to_webhook,
        )

    def testKafkaStripMetadata(self):
        """KafkaClient.strip_metadata extracts metadata to root"""
        from parsedmarc.kafkaclient import KafkaClient
        report = {
            "report_metadata": {
                "org_name": "TestOrg",
                "org_email": "test@example.com",
                "report_id": "r-123",
                "begin_date": "2024-01-01",
                "end_date": "2024-01-02",
            },
            "records": [],
        }
        result = KafkaClient.strip_metadata(report)
        self.assertEqual(result["org_name"], "TestOrg")
        self.assertEqual(result["org_email"], "test@example.com")
        self.assertEqual(result["report_id"], "r-123")
        self.assertNotIn("report_metadata", result)

    def testKafkaGenerateDateRange(self):
        """KafkaClient.generate_date_range generates date range list"""
        from parsedmarc.kafkaclient import KafkaClient
        report = {
            "report_metadata": {
                "begin_date": "2024-01-01 00:00:00",
                "end_date": "2024-01-02 00:00:00",
            }
        }
        result = KafkaClient.generate_date_range(report)
        self.assertEqual(len(result), 2)
        self.assertIn("2024-01-01", result[0])
        self.assertIn("2024-01-02", result[1])

    def testSplunkHECClientInit(self):
        """HECClient initializes with correct URL and headers"""
        from parsedmarc.splunk import HECClient
        client = HECClient(
            url="https://splunk.example.com:8088",
            access_token="my-token",
            index="main",
        )
        self.assertIn("/services/collector/event/1.0", client.url)
        self.assertEqual(client.access_token, "my-token")
        self.assertEqual(client.index, "main")
        self.assertEqual(client.source, "parsedmarc")
        self.assertIn("Splunk my-token", client.session.headers["Authorization"])

    def testSplunkHECClientStripTokenPrefix(self):
        """HECClient strips 'Splunk ' prefix from token"""
        from parsedmarc.splunk import HECClient
        client = HECClient(
            url="https://splunk.example.com",
            access_token="Splunk my-token",
            index="main",
        )
        self.assertEqual(client.access_token, "my-token")

    def testSplunkBackwardCompatAlias(self):
        """HECClient forensic alias points to failure method"""
        from parsedmarc.splunk import HECClient
        self.assertIs(
            HECClient.save_forensic_reports_to_splunk,
            HECClient.save_failure_reports_to_splunk,
        )

    def testSyslogClientUdpInit(self):
        """SyslogClient creates UDP handler"""
        from parsedmarc.syslog import SyslogClient
        client = SyslogClient("localhost", 514, protocol="udp")
        self.assertEqual(client.server_name, "localhost")
        self.assertEqual(client.server_port, 514)
        self.assertEqual(client.protocol, "udp")

    def testSyslogClientInvalidProtocol(self):
        """SyslogClient with invalid protocol raises ValueError"""
        from parsedmarc.syslog import SyslogClient
        with self.assertRaises(ValueError):
            SyslogClient("localhost", 514, protocol="invalid")

    def testSyslogBackwardCompatAlias(self):
        """SyslogClient forensic alias points to failure method"""
        from parsedmarc.syslog import SyslogClient
        self.assertIs(
            SyslogClient.save_forensic_report_to_syslog,
            SyslogClient.save_failure_report_to_syslog,
        )

    def testLogAnalyticsConfig(self):
        """LogAnalyticsConfig stores all fields"""
        from parsedmarc.loganalytics import LogAnalyticsConfig
        config = LogAnalyticsConfig(
            client_id="cid",
            client_secret="csec",
            tenant_id="tid",
            dce="https://dce.example.com",
            dcr_immutable_id="dcr-123",
            dcr_aggregate_stream="agg-stream",
            dcr_failure_stream="fail-stream",
            dcr_smtp_tls_stream="tls-stream",
        )
        self.assertEqual(config.client_id, "cid")
        self.assertEqual(config.client_secret, "csec")
        self.assertEqual(config.tenant_id, "tid")
        self.assertEqual(config.dce, "https://dce.example.com")
        self.assertEqual(config.dcr_immutable_id, "dcr-123")
        self.assertEqual(config.dcr_aggregate_stream, "agg-stream")
        self.assertEqual(config.dcr_failure_stream, "fail-stream")
        self.assertEqual(config.dcr_smtp_tls_stream, "tls-stream")

    def testLogAnalyticsClientValidationError(self):
        """LogAnalyticsClient raises on missing required config"""
        from parsedmarc.loganalytics import LogAnalyticsClient, LogAnalyticsException
        with self.assertRaises(LogAnalyticsException):
            LogAnalyticsClient(
                client_id="",
                client_secret="csec",
                tenant_id="tid",
                dce="https://dce.example.com",
                dcr_immutable_id="dcr-123",
                dcr_aggregate_stream="agg",
                dcr_failure_stream="fail",
                dcr_smtp_tls_stream="tls",
            )

    def testSmtpTlsCsvRows(self):
        """parsed_smtp_tls_reports_to_csv_rows produces correct rows"""
        import json
        report_json = json.dumps({
            "organization-name": "Org",
            "date-range": {"start-datetime": "2024-01-01T00:00:00Z", "end-datetime": "2024-01-02T00:00:00Z"},
            "contact-info": "a@b.com",
            "report-id": "r1",
            "policies": [{
                "policy": {"policy-type": "sts", "policy-domain": "example.com",
                           "policy-string": ["v: STSv1"], "mx-host-pattern": ["*.example.com"]},
                "summary": {"total-successful-session-count": 10, "total-failure-session-count": 1},
                "failure-details": [{"result-type": "cert-expired", "failed-session-count": 1}],
            }],
        })
        parsed = parsedmarc.parse_smtp_tls_report_json(report_json)
        rows = parsedmarc.parsed_smtp_tls_reports_to_csv_rows(parsed)
        self.assertTrue(len(rows) >= 2)
        self.assertEqual(rows[0]["organization_name"], "Org")
        self.assertEqual(rows[0]["policy_domain"], "example.com")

    def testParsedAggregateReportsToCsvRowsList(self):
        """parsed_aggregate_reports_to_csv_rows handles list of reports"""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/dmarcbis-draft-sample.xml",
            always_use_local_files=True, offline=True,
        )
        report = result["report"]
        # Pass as a list
        rows = parsedmarc.parsed_aggregate_reports_to_csv_rows([report])
        self.assertTrue(len(rows) > 0)
        # Verify non-str/int/bool values are cleaned
        for row in rows:
            for v in row.values():
                self.assertIn(type(v), [str, int, bool])

    def testExceptionHierarchy(self):
        """Exception class hierarchy is correct"""
        self.assertTrue(issubclass(parsedmarc.ParserError, RuntimeError))
        self.assertTrue(issubclass(parsedmarc.InvalidDMARCReport, parsedmarc.ParserError))
        self.assertTrue(issubclass(parsedmarc.InvalidAggregateReport, parsedmarc.InvalidDMARCReport))
        self.assertTrue(issubclass(parsedmarc.InvalidFailureReport, parsedmarc.InvalidDMARCReport))
        self.assertTrue(issubclass(parsedmarc.InvalidSMTPTLSReport, parsedmarc.ParserError))
        self.assertIs(parsedmarc.InvalidForensicReport, parsedmarc.InvalidFailureReport)

    def testAggregateReportNormalization(self):
        """Reports spanning >24h get normalized per day"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-norm</report_id>
                <date_range><begin>1704067200</begin><end>1704326400</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>90</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        # Span is 259200 seconds (3 days), exceeds default 24h threshold
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertTrue(report["report_metadata"]["timespan_requires_normalization"])
        # Records should be split across days
        self.assertTrue(len(report["records"]) > 1)
        total = sum(r["count"] for r in report["records"])
        self.assertEqual(total, 90)
        for r in report["records"]:
            self.assertTrue(r["normalized_timespan"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
