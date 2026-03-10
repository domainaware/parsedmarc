#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import os
import sys
import tempfile
import unittest
from base64 import urlsafe_b64encode
from glob import glob
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from lxml import etree
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
        self.assertEqual(result["report_type"], "aggregate")
        self.assertEqual(result["report"]["report_metadata"]["org_name"], "outlook.com")

    def testParseReportFileAcceptsPathForEmail(self):
        report_path = Path(
            "samples/aggregate/Report domain- borschow.com Submitter- google.com Report-ID- 949348866075514174.eml"
        )
        result = parsedmarc.parse_report_file(
            report_path,
            offline=True,
        )
        self.assertEqual(result["report_type"], "aggregate")
        self.assertEqual(result["report"]["report_metadata"]["org_name"], "google.com")

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
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as config_file:
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
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as config_file:
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
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as config_file:
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
        mock_save_forensic_opensearch.side_effect = parsedmarc.cli.opensearch.OpenSearchError(
            "forensic sink failed"
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
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as config_file:
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
                returned = _get_creds(
                    token_path, "credentials.json", ["scope"], 8080
                )
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
                returned = _get_creds(
                    token_path, "credentials.json", ["scope"], 8080
                )
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
        mocked_sleep.assert_called_once_with(graph_module.GRAPH_REQUEST_RETRY_DELAY_SECONDS)

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
        connection._find_folder_id_from_folder_path = MagicMock(return_value="folder-id")
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
        with patch.object(graph_module, "_get_cache_args", return_value={"cached": True}):
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

    def testInitCertificateAuthSkipsInteractiveAuthenticate(self):
        class DummyCertificateCredential:
            pass

        fake_credential = DummyCertificateCredential()
        with patch.object(graph_module, "CertificateCredential", DummyCertificateCredential):
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
    @patch("parsedmarc.mail.gmail.service_account.Credentials.from_service_account_file")
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

    @patch("parsedmarc.mail.gmail.service_account.Credentials.from_service_account_file")
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
    def testWatchInboxPassesSinceToMailboxFetch(self):
        mailbox_connection = SimpleNamespace()

        def fake_watch(check_callback, check_timeout):
            check_callback(mailbox_connection)
            raise _BreakLoop()

        mailbox_connection.watch = fake_watch
        callback = MagicMock()
        with patch.object(
            parsedmarc, "get_dmarc_reports_from_mailbox", return_value={}
        ) as mocked:
            with self.assertRaises(_BreakLoop):
                parsedmarc.watch_inbox(
                    mailbox_connection=mailbox_connection,
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
        connection._client = _FakeGraphClient()
        connection._request_with_retries = MagicMock(
            side_effect=lambda _method, url, **kwargs: connection._client.get(
                url, **kwargs
            )
        )

        folder_id = connection._find_folder_id_with_parent("Inbox", None)
        self.assertEqual(folder_id, "inbox-id")
        connection._request_with_retries.assert_any_call(
            "get", "/users/shared@example.com/mailFolders?$filter=displayName eq 'Inbox'"
        )
        connection._request_with_retries.assert_any_call(
            "get", "/users/shared@example.com/mailFolders/inbox?$select=id,displayName"
        )

    def testUnknownFolderStillFails(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._client = _FakeGraphClient()
        connection._request_with_retries = MagicMock(
            side_effect=lambda _method, url, **kwargs: connection._client.get(
                url, **kwargs
            )
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
