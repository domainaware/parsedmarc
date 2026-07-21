"""Tests for the top-level parsedmarc package (parsedmarc/__init__.py).

Covers the public parsing surface: parse_report_file, parse_report_email,
parse_aggregate_report_xml, parse_failure_report, parse_smtp_tls_report_json,
extract_report, get_dmarc_reports_from_mbox, and the CSV / JSON renderers.
"""

import base64
import gzip
import json
import logging
import mailbox
import os
import unittest
from datetime import datetime, timedelta, timezone
from glob import glob
from io import BytesIO
from pathlib import Path
from shutil import rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from typing import BinaryIO, cast
from unittest.mock import MagicMock, patch

from lxml import etree  # type: ignore[import-untyped]

import parsedmarc
from parsedmarc.mail import MaildirConnection, MSGraphConnection
from parsedmarc.types import (
    AggregateReport,
    FailureReport,
    ParsingResults,
    SMTPTLSReport,
)

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
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

    def testExtractReportXMLComparator(self):
        """Test XML comparator function"""
        with open("samples/extract_report/nice-input.xml") as f:
            xmlnice = f.read()
        with open("samples/extract_report/changed-input.xml") as f:
            xmlchanged = minify_xml(f.read())
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
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = f.read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportXML(self):
        """Test extract report function for XML input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = f.read()
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
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = f.read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportZip(self):
        """Test extract report function for zip input"""
        print()
        file = "samples/extract_report/nice-input.xml.zip"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = minify_xml(f.read())
        self.assertTrue(compare_xml(xmlout, xmlin))
        with open("samples/extract_report/changed-input.xml") as f:
            xmlin = f.read()
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
        report = cast(AggregateReport, result["report"])
        self.assertEqual(report["report_metadata"]["org_name"], "outlook.com")

    def testParseReportFileAcceptsPathForEmail(self):
        report_path = Path(
            "samples/aggregate/Report domain- borschow.com Submitter- google.com Report-ID- 949348866075514174.eml"
        )
        result = parsedmarc.parse_report_file(
            report_path,
            offline=True,
        )
        assert result["report_type"] == "aggregate"
        report = cast(AggregateReport, result["report"])
        self.assertEqual(report["report_metadata"]["org_name"], "google.com")

    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        print()
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            with self.subTest(sample=sample_path):
                result = parsedmarc.parse_report_file(
                    sample_path, always_use_local_files=True, offline=OFFLINE_MODE
                )
                assert result["report_type"] == "aggregate"
                parsedmarc.parsed_aggregate_reports_to_csv(
                    cast(AggregateReport, result["report"])
                )
            print("Passed!")

    def testAggregateResultWordsAreLowercase(self):
        result = parsedmarc.parse_report_file(
            "samples/aggregate_invalid/report_with_upper_cased_pass.xml",
            offline=True,
        )
        assert result["report_type"] == "aggregate"
        report = cast(AggregateReport, result["report"])
        record = report["records"][0]

        self.assertEqual(record["policy_evaluated"]["dkim"], "pass")
        self.assertEqual(record["policy_evaluated"]["spf"], "pass")
        self.assertEqual(record["auth_results"]["dkim"][0]["result"], "pass")
        self.assertEqual(record["auth_results"]["spf"][0]["result"], "pass")

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
            with self.subTest(sample=sample_path):
                with open(sample_path) as sample_file:
                    sample_content = sample_file.read()
                    email_result = parsedmarc.parse_report_email(
                        sample_content, offline=OFFLINE_MODE
                    )
                    assert email_result["report_type"] == "failure"
                result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
                assert result["report_type"] == "failure"
                parsedmarc.parsed_failure_reports_to_csv(
                    cast(FailureReport, result["report"])
                )
            print("Passed!")

    def testFailureSampleWithoutFeedbackReportPart(self):
        """A plain-text-only failure report (no message/feedback-report part)
        must still contain every field the Elasticsearch/OpenSearch outputs
        access with hard key lookups (issue #332)"""
        sample_path = "samples/failure/exim_plain_text_only_no_arf_part.eml"
        result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
        assert result["report_type"] == "failure"
        report = cast(FailureReport, result["report"])
        assert report["feedback_type"] == "auth-failure"
        assert "authentication_results" in report
        assert report["source"]["ip_address"] == "203.0.113.68"

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

    def testRFC9990SampleReport(self):
        """Test parsing the sample report from RFC 9990 Appendix B"""
        print()
        sample_path = "samples/aggregate/rfc9990-sample.xml"
        print("Testing {0}: ".format(sample_path), end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = cast(AggregateReport, result["report"])

        # Verify report_type
        self.assertEqual(result["report_type"], "aggregate")

        # Verify xml_schema
        self.assertEqual(report["xml_schema"], "1.0")

        # Verify report_metadata
        metadata = report["report_metadata"]
        self.assertEqual(metadata["org_name"], "Sample Reporter")
        self.assertEqual(metadata["org_email"], "report_sender@example-reporter.com")
        self.assertEqual(metadata["org_extra_contact_info"], "...")
        self.assertEqual(metadata["report_id"], "3v98abbp8ya9n3va8yr8oa3ya")
        self.assertEqual(
            metadata["generator"],
            "Example DMARC Aggregate Reporter v1.2",
        )

        # Verify RFC 9990 policy_published fields
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
        # pct is removed in RFC 9989 (and so absent from the RFC 9990
        # sample); fo is still part of RFC 9990's PolicyPublishedType but
        # the appendix sample happens not to set it.
        self.assertIsNone(pp["pct"])
        self.assertIsNone(pp["fo"])

        # Verify record
        self.assertEqual(len(report["records"]), 1)
        rec = report["records"][0]
        self.assertEqual(rec["source"]["ip_address"], "192.0.2.123")
        self.assertEqual(rec["count"], 123)
        self.assertEqual(rec["policy_evaluated"]["disposition"], "pass")
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

    def testRFC9990FieldsAbsentFromRFC7489Report(self):
        """Test that RFC 7489 reports have None for RFC 9990-only fields"""
        print()
        sample_path = (
            "samples/aggregate/example.net!example.com!1529366400!1529452799.xml"
        )
        print("Testing {0}: ".format(sample_path), end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = cast(AggregateReport, result["report"])
        pp = report["policy_published"]

        # RFC 7489 fields present
        self.assertEqual(pp["pct"], "100")
        self.assertEqual(pp["fo"], "0")

        # RFC 9990-only fields absent (None)
        self.assertIsNone(pp["np"])
        self.assertIsNone(pp["testing"])
        self.assertIsNone(pp["discovery_method"])

        # generator absent (None)
        self.assertIsNone(report["report_metadata"]["generator"])
        print("Passed!")

    def testRFC9990WithExplicitFields(self):
        """Test RFC 9990 report with explicit testing and discovery_method"""
        print()
        sample_path = (
            "samples/aggregate/"
            "rfc9990-example.net!example.com!1700000000!1700086399.xml"
        )
        print("Testing {0}: ".format(sample_path), end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = cast(AggregateReport, result["report"])
        pp = report["policy_published"]

        self.assertEqual(pp["np"], "reject")
        self.assertEqual(pp["testing"], "y")
        self.assertEqual(pp["discovery_method"], "treewalk")
        print("Passed!")

    def testRFC9990NamespaceCaptured(self):
        """The dmarc-2.0 namespace on <feedback> is preserved on the
        parsed report so consumers can distinguish RFC 9990 from RFC 7489
        reports without inferring from the version element value."""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/rfc9990-sample.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
        self.assertEqual(
            report["xml_namespace"],
            "urn:ietf:params:xml:ns:dmarc-2.0",
        )

    def testRFC9990NamespaceAbsentOnRFC7489Report(self):
        """RFC 7489 reports don't declare the dmarc-2.0 namespace, so
        xml_namespace is None."""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/example.net!example.com!1529366400!1529452799.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
        self.assertIsNone(report["xml_namespace"])

    def testRFC9990DetectionAcceptsNamespacelessReports(self):
        """A report that follows the RFC 9990 shape without declaring the
        namespace (e.g. emits np/testing/discovery_method) is still
        treated as RFC 9990 for validation purposes — warnings fire,
        the namespace field reports it honestly as absent."""
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_aggregate_report_xml(
                """<?xml version="1.0"?>
                <feedback>
                    <report_metadata>
                        <org_name>Test</org_name>
                        <email>t@example.com</email>
                        <report_id>r1</report_id>
                        <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
                    </report_metadata>
                    <policy_published>
                        <domain>example.com</domain>
                        <p>none</p>
                        <np>reject</np>
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
                            <dkim>
                                <domain>example.com</domain>
                                <result>pass</result>
                            </dkim>
                        </auth_results>
                    </record>
                </feedback>""",
                offline=True,
            )
        # Namespace honestly None because none was declared.
        self.assertIsNone(report["xml_namespace"])
        # RFC 9990 detection still fired (DKIM selector warning emitted).
        self.assertTrue(
            any("selector" in msg for msg in cm.output),
            f"Expected DKIM selector warning; got: {cm.output}",
        )

    def testRFC9990DKIMMissingSelectorWarning(self):
        """A DKIM auth result with no <selector> in an RFC 9990 report
        (namespace declared) emits a warning since selector is REQUIRED."""
        xml = """<?xml version="1.0"?>
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
            <version>1.0</version>
            <report_metadata>
                <org_name>Test</org_name>
                <email>t@example.com</email>
                <report_id>r1</report_id>
                <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
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
                    <dkim>
                        <domain>example.com</domain>
                        <result>pass</result>
                    </dkim>
                </auth_results>
            </record>
        </feedback>"""
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertTrue(
            any("selector" in m and "REQUIRED" in m for m in cm.output),
            f"Expected selector REQUIRED warning; got: {cm.output}",
        )

    def testRFC9990LegacyOverrideTypeWarning(self):
        """`forwarded` and `sampled_out` were removed in RFC 9990;
        a warning fires when they appear in an RFC 9990 report."""
        xml = """<?xml version="1.0"?>
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
            <report_metadata>
                <org_name>Test</org_name>
                <email>t@example.com</email>
                <report_id>r1</report_id>
                <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                        <reason><type>forwarded</type></reason>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <dkim>
                        <domain>example.com</domain>
                        <selector>s</selector>
                        <result>pass</result>
                    </dkim>
                </auth_results>
            </record>
        </feedback>"""
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertTrue(
            any("forwarded" in m and "removed in RFC 9990" in m for m in cm.output),
            f"Expected legacy override warning; got: {cm.output}",
        )

    def testRFC9990LangAttrStringUnwrapped(self):
        """When a langAttrString element (extra_contact_info, error,
        comment, human_result) carries a lang attribute, xmltodict turns
        it into {"#text": "...", "@lang": "en"}; the parser must unwrap
        to the text payload so the report stays comparable to one
        without the lang attribute."""
        xml = """<?xml version="1.0"?>
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
            <report_metadata>
                <org_name>Test</org_name>
                <email>t@example.com</email>
                <extra_contact_info xml:lang="en">contact-here</extra_contact_info>
                <report_id>r1</report_id>
                <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
                <error xml:lang="en">a problem</error>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                        <reason>
                            <type>local_policy</type>
                            <comment xml:lang="en">a comment</comment>
                        </reason>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <dkim>
                        <domain>example.com</domain>
                        <selector>s</selector>
                        <result>pass</result>
                        <human_result xml:lang="en">looks fine</human_result>
                    </dkim>
                    <spf>
                        <domain>example.com</domain>
                        <result>pass</result>
                        <human_result xml:lang="en">spf-detail</human_result>
                    </spf>
                </auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(
            report["report_metadata"]["org_extra_contact_info"], "contact-here"
        )
        self.assertEqual(report["report_metadata"]["errors"], ["a problem"])
        rec = report["records"][0]
        reasons = rec["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(reasons[0]["comment"], "a comment")
        self.assertEqual(rec["auth_results"]["dkim"][0]["human_result"], "looks fine")
        self.assertEqual(rec["auth_results"]["spf"][0]["human_result"], "spf-detail")

    def testSmtpTlsSamples(self):
        """Test sample SMTP TLS reports"""
        print()
        sample_paths = glob("samples/smtp_tls/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            with self.subTest(sample=sample_path):
                result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
                assert result["report_type"] == "smtp_tls"
                parsedmarc.parsed_smtp_tls_reports_to_csv(
                    cast(SMTPTLSReport, result["report"])
                )
            print("Passed!")

    def testAggregateCsvExposesASNColumns(self):
        """The aggregate CSV output should include source_asn, source_as_name,
        and source_as_domain columns."""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/!example.com!1538204542!1538463818.xml",
            always_use_local_files=True,
            offline=True,
        )
        csv_text = parsedmarc.parsed_aggregate_reports_to_csv(
            cast(AggregateReport, result["report"])
        )
        header = csv_text.splitlines()[0].split(",")
        self.assertIn("source_asn", header)
        self.assertIn("source_as_name", header)
        self.assertIn("source_as_domain", header)

    def testBucketIntervalBeginAfterEnd(self):
        """begin > end should raise ValueError"""
        begin = datetime(2024, 1, 2, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalNaiveDatetime(self):
        """Non-timezone-aware datetimes should raise ValueError"""
        begin = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalDifferentTzinfo(self):
        """Different tzinfo objects should raise ValueError"""
        tz1 = timezone.utc
        tz2 = timezone(timedelta(hours=5))
        begin = datetime(2024, 1, 1, tzinfo=tz1)
        end = datetime(2024, 1, 2, tzinfo=tz2)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalNegativeCount(self):
        """Negative total_count should raise ValueError"""
        begin = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, -1)

    def testBucketIntervalZeroCount(self):
        """Zero total_count should return empty list"""
        begin = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 0)
        self.assertEqual(result, [])

    def testBucketIntervalSameBeginEnd(self):
        """Same begin and end (zero interval) should return empty list"""
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(dt, dt, 100)
        self.assertEqual(result, [])

    def testBucketIntervalSingleDay(self):
        """Single day interval should return one bucket with total count"""
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 23, 59, 59, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 100)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["count"], 100)
        self.assertEqual(result[0]["begin"], begin)

    def testBucketIntervalMultiDay(self):
        """Multi-day interval should distribute counts proportionally"""
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
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 4, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 10)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 10)
        self.assertEqual(len(result), 3)

    def testBucketIntervalPartialDays(self):
        """Partial days: 12h on day1, 24h on day2 => 1/3 vs 2/3 split"""
        begin = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 90)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 90)
        # day1: 12h, day2: 24h => 1/3 vs 2/3
        self.assertEqual(result[0]["count"], 30)
        self.assertEqual(result[1]["count"], 60)

    def testAppendParsedRecordNoNormalize(self):
        """No normalization: record appended as-is with interval fields"""
        records = []
        rec = {"count": 10, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, False)
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0]["normalized_timespan"])  # type: ignore[typeddict-item]
        self.assertEqual(records[0]["interval_begin"], "2024-01-01 00:00:00")
        self.assertEqual(records[0]["interval_end"], "2024-01-02 00:00:00")

    def testAppendParsedRecordNormalize(self):
        """Normalization: record split into daily buckets"""
        records = []
        rec = {"count": 100, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, True)
        self.assertEqual(len(records), 2)
        total = sum(r["count"] for r in records)
        self.assertEqual(total, 100)
        for r in records:
            self.assertTrue(r["normalized_timespan"])  # type: ignore[typeddict-item]

    def testAppendParsedRecordNormalizeZeroCount(self):
        """Normalization with zero count: nothing appended"""
        records = []
        rec = {"count": 0, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, True)
        self.assertEqual(len(records), 0)

    def testParseReportRecordNoneSourceIP(self):
        """Record with None source_ip should raise ValueError"""
        record = {
            "row": {
                "source_ip": None,
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
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
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "fail",
                },
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
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identities": {
                "header_from": "Example.COM",
                "envelope_from": "example.com",
            },
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
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "fail",
                    "spf": "fail",
                },
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
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "fail",
                    "spf": "fail",
                },
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
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [
                    {
                        "domain": "example.com",
                        "selector": "s1",
                        "result": "pass",
                        "human_result": "good key",
                    }
                ],
                "spf": [
                    {
                        "domain": "example.com",
                        "scope": "mfrom",
                        "result": "pass",
                        "human_result": "sender valid",
                    }
                ],
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertEqual(result["auth_results"]["dkim"][0]["human_result"], "good key")
        self.assertEqual(
            result["auth_results"]["spf"][0]["human_result"], "sender valid"
        )

    def testParseReportRecordEnvelopeFromFallback(self):
        """envelope_from falls back to last SPF domain when missing"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [],
                "spf": [
                    {"domain": "Bounce.Example.COM", "scope": "mfrom", "result": "pass"}
                ],
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
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {
                "header_from": "example.com",
                "envelope_from": None,
            },
            "auth_results": {
                "dkim": [],
                "spf": [
                    {"domain": "SPF.Example.COM", "scope": "mfrom", "result": "pass"}
                ],
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertEqual(result["identifiers"]["envelope_from"], "spf.example.com")

    def testParseReportRecordEnvelopeFromNullNoSpfDomain(self):
        """envelope_from=None with SPF results that carry no domain must not
        raise IndexError (regression: the branch gated on the raw SPF list but
        indexed the filtered list, which is empty when no result has a domain)"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {
                "header_from": "example.com",
                "envelope_from": None,
            },
            # A raw SPF result with no "domain" -> filtered list is empty.
            "auth_results": {
                "dkim": [],
                "spf": [{"scope": "mfrom", "result": "pass"}],
            },
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertIsNone(result["identifiers"]["envelope_from"])

    def testParseReportRecordEnvelopeTo(self):
        """envelope_to is preserved and moved correctly"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
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
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "fail",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(record, offline=True)
        self.assertTrue(result["alignment"]["dkim"])
        self.assertFalse(result["alignment"]["spf"])
        self.assertTrue(result["alignment"]["dmarc"])

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

    def testParseSmtpTlsFailureDetailsNonDict(self):
        """A non-dict failure-details value hits the catch-all (TypeError,
        not KeyError) and is wrapped as InvalidSMTPTLSReport"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            # Deliberate wrong type to exercise the non-KeyError catch-all.
            parsedmarc._parse_smtp_tls_failure_details("not a dict")  # pyright: ignore[reportArgumentType]
        self.assertIsInstance(ctx.exception.__cause__, TypeError)

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
        self.assertEqual(
            result["failure_details"][0]["result_type"], "certificate-expired"
        )

    def testParseSmtpTlsReportPolicyMissingField(self):
        """Missing required policy field raises InvalidSMTPTLSReport"""
        policy = {"policy": {"policy-type": "sts"}, "summary": {}}
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc._parse_smtp_tls_report_policy(policy)

    def testParseSmtpTlsReportJsonValid(self):
        """Valid SMTP TLS JSON report parses correctly"""
        report = json.dumps(
            {
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
            }
        )
        result = parsedmarc.parse_smtp_tls_report_json(report)
        self.assertEqual(result["organization_name"], "Example Corp")
        self.assertEqual(result["report_id"], "report-123")
        self.assertEqual(len(result["policies"]), 1)

    def testParseSmtpTlsReportJsonBytes(self):
        """SMTP TLS report as bytes parses correctly"""
        report = json.dumps(
            {
                "organization-name": "Org",
                "date-range": {
                    "start-datetime": "2024-01-01",
                    "end-datetime": "2024-01-02",
                },
                "contact-info": "a@b.com",
                "report-id": "r1",
                "policies": [
                    {
                        "policy": {"policy-type": "tlsa", "policy-domain": "a.com"},
                        "summary": {
                            "total-successful-session-count": 1,
                            "total-failure-session-count": 0,
                        },
                    }
                ],
            }
        ).encode("utf-8")
        result = parsedmarc.parse_smtp_tls_report_json(report)
        self.assertEqual(result["organization_name"], "Org")

    def testParseSmtpTlsReportJsonMissingField(self):
        """Missing required field raises InvalidSMTPTLSReport"""
        report = json.dumps({"organization-name": "Org"})
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(report)

    def testParseSmtpTlsReportJsonPoliciesNotList(self):
        """Non-list policies raises InvalidSMTPTLSReport"""
        report = json.dumps(
            {
                "organization-name": "Org",
                "date-range": {
                    "start-datetime": "2024-01-01",
                    "end-datetime": "2024-01-02",
                },
                "contact-info": "a@b.com",
                "report-id": "r1",
                "policies": "not-a-list",
            }
        )
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(report)

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
        self.assertEqual(
            report["records"][0]["policy_evaluated"]["disposition"], "pass"
        )

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

    def testAggregateReportCsvRowsContainRFC9990Fields(self):
        """CSV rows include np, testing, discovery_method columns"""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/rfc9990-sample.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
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
        """RFC 9990 report with <version> returns correct xml_schema"""
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

    def testSmtpTlsCsvRows(self):
        """parsed_smtp_tls_reports_to_csv_rows produces correct rows"""
        report_json = json.dumps(
            {
                "organization-name": "Org",
                "date-range": {
                    "start-datetime": "2024-01-01T00:00:00Z",
                    "end-datetime": "2024-01-02T00:00:00Z",
                },
                "contact-info": "a@b.com",
                "report-id": "r1",
                "policies": [
                    {
                        "policy": {
                            "policy-type": "sts",
                            "policy-domain": "example.com",
                            "policy-string": ["v: STSv1"],
                            "mx-host-pattern": ["*.example.com"],
                        },
                        "summary": {
                            "total-successful-session-count": 10,
                            "total-failure-session-count": 1,
                        },
                        "failure-details": [
                            {"result-type": "cert-expired", "failed-session-count": 1}
                        ],
                    }
                ],
            }
        )
        parsed = parsedmarc.parse_smtp_tls_report_json(report_json)
        rows = parsedmarc.parsed_smtp_tls_reports_to_csv_rows(parsed)
        self.assertTrue(len(rows) >= 2)
        self.assertEqual(rows[0]["organization_name"], "Org")
        self.assertEqual(rows[0]["policy_domain"], "example.com")

    def testParsedAggregateReportsToCsvRowsList(self):
        """parsed_aggregate_reports_to_csv_rows handles list of reports"""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/rfc9990-sample.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
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
        self.assertTrue(
            issubclass(parsedmarc.InvalidDMARCReport, parsedmarc.ParserError)
        )
        self.assertTrue(
            issubclass(parsedmarc.InvalidAggregateReport, parsedmarc.InvalidDMARCReport)
        )
        self.assertTrue(
            issubclass(parsedmarc.InvalidFailureReport, parsedmarc.InvalidDMARCReport)
        )
        self.assertTrue(
            issubclass(parsedmarc.InvalidSMTPTLSReport, parsedmarc.ParserError)
        )
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
            self.assertTrue(r["normalized_timespan"])  # type: ignore[typeddict-item]

    def testExtractReportFromFilePathNotFound(self):
        """extract_report_from_file_path raises ParserError for missing file"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report_from_file_path("nonexistent_file.xml")

    def testExtractReportInvalidArchive(self):
        """extract_report raises ParserError for unrecognized binary content"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report(b"\x00\x01\x02\x03\x04\x05\x06\x07")

    def testParseAggregateReportFile(self):
        """parse_aggregate_report_file parses bytes input directly"""
        print()
        sample_path = "samples/aggregate/rfc9990-sample.xml"
        print("Testing {0}: ".format(sample_path), end="")
        with open(sample_path, "rb") as f:
            data = f.read()
        report = parsedmarc.parse_aggregate_report_file(
            data,
            offline=True,
            always_use_local_files=True,
        )
        self.assertEqual(report["report_metadata"]["org_name"], "Sample Reporter")
        self.assertEqual(report["policy_published"]["domain"], "example.com")
        print("Passed!")

    def testParseInvalidAggregateSample(self):
        """Test invalid aggregate samples are handled"""
        print()
        sample_paths = glob("samples/aggregate_invalid/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            with self.subTest(sample=sample_path):
                parsed_report = cast(
                    AggregateReport,
                    parsedmarc.parse_report_file(
                        sample_path, always_use_local_files=True, offline=OFFLINE_MODE
                    )["report"],
                )
                parsedmarc.parsed_aggregate_reports_to_csv(parsed_report)
            print("Passed!")

    def testParseReportFileWithBytes(self):
        """parse_report_file handles bytes input"""
        with open("samples/aggregate/rfc9990-sample.xml", "rb") as f:
            data = f.read()
        result = parsedmarc.parse_report_file(
            data, always_use_local_files=True, offline=True
        )
        self.assertEqual(result["report_type"], "aggregate")

    def testFailureReportCsvRoundtrip(self):
        """Failure report CSV generation works on sample reports"""
        print()
        sample_paths = glob("samples/failure/*.eml")
        for sample_path in sample_paths:
            print("Testing CSV for {0}: ".format(sample_path), end="")
            with self.subTest(sample=sample_path):
                parsed_report = cast(
                    FailureReport,
                    parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)[
                        "report"
                    ],
                )
                csv_output = parsedmarc.parsed_failure_reports_to_csv(parsed_report)
                self.assertIsNotNone(csv_output)
                self.assertIn(",", csv_output)
                rows = parsedmarc.parsed_failure_reports_to_csv_rows(parsed_report)
                self.assertTrue(len(rows) > 0)
            print("Passed!")


class TestExtractReport(unittest.TestCase):
    """Tests for parsedmarc.extract_report()"""

    def testExtractReportFromBytes(self):
        """extract_report handles raw XML bytes"""
        xml = b'<?xml version="1.0"?><feedback><report_metadata></report_metadata></feedback>'
        result = parsedmarc.extract_report(xml)
        self.assertIn("<feedback>", result)

    def testExtractReportFromBase64Xml(self):
        """extract_report handles base64-encoded XML string"""
        import base64

        xml = b'<?xml version="1.0"?><feedback></feedback>'
        b64 = base64.b64encode(xml).decode()
        result = parsedmarc.extract_report(b64)
        self.assertIn("<feedback>", result)

    def testExtractReportFromGzip(self):
        """extract_report handles gzip compressed content"""
        import gzip

        xml = b'<?xml version="1.0"?><feedback></feedback>'
        compressed = gzip.compress(xml)
        result = parsedmarc.extract_report(compressed)
        self.assertIn("<feedback>", result)

    def testExtractReportFromZip(self):
        """extract_report handles zip compressed content"""
        import zipfile

        xml = b'<?xml version="1.0"?><feedback></feedback>'
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("report.xml", xml)
        result = parsedmarc.extract_report(buf.getvalue())
        self.assertIn("<feedback>", result)

    def testExtractReportFromBinaryIO(self):
        """extract_report handles file-like BinaryIO objects"""
        xml = b'<?xml version="1.0"?><feedback></feedback>'
        bio = BytesIO(xml)
        result = parsedmarc.extract_report(bio)
        self.assertIn("<feedback>", result)

    def testExtractReportFromNonSeekableStream(self):
        """extract_report handles non-seekable streams"""
        xml = b'<?xml version="1.0"?><feedback></feedback>'

        class NonSeekable:
            def __init__(self, data):
                self._data = data
                self._pos = 0

            def read(self, n=-1):
                if n == -1:
                    result = self._data[self._pos :]
                    self._pos = len(self._data)
                else:
                    result = self._data[self._pos : self._pos + n]
                    self._pos += n
                return result

            def seekable(self):
                return False

            def close(self):
                pass

        result = parsedmarc.extract_report(cast(BinaryIO, NonSeekable(xml)))
        self.assertIn("<feedback>", result)

    def testExtractReportInvalidContent(self):
        """extract_report raises ParserError for invalid content"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report(b"this is not a valid archive")

    def testExtractReportTextModeRaises(self):
        """extract_report raises ParserError for text-mode streams"""

        class TextStream:
            def read(self, n=-1):
                return "text data"

            def seekable(self):
                return True

            def seek(self, pos):
                pass

            def close(self):
                pass

        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report(cast(BinaryIO, TextStream()))


class TestMalformedXmlRecovery(unittest.TestCase):
    """Tests for XML recovery in parse_aggregate_report_xml"""

    def testRecoversMalformedXml(self):
        """Malformed XML triggers recovery path and still parses"""
        # XML with a broken tag that xmltodict will reject but lxml can recover
        malformed_xml = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>12345</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>none</p>
  </policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
  <broken_tag
</feedback>"""
        # lxml recovery may succeed or fail depending on how broken the XML is
        # Either way, no unhandled exception should escape
        try:
            report = parsedmarc.parse_aggregate_report_xml(malformed_xml, offline=True)
            self.assertIn("report_metadata", report)
        except parsedmarc.InvalidAggregateReport:
            pass  # Also acceptable

    def testBytesXmlInput(self):
        """XML bytes input is decoded"""
        xml = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>test-bytes-input</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>none</p>
  </policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml.decode(), offline=True)
        self.assertEqual(report["report_metadata"]["report_id"], "test-bytes-input")

    def testExpatErrorRaises(self):
        """Completely invalid XML raises InvalidAggregateReport"""
        with self.assertRaises(parsedmarc.InvalidAggregateReport):
            parsedmarc.parse_aggregate_report_xml("not xml at all {}", offline=True)

    def testMissingOrgName(self):
        """Missing org_name raises InvalidAggregateReport"""
        xml = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <email>dmarc@example.com</email>
    <report_id>missing-org</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>1.2.3.4</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        # The missing-field error chains the underlying KeyError so a library
        # caller can inspect which field was absent.
        self.assertIsInstance(ctx.exception.__cause__, KeyError)

    def testReportMetadataNotAStructureRaises(self):
        """A non-structured report_metadata trips the AttributeError branch"""
        # report_metadata is plain text rather than nested elements, so the
        # parser's attribute access on it fails with AttributeError.
        xml = (
            "<feedback><report_metadata>x</report_metadata>"
            "<policy_published><domain>x.com</domain></policy_published>"
            "<record></record></feedback>"
        )
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIn("missing required section", str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, AttributeError)


class TestPolicyPublishedEdgeCases(unittest.TestCase):
    """Tests for edge cases in policy_published parsing"""

    VALID_XML_TEMPLATE = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>test-{tag}</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
    {extra_metadata}
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>reject</p>
    {policy_extra}
  </policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""

    def _parse(self, tag="default", policy_extra="", extra_metadata=""):
        xml = self.VALID_XML_TEMPLATE.format(
            tag=tag, policy_extra=policy_extra, extra_metadata=extra_metadata
        )
        return parsedmarc.parse_aggregate_report_xml(xml, offline=True)

    def testPolicyPublishedListHandled(self):
        """policy_published as a list uses first element"""
        # The code checks `if type(policy_published) is list`
        # This is tested implicitly when xmltodict returns a list;
        # we test via the np field presence
        report = self._parse(tag="np", policy_extra="<np>quarantine</np>")
        self.assertEqual(report["policy_published"]["np"], "quarantine")

    def testNpFieldValues(self):
        """np field is parsed correctly"""
        for val in ["none", "quarantine", "reject"]:
            report = self._parse(tag=f"np-{val}", policy_extra=f"<np>{val}</np>")
            self.assertEqual(report["policy_published"]["np"], val)

    def testTestingField(self):
        """testing field is parsed correctly"""
        for val in ["y", "n"]:
            report = self._parse(
                tag=f"testing-{val}", policy_extra=f"<testing>{val}</testing>"
            )
            self.assertEqual(report["policy_published"]["testing"], val)

    def testDiscoveryMethodField(self):
        """discovery_method field is parsed correctly"""
        for val in ["psl", "treewalk"]:
            report = self._parse(
                tag=f"disc-{val}",
                policy_extra=f"<discovery_method>{val}</discovery_method>",
            )
            self.assertEqual(report["policy_published"]["discovery_method"], val)

    def testGeneratorField(self):
        """generator field in report_metadata is parsed"""
        report = self._parse(
            tag="gen", extra_metadata="<generator>TestGen/1.0</generator>"
        )
        self.assertEqual(report["report_metadata"]["generator"], "TestGen/1.0")

    def testPctFieldNone(self):
        """pct defaults to None when absent (removed in RFC 9989)"""
        report = self._parse(tag="no-pct")
        self.assertIsNone(report["policy_published"]["pct"])

    def testFoFieldNone(self):
        """fo defaults to None when absent (RFC 9990 keeps it optional)"""
        report = self._parse(tag="no-fo")
        self.assertIsNone(report["policy_published"]["fo"])

    def testReportMetadataErrors(self):
        """Report metadata errors are captured"""
        report = self._parse(
            tag="errors",
            extra_metadata="<error>DNS timeout</error>",
        )
        self.assertIn("DNS timeout", report["report_metadata"]["errors"])

    def testReportMetadataErrorsList(self):
        """Report metadata errors as list are captured"""
        report = self._parse(
            tag="errors-list",
            extra_metadata="<error>error1</error><error>error2</error>",
        )
        self.assertIn("error1", report["report_metadata"]["errors"])
        self.assertIn("error2", report["report_metadata"]["errors"])

    def testRecordParseFailureSkipped(self):
        """Bad records are skipped with a warning, not crashing"""
        xml = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>bad-records</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>bad-ip</source_ip><count>not-a-number</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        # At least the valid record should be parsed
        self.assertTrue(len(report["records"]) >= 1)


class TestParseReportFile(unittest.TestCase):
    """Tests for parse_report_file with various input types"""

    def testParseReportFileFromBytes(self):
        """parse_report_file works with bytes input"""
        xml_path = "samples/aggregate/!example.com!1538204542!1538463818.xml"
        with open(xml_path, "rb") as f:
            content = f.read()
        result = parsedmarc.parse_report_file(content, offline=True)
        self.assertEqual(result["report_type"], "aggregate")

    def testParseReportFileFromBinaryIO(self):
        """parse_report_file works with BinaryIO input"""
        xml_path = "samples/aggregate/!example.com!1538204542!1538463818.xml"
        with open(xml_path, "rb") as f:
            result = parsedmarc.parse_report_file(f, offline=True)
        self.assertEqual(result["report_type"], "aggregate")

    def testParseReportFileFromPathlib(self):
        """parse_report_file works with pathlib.Path input"""
        xml_path = Path("samples/aggregate/!example.com!1538204542!1538463818.xml")
        result = parsedmarc.parse_report_file(xml_path, offline=True)
        self.assertEqual(result["report_type"], "aggregate")

    def testParseReportFileSmtpTls(self):
        """parse_report_file detects SMTP TLS reports"""
        result = parsedmarc.parse_report_file(
            "samples/smtp_tls/smtp_tls.json", offline=True
        )
        self.assertEqual(result["report_type"], "smtp_tls")

    def testParseReportFileEmail(self):
        """parse_report_file detects failure reports in email format"""
        eml_path = "samples/failure/dmarc_ruf_report_linkedin.eml"
        result = parsedmarc.parse_report_file(eml_path, offline=True)
        self.assertEqual(result["report_type"], "failure")

    def testParseReportFileInvalid(self):
        """parse_report_file raises ParserError for invalid content"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_file(b"this is not a report", offline=True)

    def testParseReportFileInvalidAggregateReason(self):
        """Malformed aggregate XML explains the aggregate-specific reason"""
        xml = (
            b'<?xml version="1.0"?>\n<feedback>\n'
            b"<report_metadata><email>dmarc@example.com</email>"
            b"<report_id>no-org</report_id></report_metadata>\n"
            b"<policy_published><domain>example.com</domain><p>none</p>"
            b"</policy_published>\n</feedback>"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(xml, offline=True)
        message = str(ctx.exception)
        # The reason must name the aggregate format and the missing field,
        # not collapse to a bare "Not a valid report".
        self.assertIn("aggregate", message.lower())
        self.assertIn("org_name", message)
        self.assertNotIn("Not a valid report", message)

    def testParseReportFileInvalidSmtpTlsReason(self):
        """Malformed SMTP TLS JSON explains the SMTP-TLS-specific reason"""
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b'{"organization-name": "x"}', offline=True)
        message = str(ctx.exception)
        self.assertIn("SMTP TLS", message)
        self.assertIn("date-range", message)

    def testParseReportFileInvalidFailureReason(self):
        """A malformed failure report (email path) explains the reason"""
        # A real DMARC failure report arrives as a multipart/report email;
        # parse_report_file reaches it only via the email branch. Omit the
        # required Source-IP so parse_failure_report rejects it.
        eml = (
            b"From: dmarc-noreply@example.com\n"
            b"Subject: DMARC Failure Report\n"
            b"MIME-Version: 1.0\n"
            b"Content-Type: multipart/report; "
            b'report-type=feedback-report; boundary="b"\n\n'
            b"--b\n"
            b"Content-Type: text/plain\n\n"
            b"This is a DMARC failure report.\n"
            b"--b\n"
            b"Content-Type: message/feedback-report\n\n"
            b"Feedback-Type: auth-failure\n"
            b"Version: 1\n"
            b"--b\n"
            b"Content-Type: message/rfc822\n\n"
            b"From: spoof@victim.example\n"
            b"Subject: hi\n"
            b"--b--\n"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(eml, offline=True)
        message = str(ctx.exception)
        # The reason must name the failure format and the missing field,
        # not collapse to a bare "Not a valid report".
        self.assertIn("failure", message.lower())
        self.assertIn("source_ip", message)
        self.assertNotIn("Not a valid report", message)

    def testParseReportFileUnrecognizedGzip(self):
        """Gzipped junk decompresses to a str that matches no format.

        Exercises the str branch of the content sniff (the decompressed
        payload is a str, not bytes).
        """
        blob = gzip.compress(b"plain junk not a report")
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(blob, offline=True)
        self.assertIn("recognized report format", str(ctx.exception))

    def testParseReportFileUnrecognizedFormat(self):
        """Content matching no known format says so explicitly"""
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b"this is not a report", offline=True)
        self.assertIn("recognized report format", str(ctx.exception))

    def testParseReportFilePreservesCause(self):
        """The raised ParserError chains the underlying parse failure"""
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b"<feedback></feedback>", offline=True)
        # raise ... from email_error must populate __cause__ for callers and
        # tracebacks, even though the cross-format message is content-sniffed.
        self.assertIsNotNone(ctx.exception.__cause__)

    def _parse_unexpected_error(self):
        # <feedback></feedback> parses as XML but trips a NoneType subscript
        # deep in the aggregate parser, hitting the catch-all "Unexpected
        # error" branch (not a narrow KeyError/ExpatError).
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b"<feedback></feedback>", offline=True)
        return str(ctx.exception)

    def testUnexpectedErrorOmitsOriginWhenNotDebug(self):
        """Catch-all errors stay clean when the logger is above DEBUG"""
        logger = logging.getLogger("parsedmarc.log")
        previous = logger.level
        logger.setLevel(logging.WARNING)
        try:
            message = self._parse_unexpected_error()
        finally:
            logger.setLevel(previous)
        self.assertIn("Unexpected error", message)
        self.assertNotIn("raised at", message)

    def testUnexpectedErrorCitesOriginInDebug(self):
        """Catch-all errors cite the source file:line when the logger is DEBUG"""
        logger = logging.getLogger("parsedmarc.log")
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            message = self._parse_unexpected_error()
        finally:
            logger.setLevel(previous)
        self.assertIn("raised at", message)
        self.assertIn("__init__.py:", message)

    def testExcOriginEmptyWhenNoTraceback(self):
        """_exc_origin returns '' for an exception with no traceback"""
        logger = logging.getLogger("parsedmarc.log")
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            # A never-raised exception has __traceback__ is None, so there is
            # no origin frame to cite even though debug logging is on.
            self.assertEqual(parsedmarc._exc_origin(ValueError("x")), "")
        finally:
            logger.setLevel(previous)


class TestParseReportEmail(unittest.TestCase):
    """Tests for parse_report_email edge cases"""

    def testSmtpTlsEmailReport(self):
        """parse_report_email handles SMTP TLS reports in email format"""
        eml_path = "samples/smtp_tls/google.com_smtp_tls_report.eml"
        with open(eml_path, "rb") as f:
            content = f.read()
        result = parsedmarc.parse_report_email(content, offline=True)
        self.assertEqual(result["report_type"], "smtp_tls")

    def testInvalidEmailRaisesError(self):
        """parse_report_email raises error for non-DMARC email"""
        email_str = """From: test@example.com
Subject: Hello World
Content-Type: text/plain

This is not a DMARC report."""
        with self.assertRaises(parsedmarc.InvalidDMARCReport):
            parsedmarc.parse_report_email(email_str, offline=True)

    def testUnparseableDateRaisesParserError(self):
        """An unparseable Date header trips the initial mail-parse catch-all"""
        # human_timestamp_to_datetime() raises on a junk Date, which the
        # catch-all around the initial parse turns into a ParserError.
        email_str = "From: a@b.c\nDate: not-a-real-date\nSubject: x\n\nbody"
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_email(email_str, offline=True)
        self.assertIn("not-a-real-date", str(ctx.exception))

    def testFailureTextReportParses(self):
        """A valid legacy text/plain failure report parses to a failure
        report (the success path that builds the synthetic feedback report
        and extracts the message sample)"""
        # The field-name regex matches letters and spaces only, so the legacy
        # fields are space-separated ("Received Date", "Sender IP Address").
        eml = (
            "From: report@example.com\nSubject: Failure Report\n"
            "Content-Type: text/plain\n\n"
            "A message claiming to be from you has failed authentication.\n"
            "Received Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
            "Sender IP Address: 192.0.2.1\n"
            "detected.\n"
            "From: spoof@example.com\nTo: victim@example.com\nSubject: spam\n"
        )
        result = parsedmarc.parse_report_email(eml, offline=True)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        self.assertEqual(report["source"]["ip_address"], "192.0.2.1")

    def testFailureTextMissingFieldsRaises(self):
        """A text/plain failure report missing its fields is rejected with
        the subject named (not silently dropped)"""
        # Has the trigger phrase and "detected." but none of the
        # Received-Date / Sender-IP-Address fields, so building the synthetic
        # feedback report raises KeyError, surfaced as InvalidDMARCReport.
        eml = (
            "From: a@b.c\nSubject: Failure\nContent-Type: text/plain\n\n"
            "A message claiming to be from you has failed. "
            "No fields here detected. nothing\n"
        )
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
            parsedmarc.parse_report_email(eml, offline=True)
        self.assertIn("Failure", str(ctx.exception))

    def testAttachmentMalformedXmlRaises(self):
        """A base64 attachment of malformed aggregate XML is rejected"""
        att = base64.b64encode(b"<feedback></feedback>").decode()
        eml = (
            "From: a@b.c\nSubject: Agg\nMIME-Version: 1.0\n"
            "Content-Type: application/octet-stream\n"
            "Content-Transfer-Encoding: base64\n\n" + att + "\n"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_email(eml, offline=True)
        self.assertIn("not a valid DMARC report", str(ctx.exception))

    def testAttachmentInvalidJsonRaises(self):
        """A base64 attachment of invalid SMTP TLS JSON is rejected.

        parse_smtp_tls_report_json raises InvalidSMTPTLSReport, a sibling of
        InvalidDMARCReport, so it falls through to the generic catch-all and
        becomes a ParserError naming the subject.
        """
        att = base64.b64encode(b"{not valid json").decode()
        eml = (
            "From: a@b.c\nSubject: Tls\nMIME-Version: 1.0\n"
            "Content-Type: application/octet-stream\n"
            "Content-Transfer-Encoding: base64\n\n" + att + "\n"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_email(eml, offline=True)
        self.assertIn("Tls", str(ctx.exception))


class TestFailureReportParsing(unittest.TestCase):
    """Tests for failure report field defaults and edge cases"""

    def _make_feedback_report(self, **overrides):
        """Create a minimal feedback report string"""
        fields = {
            "Feedback-Type": "auth-failure",
            "User-Agent": "test/1.0",
            "Version": "1",
            "Original-Mail-From": "sender@example.com",
            "Arrival-Date": "Thu, 1 Jan 2024 00:00:00 +0000",
            "Source-IP": "203.0.113.1",
            "Reported-Domain": "example.com",
            "Auth-Failure": "dmarc",
        }
        fields.update(overrides)
        return "\n".join(f"{k}: {v}" for k, v in fields.items())

    def _make_sample(self):
        return """From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test body"""

    def _default_msg_date(self):
        return datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def testMissingVersion(self):
        """Missing version defaults to None"""
        report_str = self._make_feedback_report()
        lines = [ln for ln in report_str.split("\n") if not ln.startswith("Version:")]
        report_str = "\n".join(lines)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertIsNone(report["version"])

    def testMissingUserAgent(self):
        """Missing user_agent defaults to None"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("User-Agent:")
        ]
        report_str = "\n".join(lines)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertIsNone(report["user_agent"])

    def testMissingDeliveryResult(self):
        """Missing delivery_result maps to 'other' when field absent"""
        report_str = self._make_feedback_report()
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        # When delivery_result is not in the parsed report, it's set to None,
        # but then the validation check maps None (not in delivery_results list) to "other"
        self.assertEqual(report["delivery_result"], "other")

    def testDeliveryResultMapped(self):
        """Known delivery_result values are mapped correctly"""
        for val in ["delivered", "spam", "policy", "reject"]:
            report_str = self._make_feedback_report(**{"Delivery-Result": val})
            report = parsedmarc.parse_failure_report(
                report_str, self._make_sample(), self._default_msg_date(), offline=True
            )
            self.assertEqual(report["delivery_result"], val)

    def testDeliveryResultUnknownMapsToOther(self):
        """Unknown delivery_result maps to 'other'"""
        report_str = self._make_feedback_report(**{"Delivery-Result": "unknown-value"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["delivery_result"], "other")

    def testIdentityAlignmentNone(self):
        """identity_alignment='none' results in empty auth mechanisms"""
        report_str = self._make_feedback_report(**{"Identity-Alignment": "none"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["authentication_mechanisms"], [])

    def testIdentityAlignmentMultiple(self):
        """identity_alignment with multiple values is split"""
        report_str = self._make_feedback_report(**{"Identity-Alignment": "dkim,spf"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["authentication_mechanisms"], ["dkim", "spf"])

    def testIdentityAlignmentCFWSWhitespaceStripped(self):
        """RFC 9991 ABNF allows CFWS around the commas in
        Identity-Alignment. The previous parser left leading whitespace
        on the second token ('dkim, spf' -> ['dkim', ' spf']); CFWS-aware
        splitting yields ['dkim', 'spf']."""
        report_str = self._make_feedback_report(**{"Identity-Alignment": "dkim, spf"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["authentication_mechanisms"], ["dkim", "spf"])

    def testAuthFailureCFWSWhitespaceStripped(self):
        """Auth-Failure (also comma-separated per RFC 9991) is whitespace-
        stripped per token."""
        report_str = self._make_feedback_report(**{"Auth-Failure": "dmarc, spf"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["auth_failure"], ["dmarc", "spf"])

    def testMissingIdentityAlignmentWarns(self):
        """Identity-Alignment is REQUIRED per RFC 9991; the parser
        defaults silently for permissiveness but logs a warning so the
        broken reporter is visible."""
        report_str = self._make_feedback_report()
        lines = [
            ln
            for ln in report_str.split("\n")
            if not ln.startswith("Identity-Alignment:")
        ]
        report_str = "\n".join(lines)
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_failure_report(
                report_str,
                self._make_sample(),
                self._default_msg_date(),
                offline=True,
            )
        self.assertEqual(report["authentication_mechanisms"], [])
        self.assertTrue(
            any("Identity-Alignment" in m and "RFC 9991" in m for m in cm.output),
            f"Expected Identity-Alignment RFC 9991 warning; got: {cm.output}",
        )

    def testMissingAuthFailureWarns(self):
        """Auth-Failure is REQUIRED per RFC 9991; the parser defaults
        to 'dmarc' but logs a warning."""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Auth-Failure:")
        ]
        report_str = "\n".join(lines)
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_failure_report(
                report_str,
                self._make_sample(),
                self._default_msg_date(),
                offline=True,
            )
        self.assertEqual(report["auth_failure"], ["dmarc"])
        self.assertTrue(
            any("Auth-Failure" in m and "RFC 9991" in m for m in cm.output),
            f"Expected Auth-Failure RFC 9991 warning; got: {cm.output}",
        )

    def testMissingReportedDomainFallback(self):
        """Missing reported_domain falls back to sample from domain"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Reported-Domain:")
        ]
        report_str = "\n".join(lines)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["reported_domain"], "example.com")

    def testMissingArrivalDateWithMsgDate(self):
        """Missing arrival_date uses msg_date fallback"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Arrival-Date:")
        ]
        report_str = "\n".join(lines)
        msg_date = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), msg_date, offline=True
        )
        self.assertIn("2024-06-15", report["arrival_date"])

    def testMissingArrivalDateNoMsgDateRaises(self):
        """Missing arrival_date with no msg_date raises"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Arrival-Date:")
        ]
        report_str = "\n".join(lines)
        with self.assertRaises(parsedmarc.InvalidFailureReport):
            parsedmarc.parse_failure_report(
                report_str,
                self._make_sample(),
                cast(datetime, None),  # intentionally None to test error path
                offline=True,
            )


class TestSmtpTlsReportErrors(unittest.TestCase):
    """Tests for SMTP TLS report error handling"""

    def testMissingRequiredField(self):
        """Missing required field raises InvalidSMTPTLSReport"""
        json_str = json.dumps({"policies": []})
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(json_str)

    def testInvalidJson(self):
        """Invalid JSON raises InvalidSMTPTLSReport"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json("not json {{{")

    def testInvalidJsonPreservesCause(self):
        """Invalid JSON chains the underlying JSONDecodeError"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json("not json {{{")
        self.assertIsInstance(ctx.exception.__cause__, json.JSONDecodeError)

    def testNestedMissingKeyNamesTheField(self):
        """A KeyError on a nested field reports which field was missing"""
        # All five required top-level fields are present, so this gets past the
        # top-level check and raises KeyError on date-range["start-datetime"].
        report = json.dumps(
            {
                "organization-name": "x",
                "date-range": {},
                "contact-info": "x",
                "report-id": "x",
                "policies": [],
            }
        )
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(report)
        self.assertIn("start-datetime", str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, KeyError)


class TestBucketIntervalEdgeCases(unittest.TestCase):
    """Tests for _bucket_interval_by_day edge cases"""

    def testDayCursorAdjustment(self):
        """When begin is before midnight due to tz, day_cursor adjusts back"""
        # Use a timezone where midnight calculation might cause day_cursor > begin
        import pytz

        tz = pytz.FixedOffset(-600)  # UTC-10
        begin = datetime(2024, 1, 1, 23, 30, 0, tzinfo=timezone.utc).astimezone(tz)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc).astimezone(tz)
        buckets = parsedmarc._bucket_interval_by_day(begin, end, 100)
        total = sum(b["count"] for b in buckets)
        self.assertEqual(total, 100)


class TestGetDmarcReportsFromMbox(unittest.TestCase):
    """Tests for mbox parsing"""

    def testEmptyMbox(self):
        """Empty mbox returns empty results"""
        with NamedTemporaryFile(suffix=".mbox", delete=False) as f:
            f.write(b"")
            path = f.name
        try:
            results = parsedmarc.get_dmarc_reports_from_mbox(path, offline=True)
            self.assertEqual(results["aggregate_reports"], [])
            self.assertEqual(results["failure_reports"], [])
            self.assertEqual(results["smtp_tls_reports"], [])
        finally:
            os.remove(path)

    def testMboxWithAggregateReport(self):
        """Mbox with aggregate report email is parsed"""
        from email.mime.multipart import MIMEMultipart
        from email.mime.application import MIMEApplication
        import gzip

        xml = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>mbox-test-123</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        compressed = gzip.compress(xml)

        msg = MIMEMultipart()
        msg["From"] = "dmarc@example.com"
        msg["To"] = "postmaster@example.com"
        msg["Subject"] = "DMARC Aggregate Report"
        msg["Date"] = "Thu, 1 Jan 2024 00:00:00 +0000"
        att = MIMEApplication(compressed, "gzip")
        att.add_header("Content-Disposition", "attachment", filename="report.xml.gz")
        msg.attach(att)

        with NamedTemporaryFile(suffix=".mbox", delete=False, mode="w") as f:
            # mbox format requires "From " line
            f.write("From dmarc@example.com Thu Jan  1 00:00:00 2024\n")
            f.write(msg.as_string())
            f.write("\n")
            path = f.name
        try:
            results = parsedmarc.get_dmarc_reports_from_mbox(path, offline=True)
            self.assertTrue(len(results["aggregate_reports"]) >= 1)
        finally:
            os.remove(path)


class TestGetDmarcReportsFromMailboxValidation(unittest.TestCase):
    """Input validation on get_dmarc_reports_from_mailbox.

    These guards prevent two real footguns: the test/delete combo
    would otherwise delete every message after parsing — silently
    destructive — and a None connection would NPE deep in the
    iteration loop with a confusing traceback. Fail fast at the
    door instead."""

    def test_delete_and_test_combination_raises(self):
        from unittest.mock import MagicMock

        with self.assertRaises(ValueError) as ctx:
            parsedmarc.get_dmarc_reports_from_mailbox(
                connection=MagicMock(), delete=True, test=True
            )
        self.assertIn("mutually exclusive", str(ctx.exception))

    def test_none_connection_raises(self):
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.get_dmarc_reports_from_mailbox(
                # Deliberately invalid: exercises the runtime None check
                connection=None  # pyright: ignore[reportArgumentType]
            )
        self.assertIn("connection", str(ctx.exception).lower())


class TestMigrateForensicArchiveFolderErrorHandling(unittest.TestCase):
    """The one migration scenario a real on-disk Maildir can't reproduce: a
    backend that raises mid-operation. _migrate_forensic_archive_folder must
    warn and continue (warn, don't crash) so a mailbox it cannot reorganize
    doesn't abort the whole run.

    The rename / merge / no-op behavior is covered for real (no mocks) in
    TestMigrateForensicArchiveFolderMaildir; only this failure path needs a
    mock, to force a folder operation to raise."""

    def test_backend_error_is_warned_not_raised(self):
        conn = MagicMock()
        conn.folder_exists.side_effect = lambda name: name.endswith("/Forensic")
        conn.rename_folder.side_effect = RuntimeError("server said no")
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            parsedmarc._migrate_forensic_archive_folder(conn, "Archive")
        self.assertTrue(
            any("Could not migrate" in line for line in cm.output),
            cm.output,
        )


class TestMigrateForensicArchiveFolderMaildir(unittest.TestCase):
    """End-to-end migration against a real on-disk Maildir via mailsuite's
    MaildirConnection — no mocks. This exercises the actual mailsuite 2.1.0
    folder API (folder_exists / rename_folder / merge_folders / delete_folder)
    and the on-disk result, so it would catch a real behavioral break that a
    mock-based test cannot (e.g. a signature mismatch, or messages left behind
    in the legacy folder)."""

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        self.conn = MaildirConnection(self._tmp, maildir_create=True)
        # Parent must exist before nested subfolders, as get_dmarc_reports_-
        # from_mailbox creates it (create_folder(archive_folder)) first.
        self.conn.create_folder("Archive")

    def _seed(self, folder, subject):
        """Drop a real RFC 822 message into an on-disk Maildir subfolder."""
        self.conn.create_folder(folder)
        box = mailbox.Maildir(os.path.join(self._tmp, "." + folder))
        box.add(
            mailbox.MaildirMessage(
                "From: reporter@example.com\n"
                "To: dmarc@example.org\n"
                f"Subject: {subject}\n\nbody\n"
            )
        )
        box.flush()

    def test_rename_moves_legacy_folder_and_its_messages(self):
        """Only the legacy folder exists: it (and the message inside it) is
        renamed to Failure, leaving nothing behind in Forensic."""
        self._seed("Archive/Forensic", "legacy failure report")
        self.assertTrue(self.conn.folder_exists("Archive/Forensic"))
        self.assertFalse(self.conn.folder_exists("Archive/Failure"))

        parsedmarc._migrate_forensic_archive_folder(self.conn, "Archive")

        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertTrue(self.conn.folder_exists("Archive/Failure"))
        self.assertEqual(len(self.conn.fetch_messages("Archive/Failure")), 1)

    def test_merge_consolidates_messages_when_both_exist(self):
        """Both folders exist: the legacy folder's messages are merged into
        the existing Failure folder (which keeps its own), and the emptied
        legacy folder is deleted."""
        self._seed("Archive/Failure", "post-rename failure report")
        self._seed("Archive/Forensic", "legacy failure report")

        parsedmarc._migrate_forensic_archive_folder(self.conn, "Archive")

        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertTrue(self.conn.folder_exists("Archive/Failure"))
        self.assertEqual(len(self.conn.fetch_messages("Archive/Failure")), 2)

    def test_no_legacy_folder_is_noop(self):
        """No legacy folder (the common case): nothing is created or changed."""
        parsedmarc._migrate_forensic_archive_folder(self.conn, "Archive")
        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertFalse(self.conn.folder_exists("Archive/Failure"))

    def test_orchestration_migrates_before_creating_folders(self):
        """get_dmarc_reports_from_mailbox runs the migration *before* it
        creates folders: a seeded legacy Forensic folder ends up consolidated
        into the newly-created Failure subfolder (message and all), not split
        across the two. Driven through the real orchestration with an empty
        INBOX, so no parsing or network occurs."""
        self._seed("Archive/Forensic", "legacy failure report")

        result = parsedmarc.get_dmarc_reports_from_mailbox(connection=self.conn)

        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertTrue(self.conn.folder_exists("Archive/Failure"))
        self.assertEqual(len(self.conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(result["failure_reports"], [])


class TestGetDmarcReportsFromMailboxMaildir(unittest.TestCase):
    """parsedmarc's real mailbox processing loop, end to end on an on-disk
    Maildir (mailsuite MaildirConnection, no mocks, offline parsing): fetch
    from INBOX, parse and classify each message, then route it to the matching
    archive subfolder — or delete it / leave it, per mode. This path was
    previously untestable without a live IMAP server (see AGENTS.md), so it sat
    uncovered; the Maildir backend lets it run in CI with no network or
    credentials, asserting on the observable result (parsed counts + where each
    message physically ended up), not on mock call records."""

    AGGREGATE = "samples/aggregate/twilight.eml"
    FAILURE = "samples/failure/dmarc_ruf_report_linkedin.eml"
    SMTP_TLS = "samples/smtp_tls/google.com_smtp_tls_report.eml"
    JUNK = b"From: noise@example.com\nSubject: not a report\n\nplain text\n"

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        # Aggregate dedup is a module-global ExpiringDict; reset it so an
        # aggregate report "seen" by an earlier test isn't silently dropped
        # from this test's results.
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        # Use a not-yet-existing subpath so mailbox.Maildir(create=True) builds
        # cur/new/tmp (it skips creation if the directory already exists, which
        # mkdtemp's would). Deliver straight to disk; the connection is built
        # afterwards (in _run) so its first read sees every delivered message.
        self._maildir = os.path.join(self._tmp, "Maildir")
        self._inbox = mailbox.Maildir(self._maildir, create=True)

    def _deliver(self, source):
        raw = open(source, "rb").read() if isinstance(source, str) else source
        self._inbox.add(mailbox.MaildirMessage(raw))
        self._inbox.flush()

    def _run(self, **kwargs):
        conn = MaildirConnection(self._maildir, maildir_create=True)
        result = parsedmarc.get_dmarc_reports_from_mailbox(
            connection=conn, offline=True, **kwargs
        )
        return conn, result

    def test_each_report_type_routed_to_its_archive_subfolder(self):
        """One report of each type plus an unparseable message: each is filed
        under the correct subfolder (Aggregate / Failure / SMTP-TLS / Invalid)
        and the INBOX is drained."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)
        self._deliver(self.SMTP_TLS)
        self._deliver(self.JUNK)

        conn, result = self._run()

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/SMTP-TLS")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)

    def test_delete_mode_removes_processed_messages(self):
        """delete=True: a parsed message is removed from the INBOX rather than
        archived."""
        self._deliver(self.FAILURE)

        conn, result = self._run(delete=True)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        # The Failure folder is created but nothing is filed there — deleted.
        self.assertEqual(conn.fetch_messages("Archive/Failure"), [])

    def test_test_mode_parses_without_moving_or_creating_folders(self):
        """test=True: the report is parsed and returned, but the message stays
        in the INBOX and no archive folders are created/touched."""
        self._deliver(self.FAILURE)

        conn, result = self._run(test=True)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertFalse(conn.folder_exists("Archive/Failure"))


class TestEmailResultsErrorBranches(unittest.TestCase):
    """email_results requires mail_to to be a list — this is enforced
    by an assert. A regression that dropped the assert would mean the
    SMTP code further down would silently iterate over the characters
    of a string."""

    def test_mail_to_must_be_list(self):
        with self.assertRaises(AssertionError):
            parsedmarc.email_results(
                {
                    "aggregate_reports": [],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
                host="smtp.example.com",
                mail_from="from@example.com",
                # str, not list — triggers assert
                mail_to="admin@example.com",  # pyright: ignore[reportArgumentType]
            )


class TestEmailResultsViaMsGraph(unittest.TestCase):
    """email_results_via_msgraph() shares its
    subject/message/attachment-building logic with email_results() via the
    extracted _build_report_email_content() helper, so both transports stay
    in lockstep instead of drifting into two different sets of defaults."""

    @staticmethod
    def _results() -> ParsingResults:
        return {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

    def testEmailResultsViaMsGraphBuildsSameContentAsEmailResults(self):
        connection = MagicMock(spec=MSGraphConnection, mailbox_name="mb@example.com")
        results = self._results()

        parsedmarc.email_results_via_msgraph(results, connection, ["admin@example.com"])

        connection.send_message.assert_called_once()
        graph_kwargs = connection.send_message.call_args.kwargs

        with patch("parsedmarc.send_email") as mock_send_email:
            parsedmarc.email_results(
                results,
                host="smtp.example.com",
                mail_from="from@example.com",
                mail_to=["admin@example.com"],
            )
        mock_send_email.assert_called_once()
        smtp_kwargs = mock_send_email.call_args.kwargs

        self.assertEqual(graph_kwargs["subject"], smtp_kwargs["subject"])
        self.assertEqual(graph_kwargs["plain_message"], smtp_kwargs["plain_message"])
        self.assertEqual(
            graph_kwargs["attachments"][0][0],
            smtp_kwargs["attachments"][0][0],
        )
        self.assertEqual(graph_kwargs["message_to"], ["admin@example.com"])
        self.assertEqual(graph_kwargs["message_from"], "mb@example.com")

    def testEmailResultsViaMsGraphAppendsZipExtension(self):
        connection = MagicMock(spec=MSGraphConnection, mailbox_name="mb@example.com")

        parsedmarc.email_results_via_msgraph(
            self._results(),
            connection,
            ["admin@example.com"],
            attachment_filename="report",
        )

        graph_kwargs = connection.send_message.call_args.kwargs
        self.assertEqual(graph_kwargs["attachments"][0][0], "report.zip")


class TestAppendJson(unittest.TestCase):
    """append_json writes new files cleanly and merges into existing
    JSON arrays without breaking valid JSON."""

    def test_writes_new_file(self):
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        os.remove(path)  # ensure file is fresh
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"a": 1}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"a": 1}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_appends_to_existing_file(self):
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"a": 1}]))
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"b": 2}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"a": 1}, {"b": 2}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_empty_list_on_existing_file_is_noop(self):
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"a": 1}]))
            parsedmarc.append_json(path, [])
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"a": 1}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_corrupt_existing_file_is_overwritten_cleanly(self):
        """If the existing JSON file is corrupt (e.g. truncated by a
        prior crash, or hit the pre-fix `append_json` bug), the
        read-merge-write path falls back to overwriting with the new
        content rather than silently failing to record.

        Recording at the cost of losing prior corrupt data is the
        lesser evil — those bytes are already unparseable, so no
        downstream consumer can read them anyway."""
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write("{ this is not valid json at all")
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"new": "data"}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"new": "data"}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_existing_file_with_non_list_root_is_overwritten(self):
        """If the existing file parses cleanly but the root isn't a
        list (e.g. someone wrote {"foo": 1} by hand), the
        isinstance(loaded, list) guard kicks in and we overwrite
        rather than concatenating a dict and a list."""
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write('{"not": "a list"}')
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"new": "data"}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"new": "data"}])
        finally:
            if os.path.exists(path):
                os.remove(path)


class TestAppendCsv(unittest.TestCase):
    def test_writes_new_file_with_header(self):
        with NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
            path = tf.name
        os.remove(path)
        try:
            parsedmarc.append_csv(path, "h1,h2\nv1,v2\n")
            with open(path) as f:
                content = f.read()
            self.assertEqual(content, "h1,h2\nv1,v2\n")
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_appends_strips_header_on_existing_file(self):
        """Second append must not re-emit the header line."""
        with NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_csv(path, "h1,h2\nv1,v2\n")
            parsedmarc.append_csv(path, "h1,h2\nv3,v4\n")
            with open(path) as f:
                content = f.read()
            # Only one header line in the merged output.
            self.assertEqual(content.count("h1,h2"), 1)
            self.assertIn("v3,v4", content)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_append_empty_csv_on_existing_file_is_noop(self):
        """append_csv with just a header row (no data) should not
        rewrite the file when one already exists."""
        with NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_csv(path, "h1,h2\nv1,v2\n")
            parsedmarc.append_csv(path, "h1,h2\n")
            with open(path) as f:
                content = f.read()
            # File unchanged.
            self.assertEqual(content, "h1,h2\nv1,v2\n")
        finally:
            if os.path.exists(path):
                os.remove(path)


def _minimal_aggregate_xml(
    policy_published: str = (
        "<policy_published><domain>example.com</domain><p>none</p></policy_published>"
    ),
    org_name: str = "TestOrg",
    email: str = "test@example.com",
    reason: str = "",
) -> str:
    """A minimal, valid aggregate report with substitutable sections."""
    return f"""<?xml version="1.0"?>
    <feedback>
        <report_metadata>
            <org_name>{org_name}</org_name>
            <email>{email}</email>
            <report_id>edge-case</report_id>
            <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
        </report_metadata>
        {policy_published}
        <record>
            <row>
                <source_ip>192.0.2.1</source_ip>
                <count>1</count>
                <policy_evaluated>
                    <disposition>none</disposition>
                    <dkim>pass</dkim>
                    <spf>pass</spf>
                    {reason}
                </policy_evaluated>
            </row>
            <identifiers><header_from>example.com</header_from></identifiers>
            <auth_results>
                <spf><domain>example.com</domain><result>pass</result></spf>
            </auth_results>
        </record>
    </feedback>"""


class TestAggregateReportEdgeCases(unittest.TestCase):
    """Parsing edge cases for aggregate report XML documents."""

    def testBytesInputIsDecoded(self):
        """parse_aggregate_report_xml accepts bytes input"""
        xml = _minimal_aggregate_xml().encode("utf-8")
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["report_id"], "edge-case")

    def testPolicyPublishedListUsesFirstEntry(self):
        """When a reporter emits multiple policy_published elements, the
        first one is used"""
        policies = (
            "<policy_published><domain>example.com</domain><p>reject</p>"
            "</policy_published>"
            "<policy_published><domain>other.example</domain><p>none</p>"
            "</policy_published>"
        )
        report = parsedmarc.parse_aggregate_report_xml(
            _minimal_aggregate_xml(policy_published=policies), offline=True
        )
        self.assertEqual(report["policy_published"]["domain"], "example.com")
        self.assertEqual(report["policy_published"]["p"], "reject")

    def testUnknownPolicyOverrideTypeWarnsUnderRFC9990(self):
        """An override reason type that RFC 9990 does not define (and RFC
        7489 never defined) logs an 'Unknown policy override reason type'
        warning; it is stored as-is. RFC 9990's PolicyOverrideType
        enumeration is {local_policy, mailing_list, other,
        policy_test_mode, trusted_forwarder}."""
        policies = (
            "<policy_published><domain>example.com</domain><p>none</p>"
            "<np>none</np></policy_published>"
        )
        reason = "<reason><type>banana</type></reason>"
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_aggregate_report_xml(
                _minimal_aggregate_xml(policy_published=policies, reason=reason),
                offline=True,
            )
        self.assertTrue(
            any(
                "Unknown policy override reason type" in message
                for message in cm.output
            )
        )
        reasons = report["records"][0]["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(reasons[0]["type"], "banana")

    def testMissingOrgNameAndEmailIsInvalid(self):
        """A report with empty org_name and email raises
        InvalidAggregateReport, since org_name has no fallback source"""
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(
                _minimal_aggregate_xml(org_name="", email=""), offline=True
            )
        self.assertIn("Organization name is missing", str(ctx.exception))

    def testMalformedEmailAttributeOnlyIsDiscarded(self):
        """An <email> element that xmltodict turns into an attributes-only
        dict (no text) is discarded rather than crashing"""
        xml = _minimal_aggregate_xml().replace(
            "<email>test@example.com</email>", '<email xml:lang="en"></email>'
        )
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIsNone(report["report_metadata"]["org_email"])


class _NonSeekableStream:
    """A minimal non-seekable stream, like sys.stdin / a socket file."""

    def __init__(self, data):
        self._data = data
        self._pos = 0

    def seekable(self):
        return False

    def read(self, size=-1):
        if size < 0:
            result = self._data[self._pos :]
            self._pos = len(self._data)
        else:
            result = self._data[self._pos : self._pos + size]
            self._pos += size
        return result


class _BrokenSeekableStream(_NonSeekableStream):
    """A stream whose seekable() itself raises, as some wrapped streams do."""

    def seekable(self):
        raise OSError("stream does not support seekable()")


class TestExtractReportStreams(unittest.TestCase):
    """extract_report accepts file objects that cannot seek (stdin, pipes,
    sockets) and must reject text-mode streams with a clear error."""

    def testNonSeekableTextStreamRaisesParserError(self):
        """A non-seekable text-mode stream raises ParserError instead of
        failing later on a bytes/str mismatch"""
        with open("samples/extract_report/nice-input.xml") as f:
            text = f.read()
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.extract_report(cast(BinaryIO, _NonSeekableStream(text)))
        self.assertIn("binary", str(ctx.exception))

    def testNonSeekableBytesStreamIsExtracted(self):
        """A non-seekable binary stream is buffered and extracted"""
        with open("samples/extract_report/nice-input.xml", "rb") as f:
            data = f.read()
        result = parsedmarc.extract_report(cast(BinaryIO, _NonSeekableStream(data)))
        self.assertIn("<feedback>", result)

    def testStreamWithBrokenSeekableIsExtracted(self):
        """A stream whose seekable() raises is treated as non-seekable"""
        with open("samples/extract_report/nice-input.xml", "rb") as f:
            data = f.read()
        result = parsedmarc.extract_report(cast(BinaryIO, _BrokenSeekableStream(data)))
        self.assertIn("<feedback>", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
