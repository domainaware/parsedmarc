#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from glob import glob
from unittest.mock import MagicMock, patch

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
        self.assertEqual(decoded_str, b"any carnal pleas")

    def testPSLDownload(self):
        """Test Public Suffix List domain lookups"""
        subdomain = "foo.example.com"
        result = parsedmarc.utils.get_base_domain(subdomain)
        self.assertEqual(result, "example.com")

        # Test newer PSL entries
        subdomain = "e3191.c.akamaiedge.net"
        result = parsedmarc.utils.get_base_domain(subdomain)
        self.assertEqual(result, "c.akamaiedge.net")

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

    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        print()
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            with self.subTest(sample=sample_path):
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
        """Test sample failure/ruf DMARC reports"""
        print()
        sample_paths = glob("samples/forensic/*.eml")
        for sample_path in sample_paths:
            print("Testing {0}: ".format(sample_path), end="")
            with self.subTest(sample=sample_path):
                with open(sample_path) as sample_file:
                    sample_content = sample_file.read()
                    parsed_report = parsedmarc.parse_report_email(
                        sample_content, offline=OFFLINE_MODE
                    )["report"]
                parsed_report = parsedmarc.parse_report_file(
                    sample_path, offline=OFFLINE_MODE
                )["report"]
                parsedmarc.parsed_failure_reports_to_csv(parsed_report)
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
            with self.subTest(sample=sample_path):
                parsed_report = parsedmarc.parse_report_file(
                    sample_path, offline=OFFLINE_MODE
                )["report"]
                parsedmarc.parsed_smtp_tls_reports_to_csv(parsed_report)
            print("Passed!")

    # ===================================================================
    # New tests for _bucket_interval_by_day
    # ===================================================================

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

    # ===================================================================
    # Tests for _append_parsed_record
    # ===================================================================

    def testAppendParsedRecordNoNormalize(self):
        """No normalization: record appended as-is with interval fields"""
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
        report = json.dumps({"organization-name": "Org"})
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(report)

    def testParseSmtpTlsReportJsonPoliciesNotList(self):
        """Non-list policies raises InvalidSMTPTLSReport"""
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
        dt = parsedmarc.utils.human_timestamp_to_datetime("2024-01-01 00:00:00")
        self.assertIsInstance(dt, datetime)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 1)

    def testHumanTimestampToDatetimeUtc(self):
        """human_timestamp_to_datetime with to_utc=True returns UTC"""
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

    # ===================================================================
    # Additional backward compatibility alias tests
    # ===================================================================

    def testGelfBackwardCompatAlias(self):
        """GelfClient forensic alias points to failure method"""
        from parsedmarc.gelf import GelfClient
        self.assertIs(
            GelfClient.save_forensic_report_to_gelf,
            GelfClient.save_failure_report_to_gelf,
        )

    def testS3BackwardCompatAlias(self):
        """S3Client forensic alias points to failure method"""
        from parsedmarc.s3 import S3Client
        self.assertIs(
            S3Client.save_forensic_report_to_s3,
            S3Client.save_failure_report_to_s3,
        )

    def testKafkaBackwardCompatAlias(self):
        """KafkaClient forensic alias points to failure method"""
        from parsedmarc.kafkaclient import KafkaClient
        self.assertIs(
            KafkaClient.save_forensic_reports_to_kafka,
            KafkaClient.save_failure_reports_to_kafka,
        )

    # ===================================================================
    # Additional extract/parse tests
    # ===================================================================

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
        sample_path = "samples/aggregate/dmarcbis-draft-sample.xml"
        print("Testing {0}: ".format(sample_path), end="")
        with open(sample_path, "rb") as f:
            data = f.read()
        report = parsedmarc.parse_aggregate_report_file(
            data, offline=True, always_use_local_files=True,
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
                parsed_report = parsedmarc.parse_report_file(
                    sample_path, always_use_local_files=True, offline=OFFLINE_MODE
                )["report"]
                parsedmarc.parsed_aggregate_reports_to_csv(parsed_report)
            print("Passed!")

    def testParseReportFileWithBytes(self):
        """parse_report_file handles bytes input"""
        with open("samples/aggregate/dmarcbis-draft-sample.xml", "rb") as f:
            data = f.read()
        result = parsedmarc.parse_report_file(
            data, always_use_local_files=True, offline=True
        )
        self.assertEqual(result["report_type"], "aggregate")

    def testFailureReportCsvRoundtrip(self):
        """Failure report CSV generation works on sample reports"""
        print()
        sample_paths = glob("samples/forensic/*.eml")
        for sample_path in sample_paths:
            print("Testing CSV for {0}: ".format(sample_path), end="")
            with self.subTest(sample=sample_path):
                parsed_report = parsedmarc.parse_report_file(
                    sample_path, offline=OFFLINE_MODE
                )["report"]
                csv_output = parsedmarc.parsed_failure_reports_to_csv(parsed_report)
                self.assertIsNotNone(csv_output)
                self.assertIn(",", csv_output)
                rows = parsedmarc.parsed_failure_reports_to_csv_rows(parsed_report)
                self.assertTrue(len(rows) > 0)
            print("Passed!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
