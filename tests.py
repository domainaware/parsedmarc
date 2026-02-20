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
        """Test sample failure/ruf DMARC reports"""
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
        # adkim/aspf/pct/fo default when not in XML
        self.assertEqual(pp["adkim"], "r")
        self.assertEqual(pp["aspf"], "r")
        self.assertEqual(pp["pct"], "100")
        self.assertEqual(pp["fo"], "0")

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
            parsed_report = parsedmarc.parse_report_file(
                sample_path, offline=OFFLINE_MODE
            )["report"]
            parsedmarc.parsed_smtp_tls_reports_to_csv(parsed_report)
            print("Passed!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
