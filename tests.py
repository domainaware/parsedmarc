from __future__ import absolute_import, print_function, unicode_literals

import os
import unittest
from glob import glob

from lxml import etree

import parsedmarc
import parsedmarc.utils


def minify_xml(xml_string):
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.fromstring(xml_string.encode('utf-8'), parser)
    return etree.tostring(tree, pretty_print=False).decode('utf-8')


def compare_xml(xml1, xml2):
    parser = etree.XMLParser(remove_blank_text=True)
    tree1 = etree.fromstring(xml1.encode('utf-8'), parser)
    tree2 = etree.fromstring(xml2.encode('utf-8'), parser)
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
        print()
        xmlnice = open("samples/extract_report/nice-input.xml").read()
        print(xmlnice)
        xmlchanged = minify_xml(open(
            "samples/extract_report/changed-input.xml").read())
        print(xmlchanged)
        self.assertTrue(compare_xml(xmlnice, xmlnice))
        self.assertTrue(compare_xml(xmlchanged, xmlchanged))
        self.assertFalse(compare_xml(xmlnice, xmlchanged))
        self.assertFalse(compare_xml(xmlchanged, xmlnice))
        print("Passed!")

    def testExtractReportBytes(self):
        """Test extract report function for bytes string input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        with open(file, 'rb') as f:
            data = f.read()
        print("Testing {0}: " .format(file), end="")
        xmlout = parsedmarc.extract_report(data)
        xmlin = open("samples/extract_report/nice-input.xml").read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportXML(self):
        """Test extract report function for XML input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        print("Testing {0}: " .format(file), end="")
        xmlout = parsedmarc.extract_report(file)
        xmlin = open("samples/extract_report/nice-input.xml").read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportGZip(self):
        """Test extract report function for gzip input"""
        print()
        file = "samples/extract_report/nice-input.xml.gz"
        print("Testing {0}: " .format(file), end="")
        xmlout = parsedmarc.extract_report(file)
        xmlin = open("samples/extract_report/nice-input.xml").read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportZip(self):
        """Test extract report function for zip input"""
        print()
        file = "samples/extract_report/nice-input.xml.zip"
        print("Testing {0}: " .format(file), end="")
        xmlout = parsedmarc.extract_report(file)
        print(xmlout)
        xmlin = minify_xml(open(
            "samples/extract_report/nice-input.xml").read())
        print(xmlin)
        self.assertTrue(compare_xml(xmlout, xmlin))
        xmlin = minify_xml(open(
            "samples/extract_report/changed-input.xml").read())
        print(xmlin)
        self.assertFalse(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        print()
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: " .format(sample_path), end="")
            parsed_report = parsedmarc.parse_report_file(
                sample_path, always_use_local_files=True)["report"]
            parsedmarc.parsed_aggregate_reports_to_csv(parsed_report)
            print("Passed!")

    def testEmptySample(self):
        """Test empty/unparasable report"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_file('samples/empty.xml')

    def testForensicSamples(self):
        """Test sample forensic/ruf/failure DMARC reports"""
        print()
        sample_paths = glob("samples/forensic/*.eml")
        for sample_path in sample_paths:
            print("Testing {0}: ".format(sample_path), end="")
            with open(sample_path) as sample_file:
                sample_content = sample_file.read()
                parsed_report = parsedmarc.parse_report_email(
                    sample_content)["report"]
            parsed_report = parsedmarc.parse_report_file(
                sample_path)["report"]
            parsedmarc.parsed_forensic_reports_to_csv(parsed_report)
            print("Passed!")

    def testSmtpTlsSamples(self):
        """Test sample SMTP TLS reports"""
        print()
        sample_paths = glob("samples/smtp_tls/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: " .format(sample_path), end="")
            parsed_report = parsedmarc.parse_report_file(
                sample_path)["report"]
            parsedmarc.parsed_smtp_tls_reports_to_csv(parsed_report)
            print("Passed!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
