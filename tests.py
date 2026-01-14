#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import json
import os
import unittest
from glob import glob

from lxml import etree

import parsedmarc
import parsedmarc.utils


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
                sample_path, always_use_local_files=True
            )["report"]
            parsedmarc.parsed_aggregate_reports_to_csv(parsed_report)
            print("Passed!")

    def testEmptySample(self):
        """Test empty/unparasable report"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_file("samples/empty.xml")

    def testForensicSamples(self):
        """Test sample forensic/ruf/failure DMARC reports"""
        print()
        sample_paths = glob("samples/forensic/*.eml")
        for sample_path in sample_paths:
            print("Testing {0}: ".format(sample_path), end="")
            with open(sample_path) as sample_file:
                sample_content = sample_file.read()
                parsed_report = parsedmarc.parse_report_email(sample_content)["report"]
            parsed_report = parsedmarc.parse_report_file(sample_path)["report"]
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
            parsed_report = parsedmarc.parse_report_file(sample_path)["report"]
            parsedmarc.parsed_smtp_tls_reports_to_csv(parsed_report)
            print("Passed!")

    def testGoogleSecOpsAggregateReport(self):
        """Test Google SecOps aggregate report conversion"""
        print()
        from parsedmarc.google_secops import GoogleSecOpsClient
        
        client = GoogleSecOpsClient(use_stdout=True)
        sample_path = "samples/aggregate/example.net!example.com!1529366400!1529452799.xml"
        print("Testing Google SecOps aggregate conversion for {0}: ".format(sample_path), end="")
        
        parsed_file = parsedmarc.parse_report_file(sample_path, always_use_local_files=True)
        parsed_report = parsed_file["report"]
        
        events = client.save_aggregate_report_to_google_secops(parsed_report)
        
        # Verify we got events
        assert len(events) > 0, "Expected at least one event"
        
        # Verify each event is valid JSON
        for event in events:
            event_dict = json.loads(event)
            assert "event_type" in event_dict
            assert event_dict["event_type"] == "DMARC_AGGREGATE"
            assert "metadata" in event_dict
            assert "principal" in event_dict
            assert "target" in event_dict
            assert "security_result" in event_dict
        
        print("Passed!")

    def testGoogleSecOpsForensicReport(self):
        """Test Google SecOps forensic report conversion"""
        print()
        from parsedmarc.google_secops import GoogleSecOpsClient
        
        # Test without payload
        client = GoogleSecOpsClient(include_ruf_payload=False, use_stdout=True)
        sample_path = "samples/forensic/dmarc_ruf_report_linkedin.eml"
        print("Testing Google SecOps forensic conversion (no payload) for {0}: ".format(sample_path), end="")
        
        parsed_file = parsedmarc.parse_report_file(sample_path)
        parsed_report = parsed_file["report"]
        
        events = client.save_forensic_report_to_google_secops(parsed_report)
        
        # Verify we got events
        assert len(events) > 0, "Expected at least one event"
        
        # Verify each event is valid JSON
        for event in events:
            event_dict = json.loads(event)
            assert "event_type" in event_dict
            assert event_dict["event_type"] == "DMARC_FORENSIC"
            
            # Verify no payload in additional fields
            if "additional" in event_dict and "fields" in event_dict["additional"]:
                for field in event_dict["additional"]["fields"]:
                    assert field["key"] != "message_sample", "Payload should not be included when disabled"
        
        print("Passed!")
        
        # Test with payload
        client_with_payload = GoogleSecOpsClient(
            include_ruf_payload=True,
            ruf_payload_max_bytes=100,
            use_stdout=True
        )
        print("Testing Google SecOps forensic conversion (with payload) for {0}: ".format(sample_path), end="")
        
        events_with_payload = client_with_payload.save_forensic_report_to_google_secops(parsed_report)
        
        # Verify we got events
        assert len(events_with_payload) > 0, "Expected at least one event"
        
        # Verify payload is included
        for event in events_with_payload:
            event_dict = json.loads(event)
            
            # Check if message_sample is in additional fields
            has_sample = False
            if "additional" in event_dict and "fields" in event_dict["additional"]:
                for field in event_dict["additional"]["fields"]:
                    if field["key"] == "message_sample":
                        has_sample = True
                        # Verify truncation: max_bytes (100) + "... [truncated]" suffix (16 chars)
                        # Allow some margin for the actual payload length
                        max_expected_length = 100 + len("... [truncated]") + 10
                        assert len(field["value"]) <= max_expected_length, f"Payload should be truncated, got {len(field['value'])} bytes"
                        break
            
            assert has_sample, "Payload should be included when enabled"
        
        print("Passed!")

    def testGoogleSecOpsConfiguration(self):
        """Test Google SecOps client configuration"""
        print()
        from parsedmarc.google_secops import GoogleSecOpsClient
        
        print("Testing Google SecOps client configuration: ", end="")
        
        # Test stdout configuration
        client1 = GoogleSecOpsClient(use_stdout=True)
        assert client1.include_ruf_payload is False
        assert client1.ruf_payload_max_bytes == 4096
        assert client1.static_observer_vendor == "parsedmarc"
        assert client1.static_observer_name is None
        assert client1.static_environment is None
        assert client1.use_stdout is True
        
        # Test custom configuration
        client2 = GoogleSecOpsClient(
            include_ruf_payload=True,
            ruf_payload_max_bytes=8192,
            static_observer_name="test-observer",
            static_observer_vendor="test-vendor",
            static_environment="prod",
            use_stdout=True
        )
        assert client2.include_ruf_payload is True
        assert client2.ruf_payload_max_bytes == 8192
        assert client2.static_observer_name == "test-observer"
        assert client2.static_observer_vendor == "test-vendor"
        assert client2.static_environment == "prod"
        
        print("Passed!")

    def testGoogleSecOpsSmtpTlsReport(self):
        """Test Google SecOps SMTP TLS report conversion"""
        print()
        from parsedmarc.google_secops import GoogleSecOpsClient
        
        client = GoogleSecOpsClient(use_stdout=True)
        sample_path = "samples/smtp_tls/rfc8460.json"
        print("Testing Google SecOps SMTP TLS conversion for {0}: ".format(sample_path), end="")
        
        parsed_file = parsedmarc.parse_report_file(sample_path)
        parsed_report = parsed_file["report"]
        
        events = client.save_smtp_tls_report_to_google_secops(parsed_report)
        
        # Verify we got events
        assert len(events) > 0, "Expected at least one event"
        
        # Verify each event is valid JSON
        for event in events:
            event_dict = json.loads(event)
            assert "event_type" in event_dict
            assert event_dict["event_type"] == "SMTP_TLS_REPORT"
            assert "metadata" in event_dict
            assert "target" in event_dict
            assert "security_result" in event_dict
            
            # Verify failed_session_count is in detection_fields as an integer
            found_count = False
            for field in event_dict["security_result"][0]["detection_fields"]:
                if field["key"] == "smtp_tls.failed_session_count":
                    assert isinstance(field["value"], int), "failed_session_count should be an integer"
                    found_count = True
                    break
            assert found_count, "failed_session_count should be in detection_fields"
        
        print("Passed!")


if __name__ == "__main__":
    unittest.main(verbosity=2)
