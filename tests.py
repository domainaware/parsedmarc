from __future__ import print_function, unicode_literals, absolute_import

import unittest
from glob import glob
import json

import parsedmarc


class Test(unittest.TestCase):
    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            print("Testing {0}...\n".format(sample_path))
            parsed_report = parsedmarc.parse_report_file(
                sample_path)["report"]
            print(json.dumps(parsed_report, ensure_ascii=False, indent=2))
            print("\n")
            print(parsedmarc.parsed_aggregate_reports_to_csv(parsed_report))

    def testForensicSamples(self):
        """Test sample forensic/ruf/failure DMARC reports"""
        sample_paths = glob("samples/forensic/*.eml")
        for sample_path in sample_paths:
            print("Testing {0}...\n".format(sample_path))
            with open(sample_path) as sample_file:
                sample_content = sample_file.read()
                parsed_report = parsedmarc.parse_report_email(
                    sample_content)["report"]
            print(json.dumps(parsed_report, ensure_ascii=False, indent=2))
            print("\n")
            print(parsedmarc.parsed_forensic_reports_to_csv(parsed_report))


if __name__ == "__main__":
    unittest.main(verbosity=2)
