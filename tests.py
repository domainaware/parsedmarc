from __future__ import print_function, unicode_literals, absolute_import

import unittest
from glob import glob
import json

import parsedmarc


class Test(unittest.TestCase):
    def testSamples(self):
        """Test sample aggregate DMARC reports"""
        sample_paths = glob("samples/*.sample")
        for sample_path in sample_paths:
            print("Testing {0}...\n".format(sample_path))
            parsed_report = parsedmarc.parse_aggregate_report_file(sample_path)
            print(json.dumps(parsed_report, ensure_ascii=False, indent=2))
            print("\n")
            print(parsedmarc.parsed_aggregate_reports_to_csv(parsed_report))


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(Test)
    unittest.TextTestRunner(verbosity=2).run(suite)
