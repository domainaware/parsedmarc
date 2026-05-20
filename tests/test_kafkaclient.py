"""Tests for parsedmarc.kafkaclient"""

import unittest


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

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

    def testKafkaBackwardCompatAlias(self):
        """KafkaClient forensic alias points to failure method"""
        from parsedmarc.kafkaclient import KafkaClient

        self.assertIs(
            KafkaClient.save_forensic_reports_to_kafka,  # type: ignore[attr-defined]
            KafkaClient.save_failure_reports_to_kafka,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
