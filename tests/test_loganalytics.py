"""Tests for parsedmarc.loganalytics"""

import unittest


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
