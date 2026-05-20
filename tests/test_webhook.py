"""Tests for parsedmarc.webhook"""

import unittest
from unittest.mock import MagicMock

import parsedmarc
import parsedmarc.webhook


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

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
        client.session.post.assert_called_with(
            "http://a", data='{"test": 1}', timeout=60
        )
        client.save_failure_report_to_webhook('{"fail": 1}')
        client.session.post.assert_called_with(
            "http://f", data='{"fail": 1}', timeout=60
        )
        client.save_smtp_tls_report_to_webhook('{"tls": 1}')
        client.session.post.assert_called_with(
            "http://t", data='{"tls": 1}', timeout=60
        )

    def testWebhookBackwardCompatAlias(self):
        """WebhookClient forensic alias points to failure method"""
        from parsedmarc.webhook import WebhookClient

        self.assertIs(
            WebhookClient.save_forensic_report_to_webhook,  # type: ignore[attr-defined]
            WebhookClient.save_failure_report_to_webhook,
        )


class TestWebhookClient(unittest.TestCase):
    """Tests for webhook client initialization and close"""

    def testClose(self):
        """WebhookClient.close() closes session"""
        client = parsedmarc.webhook.WebhookClient(
            aggregate_url="http://invalid.test/agg",
            failure_url="http://invalid.test/fail",
            smtp_tls_url="http://invalid.test/tls",
        )
        mock_close = MagicMock()
        client.session.close = mock_close
        client.close()
        mock_close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
