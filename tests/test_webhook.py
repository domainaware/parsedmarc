"""Tests for parsedmarc.webhook"""

import unittest
from unittest.mock import MagicMock

from parsedmarc.webhook import WebhookClient


def _client():
    return WebhookClient(
        aggregate_url="http://agg.example.com",
        failure_url="http://fail.example.com",
        smtp_tls_url="http://tls.example.com",
    )


class TestWebhookClientInit(unittest.TestCase):
    """The constructor stores URLs per report type. A mix-up here
    would route reports to the wrong endpoint silently."""

    def test_urls_and_timeout_stored(self):
        client = _client()
        self.assertEqual(client.aggregate_url, "http://agg.example.com")
        self.assertEqual(client.failure_url, "http://fail.example.com")
        self.assertEqual(client.smtp_tls_url, "http://tls.example.com")
        self.assertEqual(client.timeout, 60)

    def test_custom_timeout_respected(self):
        client = WebhookClient(
            aggregate_url="a", failure_url="f", smtp_tls_url="t", timeout=120
        )
        self.assertEqual(client.timeout, 120)

    def test_session_headers_set(self):
        """The Content-Type is required by virtually every webhook
        receiver to know how to deserialize the body."""
        client = _client()
        self.assertEqual(client.session.headers["Content-Type"], "application/json")
        self.assertIn("parsedmarc", client.session.headers["User-Agent"])


class TestWebhookClientSaveMethods(unittest.TestCase):
    """Each save_* sends the payload to the URL configured for that
    report type. A typo on which URL each method uses would
    permanently mis-route reports of that type."""

    def test_aggregate_posts_to_aggregate_url(self):
        client = _client()
        client.session = MagicMock()
        client.save_aggregate_report_to_webhook('{"agg": 1}')
        client.session.post.assert_called_once_with(
            "http://agg.example.com", content='{"agg": 1}', timeout=60
        )

    def test_failure_posts_to_failure_url(self):
        client = _client()
        client.session = MagicMock()
        client.save_failure_report_to_webhook('{"fail": 1}')
        client.session.post.assert_called_once_with(
            "http://fail.example.com", content='{"fail": 1}', timeout=60
        )

    def test_smtp_tls_posts_to_smtp_tls_url(self):
        client = _client()
        client.session = MagicMock()
        client.save_smtp_tls_report_to_webhook('{"tls": 1}')
        client.session.post.assert_called_once_with(
            "http://tls.example.com", content='{"tls": 1}', timeout=60
        )


class TestWebhookClientDictPayload(unittest.TestCase):
    """``_send_to_webhook`` accepts ``bytes | str | dict``. httpx only
    form-encodes a dict via ``data=``; string/bytes payloads must use
    ``content=`` since httpx's ``data=`` is form-encoding only."""

    def test_dict_payload_uses_data_kwarg(self):
        client = _client()
        client.session = MagicMock()
        client._send_to_webhook("http://agg.example.com", {"agg": 1})
        client.session.post.assert_called_once_with(
            "http://agg.example.com", data={"agg": 1}, timeout=60
        )


class TestWebhookErrorHandling(unittest.TestCase):
    """HTTP / network failures from the webhook receiver must NOT
    abort the surrounding parse-and-output batch — they're logged
    and swallowed. Misbehaving webhooks shouldn't take down DMARC
    processing."""

    def test_network_error_is_logged_and_swallowed(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.side_effect = OSError("connection refused")
        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            # Should NOT raise.
            client.save_aggregate_report_to_webhook('{"a": 1}')
        self.assertTrue(any("Webhook Error" in m for m in cm.output))
        self.assertTrue(any("connection refused" in m for m in cm.output))

    def test_error_in_failure_save_is_swallowed(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.side_effect = RuntimeError("timeout")
        with self.assertLogs("parsedmarc.log", level="ERROR"):
            client.save_failure_report_to_webhook('{"f": 1}')

    def test_error_in_smtp_tls_save_is_swallowed(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.side_effect = RuntimeError("boom")
        with self.assertLogs("parsedmarc.log", level="ERROR"):
            client.save_smtp_tls_report_to_webhook('{"t": 1}')


class TestWebhookClientClose(unittest.TestCase):
    def test_close_closes_session(self):
        client = _client()
        mock_close = MagicMock()
        client.session.close = mock_close
        client.close()
        mock_close.assert_called_once()


class TestWebhookBackwardCompatAlias(unittest.TestCase):
    def test_forensic_alias_points_to_failure_method(self):
        self.assertIs(
            WebhookClient.save_forensic_report_to_webhook,
            WebhookClient.save_failure_report_to_webhook,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
