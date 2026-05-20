"""Tests for parsedmarc.splunk"""

import unittest


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

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
            HECClient.save_forensic_reports_to_splunk,  # type: ignore[attr-defined]
            HECClient.save_failure_reports_to_splunk,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
