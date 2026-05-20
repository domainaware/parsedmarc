"""Tests for parsedmarc.syslog"""

import unittest


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

    def testSyslogClientUdpInit(self):
        """SyslogClient creates UDP handler"""
        from parsedmarc.syslog import SyslogClient

        client = SyslogClient("localhost", 514, protocol="udp")
        self.assertEqual(client.server_name, "localhost")
        self.assertEqual(client.server_port, 514)
        self.assertEqual(client.protocol, "udp")

    def testSyslogClientInvalidProtocol(self):
        """SyslogClient with invalid protocol raises ValueError"""
        from parsedmarc.syslog import SyslogClient

        with self.assertRaises(ValueError):
            SyslogClient("localhost", 514, protocol="invalid")

    def testSyslogBackwardCompatAlias(self):
        """SyslogClient forensic alias points to failure method"""
        from parsedmarc.syslog import SyslogClient

        self.assertIs(
            SyslogClient.save_forensic_report_to_syslog,  # type: ignore[attr-defined]
            SyslogClient.save_failure_report_to_syslog,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
