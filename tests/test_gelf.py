"""Tests for parsedmarc.gelf"""

import unittest


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

    def testGelfBackwardCompatAlias(self):
        """GelfClient forensic alias points to failure method"""
        from parsedmarc.gelf import GelfClient

        self.assertIs(
            GelfClient.save_forensic_report_to_gelf,  # type: ignore[attr-defined]
            GelfClient.save_failure_report_to_gelf,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
