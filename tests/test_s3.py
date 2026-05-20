"""Tests for parsedmarc.s3"""

import unittest


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

    def testS3BackwardCompatAlias(self):
        """S3Client forensic alias points to failure method"""
        from parsedmarc.s3 import S3Client

        self.assertIs(
            S3Client.save_forensic_report_to_s3,  # type: ignore[attr-defined]
            S3Client.save_failure_report_to_s3,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
