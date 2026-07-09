"""Shared timezone-forcing helper for timestamp regression tests."""

import os
import time
import unittest


def force_tz(testcase: unittest.TestCase, tz: str = "Europe/Warsaw") -> None:
    """Set the process timezone to *tz* for the duration of *testcase*.

    Registers a cleanup that restores the previous ``TZ`` value.
    Requires POSIX ``time.tzset()``; guard callers with
    ``@unittest.skipUnless(hasattr(time, "tzset"), ...)``.

    The default zone is fixed and non-UTC (UTC+1 in January, UTC+2 in
    summer), so code that wrongly interprets a UTC wall-clock string as
    local time produces a shifted epoch under it.
    """
    old_tz = os.environ.get("TZ")
    os.environ["TZ"] = tz
    time.tzset()

    def restore() -> None:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        time.tzset()

    testcase.addCleanup(restore)
