"""Tests for parsedmarc.parallel"""

import functools
import logging
import os
import tempfile
import unittest
from unittest.mock import patch

import parsedmarc
from parsedmarc.parallel import (
    _init_worker_logging,
    _parse_report_email_job,
    _parse_report_file_job,
    parallel_map,
)

# Stable sample files reused from tests/test_cli.py's TestDirectoryFilePaths,
# plus a third plain aggregate sample, so parity/order tests exercise more
# than one worker submission.
SAMPLE_PATHS = [
    "samples/aggregate/!example.com!1538204542!1538463818.xml",
    "samples/aggregate/!large-example.com!1711897200!1711983600.xml",
    "samples/aggregate/example.net!example.com!1529366400!1529452799.xml",
]


def _echo_job(x):
    """Trivial module-level (spawn-picklable) worker used to exercise
    parallel_map's scheduling behavior without involving real parsing."""
    return x


class _CountingIterable:
    """Wraps a range so tests can observe how many items parallel_map has
    pulled from a lazily-iterated jobs source at any point during
    iteration, without materializing the whole sequence up front."""

    def __init__(self, n):
        self.n = n
        self.pulled = 0

    def __iter__(self):
        for i in range(self.n):
            self.pulled += 1
            yield i


class _ParallelTestCase(unittest.TestCase):
    """Common env setup shared by parallel.py tests: offline mode, no DNS."""

    def setUp(self):
        self._env_patcher = patch.dict(
            os.environ, {"GITHUB_ACTIONS": "true"}, clear=False
        )
        self._env_patcher.start()
        self.addCleanup(self._env_patcher.stop)


class TestParallelMapParseReportFile(_ParallelTestCase):
    """parallel_map + _parse_report_file_job over real sample files must
    behave identically to calling parse_report_file sequentially, and
    must preserve submission order in its results."""

    def test_results_match_sequential_parsing_in_order(self):
        expected = [
            (path, parsedmarc.parse_report_file(path, offline=True))
            for path in SAMPLE_PATHS
        ]

        job = functools.partial(_parse_report_file_job, kwargs=dict(offline=True))
        results = list(parallel_map(job, SAMPLE_PATHS, n_procs=2))

        self.assertEqual(len(results), len(SAMPLE_PATHS))
        # Order must match submission order (SAMPLE_PATHS), not completion
        # order.
        self.assertEqual([path for path, _ in results], SAMPLE_PATHS)
        for (path, report), (expected_path, expected_report) in zip(results, expected):
            self.assertEqual(path, expected_path)
            self.assertNotIsInstance(report, Exception)
            self.assertEqual(report, expected_report)


class TestParallelMapJunkFile(_ParallelTestCase):
    """A worker crash on an unparseable file must surface as an Exception
    *value* in the result tuple, not hang the whole run. This is a
    regression guard for the old Pipe/Process CLI worker, which left the
    parent blocked forever on conn.recv() when a child died from a
    non-ParserError exception."""

    def test_junk_file_yields_exception_value_and_completes(self):
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="wb") as tf:
            tf.write(b"not a report")
            junk_path = tf.name
        self.addCleanup(os.remove, junk_path)

        job = functools.partial(_parse_report_file_job, kwargs=dict(offline=True))
        results = list(parallel_map(job, [junk_path, junk_path], n_procs=2))

        self.assertEqual(len(results), 2)
        for path, result in results:
            self.assertEqual(path, junk_path)
            self.assertIsInstance(result, Exception)


class TestParallelMapBoundedLaziness(unittest.TestCase):
    """The jobs iterable must never be materialized up front. At any point
    during iteration, the number of items pulled from the source should
    stay within window_factor * n_procs of the number of results already
    yielded, bounding memory use for very large inputs (e.g. a 20,000
    message mbox)."""

    def test_consumption_stays_bounded_and_results_are_complete_and_ordered(self):
        n = 20
        window_factor = 2
        n_procs = 2
        window_size = window_factor * n_procs

        jobs = _CountingIterable(n)
        results = []
        gen = parallel_map(
            _echo_job, jobs, n_procs=n_procs, window_factor=window_factor
        )
        for result in gen:
            results.append(result)
            # +1 buffer: the generator may pull one extra job before it
            # can submit-then-harvest on a given step.
            self.assertLessEqual(jobs.pulled, window_size + len(results) + 1)

        self.assertEqual(results, list(range(n)))


class TestParallelMapShouldStop(unittest.TestCase):
    """should_stop lets a caller (e.g. a CLI handling SIGTERM) end a run
    early without raising, while still yielding results already
    completed in the submission window."""

    def test_should_stop_ends_iteration_early(self):
        n = 20
        jobs = _CountingIterable(n)

        results = list(
            parallel_map(_echo_job, jobs, n_procs=2, should_stop=lambda: True)
        )

        self.assertLess(len(results), n)
        self.assertLess(jobs.pulled, n)
        # Results still seen so far must be a prefix of submission order.
        self.assertEqual(results, list(range(len(results))))


class TestParallelMapEmptyJobs(unittest.TestCase):
    """An empty jobs iterable must return immediately without spawning a
    process pool."""

    def test_empty_jobs_yields_nothing_and_spawns_no_pool(self):
        with patch("parsedmarc.parallel.ProcessPoolExecutor") as mock_executor:
            results = list(parallel_map(_echo_job, [], n_procs=2))
        self.assertEqual(results, [])
        mock_executor.assert_not_called()


class TestWorkerLogging(_ParallelTestCase):
    """Worker processes must reconstruct the parent parsedmarc logger's
    level and FileHandler(s) so records emitted during parsing (e.g.
    parse_report_file's "Parsing <path>" debug line) aren't silently
    dropped just because they happened in a child process."""

    def setUp(self):
        super().setUp()
        from parsedmarc.log import logger as plog

        self._saved_handlers = list(plog.handlers)
        self._saved_level = plog.level

    def tearDown(self):
        from parsedmarc.log import logger as plog

        for handler in list(plog.handlers):
            if handler not in self._saved_handlers:
                plog.removeHandler(handler)
                if isinstance(handler, logging.FileHandler):
                    handler.close()
        plog.handlers[:] = self._saved_handlers
        plog.setLevel(self._saved_level)
        super().tearDown()

    def test_worker_debug_log_reaches_parent_file_handler(self):
        from parsedmarc.log import configure_logging

        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
            log_path = tf.name
        self.addCleanup(lambda: os.path.exists(log_path) and os.remove(log_path))

        configure_logging(logging.DEBUG, log_path)

        sample = SAMPLE_PATHS[0]
        job = functools.partial(_parse_report_file_job, kwargs=dict(offline=True))
        results = list(parallel_map(job, [sample], n_procs=2))

        self.assertEqual(len(results), 1)
        path, report = results[0]
        self.assertEqual(path, sample)
        self.assertNotIsInstance(report, Exception)

        with open(log_path) as f:
            contents = f.read()
        # parse_report_file logs `Parsing {file_path}` at DEBUG
        # (parsedmarc/__init__.py) -- this line only appears if the
        # worker process's reconstructed logger actually wrote to the
        # parent's log file.
        self.assertIn(f"Parsing {sample}", contents)


class TestInitWorkerLogging(unittest.TestCase):
    """_init_worker_logging must be usable directly as a pool initializer:
    with no log files it just sets the level (adds a console handler),
    and with log files it attaches a FileHandler per path."""

    def setUp(self):
        from parsedmarc.log import logger as plog

        self._saved_handlers = list(plog.handlers)
        self._saved_level = plog.level

    def tearDown(self):
        from parsedmarc.log import logger as plog

        for handler in list(plog.handlers):
            if handler not in self._saved_handlers:
                plog.removeHandler(handler)
                if isinstance(handler, logging.FileHandler):
                    handler.close()
        plog.handlers[:] = self._saved_handlers
        plog.setLevel(self._saved_level)

    def test_no_log_files_sets_level_only(self):
        from parsedmarc.log import logger as plog

        _init_worker_logging(logging.WARNING, [])
        self.assertEqual(plog.level, logging.WARNING)

    def test_log_files_attach_file_handlers(self):
        from parsedmarc.log import logger as plog

        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
            log_path = tf.name
        self.addCleanup(lambda: os.path.exists(log_path) and os.remove(log_path))

        _init_worker_logging(logging.DEBUG, [log_path])

        self.assertEqual(plog.level, logging.DEBUG)
        file_handlers = [h for h in plog.handlers if isinstance(h, logging.FileHandler)]
        self.assertTrue(any(h.baseFilename == log_path for h in file_handlers))
        for h in file_handlers:
            h.close()


class TestParseReportEmailJob(_ParallelTestCase):
    """_parse_report_email_job must return a ParserError as a value (never
    raise it) on an invalid message."""

    def test_invalid_email_returns_parser_error_value(self):
        result = _parse_report_email_job(
            b"not a valid email", kwargs=dict(offline=True)
        )
        self.assertIsInstance(result, parsedmarc.ParserError)


if __name__ == "__main__":
    unittest.main(verbosity=2)
