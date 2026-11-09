"""Tests for parsedmarc.parallel"""

import functools
import logging
import math
import multiprocessing
import os
import tempfile
import time
import unittest
from concurrent.futures import ProcessPoolExecutor
from unittest.mock import patch

import parsedmarc
from parsedmarc.parallel import (
    _email_timeout_result,
    _file_timeout_result,
    _init_worker,
    _parse_report_email_job,
    _parse_report_file_job,
    parallel_map,
)
from tests.timing import budget

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
    """Common env setup shared by parallel.py tests: offline mode, no DNS,
    and a cold IP address cache."""

    def setUp(self):
        self._env_patcher = patch.dict(
            os.environ, {"GITHUB_ACTIONS": "true"}, clear=False
        )
        self._env_patcher.start()
        self.addCleanup(self._env_patcher.stop)
        # Earlier test modules (e.g. tests/test_init.py) may run with DNS
        # enabled locally and warm the shared module-level
        # parsedmarc.IP_ADDRESS_CACHE. get_ip_address_info consults the
        # cache before the offline check, so a warm cache would leak
        # DNS-enriched entries into offline parses run in this process
        # while spawned workers start cold, breaking parity.
        parsedmarc.IP_ADDRESS_CACHE.clear()


class TestParallelMapParseReportFile(_ParallelTestCase):
    """parallel_map + _parse_report_file_job over real sample files must
    behave identically to calling parse_report_file sequentially, and
    must preserve submission order in its results."""

    def test_results_match_sequential_parsing_in_order(self):
        expected = [
            (path, parsedmarc.parse_report_file(path, offline=True))
            for path in SAMPLE_PATHS
        ]

        job = functools.partial(
            _parse_report_file_job, config=parsedmarc.ParserConfig(offline=True)
        )
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

        job = functools.partial(
            _parse_report_file_job, config=parsedmarc.ParserConfig(offline=True)
        )
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


class TestParallelMapValidation(unittest.TestCase):
    """parallel_map is a reusable helper, so it validates n_procs itself
    with a clear message instead of surfacing ProcessPoolExecutor's
    max_workers error later - and it must do so eagerly at the call, not
    on first iteration of the returned iterator (callers that pass the
    iterator elsewhere before consuming it would otherwise see the error
    far from the bad argument)."""

    def test_n_procs_below_one_raises_value_error_eagerly(self):
        with self.assertRaises(ValueError):
            parallel_map(_echo_job, [1, 2], n_procs=0)


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
        job = functools.partial(
            _parse_report_file_job, config=parsedmarc.ParserConfig(offline=True)
        )
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
    """_init_worker must be usable directly as a pool initializer: with no
    log files it sets the level (configure_logging still ensures a console
    handler), and with log files it attaches a FileHandler per path. The
    IP-lookup state and PSL overrides it also restores are passed through
    unchanged here so these tests exercise only the logging side. It also
    gives SIGTERM its default action and ignores SIGINT, so the test
    process's own handlers are put back after each test."""

    def setUp(self):
        import signal

        from parsedmarc.log import logger as plog

        self._saved_handlers = list(plog.handlers)
        self._saved_level = plog.level
        for name in ("SIGTERM", "SIGINT"):
            if hasattr(signal, name):
                number = getattr(signal, name)
                self.addCleanup(signal.signal, number, signal.getsignal(number))

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
        from parsedmarc import utils
        from parsedmarc.log import logger as plog

        _init_worker(
            logging.WARNING,
            [],
            utils._get_ip_worker_state(),
            list(utils.psl_overrides),
        )
        self.assertEqual(plog.level, logging.WARNING)

    def test_log_files_attach_file_handlers(self):
        from parsedmarc import utils
        from parsedmarc.log import logger as plog

        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
            log_path = tf.name
        self.addCleanup(lambda: os.path.exists(log_path) and os.remove(log_path))

        _init_worker(
            logging.DEBUG,
            [log_path],
            utils._get_ip_worker_state(),
            list(utils.psl_overrides),
        )

        self.assertEqual(plog.level, logging.DEBUG)
        file_handlers = [h for h in plog.handlers if isinstance(h, logging.FileHandler)]
        self.assertTrue(any(h.baseFilename == log_path for h in file_handlers))
        for h in file_handlers:
            h.close()


def _ip_worker_state_job(_):
    """Read the worker process's IP-lookup state and PSL overrides so a
    test can compare them with what the parent configured. Module-level and
    picklable (a spawn child re-imports this module to unpickle it)."""
    from parsedmarc import utils

    return (utils._IPINFO_API_TOKEN, utils._IP_DB_PATH, list(utils.psl_overrides))


class TestWorkerIPState(unittest.TestCase):
    """parallel_map workers must make the same IPinfo API / MMDB selections
    and use the same PSL overrides the parent configured, whatever the
    start method.

    parsedmarc.utils._IPINFO_API_TOKEN (configure_ipinfo_api),
    parsedmarc.utils._IP_DB_PATH (load_ip_db), and the module-level
    parsedmarc.utils.psl_overrides list (load_psl_overrides) are process
    globals. Under ``fork`` a worker inherits them ("All resources of the
    parent are inherited by the child process"), but under ``spawn`` and
    ``forkserver`` it does not ("The child process will only inherit those
    resources necessary to run the process object's ``run()`` method") -
    https://docs.python.org/3/library/multiprocessing.html. The pool
    initializer therefore restores the parent's snapshot in every worker.
    This test forces each non-fork start method so it guards that path on
    every Python version, not only the ones whose default start method
    already exercises it (Linux defaults to forkserver from 3.14, macOS
    and Windows to spawn).

    With the ``psl_overrides`` restore removed from ``_init_worker``, the
    PSL assertion failed under both ``spawn`` and ``forkserver``: each
    worker reported the bundled ``psl_overrides.txt`` list it loads at
    import, not the parent's ``["example.test"]``.
    """

    def test_workers_see_parent_ip_state_under_spawn_and_forkserver(self):
        import multiprocessing

        import parsedmarc.utils as utils

        methods = [
            m
            for m in ("spawn", "forkserver")
            if m in multiprocessing.get_all_start_methods()
        ]
        self.assertIn("spawn", methods)

        original_state = utils._get_ip_worker_state()
        original_psl = list(utils.psl_overrides)
        original_method = multiprocessing.get_start_method()
        utils._set_ip_worker_state(
            "worker-state-test-token", "/parent/only/ipinfo_lite.mmdb"
        )
        utils.psl_overrides[:] = ["example.test"]
        self.addCleanup(utils._set_ip_worker_state, *original_state)
        self.addCleanup(utils.psl_overrides.__setitem__, slice(None), original_psl)
        self.addCleanup(multiprocessing.set_start_method, original_method, force=True)

        for method in methods:
            with self.subTest(start_method=method):
                multiprocessing.set_start_method(method, force=True)

                results = list(parallel_map(_ip_worker_state_job, range(8), n_procs=2))

                self.assertEqual(len(results), 8)
                for token, db_path, psl in results:
                    self.assertEqual(token, "worker-state-test-token")
                    self.assertEqual(db_path, "/parent/only/ipinfo_lite.mmdb")
                    self.assertEqual(psl, ["example.test"])


class TestParseReportEmailJob(_ParallelTestCase):
    """_parse_report_email_job must return a ParserError as a value (never
    raise it) on an invalid message."""

    def test_invalid_email_returns_parser_error_value(self):
        result = _parse_report_email_job(
            b"not a valid email", config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertIsInstance(result, parsedmarc.ParserError)


# parse_timeout tests: a job that sleeps _SLOW seconds stands in for a parse
# that never ends, and _TIMEOUT is far below it, so a test that finishes in
# about _TIMEOUT seconds shows the job was stopped rather than waited for.
_TIMEOUT = 0.5
_SLOW = 5.0


def _sleep_job(seconds):
    """Sleep ``seconds`` and return it. Module-level so it pickles."""
    time.sleep(seconds)
    return seconds


def _timeout_value(job, seconds):
    return ("timed out", job, seconds)


class TestParallelMapParseTimeout(unittest.TestCase):
    """parse_timeout stops a job that runs too long and yields
    timeout_result(job, parse_timeout) in its place.

    Without a timeout each _SLOW job holds the run for its full 5 s. With a
    0.5 s timeout one stop costs the timeout, a wait slice (0.05 s here)
    and one pool start (about 0.3 s under spawn on the workstation, a few
    milliseconds under fork), so every bound below allows for two pool
    starts and stays far under the 5 s the job would take.
    """

    def _run(self, jobs, n_procs, **kwargs):
        kwargs.setdefault("parse_timeout", _TIMEOUT)
        kwargs.setdefault("timeout_result", _timeout_value)
        start = time.monotonic()
        results = list(parallel_map(_sleep_job, jobs, n_procs, **kwargs))
        return results, time.monotonic() - start

    def test_timed_out_job_yields_timeout_value_in_order(self):
        results, elapsed = self._run([0.0, _SLOW, 0.1, 0.2], n_procs=2)
        self.assertEqual(results, [0.0, ("timed out", _SLOW, _TIMEOUT), 0.1, 0.2])
        self.assertLess(elapsed, budget(4))

    def test_timeout_of_first_job_resubmits_the_rest(self):
        """With one worker the later jobs are still queued when the first
        times out; the pool they were queued in is killed, so they must be
        submitted again to the new pool."""
        results, elapsed = self._run([_SLOW, 0.0, 0.1], n_procs=1)
        self.assertEqual(results, [("timed out", _SLOW, _TIMEOUT), 0.0, 0.1])
        self.assertLess(elapsed, budget(4))

    def test_two_consecutive_timeouts_with_one_process(self):
        """The second slow job times out in the rebuilt pool too, and its
        clock starts only once it runs, so the run takes at least two
        timeouts."""
        results, elapsed = self._run([_SLOW, _SLOW, 0.0], n_procs=1)
        timed_out = ("timed out", _SLOW, _TIMEOUT)
        self.assertEqual(results, [timed_out, timed_out, 0.0])
        self.assertGreaterEqual(elapsed, 2 * _TIMEOUT)
        self.assertLess(elapsed, budget(6))

    def test_job_waiting_behind_a_slow_neighbour_is_not_charged_for_the_wait(self):
        """ProcessPoolExecutor marks one job more than it has workers as
        running, so with one worker the second job reads as running from the
        start. Both jobs here finish within the timeout; timing the second
        from when its future first reads as running stopped it after 1.0 s,
        0.3 s before it would have finished."""
        results, elapsed = self._run([0.7, 0.7], n_procs=1, parse_timeout=1.0)
        self.assertEqual(results, [0.7, 0.7])
        self.assertLess(elapsed, budget(4))

    def test_heartbeat_is_called_during_a_long_job(self):
        beats = []
        results, elapsed = self._run(
            [1.0],
            n_procs=1,
            parse_timeout=3.0,
            heartbeat=lambda: beats.append(time.monotonic()),
            heartbeat_interval=0.1,
        )
        self.assertEqual(results, [1.0])
        # About ten in the 1 s the job runs; five leaves room for a slow
        # pool start, which no heartbeat waits on.
        self.assertGreaterEqual(len(beats), 5)
        self.assertLess(elapsed, budget(4))

    def test_zero_timeout_means_no_deadline(self):
        """With parse_timeout 0 a job longer than any timeout used here
        finishes, through the pool that never kills a job."""
        with patch("parsedmarc.parallel._DeadlinePool") as deadline_pool:
            results, elapsed = self._run([1.0], n_procs=1, parse_timeout=0.0)
        self.assertEqual(results, [1.0])
        deadline_pool.assert_not_called()
        self.assertGreaterEqual(elapsed, 1.0)

    def test_invalid_timeout_arguments_raise_eagerly(self):
        for parse_timeout in (-1.0, math.nan, math.inf):
            with self.subTest(parse_timeout=parse_timeout):
                with self.assertRaises(ValueError):
                    parallel_map(
                        _sleep_job,
                        [0.0],
                        1,
                        parse_timeout=parse_timeout,
                        timeout_result=_timeout_value,
                    )
        with self.assertRaises(ValueError):
            parallel_map(_sleep_job, [0.0], 1, parse_timeout=_TIMEOUT)

    def test_timed_out_workers_are_reaped_under_every_start_method(self):
        """The killed worker is gone when parallel_map returns, rather than
        sleeping on for the rest of its 5 s. Stopping it needs the
        executor's private ``_processes`` mapping; if a Python version drops
        it, this test fails instead of the worker silently surviving."""
        self.assertIsInstance(ProcessPoolExecutor(max_workers=1)._processes, dict)
        original_method = multiprocessing.get_start_method()
        self.addCleanup(multiprocessing.set_start_method, original_method, force=True)
        before = set(multiprocessing.active_children())
        for method in multiprocessing.get_all_start_methods():
            with self.subTest(start_method=method):
                multiprocessing.set_start_method(method, force=True)
                results, elapsed = self._run([_SLOW], n_procs=1)
                self.assertEqual(results, [("timed out", _SLOW, _TIMEOUT)])
                self.assertLess(elapsed, budget(3))
                self.assertLessEqual(set(multiprocessing.active_children()), before)

    def test_should_stop_ends_iteration_early_with_a_timeout(self):
        jobs = _CountingIterable(20)
        results = list(
            parallel_map(
                _echo_job,
                jobs,
                2,
                should_stop=lambda: True,
                parse_timeout=_TIMEOUT,
                timeout_result=_timeout_value,
            )
        )
        self.assertLess(len(results), 20)
        self.assertLess(jobs.pulled, 20)
        self.assertEqual(results, list(range(len(results))))

    def test_leaving_early_kills_the_pool(self):
        """An exception out of the loop (here from the heartbeat) ends the
        run at once instead of waiting for the running job."""
        before = set(multiprocessing.active_children())

        def failing_heartbeat():
            raise RuntimeError("connection lost")

        start = time.monotonic()
        with self.assertRaises(RuntimeError):
            self._run(
                [_SLOW],
                n_procs=1,
                parse_timeout=30.0,
                heartbeat=failing_heartbeat,
                heartbeat_interval=0.1,
            )
        self.assertLess(time.monotonic() - start, budget(3))
        self.assertLessEqual(set(multiprocessing.active_children()), before)


class TestTimeoutResults(unittest.TestCase):
    """The values parallel_map yields for a timed-out email or file job have
    the shapes the callers handle for an unparseable input."""

    def test_email_timeout_result_is_an_invalid_dmarc_report(self):
        result = _email_timeout_result(b"message", 300.0)
        self.assertIsInstance(result, parsedmarc.ParseTimeoutError)
        self.assertIsInstance(result, parsedmarc.InvalidDMARCReport)
        self.assertIn("300 seconds", str(result))

    def test_file_timeout_result_pairs_the_path_with_the_error(self):
        file_path, error = _file_timeout_result("reports/a.xml", 2.5)
        self.assertEqual(file_path, "reports/a.xml")
        self.assertIsInstance(error, parsedmarc.ParseTimeoutError)
        self.assertIn("2.5 seconds", str(error))


def _signal_handler_job(signal_name):
    """Report whether the worker's handler for ``signal_name`` is the
    default (``"default"``), ignores it (``"ignored"``) or is something else.
    Module-level so it pickles."""
    import signal

    handler = signal.getsignal(getattr(signal, signal_name))
    if handler is signal.SIG_DFL:
        return "default"
    if handler is signal.SIG_IGN:
        return "ignored"
    return "other"


def _parent_signal_handler(signum, frame):
    """A handler that, like the CLI's, only notes the signal."""


def _use_fork(test):
    """Switch ``test`` to the ``fork`` start method, or skip it."""
    if "fork" not in multiprocessing.get_all_start_methods():
        test.skipTest("the fork start method is not available")
    original_method = multiprocessing.get_start_method()
    test.addCleanup(multiprocessing.set_start_method, original_method, force=True)
    multiprocessing.set_start_method("fork", force=True)


class TestWorkerSignalHandlers(unittest.TestCase):
    """Under ``fork`` a worker inherits the parent's signal handlers. The
    CLI installs SIGTERM and SIGINT handlers that only set a flag, so a
    worker running them ignores the SIGTERM ``ProcessPoolExecutor`` sends
    when it tears down a broken pool, and the teardown waits for it
    forever. The pool initializer restores the default SIGTERM action and
    ignores SIGINT, which the parent coordinates, in the plain pool and in
    the pool built for a ``parse_timeout``."""

    def test_workers_take_sigterm_and_ignore_sigint_under_fork(self):
        import signal

        _use_fork(self)
        names = [n for n in ("SIGTERM", "SIGINT") if hasattr(signal, n)]
        for name in names:
            number = getattr(signal, name)
            self.addCleanup(signal.signal, number, signal.getsignal(number))
            signal.signal(number, _parent_signal_handler)
        expected = {"SIGTERM": "default", "SIGINT": "ignored"}

        for kwargs in ({}, {"parse_timeout": 30.0, "timeout_result": _timeout_value}):
            with self.subTest(**kwargs):
                results = list(
                    parallel_map(_signal_handler_job, names, n_procs=1, **kwargs)
                )
                self.assertEqual(
                    dict(zip(names, results)), {n: expected[n] for n in names}
                )

    def test_ctrl_c_lets_the_running_jobs_finish_under_fork(self):
        """A terminal sends Ctrl-C's SIGINT to every process in its
        foreground process group, the workers included. The parent's handler
        (here, as in the CLI, one that only notes the signal) lets the batch
        finish, so the workers must survive the signal too; with the default
        action each worker died and the run ended in ``BrokenProcessPool``.
        The test signals the parent and each worker itself rather than its
        whole process group, which holds the test runner too."""
        import signal
        import threading

        _use_fork(self)
        received = []
        self.addCleanup(signal.signal, signal.SIGINT, signal.getsignal(signal.SIGINT))
        signal.signal(signal.SIGINT, lambda signum, frame: received.append(signum))

        for kwargs in ({}, {"parse_timeout": 30.0, "timeout_result": _timeout_value}):
            with self.subTest(**kwargs):
                received.clear()
                before = set(multiprocessing.active_children())

                def interrupt(before=before):
                    for child in set(multiprocessing.active_children()) - before:
                        os.kill(child.pid, signal.SIGINT)
                    os.kill(os.getpid(), signal.SIGINT)

                timer = threading.Timer(0.5, interrupt)
                timer.start()
                self.addCleanup(timer.cancel)
                results = list(parallel_map(_sleep_job, [2.0, 2.0], 2, **kwargs))
                timer.join()
                self.assertEqual(results, [2.0, 2.0])
                self.assertEqual(received, [signal.SIGINT])


def _exit_job(value):
    """End the worker process at once when ``value`` is ``"exit"``, as the
    out-of-memory killer or a crash would; otherwise sleep ``value``
    seconds and return it. Module-level so it pickles."""
    if value == "exit":
        os._exit(1)
    time.sleep(value)
    return value


class TestWorkerDeath(unittest.TestCase):
    """A worker process that dies breaks the pool, and
    ``ProcessPoolExecutor`` then fails every unfinished job with
    ``BrokenProcessPool``. ``parallel_map`` raises ``ParserError`` from it,
    promptly, and leaves no worker behind, in the plain pool and in the pool
    built for a ``parse_timeout``. Without the conversion the
    ``BrokenProcessPool`` escaped to the caller, which handles only
    ``ParserError``."""

    def test_dying_worker_raises_parser_error(self):
        from concurrent.futures.process import BrokenProcessPool

        methods = [
            m
            for m in ("fork", "forkserver")
            if m in multiprocessing.get_all_start_methods()
        ]
        original_method = multiprocessing.get_start_method()
        self.addCleanup(multiprocessing.set_start_method, original_method, force=True)
        for method in methods:
            for kwargs in (
                {},
                {"parse_timeout": 30.0, "timeout_result": _timeout_value},
            ):
                with self.subTest(start_method=method, **kwargs):
                    multiprocessing.set_start_method(method, force=True)
                    before = set(multiprocessing.active_children())
                    start = time.monotonic()
                    with self.assertRaises(parsedmarc.ParserError) as caught:
                        list(
                            parallel_map(
                                _exit_job, [0.1, "exit", 0.1, 0.1], 2, **kwargs
                            )
                        )
                    # About a pool start; the 30 s timeout plays no part.
                    self.assertLess(time.monotonic() - start, budget(5))
                    self.assertIn("worker process died", str(caught.exception))
                    self.assertIsInstance(caught.exception.__cause__, BrokenProcessPool)
                    self.assertLessEqual(set(multiprocessing.active_children()), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
