"""Tests for parsedmarc.parallel"""

import functools
import logging
import math
import multiprocessing
import os
import pickle
import shutil
import tempfile
import time
import types
import unittest
from concurrent.futures import ProcessPoolExecutor
from unittest.mock import patch

import parsedmarc
from parsedmarc.parallel import (
    _MAX_ERROR_TEXT,
    _email_timeout_result,
    _file_timeout_result,
    _init_worker,
    _parse_report_email_job,
    _parse_report_file_job,
    _short_error_text,
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

    def test_timed_initializer_keeps_the_start_queue_and_initializes(self):
        """The initializer of a pool built for a ``parse_timeout`` stores its
        start queue for the jobs and then runs ``_init_worker``. Called here
        in the test process, where coverage can see it."""
        import signal

        from parsedmarc import parallel, utils
        from parsedmarc.log import logger as plog

        self.addCleanup(setattr, parallel, "_start_queue", parallel._start_queue)
        start_queue = multiprocessing.get_context().SimpleQueue()
        self.addCleanup(start_queue.close)
        parallel._init_timed_worker(
            start_queue,
            logging.WARNING,
            [],
            utils._get_ip_worker_state(),
            list(utils.psl_overrides),
        )
        self.assertIs(parallel._start_queue, start_queue)
        self.assertEqual(plog.level, logging.WARNING)
        self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)


class TestRunTimedJob(unittest.TestCase):
    """``_run_timed_job`` writes its token to the worker's start queue before
    it runs the job, and only runs the job when the worker has no queue. It
    leaves the outcome, a value or an exception the job raised, in a file
    ``_take_outcome`` reads back unchanged and removes. It runs in a worker,
    so it is called here in the test process."""

    def setUp(self):
        from parsedmarc import parallel

        self.addCleanup(setattr, parallel, "_start_queue", parallel._start_queue)
        self.result_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.result_dir, ignore_errors=True)

    def test_token_is_put_on_the_start_queue_before_the_job_runs(self):
        from parsedmarc import parallel

        start_queue = multiprocessing.get_context().SimpleQueue()
        self.addCleanup(start_queue.close)
        parallel._start_queue = start_queue
        seen_before_the_job = []

        def job(value):
            seen_before_the_job.append(start_queue.get())
            return value * 2

        self.assertIsNone(parallel._run_timed_job(job, 7, 21, self.result_dir))
        self.assertEqual(seen_before_the_job, [7])
        self.assertTrue(start_queue.empty())
        self.assertEqual(parallel._take_outcome(self.result_dir, 7), 42)
        self.assertEqual(os.listdir(self.result_dir), [])

    def test_without_a_start_queue_the_job_just_runs(self):
        from parsedmarc import parallel

        parallel._start_queue = None
        parallel._run_timed_job(_echo_job, 7, 21, self.result_dir)
        self.assertEqual(parallel._take_outcome(self.result_dir, 7), _echo_job(21))

    def test_an_error_value_travels_unchanged(self):
        """The parse jobs return their errors as values, a file job paired
        with its path."""
        from parsedmarc import parallel

        parallel._start_queue = None
        error = parsedmarc.InvalidDMARCReport("not a report")
        parallel._run_timed_job(_echo_job, 3, ("reports/a.xml", error), self.result_dir)
        path, value = parallel._take_outcome(self.result_dir, 3)
        self.assertEqual(path, "reports/a.xml")
        self.assertIs(type(value), parsedmarc.InvalidDMARCReport)
        self.assertEqual(str(value), "not a report")

    def test_a_raised_exception_is_raised_again_by_the_reader(self):
        from parsedmarc import parallel

        parallel._start_queue = None
        parallel._run_timed_job(_raising_job, 4, "boom", self.result_dir)
        with self.assertRaises(ValueError) as caught:
            parallel._take_outcome(self.result_dir, 4)
        self.assertEqual(str(caught.exception), "boom")


class TestTimedJobThatRaises(unittest.TestCase):
    """A job that raises, rather than returning its error as a value, still
    raises out of ``parallel_map`` with a ``parse_timeout``, as it does
    without one, after its exception went through the result file."""

    def test_exception_is_raised_to_the_caller(self):
        with self.assertRaises(ValueError) as caught:
            list(
                parallel_map(
                    _raising_job,
                    ["boom"],
                    1,
                    parse_timeout=30.0,
                    timeout_result=_timeout_value,
                )
            )
        self.assertEqual(str(caught.exception), "boom")
        self.assertEqual(multiprocessing.active_children(), [])


class TestUnwritableTemporaryDirectory(unittest.TestCase):
    """With a ``parse_timeout`` the results travel through a temporary
    directory. When it cannot be created, or the workers cannot write in
    it, ``parallel_map`` raises a ``ParserError`` naming the cause, which
    the CLI logs, instead of a raw ``OSError``. Without a timeout no such
    directory is used."""

    _TEXT = "parse_timeout needs a writable temporary directory (TMPDIR)"

    def _timed_run(self):
        return list(
            parallel_map(
                _echo_job,
                [1, 2],
                1,
                parse_timeout=30.0,
                timeout_result=_timeout_value,
            )
        )

    def test_directory_that_cannot_be_created(self):
        refusal = PermissionError(13, "Permission denied", "/tmp/parsedmarc-x")
        with patch("parsedmarc.parallel.mkdtemp", side_effect=refusal):
            with self.assertRaises(parsedmarc.ParserError) as caught:
                self._timed_run()
            self.assertEqual(list(parallel_map(_echo_job, [1, 2], 1)), [1, 2])
        self.assertIn(self._TEXT, str(caught.exception))
        self.assertIn("Permission denied", str(caught.exception))
        self.assertIs(caught.exception.__cause__, refusal)

    def test_directory_the_workers_cannot_write(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root can write in a read-only directory")
        parent = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, parent, ignore_errors=True)
        read_only = os.path.join(parent, "read-only")
        os.mkdir(read_only, 0o500)
        # The pool removes the directory itself when it stops.
        self.addCleanup(lambda: os.path.isdir(read_only) and os.chmod(read_only, 0o700))
        with patch("parsedmarc.parallel.mkdtemp", return_value=read_only):
            with self.assertRaises(parsedmarc.ParserError) as caught:
                self._timed_run()
        self.assertIn(self._TEXT, str(caught.exception))
        self.assertIn("Permission denied", str(caught.exception))
        self.assertEqual(multiprocessing.active_children(), [])


def _unpicklable_job(value):
    """Return a lambda, which pickle cannot serialise, for ``None``, and
    ``value`` otherwise. Module-level so the job itself pickles."""
    if value is None:
        return lambda: None
    return value


class _NeedsTwoArguments(Exception):
    """An exception whose pickle does not load: pickling keeps only
    ``args`` (one item here), and loading calls the class with them."""

    def __init__(self, first, second):
        super().__init__(f"{first} {second}")


class TestOutcomesThatCannotBeHandedBack(unittest.TestCase):
    """An outcome the worker cannot pickle, or the parent cannot unpickle,
    becomes a ``ParserError`` saying so; the worker never sends it through
    the executor, whose message must stay short."""

    def test_unpicklable_result_raises_parser_error_and_the_pool_goes_on(self):
        from parsedmarc import utils
        from parsedmarc.parallel import _DeadlinePool

        initargs = (logging.WARNING, [], utils._get_ip_worker_state(), [])
        pool = _DeadlinePool(_unpicklable_job, 1, initargs)
        self.addCleanup(pool.close)
        pending = pool.submit(None)
        pending.future.result(timeout=budget(10))
        pool.settle(pending)
        with self.assertRaises(parsedmarc.ParserError) as caught:
            pending.future.result()
        self.assertIn("could not be handed back", str(caught.exception))
        # The pickler's own complaint about the lambda.
        self.assertIn("Can't get local object", str(caught.exception))

        following = pool.submit(5)
        following.future.result(timeout=budget(10))
        pool.settle(following)
        self.assertEqual(following.future.result(), 5)

    def test_result_file_that_does_not_load_raises_parser_error(self):
        from parsedmarc import parallel

        result_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, result_dir, ignore_errors=True)
        with open(parallel._result_path(result_dir, 9), "wb") as result_file:
            pickle.dump(("value", _NeedsTwoArguments("a", "b")), result_file)
        with self.assertRaises(parsedmarc.ParserError) as caught:
            parallel._take_outcome(result_dir, 9)
        self.assertIn("could not be handed back", str(caught.exception))
        self.assertIn("TypeError", str(caught.exception))


def _raising_job(message):
    """Raise ``ValueError(message)``. Module-level so it pickles."""
    raise ValueError(message)


class _ExecutorWithoutProcesses:
    """An executor without the private ``_processes`` and
    ``_executor_manager_thread`` attributes ``_kill_workers`` reads, as a
    Python version that dropped them would be. Records its shutdown."""

    def __init__(self):
        self.shutdowns = []

    def shutdown(self, wait=True, *, cancel_futures=False):
        self.shutdowns.append((wait, cancel_futures))


class TestKillWorkersWithoutProcesses(unittest.TestCase):
    """Without ``_processes`` the workers cannot be killed: ``_kill_workers``
    warns that they keep running, and still shuts the executor down without
    waiting and with its queued jobs cancelled."""

    def test_warns_and_shuts_down_without_waiting(self):
        from parsedmarc.log import logger as plog
        from parsedmarc.parallel import _kill_workers

        self.addCleanup(setattr, plog, "disabled", plog.disabled)
        plog.disabled = False
        executor = _ExecutorWithoutProcesses()
        with self.assertLogs("parsedmarc.log", level="WARNING") as logs:
            _kill_workers(executor)  # pyright: ignore[reportArgumentType]
        self.assertIn("Cannot stop the worker processes", "\n".join(logs.output))
        self.assertEqual(executor.shutdowns, [(False, True)])


class TestPlainPoolHeartbeat(unittest.TestCase):
    """Without a ``parse_timeout``, a ``heartbeat`` is still called every
    ``heartbeat_interval`` seconds while the parent waits for a slow job."""

    def test_heartbeat_is_called_while_a_plain_job_runs(self):
        calls = []
        start = time.monotonic()
        results = list(
            parallel_map(
                _sleep_job,
                [0.5],
                1,
                heartbeat=lambda: calls.append(time.monotonic()),
                heartbeat_interval=0.1,
            )
        )
        self.assertEqual(results, [0.5])
        self.assertGreaterEqual(len(calls), 2)
        # One pool start and the 0.5 s job; no heartbeat may hold it up.
        self.assertLess(time.monotonic() - start, budget(3))


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


def _start_queue_unset_job(seconds):
    """Sleep ``seconds``, then report whether the worker has no start queue,
    which only a pool built for a ``parse_timeout`` gives it. Module-level
    so it pickles."""
    from parsedmarc import parallel

    time.sleep(seconds)
    return parallel._start_queue is None


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

    def _run(self, jobs, n_procs, job=_sleep_job, **kwargs):
        kwargs.setdefault("parse_timeout", _TIMEOUT)
        kwargs.setdefault("timeout_result", _timeout_value)
        start = time.monotonic()
        results = list(parallel_map(job, jobs, n_procs, **kwargs))
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
        """With parse_timeout 0 a job runs in the plain pool, whose workers
        never get a start queue, and finishes; the same probe under a
        timeout reads the queue, so it can tell the two pools apart."""
        results, elapsed = self._run(
            [0.3], n_procs=1, job=_start_queue_unset_job, parse_timeout=0.0
        )
        self.assertEqual(results, [True])
        self.assertGreaterEqual(elapsed, 0.3)
        results, _ = self._run(
            [0.3], n_procs=1, job=_start_queue_unset_job, parse_timeout=30.0
        )
        self.assertEqual(results, [False])

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

    def test_closing_the_iterator_kills_the_pool(self):
        """A caller that stops reading and closes the iterator ends the run
        at once: the workers still running a slow job are killed instead
        of waited for, and the pool's start queue is closed."""
        from parsedmarc.parallel import _DeadlinePool

        start_queues = []
        new_executor = _DeadlinePool._new_executor

        def recording_new_executor(pool):
            executor, start_queue, result_dir = new_executor(pool)
            start_queues.append(start_queue)
            return executor, start_queue, result_dir

        before = set(multiprocessing.active_children())
        with patch.object(_DeadlinePool, "_new_executor", recording_new_executor):
            results = parallel_map(
                _sleep_job,
                [0.0, _SLOW, _SLOW],
                2,
                parse_timeout=30.0,
                timeout_result=_timeout_value,
            )
            # parallel_map is typed to return an Iterator; it is a generator.
            assert isinstance(results, types.GeneratorType)
            self.assertEqual(next(results), 0.0)
            start = time.monotonic()
            results.close()
        self.assertLess(time.monotonic() - start, budget(3))
        self.assertLessEqual(set(multiprocessing.active_children()), before)
        self.assertEqual(len(start_queues), 1)
        self.assertTrue(start_queues[0]._reader.closed)
        self.assertTrue(start_queues[0]._writer.closed)


class TestPlainPoolEarlyExit(unittest.TestCase):
    """Without a ``parse_timeout`` the pool is a plain
    ``ProcessPoolExecutor``, whose ``with`` block waits for every job in the
    window on the way out. Workers ignore SIGINT, so a caller that leaves
    early (a ``KeyboardInterrupt``, closing the iterator) would wait for the
    whole window; the workers are killed instead."""

    def test_closing_the_iterator_kills_the_workers(self):
        """Before the fix the close waited for both slow jobs, 5.0 s on the
        workstation."""
        before = set(multiprocessing.active_children())
        results = parallel_map(_sleep_job, [0.0, _SLOW, _SLOW], 2)
        # parallel_map is typed to return an Iterator; it is a generator.
        assert isinstance(results, types.GeneratorType)
        self.assertEqual(next(results), 0.0)
        start = time.monotonic()
        results.close()
        self.assertLess(time.monotonic() - start, budget(3))
        self.assertLessEqual(set(multiprocessing.active_children()), before)


class TestStartTokensAreDrained(unittest.TestCase):
    """With a ``parse_timeout`` the pool maps each job's start token to its
    entry, input included, until the parent reads the token. When results
    are already done at harvest time the parent never waits, so the tokens
    must still be read every round, or the map keeps every finished job's
    input and outgrows the submission window."""

    def test_token_map_stays_within_the_window(self):
        """The caller pauses after each result, so every later result is
        done before it is harvested. Bound: the window, plus the job just
        harvested, whose token may arrive after the last read. Before the
        fix the map held every job of the run (200 entries for 200 jobs)."""
        from parsedmarc.parallel import _DeadlinePool

        sizes = []
        resubmit = _DeadlinePool.resubmit

        def recording_resubmit(pool, pending):
            resubmit(pool, pending)
            sizes.append(len(pool._by_token))

        n_procs = 2
        window_size = 2 * n_procs
        results = []
        with patch.object(_DeadlinePool, "resubmit", recording_resubmit):
            for result in parallel_map(
                _echo_job,
                range(200),
                n_procs,
                parse_timeout=5.0,
                timeout_result=_timeout_value,
            ):
                results.append(result)
                time.sleep(0.005)
        self.assertEqual(results, list(range(200)))
        self.assertEqual(len(sizes), 200)
        self.assertLessEqual(max(sizes), window_size + 1)


def _slow_or_large_job(job):
    """``("sleep", seconds)`` sleeps and returns ``seconds``. ``("slow",
    marker)`` writes the time it started to the file ``marker`` and sleeps
    for a minute. ``("large", marker, offset, size)`` waits for ``marker``
    and returns ``size`` bytes ``offset`` seconds after the time in it, so
    that handing them back spans the moment the slow job's timeout kills
    the workers. Module-level so it pickles."""
    if job[0] == "sleep":
        time.sleep(job[1])
        return job[1]
    if job[0] == "slow":
        with open(job[1] + ".tmp", "w") as marker:
            marker.write(repr(time.time()))
        os.replace(job[1] + ".tmp", job[1])
        time.sleep(60)
        return None
    _, marker_path, offset, size = job
    deadline = time.monotonic() + 30
    while not os.path.exists(marker_path) and time.monotonic() < deadline:
        time.sleep(0.005)
    with open(marker_path) as marker:
        slow_started = float(marker.read())
    payload = b"x" * size
    time.sleep(max(0.0, slow_started + offset - time.time()))
    return payload


def _kill_during_large_result_jobs(marker_path, size):
    """The jobs of a run in which a 0.5 s ``parse_timeout`` kills the
    workers while the large job hands back its result. The large job runs
    after a short one, so it has run only about 0.2 s when the slow job
    expires and is not itself overdue; it returns 0.4 s after the slow job
    started, and pickling and sending its result take longer than the
    remaining 0.1 s."""
    return [("slow", marker_path), ("sleep", 0.3), ("large", marker_path, 0.4, size)]


# Run by TestKillDuringResultTransmission in a child interpreter. The start
# method, a marker file path and the result size are the arguments.
_KILL_DURING_LARGE_RESULT_SCRIPT = """
import multiprocessing
import sys

from parsedmarc.parallel import parallel_map
from tests.test_parallel import (
    _kill_during_large_result_jobs, _slow_or_large_job, _timeout_value,
)

if __name__ == "__main__":
    multiprocessing.set_start_method(sys.argv[1], force=True)
    size = int(sys.argv[3])
    jobs = _kill_during_large_result_jobs(sys.argv[2], size)
    results = list(
        parallel_map(
            _slow_or_large_job, jobs, 2, parse_timeout=0.5,
            timeout_result=_timeout_value,
        )
    )
    assert results[:2] == [_timeout_value(jobs[0], 0.5), 0.3], results[:2]
    assert len(results[2]) == size
    print("done", flush=True)
"""


class TestKillDuringResultTransmission(unittest.TestCase):
    """A timeout kills every worker, so it can kill one while it hands back
    a large result. Sent through the executor's own pipe, the cut-off result
    left the executor's management thread waiting for the rest forever, and
    the interpreter then hung at exit joining that thread. Results now
    travel through files, and every start method is tried."""

    def _start_methods(self):
        original_method = multiprocessing.get_start_method()
        self.addCleanup(multiprocessing.set_start_method, original_method, force=True)
        return [
            m
            for m in ("fork", "forkserver", "spawn")
            if m in multiprocessing.get_all_start_methods()
        ]

    def test_large_result_survives_a_neighbour_timeout(self):
        from parsedmarc import parallel

        size = 128 * 1024 * 1024
        managers = []
        kill_workers = parallel._kill_workers

        def recording_kill_workers(executor):
            manager = getattr(executor, "_executor_manager_thread", None)
            kill_workers(executor)
            managers.append(manager)

        for method in self._start_methods():
            with self.subTest(start_method=method):
                multiprocessing.set_start_method(method, force=True)
                managers.clear()
                marker_dir = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, marker_dir, ignore_errors=True)
                marker_path = os.path.join(marker_dir, "slow-started")
                jobs = _kill_during_large_result_jobs(marker_path, size)
                start = time.monotonic()
                with patch.object(parallel, "_kill_workers", recording_kill_workers):
                    results = list(
                        parallel_map(
                            _slow_or_large_job,
                            jobs,
                            2,
                            parse_timeout=0.5,
                            timeout_result=_timeout_value,
                        )
                    )
                # A timeout, at most one re-run of the large job and two pool
                # starts; the slow job alone would take a minute.
                self.assertLess(time.monotonic() - start, budget(10))
                self.assertEqual(results[:2], [_timeout_value(jobs[0], 0.5), 0.3])
                large = results[2]
                assert isinstance(large, bytes)
                self.assertEqual(len(large), size)
                self.assertEqual(large.count(b"x"), size)
                self.assertGreaterEqual(len(managers), 1)
                for manager in managers:
                    self.assertFalse(manager is not None and manager.is_alive())
                self.assertEqual(multiprocessing.active_children(), [])

    def test_interpreter_exits_after_a_kill_during_a_large_result(self):
        """Before the fix the child interpreter never exited (killed after
        25 s on the workstation, with a 400 MiB result)."""
        import subprocess
        import sys

        for method in self._start_methods():
            with self.subTest(start_method=method):
                marker_dir = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, marker_dir, ignore_errors=True)
                limit = budget(30)
                start = time.monotonic()
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        _KILL_DURING_LARGE_RESULT_SCRIPT,
                        method,
                        os.path.join(marker_dir, "slow-started"),
                        str(256 * 1024 * 1024),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=limit,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), "done")
                self.assertLess(time.monotonic() - start, limit)


class TestResultFilesAreRemoved(unittest.TestCase):
    """The pool built for a timeout keeps results in a directory of its
    own, removed with every file left in it when the pool is closed or
    killed."""

    def _pool(self):
        from parsedmarc import utils
        from parsedmarc.parallel import _DeadlinePool

        initargs = (logging.WARNING, [], utils._get_ip_worker_state(), [])
        return _DeadlinePool(_sleep_job, 1, initargs)

    def test_close_removes_the_result_directory(self):
        pool = self._pool()
        pending = pool.submit(0.0)
        pending.future.result(timeout=budget(10))
        result_dir = pool.result_dir
        self.assertEqual(os.listdir(result_dir), ["0"])
        pool.close()
        self.assertFalse(os.path.exists(result_dir))

    def test_kill_removes_the_result_directory_and_its_files(self):
        pool = self._pool()
        pool.submit(0.0).future.result(timeout=budget(10))
        pool.submit(_SLOW)
        result_dir = pool.result_dir
        self.assertEqual(os.listdir(result_dir), ["0"])
        pool.kill()
        self.assertFalse(os.path.exists(result_dir))
        self.assertEqual(multiprocessing.active_children(), [])


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

    def test_ctrl_c_lets_the_running_jobs_finish_under_every_start_method(self):
        """A terminal sends Ctrl-C's SIGINT to every process in its
        foreground process group, the workers included. The parent's handler
        (here, as in the CLI, one that only notes the signal) lets the batch
        finish, so the workers must survive the signal too; with the default
        action each worker died and the run ended in ``BrokenProcessPool``.
        Each job writes its worker's pid as it starts, and the signal goes
        out once every worker has one, so a spawned worker's initializer has
        run. The test signals the parent and each worker itself rather than
        its whole process group, which holds the test runner too."""
        import signal
        import threading

        n_procs = 2
        received = []
        self.addCleanup(signal.signal, signal.SIGINT, signal.getsignal(signal.SIGINT))
        signal.signal(signal.SIGINT, lambda signum, frame: received.append(signum))
        original_method = multiprocessing.get_start_method()
        self.addCleanup(multiprocessing.set_start_method, original_method, force=True)
        available = multiprocessing.get_all_start_methods()

        for method in ("fork", "forkserver", "spawn"):
            for kwargs in (
                {},
                {"parse_timeout": 30.0, "timeout_result": _timeout_value},
            ):
                with self.subTest(start_method=method, **kwargs):
                    if method not in available:
                        self.skipTest(f"the {method} start method is not available")
                    multiprocessing.set_start_method(method, force=True)
                    received.clear()
                    pid_dir = tempfile.mkdtemp()
                    self.addCleanup(shutil.rmtree, pid_dir, ignore_errors=True)
                    signalled = []

                    def interrupt(pid_dir=pid_dir, signalled=signalled):
                        deadline = time.monotonic() + 30.0
                        pids = []
                        while time.monotonic() < deadline:
                            pids = os.listdir(pid_dir)
                            if len(pids) >= n_procs:
                                break
                            time.sleep(0.05)
                        for pid in pids:
                            os.kill(int(pid), signal.SIGINT)
                            signalled.append(pid)
                        os.kill(os.getpid(), signal.SIGINT)

                    timer = threading.Thread(target=interrupt)
                    timer.start()
                    jobs = [(pid_dir, 2.0)] * n_procs
                    try:
                        results = list(
                            parallel_map(
                                _pid_marking_sleep_job, jobs, n_procs, **kwargs
                            )
                        )
                    except KeyboardInterrupt:
                        # A worker that took the signal returns its
                        # KeyboardInterrupt as the job's outcome.
                        results = ["KeyboardInterrupt in a worker"]
                    finally:
                        timer.join()
                    self.assertEqual(len(set(signalled)), n_procs)
                    self.assertEqual(results, [2.0] * n_procs)
                    self.assertEqual(received, [signal.SIGINT])


def _pid_marking_sleep_job(job):
    """Write this worker's pid as a file name under ``job[0]``, then sleep
    ``job[1]`` seconds and return it. Module-level so it pickles."""
    pid_dir, seconds = job
    with open(os.path.join(pid_dir, str(os.getpid())), "w"):
        pass
    time.sleep(seconds)
    return seconds


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


class _BrokenStr(Exception):
    def __str__(self) -> str:
        raise RuntimeError("no text")


class TestShortErrorText(unittest.TestCase):
    """The error text a worker hands back fits the pipe's atomic-write bound."""

    def test_cap_is_in_bytes_not_characters(self):
        text = _short_error_text(ValueError("\u00e9" * 300))
        self.assertLessEqual(len(text.encode("utf-8")), _MAX_ERROR_TEXT)
        self.assertTrue(text.startswith("ValueError: \u00e9"))

    def test_broken_str_falls_back_to_the_type_name(self):
        self.assertEqual(_short_error_text(_BrokenStr()), "_BrokenStr")
