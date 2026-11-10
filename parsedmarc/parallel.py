"""Bounded-window multiprocessing helpers for parallel report parsing."""

from __future__ import annotations

import itertools
import logging
import math
import multiprocessing
import signal
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from multiprocessing.context import BaseContext
    from multiprocessing.queues import SimpleQueue

    from parsedmarc import ParserError
    from parsedmarc.config import ParserConfig
    from parsedmarc.types import ParsedReport

_J = TypeVar("_J")
_R = TypeVar("_R")

# How long to wait for a killed worker process, and for the executor's
# management thread, to exit after a timed-out job's pool is torn down.
_KILL_JOIN_SECONDS = 5.0

# Set in each worker of a pool built for a parse_timeout, by
# _init_timed_worker(); _run_timed_job() writes a job's token to it as the
# job starts, so the parent can start that job's clock.
_start_queue: SimpleQueue[int] | None = None


def _init_worker(
    log_level: int,
    log_files: list[str],
    ip_worker_state: tuple[str | None, str | None],
    psl_overrides: list[str],
) -> None:
    """Pool initializer that reconstructs the parent's lookup context.

    A spawned or forkserver worker process does not inherit the parent
    process's already-configured logging handlers, so without this the
    child's log records (including any that would surface a parsing bug)
    are silently dropped. It also does not inherit the parent's IP-lookup
    globals (``parsedmarc.utils._IPINFO_API_TOKEN`` and
    ``parsedmarc.utils._IP_DB_PATH`` — under these start methods the child
    "will only inherit those resources necessary to run the process
    object's ``run()`` method",
    https://docs.python.org/3/library/multiprocessing.html), so its IP
    enrichment would silently fall back to the bundled MMDB and skip the
    IPinfo API; the snapshot captured by the parent is restored here.

    The module-level ``parsedmarc.utils.psl_overrides`` list is restored
    too. A fresh worker loads the bundled ``psl_overrides.txt`` when it
    imports ``parsedmarc.utils``. Its reverse DNS map starts empty
    (``ParserConfig.__setstate__`` rebinds it to the module default), and
    its first map load calls ``load_psl_overrides()`` with the config's
    ``psl_overrides_path``/``psl_overrides_url``, so the operator's
    overrides do take effect, but only after that load: ``get_base_domain()``
    calls made before that load (the first aggregate report's ``org_name``
    and the first source IP's reverse DNS name) would use the bundled list.
    It is restored in place (``[:] =``), never rebound, because
    ``load_psl_overrides()``, ``get_base_domain()``, and
    ``cli._restore_utils_globals()`` all share that one list object.

    These are the same three globals ``cli._utils_globals_snapshot()``
    enumerates for SIGHUP reload; keep the lists in sync.

    Called once per worker process by ``ProcessPoolExecutor``'s
    ``initializer``/``initargs``.
    """
    from parsedmarc import utils
    from parsedmarc.log import configure_logging

    # Under fork a worker inherits the parent's signal handlers, and the CLI
    # installs SIGTERM and SIGINT handlers that only set a flag. A worker
    # running them ignores the SIGTERM ProcessPoolExecutor sends when it
    # tears down a broken pool, and the teardown then waits for it forever,
    # so SIGTERM gets its default action. Ctrl-C sends SIGINT to the whole
    # process group, workers included, under every start method; the parent
    # decides how to shut down and lets the batch in progress finish, so
    # workers ignore SIGINT. Under spawn or forkserver a Ctrl-C that lands
    # before this line has run still kills the worker, which then ends the
    # batch as a worker that died does.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    utils._set_ip_worker_state(*ip_worker_state)
    utils.psl_overrides[:] = psl_overrides

    if not log_files:
        configure_logging(log_level, None)
        return
    for log_file in log_files:
        configure_logging(log_level, log_file)


def _init_timed_worker(start_queue: SimpleQueue[int], *initargs: Any) -> None:
    """Pool initializer for a pool whose jobs have a ``parse_timeout``.

    Keeps ``start_queue`` for ``_run_timed_job()`` and then runs
    ``_init_worker(*initargs)``.
    """
    global _start_queue
    _start_queue = start_queue
    _init_worker(*initargs)


def _run_timed_job(func: Callable[[_J], _R], token: int, job: _J) -> _R:
    """Worker job that reports ``token`` as started, then returns ``func(job)``.

    The parent cannot tell from the future alone when a job starts:
    ``ProcessPoolExecutor`` marks a future running when it moves the job to
    its call queue, which holds one job more than there are workers, so one
    job can be "running" while it still waits behind a slow neighbour. The
    token written here, before ``func`` runs, is what starts the job's clock.
    """
    if _start_queue is not None:
        _start_queue.put(token)
    return func(job)


def _email_timeout_result(msg_content: bytes | str, seconds: float) -> ParserError:
    """Return the ``_parse_report_email_job`` value for a timed-out message.

    Passed to ``parallel_map()`` as ``timeout_result``. The value is a
    ``ParseTimeoutError``, an ``InvalidDMARCReport``, so the mbox loop warns
    and continues and the mailbox loop files the message under ``Invalid``,
    as for any other message that cannot be parsed.
    """
    from parsedmarc import ParseTimeoutError

    return ParseTimeoutError(
        f"Parsing the message took longer than parse_timeout "
        f"({seconds:g} seconds) and was stopped"
    )


def _file_timeout_result(file_path: str, seconds: float) -> tuple[str, Exception]:
    """Return the ``_parse_report_file_job`` value for a timed-out file.

    Passed to ``parallel_map()`` as ``timeout_result``. The value pairs
    ``file_path`` with a ``ParseTimeoutError``, a ``ParserError``, so the CLI
    logs the failure and, with ``archive_directory`` set, moves the file to
    ``Invalid``.
    """
    from parsedmarc import ParseTimeoutError

    return file_path, ParseTimeoutError(
        f"Parsing took longer than parse_timeout ({seconds:g} seconds) and was stopped"
    )


def _parse_report_email_job(
    msg_content: bytes | str, *, config: ParserConfig
) -> ParsedReport | ParserError:
    """Worker job that parses a single report email.

    Module-level and picklable so it can run in a ``ProcessPoolExecutor``
    worker. ``config`` is forwarded to ``parse_report_email``. The config's
    caches (``ip_address_cache``, ``seen_aggregate_report_ids``,
    ``reverse_dns_map``) never cross the process boundary -
    ``ParserConfig.__getstate__`` drops them, and each worker accumulates
    its own via the module defaults it rebinds to on unpickling (see
    ``ParserConfig.__setstate__``). ``keep_alive`` is not a ``ParserConfig``
    field - it is a bound method of the live mailbox connection in the
    parent process and is not picklable - so nothing unpicklable is ever
    submitted to the pool.

    Returns the parsed report on success. A ``ParserError`` raised by
    ``parse_report_email`` is caught and returned as a value (never
    re-raised) so that a single invalid message doesn't need special
    handling on the submission side. ``parse_report_email`` raises only
    ``ParserError`` subclasses, whatever the input, so no other exception
    is expected to propagate from here.
    """
    from parsedmarc import ParserError, parse_report_email

    try:
        return parse_report_email(msg_content, config=config)
    except ParserError as e:
        return e


def _parse_report_file_job(
    file_path: str, *, config: ParserConfig
) -> tuple[str, ParsedReport | Exception]:
    """Worker job that parses a single report file.

    Module-level and picklable so it can run in a ``ProcessPoolExecutor``
    worker. ``config`` is forwarded to ``parse_report_file``.

    Catches any ``Exception`` (not just ``ParserError``) and returns it
    paired with ``file_path`` rather than letting it propagate. This is a
    deliberate behavior change from the old hand-rolled
    ``Pipe``/``Process`` CLI worker, where a non-``ParserError`` exception
    in the child crashed the child without sending anything back over the
    pipe, leaving the parent blocked forever on ``conn.recv()``. Returning
    the exception as a value lets the caller log it and move on.
    """
    from parsedmarc import parse_report_file

    try:
        return file_path, parse_report_file(file_path, config=config)
    except Exception as e:
        return file_path, e


def _check_parse_timeout(parse_timeout: float) -> None:
    """Raise ``ValueError`` unless ``parse_timeout`` is finite and >= 0."""
    if not math.isfinite(parse_timeout) or parse_timeout < 0:
        raise ValueError(
            f"parse_timeout must be a finite number of seconds >= 0, "
            f"got {parse_timeout!r}"
        )


class _Pending(Generic[_J, _R]):
    """One job in ``parallel_map()``'s submission window under a timeout.

    ``started_at`` is the ``time.monotonic()`` time at which the parent
    learned that the job started, ``None`` until then. ``future`` is
    replaced when the job is resubmitted to a new pool, and by an already
    resolved future holding the ``timeout_result`` value when it times out.
    """

    __slots__ = ("future", "job", "started_at", "token")

    def __init__(self, job: _J, token: int, future: Future[_R]) -> None:
        self.job = job
        self.token = token
        self.future = future
        self.started_at: float | None = None


class _DeadlinePool(Generic[_J, _R]):
    """A process pool whose jobs report when they start, and can be killed.

    Each job runs through ``_run_timed_job()``, which writes the job's token
    to a queue the parent reads in ``stamp_starts()``. ``replace()`` kills
    every worker process and builds a fresh pool with a fresh queue, since a
    worker killed while writing to the old queue may leave it unusable.
    """

    def __init__(
        self,
        func: Callable[[_J], _R],
        n_procs: int,
        initargs: tuple[Any, ...],
    ) -> None:
        self._func = func
        self._n_procs = n_procs
        self._initargs = initargs
        self._tokens = itertools.count()
        self._by_token: dict[int, _Pending[_J, _R]] = {}
        self._context: BaseContext = multiprocessing.get_context()
        self._executor, self._start_queue = self._new_executor()

    def _new_executor(self) -> tuple[ProcessPoolExecutor, SimpleQueue[int]]:
        start_queue: SimpleQueue[int] = self._context.SimpleQueue()
        executor = ProcessPoolExecutor(
            max_workers=self._n_procs,
            mp_context=self._context,
            initializer=_init_timed_worker,
            initargs=(start_queue, *self._initargs),
        )
        return executor, start_queue

    def submit(self, job: _J) -> _Pending[_J, _R]:
        """Submit ``job`` and return its new, not yet started, entry."""
        pending: _Pending[_J, _R] = _Pending(job, -1, Future())
        self.resubmit(pending)
        return pending

    def resubmit(self, pending: _Pending[_J, _R]) -> None:
        """Submit ``pending``'s job to the current pool, with a new token."""
        pending.token = next(self._tokens)
        pending.started_at = None
        pending.future = self._executor.submit(
            _run_timed_job, self._func, pending.token, pending.job
        )
        self._by_token[pending.token] = pending

    def stamp_starts(self, now: float) -> None:
        """Set ``started_at`` to ``now`` on each job that has reported starting."""
        while not self._start_queue.empty():
            pending = self._by_token.pop(self._start_queue.get(), None)
            if pending is not None:
                pending.started_at = now

    def kill(self) -> None:
        """Kill the worker processes, as ``_kill_workers()`` does, and close
        the start queue."""
        _kill_workers(self._executor)
        self._start_queue.close()
        self._by_token.clear()

    def replace(self) -> None:
        """Kill this pool's workers and continue with a fresh pool."""
        self.kill()
        self._executor, self._start_queue = self._new_executor()

    def close(self) -> None:
        """Shut the pool down once every job has finished."""
        self._executor.shutdown(wait=True)
        self._start_queue.close()
        self._by_token.clear()


def _kill_workers(executor: ProcessPoolExecutor) -> None:
    """Kill ``executor``'s worker processes and wait, boundedly, for them.

    ``ProcessPoolExecutor`` has no public way to stop a running job, and
    ``shutdown()`` waits for it or, with ``wait=False``, leaves it running,
    so the workers are read from ``_processes``, a private attribute present
    in every supported Python version. Without it the workers are left to
    finish on their own and a warning says so.
    """
    from parsedmarc.log import logger

    processes = getattr(executor, "_processes", None)
    manager_thread = getattr(executor, "_executor_manager_thread", None)
    if processes is None:
        logger.warning(
            "Cannot stop the worker processes of a parsing pool on this "
            "Python version; they keep running until they finish"
        )
        workers = []
    else:
        workers = list(processes.values())
    for worker in workers:
        worker.kill()
    executor.shutdown(wait=False, cancel_futures=True)
    for worker in workers:
        worker.join(_KILL_JOIN_SECONDS)
    if manager_thread is not None:
        manager_thread.join(_KILL_JOIN_SECONDS)


def _worker_died_error() -> ParserError:
    """Return the error ``parallel_map()`` raises when a worker dies."""
    from parsedmarc import ParserError

    return ParserError(
        "A parsing worker process died (killed, out of memory, or crashed); "
        "the rest of this batch was not parsed"
    )


def _resolved(value: _R) -> Future[_R]:
    future: Future[_R] = Future()
    future.set_result(value)
    return future


def _expire_overdue(
    pool: _DeadlinePool[_J, _R],
    window: deque[_Pending[_J, _R]],
    now: float,
    parse_timeout: float,
    timeout_result: Callable[[_J, float], _R],
) -> bool:
    """Stop every job in ``window`` running for ``parse_timeout`` or longer.

    Returns ``False`` when no job is overdue. Otherwise logs one warning per
    overdue job, records which futures are already done (killing the pool
    gives every other future ``BrokenProcessPool``), replaces the pool, and
    then, in window order, keeps each done job's result, gives each overdue
    job ``timeout_result(job, parse_timeout)``, and resubmits every other
    job from scratch. Returns ``True``.
    """
    from parsedmarc.log import logger

    done = [pending.future.done() for pending in window]
    overdue = [
        not finished
        and pending.started_at is not None
        and now - pending.started_at >= parse_timeout
        for pending, finished in zip(window, done)
    ]
    if not any(overdue):
        return False
    for _ in range(sum(overdue)):
        logger.warning(
            f"A parsing job ran longer than parse_timeout ({parse_timeout:g} "
            f"seconds) and was stopped; restarting the worker processes"
        )
    pool.replace()
    for pending, finished, expired in zip(window, done, overdue):
        if finished:
            continue
        if expired:
            pending.started_at = None
            pending.future = _resolved(timeout_result(pending.job, parse_timeout))
        else:
            pool.resubmit(pending)
    return True


def _map_with_timeout(
    func: Callable[[_J], _R],
    first_job: _J,
    jobs_iter: Iterator[_J],
    n_procs: int,
    window_size: int,
    initargs: tuple[Any, ...],
    parse_timeout: float,
    timeout_result: Callable[[_J, float], _R],
    heartbeat: Callable[[], None] | None,
    heartbeat_interval: float,
    should_stop: Callable[[], bool] | None,
) -> Iterator[_R]:
    """``parallel_map()``'s loop when ``parse_timeout`` is set.

    While it waits for a result, the parent wakes at least every
    ``min(1.0, parse_timeout / 10, heartbeat_interval)`` seconds (the wait
    slice), sooner when a deadline or heartbeat falls due, and expires
    overdue jobs with
    ``_expire_overdue()``. A ``should_stop`` stop cancels the jobs that have
    not been handed to a worker and still waits for the others, which are
    themselves bounded by the timeout. Leaving early (an exception, or the
    caller closing the iterator) kills the pool instead of waiting for it.
    """
    wait_slice = min(1.0, parse_timeout / 10)
    if heartbeat is not None:
        wait_slice = min(wait_slice, heartbeat_interval)
    pool: _DeadlinePool[_J, _R] = _DeadlinePool(func, n_procs, initargs)
    finished = False
    try:
        window: deque[_Pending[_J, _R]] = deque([pool.submit(first_job)])
        while len(window) < window_size:
            try:
                window.append(pool.submit(next(jobs_iter)))
            except StopIteration:
                break

        # Absolute, so rebuilding a pool never postpones a heartbeat.
        next_heartbeat_at = time.monotonic() + heartbeat_interval
        stopping = False
        while window:
            # Drained here as well as while waiting: when results are already
            # done at harvest time the inner loop never runs, and the
            # undrained tokens would keep each finished job (its whole input)
            # in the pool's token map.
            pool.stamp_starts(time.monotonic())
            oldest = window[0]
            while not oldest.future.done():
                now = time.monotonic()
                pool.stamp_starts(now)
                if heartbeat is not None and now >= next_heartbeat_at:
                    heartbeat()
                    now = time.monotonic()
                    next_heartbeat_at = now + heartbeat_interval
                if _expire_overdue(pool, window, now, parse_timeout, timeout_result):
                    continue
                limit = wait_slice
                started = [
                    pending.started_at
                    for pending in window
                    if pending.started_at is not None and not pending.future.done()
                ]
                if started:
                    limit = min(limit, min(started) + parse_timeout - now)
                if heartbeat is not None:
                    limit = min(limit, next_heartbeat_at - now)
                wait([oldest.future], timeout=max(limit, 0.0))

            window.popleft()
            yield oldest.future.result()

            if not stopping and should_stop is not None and should_stop():
                stopping = True
                for pending in window:
                    pending.future.cancel()
                window = deque(p for p in window if not p.future.cancelled())
            if stopping:
                continue
            try:
                window.append(pool.submit(next(jobs_iter)))
            except StopIteration:
                continue
        finished = True
    finally:
        if finished:
            pool.close()
        else:
            pool.kill()


def parallel_map(
    func: Callable[[_J], _R],
    jobs: Iterable[_J],
    n_procs: int,
    *,
    window_factor: int = 2,
    heartbeat: Callable[[], None] | None = None,
    heartbeat_interval: float = 30.0,
    should_stop: Callable[[], bool] | None = None,
    parse_timeout: float = 0.0,
    timeout_result: Callable[[_J, float], _R] | None = None,
) -> Iterator[_R]:
    """Map ``func`` over ``jobs`` using a bounded-window process pool.

    ``jobs`` is iterated lazily and is never materialized into a list, so
    this is safe to call with a generator over a very large input (e.g. a
    20,000 message mbox). At most ``window_factor * n_procs`` jobs are
    submitted ahead of the harvesting point at any time, which bounds
    memory use and lets the caller's job-producing generator itself stay
    lazy (e.g. fetching mailbox messages just-in-time).

    Results are yielded in submission order (i.e. the same order as
    ``jobs``), not completion order, so callers can rely on index-based
    bookkeeping against the original input.

    If ``jobs`` is empty, returns without spawning a process pool.

    If ``heartbeat`` is given, it is called after every
    ``heartbeat_interval`` seconds spent waiting on the oldest
    outstanding future (e.g. to keep an IMAP connection alive while a
    large report is being parsed). If ``heartbeat`` is ``None``, results
    are awaited with a plain blocking ``future.result()`` call.

    If ``should_stop`` is given, it is checked after each yielded result;
    if it returns ``True``, the pool is shut down with
    ``cancel_futures=True``: jobs still queued in the submission window
    that have not started are cancelled and their results dropped, while
    jobs already running (or finished) are waited on and their results
    yielded before returning - no completed work is discarded, but the
    stop may block briefly until in-flight jobs finish.

    Because ``spawn``/``forkserver`` workers do not inherit the parent's
    process-global lookup state, the parent's
    ``parsedmarc.utils._IPINFO_API_TOKEN``, ``_IP_DB_PATH``, and
    ``psl_overrides`` are snapshotted here, once per pool, and restored in
    every worker by the pool initializer, so IP enrichment and base-domain
    lookups match what the parent configured under every start method.

    If ``parse_timeout`` is greater than zero, a job that runs that many
    seconds is stopped and ``timeout_result(job, parse_timeout)`` is
    yielded in its place, in its position. ``ProcessPoolExecutor`` cannot
    stop one job, so every worker process is killed and a fresh pool is
    started; the other unfinished jobs in the window start again from
    scratch, and finished results are kept. A job's clock starts when its
    worker reports that it began, so a job waiting behind a slow
    neighbour is not charged for the wait. The parent checks the clocks
    only while it waits for a result, at least every ``min(1.0,
    parse_timeout / 10, heartbeat_interval)`` seconds (the wait slice), so
    a job is stopped within one wait slice after the parent next waits for
    a result; time the caller spends between results is not counted, and a
    job can run past its timeout during it. One timeout costs
    ``parse_timeout``, up to one wait slice and one pool start, plus a
    re-run of the neighbours that were still running. A neighbour that is
    itself a slow job loses its partial run and starts again, so P jobs
    that all time out cost at most ``(ceil(P / n_procs) + 1) *
    (parse_timeout + wait slice + pool start)``, plus, for each expiry, up
    to ``(n_procs + 1) * _KILL_JOIN_SECONDS`` spent joining the killed
    workers and the pool's management thread, during which no heartbeat is
    sent. With
    ``parse_timeout`` set, ``should_stop`` cancels the jobs not yet handed
    to a worker and waits for the rest, each still bounded by the timeout.
    With ``parse_timeout`` at 0 (the default) jobs have no time limit.

    Raises:
        ValueError: If ``n_procs`` is less than 1, if ``parse_timeout`` is
            negative or not finite, or if ``parse_timeout`` is set without
            ``timeout_result``. Raised eagerly at the call itself (not on
            first iteration of the returned iterator).
        ParserError: While iterating, if a worker process dies (the
            out-of-memory killer, a crash), which breaks the pool and loses
            every unfinished job. The other workers are killed first; the
            ``BrokenProcessPool`` is the error's cause.
    """
    if n_procs < 1:
        raise ValueError(f"n_procs must be at least 1, got {n_procs}")
    _check_parse_timeout(parse_timeout)
    if parse_timeout and timeout_result is None:
        raise ValueError("parse_timeout requires a timeout_result")

    def _generate() -> Iterator[_R]:
        jobs_iter = iter(jobs)
        try:
            first_job = next(jobs_iter)
        except StopIteration:
            return

        from parsedmarc import utils
        from parsedmarc.log import logger

        log_level = logger.getEffectiveLevel()
        log_files = [
            h.baseFilename
            for h in logger.handlers
            if isinstance(h, logging.FileHandler)
        ]
        ip_worker_state = utils._get_ip_worker_state()
        psl_overrides = list(utils.psl_overrides)
        initargs = (log_level, log_files, ip_worker_state, psl_overrides)

        window_size = max(window_factor * n_procs, 1)

        try:
            if parse_timeout and timeout_result is not None:
                yield from _map_with_timeout(
                    func,
                    first_job,
                    jobs_iter,
                    n_procs,
                    window_size,
                    initargs,
                    parse_timeout,
                    timeout_result,
                    heartbeat,
                    heartbeat_interval,
                    should_stop,
                )
            else:
                yield from _map_plain(
                    func,
                    first_job,
                    jobs_iter,
                    n_procs,
                    window_size,
                    initargs,
                    heartbeat,
                    heartbeat_interval,
                    should_stop,
                )
        except BrokenProcessPool as error:
            raise _worker_died_error() from error

    return _generate()


def _map_plain(
    func: Callable[[_J], _R],
    first_job: _J,
    jobs_iter: Iterator[_J],
    n_procs: int,
    window_size: int,
    initargs: tuple[Any, ...],
    heartbeat: Callable[[], None] | None,
    heartbeat_interval: float,
    should_stop: Callable[[], bool] | None,
) -> Iterator[_R]:
    """``parallel_map()``'s loop when no ``parse_timeout`` is set.

    When a worker dies the pool is broken; its other workers are killed
    and ``BrokenProcessPool`` propagates for ``parallel_map()`` to convert.
    Any other early exit (an exception, a ``KeyboardInterrupt``, the caller
    closing the iterator) kills the workers too: they ignore SIGINT, and
    leaving the ``with`` block would otherwise wait for the whole window.
    """
    with ProcessPoolExecutor(
        max_workers=n_procs,
        initializer=_init_worker,
        initargs=initargs,
    ) as executor:
        try:
            window: deque[Future[_R]] = deque()
            window.append(executor.submit(func, first_job))

            # Prime the submission window up to its bound before harvesting.
            while len(window) < window_size:
                try:
                    job = next(jobs_iter)
                except StopIteration:
                    break
                window.append(executor.submit(func, job))

            while window:
                oldest = window.popleft()
                if heartbeat is None:
                    result = oldest.result()
                else:
                    while True:
                        done, _ = wait([oldest], timeout=heartbeat_interval)
                        if done:
                            result = oldest.result()
                            break
                        heartbeat()

                yield result

                if should_stop is not None and should_stop():
                    executor.shutdown(cancel_futures=True)
                    for remaining in window:
                        if not remaining.cancelled():
                            yield remaining.result()
                    return

                try:
                    job = next(jobs_iter)
                except StopIteration:
                    continue
                window.append(executor.submit(func, job))
        except BaseException:
            _kill_workers(executor)
            raise
