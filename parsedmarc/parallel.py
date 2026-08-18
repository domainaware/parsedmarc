"""Bounded-window multiprocessing helpers for parallel report parsing."""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor, wait
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from parsedmarc import ParserError
    from parsedmarc.config import ParserConfig
    from parsedmarc.types import ParsedReport

_J = TypeVar("_J")
_R = TypeVar("_R")


def _init_worker_logging(log_level: int, log_files: list[str]) -> None:
    """Pool initializer that reconstructs the parent's logging handlers.

    A spawned or forkserver worker process does not inherit the parent
    process's already-configured logging handlers, so without this the
    child's log records (including any that would surface a parsing bug)
    are silently dropped. Called once per worker process by
    ``ProcessPoolExecutor``'s ``initializer``/``initargs``.
    """
    from parsedmarc.log import configure_logging

    if not log_files:
        configure_logging(log_level, None)
        return
    for log_file in log_files:
        configure_logging(log_level, log_file)


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
    handling on the submission side; any other exception propagates and
    surfaces as the future's exception.
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


def parallel_map(
    func: Callable[[_J], _R],
    jobs: Iterable[_J],
    n_procs: int,
    *,
    window_factor: int = 2,
    heartbeat: Callable[[], None] | None = None,
    heartbeat_interval: float = 30.0,
    should_stop: Callable[[], bool] | None = None,
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

    Raises:
        ValueError: If ``n_procs`` is less than 1. Raised eagerly at the
            call itself (not on first iteration of the returned iterator).
    """
    if n_procs < 1:
        raise ValueError(f"n_procs must be at least 1, got {n_procs}")

    def _generate() -> Iterator[_R]:
        jobs_iter = iter(jobs)
        try:
            first_job = next(jobs_iter)
        except StopIteration:
            return

        from parsedmarc.log import logger

        log_level = logger.getEffectiveLevel()
        log_files = [
            h.baseFilename
            for h in logger.handlers
            if isinstance(h, logging.FileHandler)
        ]

        window_size = max(window_factor * n_procs, 1)

        with ProcessPoolExecutor(
            max_workers=n_procs,
            initializer=_init_worker_logging,
            initargs=(log_level, log_files),
        ) as executor:
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

    return _generate()
