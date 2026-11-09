"""Timing bounds that scale with the machine running the suite."""

import email
import time

_REFERENCE_MESSAGE = (
    "From: sender@example.net\r\nTo: dmarc@example.com\r\nSubject: x\r\n\r\n"
    + "a\r\n" * 300_000
)


def budget(seconds: float) -> float:
    """Return ``seconds``, scaled up on a machine slower than the reference.

    Timed checks do real work at a limit, so their bound must scale with the
    machine running them. The reference is ``_REFERENCE_MESSAGE`` parsed by the
    email package, 0.04 s on the workstation the bounds were written on
    (Python 3.12). It is measured just before the timed call, twice, and the
    slower run sets the scale, so a brief fast moment in the reference is not
    taken as the machine's speed; a slowdown during the timed call itself is
    not covered. A faster machine keeps the written bound, and the scale is
    capped at ten, so a stall during the reference cannot hide a regression.
    """
    reference = 0.0
    for _ in range(2):
        start = time.perf_counter()
        email.message_from_string(_REFERENCE_MESSAGE)
        reference = max(reference, time.perf_counter() - start)
    return seconds * min(max(1.0, reference / 0.04), 10.0)
