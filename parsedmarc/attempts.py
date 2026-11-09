"""A persisted count of mailbox messages whose parsing never finished.

A message whose parse kills the process (the out-of-memory killer, a
container memory cap, a segfault) is never moved out of the reports folder,
so every later run fetches it and dies on it again. ``AttemptStore`` keeps a
small JSON file that counts, per message, the parse attempts that started
but never produced a result. ``get_dmarc_reports_from_mailbox()`` records an
attempt before it parses a message and clears it as soon as the parse
returns or raises ``ParserError``; a message whose count passes
``MAX_PARSE_ATTEMPTS`` is set aside as invalid without being parsed again.

The file is written atomically (a temporary file in the same directory,
fsynced, then renamed over the old one), so a crash during a write leaves
either the old file or the new one, and it is created readable by its owner
only. A write that fails turns the store off for the rest of the batch
instead of stopping the run: the protection is a backstop, and losing it
must not cost the reports.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any

from parsedmarc.log import logger

# How many parse attempts may die before the message is set aside. Two lets
# a message survive one unrelated crash (a reboot, a kill during a deploy)
# while the third run stops the loop.
MAX_PARSE_ATTEMPTS = 2

# An entry not touched for this long belongs to a message that has left the
# reports folder some other way (moved or deleted by hand); drop it on load
# so the file does not grow forever.
PRUNE_AFTER = timedelta(days=30)

FILE_VERSION = 1

# How much of the message the key hashes. Enough to tell two messages
# apart that reuse one UID, small enough to hash at no cost.
_KEY_CONTENT_PREFIX = 65536


def attempt_key(
    reports_folder: str, message_id: int | str, content: str | bytes
) -> str:
    """Return the store key of one message in one reports folder.

    The key joins the folder, the backend's message id and a hash of the
    message's first 64 KiB. The hash keeps a new message that reuses the
    UID of an old one (an IMAP folder recreated with a new UIDVALIDITY,
    which mailsuite does not expose) from inheriting the old one's count.

    Args:
        reports_folder: The folder the message was fetched from
        message_id: The backend's id of the message
        content: The fetched message

    Returns:
        str: The key
    """
    if isinstance(content, str):
        # surrogatepass: a str decoded with surrogateescape still encodes.
        raw = content[:_KEY_CONTENT_PREFIX].encode("utf-8", "surrogatepass")
    else:
        raw = content[:_KEY_CONTENT_PREFIX]
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return f"{reports_folder}\x1f{message_id}\x1f{digest}"


class AttemptStore:
    """Unfinished parse attempts per message, persisted in a JSON file.

    The file holds ``{"version": 1, "attempts": {key: {"count": n,
    "last": "<ISO 8601 time>"}}}``. A missing file is an empty store; a
    file that cannot be read or does not have that shape is logged as a
    warning and replaced on the next write.

    Args:
        path: The JSON file to read and write
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.enabled = True
        self._attempts: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        """Read the file, replacing the store's entries.

        Entries whose last attempt is older than ``PRUNE_AFTER`` are
        dropped.
        """
        self._attempts = {}
        try:
            with open(self.path, "rb") as attempts_file:
                raw = attempts_file.read()
        except FileNotFoundError:
            return
        except OSError as error:
            logger.warning(
                f"Could not read attempts file {self.path}: {error}; starting empty"
            )
            return
        attempts = _parse_attempts(raw)
        if attempts is None:
            logger.warning(
                f"Attempts file {self.path} is not a version {FILE_VERSION} "
                "attempts file; starting empty"
            )
            return
        cutoff = datetime.now(timezone.utc) - PRUNE_AFTER
        self._attempts = {
            key: entry
            for key, entry in attempts.items()
            if datetime.fromisoformat(entry["last"]) >= cutoff
        }

    def count(self, key: str) -> int:
        """Return the number of unfinished attempts recorded for ``key``."""
        entry = self._attempts.get(key)
        return entry["count"] if entry else 0

    def record(self, key: str) -> int:
        """Count one more attempt for ``key`` and write the file.

        Returns:
            int: The new count, or ``0`` when the store is off
        """
        if not self.enabled:
            return 0
        count = self.count(key) + 1
        self._attempts[key] = {
            "count": count,
            "last": datetime.now(timezone.utc).isoformat(),
        }
        if not self._flush():
            return 0
        return count

    def clear(self, key: str) -> None:
        """Forget ``key`` and write the file, if it had an entry."""
        if not self.enabled or key not in self._attempts:
            return
        del self._attempts[key]
        self._flush()

    def _flush(self) -> bool:
        """Write the store atomically; on failure, log and turn it off."""
        directory = os.path.dirname(os.path.abspath(self.path))
        body = json.dumps(
            {"version": FILE_VERSION, "attempts": self._attempts},
            sort_keys=True,
        ).encode("utf-8")
        temp_path = None
        try:
            os.makedirs(directory, exist_ok=True)
            # mkstemp creates the file with mode 0600, and os.replace
            # carries that mode over to the attempts file.
            descriptor, temp_path = tempfile.mkstemp(
                prefix=".attempts-", suffix=".tmp", dir=directory
            )
            with os.fdopen(descriptor, "wb") as temp_file:
                temp_file.write(body)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, self.path)
        except OSError as error:
            if temp_path is not None:
                with contextlib.suppress(OSError):
                    os.unlink(temp_path)
            self.enabled = False
            logger.error(
                f"Could not write attempts file {self.path}: {error}; "
                "crashed-message protection is disabled for the rest of this "
                "batch"
            )
            return False
        return True


def _parse_attempts(raw: bytes) -> dict[str, dict[str, Any]] | None:
    """Return the ``attempts`` mapping of a version 1 file, or ``None``."""
    try:
        document = json.loads(raw)
    except ValueError:
        # json.JSONDecodeError and UnicodeDecodeError are both ValueErrors.
        return None
    if not isinstance(document, dict) or document.get("version") != FILE_VERSION:
        return None
    attempts = document.get("attempts")
    if not isinstance(attempts, dict):
        return None
    for entry in attempts.values():
        if not isinstance(entry, dict):
            return None
        count = entry.get("count")
        last = entry.get("last")
        if type(count) is not int or count < 1 or not isinstance(last, str):
            return None
        try:
            last_time = datetime.fromisoformat(last)
        except ValueError:
            return None
        if last_time.tzinfo is None:
            return None
    return attempts
