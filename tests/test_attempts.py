"""Tests for parsedmarc.attempts"""

import json
import os
import stat
import sys
import unittest
from datetime import datetime, timedelta, timezone
from shutil import rmtree
from tempfile import mkdtemp
from unittest.mock import patch

from parsedmarc.attempts import (
    FILE_VERSION,
    PRUNE_AFTER,
    AttemptStore,
    attempt_key,
)


class TestAttemptKey(unittest.TestCase):
    """The key names the folder and message and hashes the content, so a
    reused UID with new content is a new message."""

    def test_same_uid_with_different_content_gets_a_different_key(self):
        first = attempt_key("INBOX", 7, "Subject: one\n\nbody\n")
        second = attempt_key("INBOX", 7, "Subject: two\n\nbody\n")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("INBOX\x1f7\x1f"))

    def test_same_message_gets_the_same_key_as_str_or_bytes(self):
        text = "Subject: one\n\nbody\n"
        self.assertEqual(
            attempt_key("INBOX", "a", text),
            attempt_key("INBOX", "a", text.encode("utf-8")),
        )

    def test_folder_and_id_are_part_of_the_key(self):
        content = "Subject: one\n\nbody\n"
        self.assertNotEqual(
            attempt_key("INBOX", 1, content), attempt_key("Reports", 1, content)
        )
        self.assertNotEqual(
            attempt_key("INBOX", 1, content), attempt_key("INBOX", 2, content)
        )

    def test_only_the_first_64_kib_is_hashed(self):
        prefix = "x" * 65536
        self.assertEqual(
            attempt_key("INBOX", 1, prefix + "tail one"),
            attempt_key("INBOX", 1, prefix + "tail two"),
        )

    def test_a_lone_surrogate_does_not_raise(self):
        # A str decoded with surrogateescape holds lone surrogates.
        key = attempt_key("INBOX", 1, "Subject: \udcff\n\n")
        self.assertNotEqual(key, attempt_key("INBOX", 1, "Subject: \n\n"))


class TestAttemptStore(unittest.TestCase):
    """The store on a real file in a temporary directory."""

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        self.path = os.path.join(self._tmp, "attempts.json")

    def _read(self):
        with open(self.path, encoding="utf-8") as attempts_file:
            return json.load(attempts_file)

    def _write(self, document):
        with open(self.path, "w", encoding="utf-8") as attempts_file:
            json.dump(document, attempts_file)

    def test_missing_file_is_an_empty_store_and_is_not_created_by_loading(self):
        store = AttemptStore(self.path)
        self.assertEqual(store.count("k"), 0)
        self.assertFalse(os.path.exists(self.path))

    def test_record_increments_and_persists(self):
        store = AttemptStore(self.path)
        self.assertEqual(store.record("k"), 1)
        self.assertEqual(store.record("k"), 2)
        document = self._read()
        self.assertEqual(document["version"], FILE_VERSION)
        self.assertEqual(document["attempts"]["k"]["count"], 2)
        last = datetime.fromisoformat(document["attempts"]["k"]["last"])
        self.assertLess(datetime.now(timezone.utc) - last, timedelta(minutes=1))

        reloaded = AttemptStore(self.path)
        self.assertEqual(reloaded.count("k"), 2)
        self.assertEqual(reloaded.record("k"), 3)

    def test_clear_rewrites_the_file_without_the_entry(self):
        store = AttemptStore(self.path)
        store.record("k")
        store.record("other")
        store.clear("k")
        self.assertEqual(list(self._read()["attempts"]), ["other"])
        self.assertEqual(AttemptStore(self.path).count("k"), 0)

    def test_clear_of_an_unknown_key_does_not_write(self):
        store = AttemptStore(self.path)
        store.clear("k")
        self.assertFalse(os.path.exists(self.path))

    def test_corrupt_file_warns_and_starts_empty(self):
        cases = {
            "not json": b"{not json",
            "not utf-8": b"\xff\xfe\x00",
            "a list": b"[]",
            "wrong version": json.dumps({"version": 2, "attempts": {}}).encode(),
            "attempts not a dict": json.dumps({"version": 1, "attempts": []}).encode(),
            "entry not a dict": json.dumps(
                {"version": 1, "attempts": {"k": 1}}
            ).encode(),
            "count a bool": json.dumps(
                {
                    "version": 1,
                    "attempts": {
                        "k": {"count": True, "last": "2026-11-09T00:00:00+00:00"}
                    },
                }
            ).encode(),
            "count zero": json.dumps(
                {
                    "version": 1,
                    "attempts": {
                        "k": {"count": 0, "last": "2026-11-09T00:00:00+00:00"}
                    },
                }
            ).encode(),
            "last not a str": json.dumps(
                {"version": 1, "attempts": {"k": {"count": 1, "last": 5}}}
            ).encode(),
            "last not a date": json.dumps(
                {"version": 1, "attempts": {"k": {"count": 1, "last": "soon"}}}
            ).encode(),
            "last without a zone": json.dumps(
                {
                    "version": 1,
                    "attempts": {"k": {"count": 1, "last": "2026-11-09T00:00:00"}},
                }
            ).encode(),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                with open(self.path, "wb") as attempts_file:
                    attempts_file.write(raw)
                with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                    store = AttemptStore(self.path)
                self.assertEqual(store.count("k"), 0)
                self.assertIn(f"Attempts file {self.path}", cm.output[0])
                # The next write replaces the corrupt file with a valid one.
                self.assertEqual(store.record("k"), 1)
                self.assertEqual(self._read()["attempts"]["k"]["count"], 1)

    def test_unreadable_file_warns_and_starts_empty(self):
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            # A directory cannot be opened as a file on any platform.
            store = AttemptStore(self._tmp)
        self.assertEqual(store.count("k"), 0)
        self.assertIn(f"Could not read attempts file {self._tmp}", cm.output[0])

    def test_entries_older_than_the_prune_age_are_dropped_on_load(self):
        now = datetime.now(timezone.utc)
        self._write(
            {
                "version": 1,
                "attempts": {
                    "old": {
                        "count": 2,
                        "last": (now - PRUNE_AFTER - timedelta(hours=1)).isoformat(),
                    },
                    "recent": {
                        "count": 1,
                        "last": (now - PRUNE_AFTER + timedelta(hours=1)).isoformat(),
                    },
                },
            }
        )
        store = AttemptStore(self.path)
        self.assertEqual(store.count("old"), 0)
        self.assertEqual(store.count("recent"), 1)
        store.record("new")
        self.assertEqual(sorted(self._read()["attempts"]), ["new", "recent"])

    def test_failed_replace_keeps_the_old_file_and_disables_the_store(self):
        store = AttemptStore(self.path)
        store.record("k")
        before = self._read()

        with patch("parsedmarc.attempts.os.replace", side_effect=OSError("disk full")):
            with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
                self.assertEqual(store.record("k"), 0)

        self.assertEqual(self._read(), before)
        self.assertIn(
            f"Could not write attempts file {self.path}: disk full; "
            "crashed-message protection is disabled",
            cm.output[0],
        )
        # No temporary file is left beside the attempts file.
        self.assertEqual(os.listdir(self._tmp), ["attempts.json"])
        # Off for the rest of the batch: nothing more is counted or written.
        self.assertFalse(store.enabled)
        self.assertEqual(store.record("other"), 0)
        store.clear("k")
        self.assertEqual(self._read(), before)

    def test_unwritable_directory_disables_the_store_without_raising(self):
        # A regular file where the parent directory should be.
        blocker = os.path.join(self._tmp, "blocker")
        with open(blocker, "w", encoding="utf-8"):
            pass
        store = AttemptStore(os.path.join(blocker, "attempts.json"))
        with self.assertLogs("parsedmarc.log", level="ERROR"):
            self.assertEqual(store.record("k"), 0)
        self.assertFalse(store.enabled)

    def test_missing_parent_directories_are_created(self):
        path = os.path.join(self._tmp, "state", "parsedmarc", "attempts.json")
        store = AttemptStore(path)
        self.assertEqual(store.record("k"), 1)
        self.assertTrue(os.path.isfile(path))

    @unittest.skipIf(sys.platform == "win32", "POSIX file modes")
    def test_file_is_readable_by_its_owner_only(self):
        old_umask = os.umask(0)
        try:
            store = AttemptStore(self.path)
            store.record("k")
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
            store.clear("k")
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        finally:
            os.umask(old_umask)


if __name__ == "__main__":
    unittest.main(verbosity=2)
