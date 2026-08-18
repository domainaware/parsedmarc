"""Tests for parsedmarc.log"""

import logging
import os
import tempfile
import unittest

from parsedmarc.log import configure_logging, logger


class TestConfigureLoggingFileHandlerDedup(unittest.TestCase):
    """Repeated configure_logging calls with the same log_file (e.g. a
    SIGHUP config reload re-running the CLI's logging setup) must not
    stack duplicate FileHandlers - a duplicate would write every record
    twice and leak a file descriptor per call."""

    def setUp(self):
        self._saved_handlers = list(logger.handlers)
        self._saved_level = logger.level

    def tearDown(self):
        for handler in list(logger.handlers):
            if handler not in self._saved_handlers:
                logger.removeHandler(handler)
                if isinstance(handler, logging.FileHandler):
                    handler.close()
        logger.handlers[:] = self._saved_handlers
        logger.setLevel(self._saved_level)

    def _temp_log_path(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
            path = tf.name
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_same_log_file_twice_attaches_one_handler_and_logs_once(self):
        log_path = self._temp_log_path()

        configure_logging(logging.INFO, log_path)
        configure_logging(logging.INFO, log_path)

        file_handlers = [
            h
            for h in logger.handlers
            if isinstance(h, logging.FileHandler)
            and h.baseFilename == os.path.abspath(log_path)
        ]
        self.assertEqual(len(file_handlers), 1)

        logger.info("dedup-check line")
        for handler in file_handlers:
            handler.flush()
        with open(log_path) as f:
            contents = f.read()
        self.assertEqual(contents.count("dedup-check line"), 1)

    def test_different_log_files_attach_one_handler_each(self):
        first_path = self._temp_log_path()
        second_path = self._temp_log_path()

        configure_logging(logging.INFO, first_path)
        configure_logging(logging.INFO, second_path)

        file_paths = [
            h.baseFilename
            for h in logger.handlers
            if isinstance(h, logging.FileHandler)
        ]
        self.assertIn(os.path.abspath(first_path), file_paths)
        self.assertIn(os.path.abspath(second_path), file_paths)


if __name__ == "__main__":
    unittest.main(verbosity=2)
