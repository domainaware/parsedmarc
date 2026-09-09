"""Tests for the map-maintenance scripts under parsedmarc/resources/maps/.

These scripts are maintainer-only batch tooling — they do not ship in the
wheel — but they still need regression coverage because they enforce the
privacy and integrity rules for the reverse-DNS map data files."""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock


class TestMapScriptsIPDetection(unittest.TestCase):
    """Full-IP detection and PSL folding in the map-maintenance scripts."""

    def test_collect_domain_info_detects_full_ips(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        # Dotted and dashed four-octet patterns with valid octets: detected.
        self.assertTrue(cdi._has_full_ip("74-208-244-234.cprapid.com"))
        self.assertTrue(cdi._has_full_ip("host.192.168.1.1.example.com"))
        self.assertTrue(cdi._has_full_ip("a-10-20-30-40-brand.com"))
        # Three octets is NOT a full IP — OVH's reverse-DNS pattern stays safe.
        self.assertFalse(cdi._has_full_ip("ip-147-135-108.us"))
        # Out-of-range octet fails the 0-255 sanity check.
        self.assertFalse(cdi._has_full_ip("999-1-2-3-foo.com"))
        # Pure domain, no IP.
        self.assertFalse(cdi._has_full_ip("example.com"))

    def test_find_unknown_detects_full_ips(self):
        import parsedmarc.resources.maps.find_unknown_base_reverse_dns as fu

        self.assertTrue(fu._has_full_ip("170-254-144-204-nobreinternet.com.br"))
        self.assertFalse(fu._has_full_ip("ip-147-135-108.us"))
        self.assertFalse(fu._has_full_ip("cprapid.com"))

    def test_apply_psl_override_dot_prefix(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        ov = [".cprapid.com", ".linode.com"]
        self.assertEqual(cdi._apply_psl_override("foo.cprapid.com", ov), "cprapid.com")
        self.assertEqual(cdi._apply_psl_override("a.b.linode.com", ov), "linode.com")

    def test_apply_psl_override_dash_prefix(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        ov = ["-nobre.com.br"]
        self.assertEqual(
            cdi._apply_psl_override("1-2-3-4-nobre.com.br", ov), "nobre.com.br"
        )

    def test_apply_psl_override_no_match(self):
        import parsedmarc.resources.maps.collect_domain_info as cdi

        ov = [".cprapid.com"]
        self.assertEqual(cdi._apply_psl_override("example.com", ov), "example.com")


class TestFindUnknownBaseReverseDNS(unittest.TestCase):
    """Missing-file error paths in find_unknown_base_reverse_dns.py's
    ``_main()``.

    Both sites below printed the intended ``"Error: ... does not exist"``
    message but had no ``sys.exit(1)`` after it, so execution fell through
    into the next ``open()`` call on the same missing path and raised an
    unhandled ``FileNotFoundError`` instead of the clean, intended exit.
    """

    def test_missing_known_unknown_list_exits_cleanly(self):
        """A missing known_unknown_base_reverse_dns.txt must print the
        intended error message and exit(1), not fall through into an
        unhandled FileNotFoundError from the subsequent open() call.

        Regression test: the nested ``load_list()`` helper in ``_main()``
        printed ``f"Error: {file_path} does not exist"`` but had no
        ``sys.exit(1)`` after it, so execution fell through into
        ``print(f"Loading {file_path}")`` and then ``open(file_path)`` on
        the same missing path, raising an unhandled ``FileNotFoundError``
        instead of the clean, intended error exit. The sibling
        duplicate-entry check a few lines below (``domain in list_var``)
        already did print-then-``sys.exit(1)``; this verifies the
        missing-file check now matches that style. Capturing stdout and
        asserting on the exact message (rather than only the exit code)
        pins the exit to this specific site, not just any ``sys.exit(1)``
        in the function.
        """
        import parsedmarc.resources.maps.find_unknown_base_reverse_dns as fu

        old_cwd = os.getcwd()
        tmp_dir = tempfile.mkdtemp()
        # Register rmtree first so, under LIFO cleanup ordering, chdir back
        # to old_cwd always runs before rmtree removes tmp_dir -- and, since
        # unittest runs each addCleanup independently, rmtree still runs
        # even if os.chdir were to raise.
        self.addCleanup(shutil.rmtree, tmp_dir, ignore_errors=True)
        self.addCleanup(os.chdir, old_cwd)
        os.chdir(tmp_dir)

        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["find_unknown_base_reverse_dns.py"]):
            with contextlib.redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as cm:
                    fu._main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Error: known_unknown_base_reverse_dns.txt does not exist",
            stdout.getvalue(),
        )

    def test_missing_base_reverse_dns_map_exits_cleanly(self):
        """A missing base_reverse_dns_map.csv must print the intended error
        message and exit(1), not fall through into an unhandled
        FileNotFoundError from the subsequent open() call.

        Regression test for the second site fixed alongside the
        ``load_list()`` one above: ``_main()`` printed
        ``f"Error: {base_reverse_dns_map_file_path} does not exist"`` but
        had no ``sys.exit(1)`` after it. Reaching this check requires
        getting past the MMDB load first. ``_load_as_name_index`` does its
        external work entirely through ``maxminddb.open_database()`` --
        the actual SDK boundary per AGENTS.md's "mock at SDK boundaries"
        rule -- so that call is mocked to a context manager over an empty
        iterable instead of loading the real, ~23MB bundled MMDB or
        mocking an internal helper of this codebase.
        """
        import parsedmarc.resources.maps.find_unknown_base_reverse_dns as fu

        old_cwd = os.getcwd()
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp_dir, ignore_errors=True)
        self.addCleanup(os.chdir, old_cwd)

        maps_dir = os.path.join(tmp_dir, "maps")
        ipinfo_dir = os.path.join(tmp_dir, "ipinfo")
        os.makedirs(maps_dir)
        os.makedirs(ipinfo_dir)
        # Both lists are loaded before the MMDB check and must exist, but
        # their content isn't exercised by this test.
        open(os.path.join(maps_dir, "known_unknown_base_reverse_dns.txt"), "w").close()
        open(os.path.join(maps_dir, "psl_overrides.txt"), "w").close()
        # A placeholder for the MMDB: only os.path.exists() touches this
        # path directly, since maxminddb.open_database() itself is mocked
        # below and never actually reads the file.
        open(os.path.join(ipinfo_dir, "ipinfo_lite.mmdb"), "w").close()
        # base_reverse_dns_map.csv is deliberately NOT created -- that's
        # the missing-file condition under test.

        os.chdir(maps_dir)

        class _EmptyMMDBReader:
            def __enter__(self):
                return iter(())

            def __exit__(self, *exc_info):
                return False

        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", ["find_unknown_base_reverse_dns.py"]):
            with mock.patch("maxminddb.open_database", return_value=_EmptyMMDBReader()):
                with contextlib.redirect_stdout(stdout):
                    with self.assertRaises(SystemExit) as cm:
                        fu._main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Error: base_reverse_dns_map.csv does not exist", stdout.getvalue()
        )


class TestDetectPSLOverrides(unittest.TestCase):
    """Cluster detection, brand-tail extraction, and full-pipeline behaviour
    for `detect_psl_overrides.py`."""

    def setUp(self):
        import parsedmarc.resources.maps.detect_psl_overrides as dpo

        self.dpo = dpo

    def test_extract_brand_tail_dot_separator(self):
        self.assertEqual(
            self.dpo.extract_brand_tail("74-208-244-234.cprapid.com"),
            ".cprapid.com",
        )

    def test_extract_brand_tail_dash_separator(self):
        self.assertEqual(
            self.dpo.extract_brand_tail("170-254-144-204-nobre.com.br"),
            "-nobre.com.br",
        )

    def test_extract_brand_tail_no_separator(self):
        self.assertEqual(
            self.dpo.extract_brand_tail("host134-254-143-190tigobusiness.com.ni"),
            "tigobusiness.com.ni",
        )

    def test_extract_brand_tail_no_ip_returns_none(self):
        self.assertIsNone(self.dpo.extract_brand_tail("plain.example.com"))

    def test_extract_brand_tail_rejects_short_tail(self):
        """A tail shorter than MIN_TAIL_LEN is rejected to avoid folding to `.com`."""
        # Four-octet IP followed by only `.br` (2 chars after the dot) — too short.
        self.assertIsNone(self.dpo.extract_brand_tail("1-2-3-4.br"))

    def test_detect_clusters_meets_threshold(self):
        domains = [
            "1-2-3-4.cprapid.com",
            "5-6-7-8.cprapid.com",
            "9-10-11-12.cprapid.com",
            "1-2-3-4-other.com.br",  # not enough of these
        ]
        clusters = self.dpo.detect_clusters(domains, threshold=3, known_overrides=set())
        self.assertIn(".cprapid.com", clusters)
        self.assertEqual(len(clusters[".cprapid.com"]), 3)
        self.assertNotIn("-other.com.br", clusters)

    def test_detect_clusters_honours_threshold(self):
        domains = [
            "1-2-3-4.cprapid.com",
            "5-6-7-8.cprapid.com",
        ]
        clusters = self.dpo.detect_clusters(domains, threshold=3, known_overrides=set())
        self.assertEqual(clusters, {})

    def test_detect_clusters_skips_known_overrides(self):
        """Tails already in psl_overrides.txt must not be re-proposed."""
        domains = [
            "1-2-3-4.cprapid.com",
            "5-6-7-8.cprapid.com",
            "9-10-11-12.cprapid.com",
        ]
        clusters = self.dpo.detect_clusters(
            domains, threshold=3, known_overrides={".cprapid.com"}
        )
        self.assertNotIn(".cprapid.com", clusters)

    def test_apply_override_matches_first(self):
        """apply_override iterates in list order and returns on the first match."""
        ov = [".cprapid.com", "-nobre.com.br"]
        self.assertEqual(
            self.dpo.apply_override("1-2-3-4.cprapid.com", ov), "cprapid.com"
        )
        self.assertEqual(
            self.dpo.apply_override("1-2-3-4-nobre.com.br", ov), "nobre.com.br"
        )
        self.assertEqual(self.dpo.apply_override("unrelated.com", ov), "unrelated.com")

    def test_has_full_ip_shared_with_other_scripts(self):
        """The detect script's IP check must agree with the other map scripts."""
        self.assertTrue(self.dpo.has_full_ip("74-208-244-234.cprapid.com"))
        self.assertFalse(self.dpo.has_full_ip("ip-147-135-108.us"))
        self.assertFalse(self.dpo.has_full_ip("example.com"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
