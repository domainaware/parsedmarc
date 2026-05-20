"""Tests for the map-maintenance scripts under parsedmarc/resources/maps/.

These scripts are maintainer-only batch tooling — they do not ship in the
wheel — but they still need regression coverage because they enforce the
privacy and integrity rules for the reverse-DNS map data files."""

import unittest


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
