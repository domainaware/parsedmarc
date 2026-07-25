"""Tests for parsedmarc.config"""

import dataclasses
import pickle
import unittest

import parsedmarc
import parsedmarc.config as parsedmarc_config


class TestParserConfigCaches(unittest.TestCase):
    """Covers per-instance cache isolation for `ParserConfig`."""

    def test_each_instance_gets_isolated_caches(self):
        """Two independently constructed ParserConfig instances must never
        share cache objects with each other or with the module defaults, and
        mutating one instance's caches must not leak into the others."""
        cfg_a = parsedmarc_config.ParserConfig()
        cfg_b = parsedmarc_config.ParserConfig()

        # All distinct objects.
        self.assertIsNot(cfg_a.ip_address_cache, cfg_b.ip_address_cache)
        self.assertIsNot(
            cfg_a.seen_aggregate_report_ids, cfg_b.seen_aggregate_report_ids
        )
        self.assertIsNot(cfg_a.reverse_dns_map, cfg_b.reverse_dns_map)

        self.assertIsNot(cfg_a.ip_address_cache, parsedmarc_config.IP_ADDRESS_CACHE)
        self.assertIsNot(
            cfg_a.seen_aggregate_report_ids,
            parsedmarc_config.SEEN_AGGREGATE_REPORT_IDS,
        )
        self.assertIsNot(cfg_a.reverse_dns_map, parsedmarc_config.REVERSE_DNS_MAP)

        self.assertIsNot(cfg_b.ip_address_cache, parsedmarc_config.IP_ADDRESS_CACHE)
        self.assertIsNot(
            cfg_b.seen_aggregate_report_ids,
            parsedmarc_config.SEEN_AGGREGATE_REPORT_IDS,
        )
        self.assertIsNot(cfg_b.reverse_dns_map, parsedmarc_config.REVERSE_DNS_MAP)

        # Mutating one instance's caches must not affect the other, nor the
        # module defaults.
        cfg_a.ip_address_cache["1.2.3.4"] = {"ip_address": "1.2.3.4"}
        cfg_a.seen_aggregate_report_ids["report-id-a"] = True
        cfg_a.reverse_dns_map["example.com"] = {"name": "Example", "type": None}

        self.assertNotIn("1.2.3.4", cfg_b.ip_address_cache)
        self.assertNotIn("report-id-a", cfg_b.seen_aggregate_report_ids)
        self.assertNotIn("example.com", cfg_b.reverse_dns_map)

        self.assertNotIn("1.2.3.4", parsedmarc_config.IP_ADDRESS_CACHE)
        self.assertNotIn("report-id-a", parsedmarc_config.SEEN_AGGREGATE_REPORT_IDS)
        self.assertNotIn("example.com", parsedmarc_config.REVERSE_DNS_MAP)

    def test_module_default_caches_are_the_public_globals(self):
        """The three module-default caches in `parsedmarc.config` must be the
        very same objects re-exported as `parsedmarc.IP_ADDRESS_CACHE`,
        `parsedmarc.SEEN_AGGREGATE_REPORT_IDS`, and
        `parsedmarc.REVERSE_DNS_MAP`, so that pre-refactor callers who
        imported these names directly from the top-level package keep
        observing the same cache objects as code that goes through
        ParserConfig.
        """
        self.assertIs(parsedmarc.IP_ADDRESS_CACHE, parsedmarc_config.IP_ADDRESS_CACHE)
        self.assertIs(
            parsedmarc.SEEN_AGGREGATE_REPORT_IDS,
            parsedmarc_config.SEEN_AGGREGATE_REPORT_IDS,
        )
        self.assertIs(parsedmarc.REVERSE_DNS_MAP, parsedmarc_config.REVERSE_DNS_MAP)


class TestParserConfigPickling(unittest.TestCase):
    """Covers the pickle strategy documented on `ParserConfig`: option fields
    round-trip, but cache contents never cross process boundaries and the
    unpickled object's caches rebind to the unpickling process's module
    defaults."""

    def test_pickle_drops_cache_contents_and_binds_process_defaults(self):
        """Pickling and unpickling a ParserConfig must preserve option
        fields, but must NOT carry cache contents across the round-trip, and
        must leave the unpickled instance's caches bound to this module's
        (the "unpickling process's") default cache objects rather than
        fresh, empty ones. Fresh-per-unpickle caches would silently defeat
        per-worker caching, since a functools.partial payload carrying a
        ParserConfig is re-pickled for every task submitted to a
        multiprocessing worker."""
        cfg = parsedmarc_config.ParserConfig(
            dns_timeout=9.5, nameservers=["192.0.2.53"]
        )
        cfg.ip_address_cache["sentinel-ip"] = "sentinel-ip-value"
        cfg.seen_aggregate_report_ids["sentinel-report-id"] = True
        cfg.reverse_dns_map["sentinel.example"] = {
            "name": "Sentinel",
            "type": None,
        }

        restored = pickle.loads(pickle.dumps(cfg))

        # Option fields compare equal (cache fields are compare=False).
        self.assertEqual(cfg, restored)
        self.assertEqual(restored.dns_timeout, 9.5)
        self.assertEqual(restored.nameservers, ["192.0.2.53"])

        # Caches rebind to this process's module defaults, not fresh copies.
        self.assertIs(restored.ip_address_cache, parsedmarc_config.IP_ADDRESS_CACHE)
        self.assertIs(
            restored.seen_aggregate_report_ids,
            parsedmarc_config.SEEN_AGGREGATE_REPORT_IDS,
        )
        self.assertIs(restored.reverse_dns_map, parsedmarc_config.REVERSE_DNS_MAP)

        # Sentinel entries placed on the original instance's caches must NOT
        # have crossed into the module defaults.
        self.assertNotIn("sentinel-ip", parsedmarc_config.IP_ADDRESS_CACHE)
        self.assertNotIn(
            "sentinel-report-id", parsedmarc_config.SEEN_AGGREGATE_REPORT_IDS
        )
        self.assertNotIn("sentinel.example", parsedmarc_config.REVERSE_DNS_MAP)


class TestParserConfigFrozenAndReplace(unittest.TestCase):
    """Covers frozen-dataclass immutability and the `dataclasses.replace`
    escape hatch for deriving variants that keep sharing caches."""

    def test_frozen_and_replace_shares_caches(self):
        """ParserConfig is frozen, so attribute assignment must raise
        FrozenInstanceError. `dataclasses.replace(cfg, ...)` must return a
        new config that shares the SAME cache objects as the source (all
        fields, including the three cache fields, are init fields), since
        that is the documented way to derive a variant that keeps warm
        caches."""
        cfg = parsedmarc_config.ParserConfig()

        with self.assertRaises(dataclasses.FrozenInstanceError):
            cfg.offline = True  # type: ignore[misc]

        variant = dataclasses.replace(cfg, offline=True)

        self.assertTrue(variant.offline)
        self.assertIs(variant.ip_address_cache, cfg.ip_address_cache)
        self.assertIs(variant.seen_aggregate_report_ids, cfg.seen_aggregate_report_ids)
        self.assertIs(variant.reverse_dns_map, cfg.reverse_dns_map)
