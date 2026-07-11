"""Tests for parsedmarc.utils"""

import os
import shutil
import tempfile
import time
import unittest
from datetime import datetime, timezone
from importlib.resources import files
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import requests
from expiringdict import ExpiringDict

import parsedmarc
import parsedmarc.resources.ipinfo
import parsedmarc.utils
from tests.tzutil import force_tz


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

    def testBase64Decoding(self):
        """Test base64 decoding"""
        # Example from Wikipedia Base64 article
        b64_str = "YW55IGNhcm5hbCBwbGVhcw"
        decoded_str = parsedmarc.utils.decode_base64(b64_str)
        self.assertEqual(decoded_str, b"any carnal pleas")

    def testPSLDownload(self):
        """Test Public Suffix List domain lookups"""
        subdomain = "foo.example.com"
        result = parsedmarc.utils.get_base_domain(subdomain)
        self.assertEqual(result, "example.com")

        # psl_overrides.txt intentionally folds CDN-customer PTRs so every
        # sender on the same network clusters under one display key.
        # ``.akamaiedge.net`` is an override, so its subdomains collapse to
        # ``akamaiedge.net`` even though the live PSL carries the finer-grained
        # ``c.akamaiedge.net`` — the override is the design decision.
        subdomain = "e3191.c.akamaiedge.net"
        result = parsedmarc.utils.get_base_domain(subdomain)
        assert result == "akamaiedge.net"

    def testIpAddressInfoSurfacesASNFields(self):
        """ASN number, name, and domain from the bundled MMDB appear on every
        IP info result, even when no PTR resolves."""
        info = parsedmarc.utils.get_ip_address_info("8.8.8.8", offline=True)
        self.assertEqual(info["asn"], 15169)
        self.assertIsInstance(info["asn"], int)
        self.assertEqual(info["as_domain"], "google.com")
        self.assertTrue(info["as_name"])

    def testIpAddressInfoFallsBackToASNMapEntryWhenNoPTR(self):
        """When reverse DNS is absent, the ASN domain should be used as a
        lookup into the reverse_dns_map so the row still gets attributed,
        while reverse_dns and base_domain remain null."""
        info = parsedmarc.utils.get_ip_address_info("8.8.8.8", offline=True)
        self.assertIsNone(info["reverse_dns"])
        self.assertIsNone(info["base_domain"])
        self.assertEqual(info["name"], "Google (Including Gmail and Google Workspace)")
        self.assertEqual(info["type"], "Email Provider")

    def testIpAddressInfoFallsBackToRawASNameOnMapMiss(self):
        """When neither PTR nor an ASN-map entry resolves, the raw AS name
        is used as source_name with type left null — better than leaving
        the row unattributed."""
        # 204.79.197.100 is in an ASN whose as_domain is not in the map at
        # the time of this test (msn.com); this exercises the as_name
        # fallback branch without depending on a specific map state.
        from unittest.mock import patch

        with patch(
            "parsedmarc.utils.get_ip_address_db_record",
            return_value={
                "country": "US",
                "asn": 64496,
                "as_name": "Some Unmapped Org, Inc.",
                "as_domain": "unmapped-for-this-test.example",
            },
        ):
            # Bypass cache to avoid prior-test pollution.
            info = parsedmarc.utils.get_ip_address_info(
                "192.0.2.1", offline=True, cache=None
            )
        self.assertIsNone(info["reverse_dns"])
        self.assertIsNone(info["base_domain"])
        self.assertIsNone(info["type"])
        self.assertEqual(info["name"], "Some Unmapped Org, Inc.")
        self.assertEqual(info["as_domain"], "unmapped-for-this-test.example")

    def testWeakFallbackAttributionIsNotCached(self):
        """A transient PTR lookup failure that lands on the raw-as_name
        fallback must not poison the cache. ``get_reverse_dns()`` swallows
        every DNSException as ``None``, so a timeout looks identical to a
        real no-PTR case — if we cached the weak attribution, the 4-hour
        TTL would lock in a misattribution even after the PTR returns.

        PTR-backed matches and ASN-domain matches are stable attributions
        and must still be cached, so we only skip the specific
        ``reverse_dns=None AND type=None AND name=as_name`` state."""
        from unittest.mock import patch
        from expiringdict import ExpiringDict

        cache = ExpiringDict(max_len=100, max_age_seconds=14400)

        # Scenario 1: weak fallback (no PTR, unmapped as_domain, raw as_name
        # used). Must NOT be cached.
        with patch(
            "parsedmarc.utils.get_ip_address_db_record",
            return_value={
                "country": "US",
                "asn": 64496,
                "as_name": "Some Unmapped Org, Inc.",
                "as_domain": "unmapped-for-this-test.example",
            },
        ):
            parsedmarc.utils.get_ip_address_info("192.0.2.1", offline=True, cache=cache)
        self.assertNotIn("192.0.2.1", cache)

        # Scenario 2: ASN-domain match (no PTR, as_domain IS in the map).
        # Stable attribution — must still be cached.
        with patch(
            "parsedmarc.utils.get_ip_address_db_record",
            return_value={
                "country": "US",
                "asn": 15169,
                "as_name": "Google LLC",
                "as_domain": "google.com",
            },
        ):
            parsedmarc.utils.get_ip_address_info("192.0.2.2", offline=True, cache=cache)
        self.assertIn("192.0.2.2", cache)

    def testIPinfoAPIPrimarySourceAndInvalidKeyIsFatal(self):
        """With an API token configured, lookups hit the API first via the
        documented ?token= query param. A 401/403 response propagates as
        ``InvalidIPinfoAPIKey`` so the CLI can exit fatally. Any other
        non-2xx or network error falls through to the MMDB silently.

        The IPinfo Lite API is documented as having no request limit, so
        there is no rate-limit/quota handling to test — only the fatal path
        on invalid tokens and the success path."""
        from unittest.mock import patch, MagicMock

        from parsedmarc.utils import (
            InvalidIPinfoAPIKey,
            configure_ipinfo_api,
            get_ip_address_db_record,
        )

        def _mock_response(status_code, json_body=None):
            resp = MagicMock()
            resp.status_code = status_code
            resp.ok = 200 <= status_code < 300
            resp.json.return_value = json_body or {}
            return resp

        try:
            # Success: API returns IPinfo-schema JSON; record comes from API.
            api_json = {
                "ip": "8.8.8.8",
                "asn": "AS15169",
                "as_name": "Google LLC",
                "as_domain": "google.com",
                "country_code": "US",
            }
            with patch(
                "parsedmarc.utils.requests.get",
                return_value=_mock_response(200, api_json),
            ) as mock_get:
                configure_ipinfo_api("fake-token", probe=False)
                record = get_ip_address_db_record("8.8.8.8")
            self.assertEqual(record["country"], "US")
            self.assertEqual(record["asn"], 15169)
            self.assertEqual(record["as_domain"], "google.com")
            # Auth must use the documented query param, not a Bearer header.
            _, kwargs = mock_get.call_args
            self.assertEqual(kwargs["params"], {"token": "fake-token"})
            self.assertNotIn("Authorization", kwargs["headers"])

            # Invalid key: 401 raises a fatal exception even on a random lookup.
            with patch(
                "parsedmarc.utils.requests.get",
                return_value=_mock_response(401),
            ):
                configure_ipinfo_api("bad-token", probe=False)
                with self.assertRaises(InvalidIPinfoAPIKey):
                    get_ip_address_db_record("8.8.8.8")

            # Any other non-2xx (e.g. 500, 503) falls back to the MMDB silently.
            configure_ipinfo_api("fake-token", probe=False)
            with patch(
                "parsedmarc.utils.requests.get",
                return_value=_mock_response(500),
            ):
                record = get_ip_address_db_record("8.8.8.8")
            # MMDB fallback fills in Google's ASN from the bundled MMDB.
            self.assertEqual(record["asn"], 15169)
        finally:
            configure_ipinfo_api(None)

    def testTimestampToDatetime(self):
        """timestamp_to_datetime converts UNIX timestamp to datetime"""
        from datetime import datetime

        ts = 1704067200
        dt = parsedmarc.utils.timestamp_to_datetime(ts)
        self.assertIsInstance(dt, datetime)
        # Should match stdlib fromtimestamp (local time)
        self.assertEqual(dt, datetime.fromtimestamp(ts))

    def testTimestampToHuman(self):
        """timestamp_to_human returns formatted string"""
        result = parsedmarc.utils.timestamp_to_human(1704067200)
        self.assertRegex(result, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

    def testHumanTimestampToDatetime(self):
        """human_timestamp_to_datetime parses timestamp string"""
        dt = parsedmarc.utils.human_timestamp_to_datetime("2024-01-01 00:00:00")
        self.assertIsInstance(dt, datetime)
        self.assertEqual(dt.year, 2024)
        self.assertEqual(dt.month, 1)
        self.assertEqual(dt.day, 1)

    def testHumanTimestampToDatetimeUtc(self):
        """human_timestamp_to_datetime with to_utc=True returns UTC"""
        dt = parsedmarc.utils.human_timestamp_to_datetime(
            "2024-01-01 12:00:00", to_utc=True
        )
        self.assertEqual(dt.tzinfo, timezone.utc)

    def testHumanTimestampToDatetimeParenthesisStripping(self):
        """Parenthesized content is stripped from timestamps"""
        dt = parsedmarc.utils.human_timestamp_to_datetime(
            "Mon, 01 Jan 2024 00:00:00 +0000 (UTC)"
        )
        self.assertEqual(dt.year, 2024)

    def testHumanTimestampToDatetimeNegativeZero(self):
        """-0000 timezone is handled"""
        dt = parsedmarc.utils.human_timestamp_to_datetime("2024-01-01 00:00:00 -0000")
        self.assertEqual(dt.year, 2024)

    def testHumanTimestampToUnixTimestamp(self):
        """human_timestamp_to_unix_timestamp converts to int"""
        ts = parsedmarc.utils.human_timestamp_to_unix_timestamp("2024-01-01 00:00:00")
        self.assertIsInstance(ts, int)

    def testHumanTimestampToUnixTimestampWithT(self):
        """T separator in timestamp is handled"""
        ts = parsedmarc.utils.human_timestamp_to_unix_timestamp("2024-01-01T00:00:00")
        self.assertIsInstance(ts, int)

    def testGetIpAddressCountry(self):
        """get_ip_address_country returns country code using bundled DBIP"""
        # 8.8.8.8 is a well-known Google DNS IP in US
        country = parsedmarc.utils.get_ip_address_country("8.8.8.8")
        self.assertEqual(country, "US")

    def testGetIpAddressCountryNotFound(self):
        """get_ip_address_country returns None for reserved IP"""
        country = parsedmarc.utils.get_ip_address_country("127.0.0.1")
        self.assertIsNone(country)

    def testGetServiceFromReverseDnsBaseDomainOffline(self):
        """get_service_from_reverse_dns_base_domain in offline mode"""
        result = parsedmarc.utils.get_service_from_reverse_dns_base_domain(
            "google.com", offline=True
        )
        self.assertIn("Google", result["name"])
        self.assertIsNotNone(result["type"])

    def testGetServiceFromReverseDnsBaseDomainUnknown(self):
        """Unknown base domain returns domain as name and None as type"""
        result = parsedmarc.utils.get_service_from_reverse_dns_base_domain(
            "unknown-domain-xyz.example", offline=True
        )
        self.assertEqual(result["name"], "unknown-domain-xyz.example")
        self.assertIsNone(result["type"])

    def testGetIpAddressInfoOffline(self):
        """get_ip_address_info in offline mode returns country but no DNS"""
        info = parsedmarc.utils.get_ip_address_info("8.8.8.8", offline=True)
        self.assertEqual(info["ip_address"], "8.8.8.8")
        self.assertEqual(info["country"], "US")
        self.assertIsNone(info["reverse_dns"])

    def testGetIpAddressInfoCache(self):
        """get_ip_address_info uses cache on second call"""
        from expiringdict import ExpiringDict

        cache = ExpiringDict(max_len=100, max_age_seconds=60)
        with patch("parsedmarc.utils.get_reverse_dns", return_value="dns.google"):
            info1 = parsedmarc.utils.get_ip_address_info(
                "8.8.8.8",
                offline=False,
                cache=cache,
                always_use_local_files=True,
            )
        self.assertIn("8.8.8.8", cache)
        info2 = parsedmarc.utils.get_ip_address_info(
            "8.8.8.8", offline=False, cache=cache
        )
        self.assertEqual(info1["ip_address"], info2["ip_address"])
        self.assertEqual(info2["reverse_dns"], "dns.google")

    def testParseEmailAddressWithDisplayName(self):
        """parse_email_address with display name"""
        result = parsedmarc.utils.parse_email_address(("John Doe", "john@example.com"))  # type: ignore[arg-type]
        self.assertEqual(result["display_name"], "John Doe")
        self.assertEqual(result["address"], "john@example.com")
        self.assertEqual(result["local"], "john")
        self.assertEqual(result["domain"], "example.com")

    def testParseEmailAddressWithoutDisplayName(self):
        """parse_email_address with empty display name"""
        result = parsedmarc.utils.parse_email_address(("", "john@example.com"))  # type: ignore[arg-type]
        self.assertIsNone(result["display_name"])
        self.assertEqual(result["address"], "john@example.com")

    def testParseEmailAddressNoAt(self):
        """parse_email_address with no @ returns None local/domain"""
        result = parsedmarc.utils.parse_email_address(("", "localonly"))  # type: ignore[arg-type]
        self.assertIsNone(result["local"])
        self.assertIsNone(result["domain"])

    def testGetFilenameSafeString(self):
        """get_filename_safe_string removes invalid chars"""
        result = parsedmarc.utils.get_filename_safe_string('file/name:with"bad*chars')
        self.assertNotIn("/", result)
        self.assertNotIn(":", result)
        self.assertNotIn('"', result)
        self.assertNotIn("*", result)

    def testGetFilenameSafeStringNone(self):
        """get_filename_safe_string with None returns 'None'"""
        result = parsedmarc.utils.get_filename_safe_string(None)  # type: ignore[arg-type]
        self.assertEqual(result, "None")

    def testGetFilenameSafeStringLong(self):
        """get_filename_safe_string truncates to 100 chars"""
        result = parsedmarc.utils.get_filename_safe_string("a" * 200)
        self.assertEqual(len(result), 100)

    def testGetFilenameSafeStringTrailingDot(self):
        """get_filename_safe_string strips trailing dots"""
        result = parsedmarc.utils.get_filename_safe_string("filename...")
        self.assertFalse(result.endswith("."))

    def testIsMboxNonMbox(self):
        """is_mbox returns False for non-mbox file"""
        result = parsedmarc.utils.is_mbox("samples/empty.xml")
        self.assertFalse(result)

    def testIsOutlookMsgNonMsg(self):
        """is_outlook_msg returns False for non-MSG content"""
        self.assertFalse(parsedmarc.utils.is_outlook_msg(b"not an outlook msg"))
        self.assertFalse(parsedmarc.utils.is_outlook_msg("string content"))

    def testIsOutlookMsgMagic(self):
        """is_outlook_msg returns True for correct magic bytes"""
        magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100
        self.assertTrue(parsedmarc.utils.is_outlook_msg(magic))


class TestLoadPSLOverrides(unittest.TestCase):
    """Covers `parsedmarc.utils.load_psl_overrides`."""

    def setUp(self):
        # Snapshot the module-level list so each test leaves it as it found it.
        self._saved = list(parsedmarc.utils.psl_overrides)

    def tearDown(self):
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend(self._saved)

    def test_offline_loads_bundled_file(self):
        """offline=True populates the list from the bundled file, no network."""
        result = parsedmarc.utils.load_psl_overrides(offline=True)
        self.assertIs(result, parsedmarc.utils.psl_overrides)
        self.assertGreater(len(result), 0)
        # The bundled file is expected to contain at least one well-known entry.
        self.assertIn(".linode.com", result)

    def test_local_file_path_overrides_bundled(self):
        """A custom local_file_path takes precedence over the bundled copy."""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as tf:
            tf.write("-custom-brand.com\n.another-brand.net\n\n   \n")
            path = tf.name
        try:
            result = parsedmarc.utils.load_psl_overrides(
                offline=True, local_file_path=path
            )
            self.assertEqual(result, ["-custom-brand.com", ".another-brand.net"])
        finally:
            os.unlink(path)

    def test_clear_before_reload(self):
        """Re-running load_psl_overrides replaces the list, not appends."""
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.append(".stale-entry.com")
        parsedmarc.utils.load_psl_overrides(offline=True)
        self.assertNotIn(".stale-entry.com", parsedmarc.utils.psl_overrides)

    def test_url_success(self):
        """A 200 response from the URL populates the list."""
        fake_body = "-fetched-brand.com\n.cdn-fetched.net\n"
        mock_response = MagicMock()
        mock_response.text = fake_body
        mock_response.raise_for_status = MagicMock()
        with patch(
            "parsedmarc.utils.requests.get", return_value=mock_response
        ) as mock_get:
            result = parsedmarc.utils.load_psl_overrides(url="https://example.test/ov")
            self.assertEqual(result, ["-fetched-brand.com", ".cdn-fetched.net"])
            mock_get.assert_called_once()

    def test_url_failure_falls_back_to_local(self):
        """A network error falls back to the bundled copy."""
        import requests

        with patch(
            "parsedmarc.utils.requests.get",
            side_effect=requests.exceptions.ConnectionError("nope"),
        ):
            result = parsedmarc.utils.load_psl_overrides(url="https://example.test/ov")
        # Bundled file still loaded.
        self.assertGreater(len(result), 0)
        self.assertIn(".linode.com", result)

    def test_always_use_local_skips_network(self):
        """always_use_local_file=True must not call requests.get."""
        with patch("parsedmarc.utils.requests.get") as mock_get:
            parsedmarc.utils.load_psl_overrides(always_use_local_file=True)
            mock_get.assert_not_called()


class TestLoadReverseDnsMapReloadsPSLOverrides(unittest.TestCase):
    """`load_reverse_dns_map` must reload `psl_overrides.txt` in the same call
    so map entries that depend on folded bases resolve correctly."""

    def setUp(self):
        self._saved = list(parsedmarc.utils.psl_overrides)

    def tearDown(self):
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend(self._saved)

    def test_map_load_triggers_psl_reload(self):
        """Calling load_reverse_dns_map offline also invokes load_psl_overrides
        with matching flags, and the overrides list is repopulated."""
        rdm = {}
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.append(".stale-from-before.com")
        with patch(
            "parsedmarc.utils.load_psl_overrides",
            wraps=parsedmarc.utils.load_psl_overrides,
        ) as spy:
            parsedmarc.utils.load_reverse_dns_map(rdm, offline=True)
        spy.assert_called_once()
        kwargs = spy.call_args.kwargs
        self.assertTrue(kwargs["offline"])
        self.assertIsNone(kwargs["url"])
        self.assertIsNone(kwargs["local_file_path"])
        self.assertNotIn(".stale-from-before.com", parsedmarc.utils.psl_overrides)

    def test_map_load_forwards_psl_overrides_kwargs(self):
        """psl_overrides_path / psl_overrides_url are forwarded verbatim."""
        rdm = {}
        with patch("parsedmarc.utils.load_psl_overrides") as spy:
            parsedmarc.utils.load_reverse_dns_map(
                rdm,
                offline=True,
                always_use_local_file=True,
                psl_overrides_path="/tmp/custom.txt",
                psl_overrides_url="https://example.test/ov",
            )
        spy.assert_called_once_with(
            always_use_local_file=True,
            local_file_path="/tmp/custom.txt",
            url="https://example.test/ov",
            offline=True,
        )


class TestGetBaseDomainWithOverrides(unittest.TestCase):
    """`get_base_domain` must honour the current psl_overrides list."""

    def setUp(self):
        self._saved = list(parsedmarc.utils.psl_overrides)
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend([".cprapid.com", "-nobre.com.br"])

    def tearDown(self):
        parsedmarc.utils.psl_overrides.clear()
        parsedmarc.utils.psl_overrides.extend(self._saved)

    def test_dot_prefixed_override_folds_subdomain(self):
        result = parsedmarc.utils.get_base_domain("74-208-244-234.cprapid.com")
        self.assertEqual(result, "cprapid.com")

    def test_dash_prefixed_override_folds_subdomain(self):
        result = parsedmarc.utils.get_base_domain("host-1-2-3-4-nobre.com.br")
        self.assertEqual(result, "nobre.com.br")

    def test_unmatched_domain_falls_through_to_psl(self):
        result = parsedmarc.utils.get_base_domain("sub.example.com")
        self.assertEqual(result, "example.com")


class TestUtilsDnsCaching(unittest.TestCase):
    """Tests for DNS query caching and reverse DNS error handling"""

    def testQueryDnsUsesCacheHit(self):
        """query_dns returns cached result without making DNS query"""
        cache = ExpiringDict(max_len=100, max_age_seconds=60)
        cache["example.com_A"] = ["1.2.3.4"]
        result = parsedmarc.utils.query_dns("example.com", "A", cache=cache)
        self.assertEqual(result, ["1.2.3.4"])

    def testQueryDnsCachesResult(self):
        """query_dns stores result in cache when cache is non-empty"""
        cache = ExpiringDict(max_len=100, max_age_seconds=60)
        # Pre-populate so ExpiringDict is truthy
        cache["seed_key"] = ["seed"]
        mock_record = MagicMock()
        mock_record.to_text.return_value = '"1.2.3.4"'
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_record]
        with patch(
            "parsedmarc.utils.dns.resolver.Resolver", return_value=mock_resolver
        ):
            result = parsedmarc.utils.query_dns(
                "test-cache.example.com", "A", cache=cache
            )
            self.assertEqual(result, ["1.2.3.4"])
            self.assertIn("test-cache.example.com_A", cache)

    def testReverseDnsReturnsNoneOnFailure(self):
        """get_reverse_dns returns None on DNS exceptions"""
        with patch(
            "parsedmarc.utils.query_dns",
            side_effect=dns.exception.DNSException("timeout"),
        ):
            result = parsedmarc.utils.get_reverse_dns("203.0.113.1")
            self.assertIsNone(result)


@unittest.skipUnless(hasattr(time, "tzset"), "requires POSIX time.tzset()")
class TestTimestampAssumeUtc(unittest.TestCase):
    """Timestamp helpers must not re-interpret known-UTC strings as local
    time. Per the Python docs, naive ``datetime.timestamp()`` and
    ``datetime.astimezone()`` assume the naive value is *local* time
    (https://docs.python.org/3/library/datetime.html#datetime.datetime.timestamp),
    so a UTC wall-clock string like ``arrival_date_utc`` parsed naive comes
    out skewed by the host's UTC offset. ``assume_utc=True`` attaches
    ``timezone.utc`` instead. Regression tests for
    https://github.com/domainaware/parsedmarc/issues/811 (bug 1)."""

    # 2024-01-15 12:00:00 UTC
    UTC_STRING = "2024-01-15 12:00:00"
    TRUE_EPOCH = 1705320000

    def setUp(self):
        # Fixed non-UTC zone (UTC+1 in January) so the local-time
        # misinterpretation this guards against would shift the epoch.
        force_tz(self)

    def testAssumeUtcYieldsAwareUtcDatetime(self):
        dt = parsedmarc.utils.human_timestamp_to_datetime(
            self.UTC_STRING, assume_utc=True
        )
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(int(dt.timestamp()), self.TRUE_EPOCH)

    def testWithoutAssumeUtcNaiveIsLocal(self):
        """Documents the default: a naive parse followed by .timestamp()
        uses local time — off by one hour under Europe/Warsaw in January.
        This is the behavior arrival_date_utc consumers must avoid."""
        dt = parsedmarc.utils.human_timestamp_to_datetime(self.UTC_STRING)
        self.assertIsNone(dt.tzinfo)
        self.assertEqual(int(dt.timestamp()), self.TRUE_EPOCH - 3600)

    def testUnixTimestampHelperAssumeUtc(self):
        self.assertEqual(
            parsedmarc.utils.human_timestamp_to_unix_timestamp(
                self.UTC_STRING, assume_utc=True
            ),
            self.TRUE_EPOCH,
        )

    def testAssumeUtcDoesNotOverrideExplicitOffset(self):
        """A timestamp that carries its own offset keeps it; assume_utc
        only applies to naive parses."""
        dt = parsedmarc.utils.human_timestamp_to_datetime(
            "2024-01-15 13:00:00 +0100", assume_utc=True
        )
        self.assertEqual(int(dt.timestamp()), self.TRUE_EPOCH)


class TestUtilsIpDbPaths(unittest.TestCase):
    """Tests for IP database path validation"""

    def setUp(self):
        # These tests exercise the db-path fallback chain, which reads the
        # module-level _IP_DB_PATH set by load_ip_db(); pin it to a known
        # state and restore afterwards. The log-dedup marker is reset so
        # the "Using IP database at ..." selection log fires regardless of
        # which test (or prior lookup) ran first.
        old_ip_db_path = parsedmarc.utils._IP_DB_PATH
        old_logged_path = parsedmarc.utils._LAST_LOGGED_IP_DB_PATH
        parsedmarc.utils._IP_DB_PATH = None
        parsedmarc.utils._LAST_LOGGED_IP_DB_PATH = None

        def restore():
            parsedmarc.utils._IP_DB_PATH = old_ip_db_path
            parsedmarc.utils._LAST_LOGGED_IP_DB_PATH = old_logged_path

        self.addCleanup(restore)

    def testCustomPathFallsBack(self):
        """Non-existent custom db path falls back to default"""
        result = parsedmarc.utils.get_ip_address_country(
            "1.1.1.1", db_path="/nonexistent/path.mmdb"
        )
        self.assertTrue(result is None or isinstance(result, str))

    def testBundledDbWorks(self):
        """Bundled IP database returns results"""
        result = parsedmarc.utils.get_ip_address_country("8.8.8.8")
        self.assertEqual(result, "US")

    def testSystemGeoIpFileDoesNotShadowBundledDb(self):
        """A country-only system GeoIP file must not shadow the bundled
        IPinfo database — shadowing silently disables ASN enrichment
        because GeoLite2/DBIP country databases carry no ASN fields.
        Regression test for
        https://github.com/domainaware/parsedmarc/issues/810.

        The fallback list includes CWD-relative names, so a decoy
        ``GeoLite2-Country.mmdb`` in the working directory reproduces the
        system-file shadowing on any machine, including CI runners with no
        /usr/share/GeoIP. On the unfixed code the decoy won the path
        search before the bundled database was ever considered."""
        old_cwd = os.getcwd()
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: (os.chdir(old_cwd), shutil.rmtree(tmp_dir)))
        with open(os.path.join(tmp_dir, "GeoLite2-Country.mmdb"), "wb"):
            pass
        os.chdir(tmp_dir)

        record = parsedmarc.utils.get_ip_address_db_record("8.8.8.8")
        self.assertEqual(record["asn"], 15169)
        self.assertEqual(record["as_name"], "Google LLC")
        self.assertEqual(record["as_domain"], "google.com")

    def testLoadedDbPathTakesPrecedenceOverSystemFiles(self):
        """The database selected by load_ip_db() (_IP_DB_PATH) wins over
        any system GeoIP file. Uses a copy of the bundled database at a
        distinct path and verifies via the selection debug log that the
        copy — not a CWD decoy — is the file actually opened."""
        tmp_dir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        self.addCleanup(lambda: (os.chdir(old_cwd), shutil.rmtree(tmp_dir)))
        with open(os.path.join(tmp_dir, "GeoLite2-Country.mmdb"), "wb"):
            pass

        bundled = str(files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb"))
        loaded_copy = os.path.join(tmp_dir, "loaded.mmdb")
        shutil.copyfile(bundled, loaded_copy)
        parsedmarc.utils._IP_DB_PATH = loaded_copy
        os.chdir(tmp_dir)

        with self.assertLogs("parsedmarc.log", level="DEBUG") as cm:
            record = parsedmarc.utils.get_ip_address_db_record("8.8.8.8")
        self.assertEqual(record["asn"], 15169)
        self.assertTrue(
            any(
                f"Using IP database at {loaded_copy}" in message
                for message in cm.output
            )
        )

    def testDbSelectionIsLoggedOncePerPath(self):
        """The "Using IP database at ..." debug log fires when the
        selected path changes, not on every lookup, so --debug runs over
        large report batches aren't flooded with one line per IP."""
        with self.assertLogs("parsedmarc.log", level="DEBUG") as cm:
            parsedmarc.utils.get_ip_address_db_record("8.8.8.8")
            parsedmarc.utils.get_ip_address_db_record("1.1.1.1")
        selection_logs = [m for m in cm.output if "Using IP database at" in m]
        self.assertEqual(len(selection_logs), 1)

    def testSystemPathUsedWhenBundledDbMissing(self):
        """When the bundled database file is missing (tier 4 of the
        precedence chain), a system/CWD GeoIP path is consulted as a last
        resort. The bundled resource can't be deleted from an installed
        package, so ``parsedmarc.utils.files`` is patched to point at a
        nonexistent path; the assertion is on observable behavior — the
        record comes from the decoy file, per the selection log."""
        tmp_dir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        self.addCleanup(lambda: (os.chdir(old_cwd), shutil.rmtree(tmp_dir)))

        bundled = str(files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb"))
        decoy = os.path.join(tmp_dir, "GeoLite2-Country.mmdb")
        shutil.copyfile(bundled, decoy)
        os.chdir(tmp_dir)

        missing = os.path.join(tmp_dir, "does-not-exist.mmdb")
        with patch("parsedmarc.utils.files") as mock_files:
            mock_files.return_value.joinpath.return_value = missing
            with self.assertLogs("parsedmarc.log", level="DEBUG") as cm:
                record = parsedmarc.utils.get_ip_address_db_record("8.8.8.8")
        self.assertEqual(record["country"], "US")
        self.assertTrue(
            any(
                "Using IP database at GeoLite2-Country.mmdb" in message
                for message in cm.output
            )
        )

    def testMissingEverythingRaisesFileNotFoundError(self):
        """When neither the bundled database nor any system path exists,
        the error names the expected bundled install location."""
        tmp_dir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        self.addCleanup(lambda: (os.chdir(old_cwd), shutil.rmtree(tmp_dir)))
        os.chdir(tmp_dir)

        missing = os.path.join(tmp_dir, "does-not-exist.mmdb")
        with patch("parsedmarc.utils.files") as mock_files:
            mock_files.return_value.joinpath.return_value = missing
            with self.assertRaises(FileNotFoundError) as ctx:
                parsedmarc.utils.get_ip_address_db_record("8.8.8.8")
        self.assertIn(missing, str(ctx.exception))

    def testOldDatabaseFileWarns(self):
        """A database file older than 30 days triggers the staleness
        warning."""
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp_dir))

        bundled = str(files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb"))
        old_copy = os.path.join(tmp_dir, "old.mmdb")
        shutil.copyfile(bundled, old_copy)
        forty_days_ago = time.time() - 40 * 24 * 3600
        os.utime(old_copy, (forty_days_ago, forty_days_ago))

        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            record = parsedmarc.utils.get_ip_address_db_record(
                "8.8.8.8", db_path=old_copy
            )
        self.assertEqual(record["asn"], 15169)
        self.assertTrue(
            any(
                "IP database is more than a month old" in message
                for message in cm.output
            )
        )


class TestUtilsParseEmail(unittest.TestCase):
    """Tests for parse_email edge cases"""

    def testMinimalEmail(self):
        """parse_email handles email with minimal headers"""
        email_str = """From: test@example.com
Subject: Test

Body text"""
        result = parsedmarc.utils.parse_email(email_str)
        self.assertEqual(result["subject"], "Test")
        self.assertEqual(result["reply_to"], [])

    def testReplyToHeaderIsParsed(self):
        """A Reply-To header populates reply_to with every address.

        Regression: parse_email read mailparser's underscored
        ``reply_to`` key, but mail_json names the header ``reply-to``,
        so the lookup always missed and every Reply-To address was
        silently dropped (reply_to was always []).
        """
        email_str = (
            "From: Sender <sender@example.com>\r\n"
            "Reply-To: Real One <real@phish.example>,"
            " Second <two@phish.example>\r\n"
            "To: victim@example.org\r\n"
            "Subject: Hi\r\n\r\nBody\r\n"
        )
        result = parsedmarc.utils.parse_email(email_str)
        self.assertEqual(
            [a["address"] for a in result["reply_to"]],
            ["real@phish.example", "two@phish.example"],
        )
        self.assertEqual(result["reply_to"][0]["display_name"], "Real One")

    def testDeliveredToHeaderIsParsed(self):
        """A Delivered-To header populates delivered_to.

        Same hyphen/underscore key mismatch as reply_to: mail_json
        names the header ``delivered-to``, so reading ``delivered_to``
        dropped it.
        """
        email_str = (
            "From: Sender <sender@example.com>\r\n"
            "Delivered-To: box@example.org\r\n"
            "To: box@example.org\r\n"
            "Subject: Hi\r\n\r\nBody\r\n"
        )
        result = parsedmarc.utils.parse_email(email_str)
        self.assertEqual(
            [a["address"] for a in result["delivered_to"]], ["box@example.org"]
        )

    def testEmailWithNoSubject(self):
        """parse_email defaults subject to None when missing"""
        email_str = """From: test@example.com
To: other@example.com

Body"""
        result = parsedmarc.utils.parse_email(email_str)
        self.assertIsNone(result["subject"])

    def testEmailBytesInput(self):
        """parse_email handles bytes input"""
        email_bytes = b"""From: test@example.com
Subject: Bytes Test
To: other@example.com

Body"""
        result = parsedmarc.utils.parse_email(email_bytes)
        self.assertEqual(result["subject"], "Bytes Test")

    def testEmailWithAttachments(self):
        """parse_email with strip_attachment_payloads removes payloads"""
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders

        msg = MIMEMultipart()
        msg["From"] = "test@example.com"
        msg["To"] = "other@example.com"
        msg["Subject"] = "Attachment Test"
        msg.attach(MIMEText("Body text"))

        attachment = MIMEBase("application", "octet-stream")
        attachment.set_payload(b"file content here")
        encoders.encode_base64(attachment)
        attachment.add_header("Content-Disposition", "attachment", filename="test.bin")
        msg.attach(attachment)

        result = parsedmarc.utils.parse_email(
            msg.as_string(), strip_attachment_payloads=True
        )
        for att in result["attachments"]:
            self.assertNotIn("payload", att)

    def testEmptyFromHeaderYieldsNone(self):
        """An email whose From header is present but empty parses with
        from=None instead of crashing.

        Regression: mailparser omits "from" from mail_json when the From
        header value is unparseable, and the headers fallback read
        ``parsed_email["Headers"]`` — a key that is never set (the parsed
        headers are stored under lowercase "headers", see parse_email) —
        so any such message raised KeyError: 'Headers'.
        """
        email_str = "From:\r\nTo: a@b.com\r\nSubject: t\r\n\r\nbody\r\n"
        result = parsedmarc.utils.parse_email(email_str)
        self.assertIsNone(result["from"])

    def testCcAndBccHeadersAreParsed(self):
        """Cc and Bcc headers are parsed into address dicts"""
        email_str = (
            "From: a@b.com\r\n"
            "To: t@e.com\r\n"
            "Cc: c@d.com, C Two <c2@d.com>\r\n"
            "Bcc: e@f.com\r\n"
            "Subject: Hi\r\n\r\nBody\r\n"
        )
        result = parsedmarc.utils.parse_email(email_str)
        self.assertEqual([a["address"] for a in result["cc"]], ["c@d.com", "c2@d.com"])
        self.assertEqual(result["cc"][1]["display_name"], "C Two")
        self.assertEqual([a["address"] for a in result["bcc"]], ["e@f.com"])

    @staticmethod
    def _multipart_email(transfer_encoding: str, payload: str) -> str:
        return (
            "From: a@b.com\r\nTo: t@e.com\r\nSubject: att\r\n"
            "MIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
            "--B\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
            '--B\r\nContent-Type: application/octet-stream; name="a.bin"\r\n'
            f"Content-Transfer-Encoding: {transfer_encoding}\r\n"
            'Content-Disposition: attachment; filename="a.bin"\r\n\r\n'
            f"{payload}\r\n"
            "--B--\r\n"
        )

    def testNonBase64AttachmentIsHashed(self):
        """A non-base64 attachment's sha256 is computed over the encoded
        payload text"""
        import hashlib

        result = parsedmarc.utils.parse_email(
            self._multipart_email("7bit", "hello world")
        )
        attachments = result["attachments"]
        self.assertEqual(len(attachments), 1)
        self.assertEqual(
            attachments[0]["sha256"], hashlib.sha256(b"hello world").hexdigest()
        )

    def testUndecodableAttachmentIsKeptWithoutHash(self):
        """An attachment whose base64 payload cannot be decoded is kept,
        just without a sha256, and parsing does not crash"""
        result = parsedmarc.utils.parse_email(
            self._multipart_email("base64", "!!!notb64!!!")
        )
        attachments = result["attachments"]
        self.assertEqual(len(attachments), 1)
        self.assertNotIn("sha256", attachments[0])
        self.assertEqual(attachments[0]["payload"], "!!!notb64!!!")


class TestUtilsOutlookMsg(unittest.TestCase):
    """Tests for Outlook MSG detection and conversion"""

    MSG_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    def testIsOutlookMsg(self):
        """is_outlook_msg detects MSG magic bytes"""
        msg_magic = self.MSG_MAGIC + b"\x00" * 100
        self.assertTrue(parsedmarc.utils.is_outlook_msg(msg_magic))

    def testIsNotOutlookMsg(self):
        """is_outlook_msg rejects non-MSG content"""
        self.assertFalse(parsedmarc.utils.is_outlook_msg(b"not an msg file"))
        self.assertFalse(parsedmarc.utils.is_outlook_msg("string input"))

    def testConvertOutlookMsgInvalidInput(self):
        """convert_outlook_msg raises ValueError for non-MSG bytes"""
        with self.assertRaises(ValueError):
            parsedmarc.utils.convert_outlook_msg(b"not an msg file")

    def testConvertOutlookMsgMissingUtility(self):
        """A missing msgconvert utility raises EmailParserError, and the
        working directory is restored"""
        old_cwd = os.getcwd()
        with patch(
            "parsedmarc.utils.subprocess.check_call",
            side_effect=FileNotFoundError("msgconvert"),
        ):
            with self.assertRaises(parsedmarc.utils.EmailParserError):
                parsedmarc.utils.convert_outlook_msg(self.MSG_MAGIC + b"\x00" * 100)
        self.assertEqual(os.getcwd(), old_cwd)

    def testConvertOutlookMsgReadsConvertedFile(self):
        """convert_outlook_msg writes the .msg for msgconvert, reads back
        the .eml it produces, and restores the working directory. The
        subprocess boundary is mocked with a fake msgconvert that converts
        the temp .msg into a fixed RFC 822 message."""
        rfc822 = b"From: a@b.com\r\nSubject: converted\r\n\r\nhi\r\n"

        def fake_msgconvert(args, stdout=None, stderr=None):
            # msgconvert is invoked in a temp dir containing sample.msg
            # and writes sample.eml next to it.
            self.assertEqual(args, ["msgconvert", "sample.msg"])
            with open("sample.msg", "rb") as f:
                self.assertTrue(parsedmarc.utils.is_outlook_msg(f.read()))
            with open("sample.eml", "wb") as f:
                f.write(rfc822)

        old_cwd = os.getcwd()
        with patch(
            "parsedmarc.utils.subprocess.check_call", side_effect=fake_msgconvert
        ):
            result = parsedmarc.utils.convert_outlook_msg(
                self.MSG_MAGIC + b"\x00" * 100
            )
        self.assertEqual(result, rfc822)
        self.assertEqual(os.getcwd(), old_cwd)

    def testParseEmailConvertsOutlookMsgBytes(self):
        """parse_email detects Outlook MSG bytes and parses the converted
        RFC 822 output"""

        def fake_msgconvert(args, stdout=None, stderr=None):
            with open("sample.eml", "wb") as f:
                f.write(b"From: a@b.com\r\nSubject: from msg\r\n\r\nhi\r\n")

        with patch(
            "parsedmarc.utils.subprocess.check_call", side_effect=fake_msgconvert
        ):
            result = parsedmarc.utils.parse_email(self.MSG_MAGIC + b"\x00" * 100)
        self.assertEqual(result["subject"], "from msg")


class TestUtilsReverseDnsMap(unittest.TestCase):
    """Tests for reverse DNS map loading"""

    def testLoadReverseDnsMapOffline(self):
        """load_reverse_dns_map in offline mode loads bundled map"""
        rdns_map = {}
        parsedmarc.utils.load_reverse_dns_map(rdns_map, offline=True)
        self.assertTrue(len(rdns_map) > 0)

    def testLoadReverseDnsMapLocalOverride(self):
        """load_reverse_dns_map uses local_file_path when provided"""
        with NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            f.write("base_reverse_dns,name,type\n")
            f.write("custom.example.com,Custom Service,hosting\n")
            path = f.name
        try:
            rdns_map = {}
            parsedmarc.utils.load_reverse_dns_map(
                rdns_map, offline=True, local_file_path=path
            )
            self.assertIn("custom.example.com", rdns_map)
            self.assertEqual(rdns_map["custom.example.com"]["name"], "Custom Service")
        finally:
            os.remove(path)

    def testLoadReverseDnsMapNetworkFailureFallback(self):
        """load_reverse_dns_map falls back to bundled on network error"""
        rdns_map = {}
        with patch(
            "parsedmarc.utils.requests.get",
            side_effect=requests.exceptions.ConnectionError("no network"),
        ):
            parsedmarc.utils.load_reverse_dns_map(rdns_map)
        self.assertTrue(len(rdns_map) > 0)

    def testLoadReverseDnsMapInvalidCsvFallback(self):
        """A fetch that returns a non-map CSV body logs a warning and
        falls back to the bundled map"""
        response = MagicMock()
        response.text = "not,the,map\nfoo,bar,baz\n"
        response.raise_for_status.return_value = None
        rdns_map = {}
        with patch("parsedmarc.utils.requests.get", return_value=response):
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                parsedmarc.utils.load_reverse_dns_map(rdns_map)
        self.assertTrue(any("Not a valid CSV file" in message for message in cm.output))
        self.assertGreater(len(rdns_map), 0)

    def testGetServiceUsesProvidedMap(self):
        """get_service_from_reverse_dns_base_domain consults a caller-
        provided non-empty map without loading anything"""
        provided: parsedmarc.utils.ReverseDNSMap = {
            "custom.example": {"name": "Custom Co", "type": "SaaS"}
        }
        with patch("parsedmarc.utils.load_reverse_dns_map") as mock_load:
            service = parsedmarc.utils.get_service_from_reverse_dns_base_domain(
                "Custom.Example", reverse_dns_map=provided
            )
        mock_load.assert_not_called()
        self.assertEqual(service["name"], "Custom Co")
        self.assertEqual(service["type"], "SaaS")


class TestPslOverrides(unittest.TestCase):
    """Tests for PSL override matching"""

    def testOverrideMatch(self):
        """PSL overrides are applied when domain ends with override"""
        # psl_overrides contains entries; test that get_base_domain
        # handles them without error
        result = parsedmarc.utils.get_base_domain("sub.example.com")
        self.assertEqual(result, "example.com")


class TestIsMbox(unittest.TestCase):
    """Tests for is_mbox utility"""

    def testValidMbox(self):
        """is_mbox returns True for valid mbox file"""
        with NamedTemporaryFile(suffix=".mbox", delete=False, mode="w") as f:
            f.write("From test@example.com Thu Jan  1 00:00:00 2024\n")
            f.write("Subject: Test\n\nBody\n\n")
            path = f.name
        try:
            self.assertTrue(parsedmarc.utils.is_mbox(path))
        finally:
            os.remove(path)

    def testEmptyFileNotMbox(self):
        """is_mbox returns False for empty file"""
        with NamedTemporaryFile(suffix=".mbox", delete=False) as f:
            path = f.name
        try:
            self.assertFalse(parsedmarc.utils.is_mbox(path))
        finally:
            os.remove(path)

    def testNonExistentNotMbox(self):
        """is_mbox returns False for non-existent file"""
        self.assertFalse(parsedmarc.utils.is_mbox("/nonexistent/file.mbox"))


class TestQueryDnsRetries(unittest.TestCase):
    """Tests for the query_dns transient-error retry loop, mocking at the
    dnspython SDK boundary (Resolver.resolve)."""

    def testTransientErrorIsRetried(self):
        """A retryable error (OSError is in _RETRYABLE_DNS_ERRORS) on the
        first attempt is retried, and the second attempt's answers are
        returned. A single nameserver is passed so the single-nameserver
        lifetime branch is exercised too."""
        answer = MagicMock()
        answer.to_text.return_value = "mail.example.com."
        with patch.object(
            dns.resolver.Resolver,
            "resolve",
            side_effect=[OSError("transient network error"), [answer]],
        ) as mock_resolve:
            records = parsedmarc.utils.query_dns(
                "example.com",
                "A",
                nameservers=["192.0.2.53"],
                timeout=0.1,
                retries=1,
            )
        self.assertEqual(records, ["mail.example.com"])
        self.assertEqual(mock_resolve.call_count, 2)

    def testErrorRaisedAfterRetriesExhausted(self):
        """When every attempt fails, the last error propagates after
        retries+1 total attempts."""
        with patch.object(
            dns.resolver.Resolver,
            "resolve",
            side_effect=OSError("persistent network error"),
        ) as mock_resolve:
            with self.assertRaises(OSError):
                parsedmarc.utils.query_dns(
                    "example.com",
                    "A",
                    nameservers=["192.0.2.53"],
                    timeout=0.1,
                    retries=2,
                )
        self.assertEqual(mock_resolve.call_count, 3)


class TestLoadIpDb(unittest.TestCase):
    """Tests for the load_ip_db() download/cache/bundled fallback chain,
    mocking at the requests SDK boundary."""

    def setUp(self):
        old_ip_db_path = parsedmarc.utils._IP_DB_PATH
        parsedmarc.utils._IP_DB_PATH = None

        def restore():
            parsedmarc.utils._IP_DB_PATH = old_ip_db_path

        self.addCleanup(restore)

        # Redirect the download cache into a per-test directory so the
        # tests never touch (or depend on) the real tempdir cache.
        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tmp_dir, ignore_errors=True))
        patcher = patch(
            "parsedmarc.utils.tempfile.gettempdir", return_value=self.tmp_dir
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def testExistingLocalFileIsUsedDirectly(self):
        """An existing local_file_path wins without any network request"""
        local_path = os.path.join(self.tmp_dir, "local.mmdb")
        with open(local_path, "wb") as f:
            f.write(b"local db")
        with patch("parsedmarc.utils.requests.get") as mock_get:
            parsedmarc.utils.load_ip_db(local_file_path=local_path)
        mock_get.assert_not_called()
        self.assertEqual(parsedmarc.utils._IP_DB_PATH, local_path)

    def testDownloadSuccessWritesCacheFile(self):
        """A successful download is written to the cache path and selected"""
        response = MagicMock()
        response.content = b"downloaded db bytes"
        response.raise_for_status.return_value = None
        with patch("parsedmarc.utils.requests.get", return_value=response) as mock_get:
            parsedmarc.utils.load_ip_db(url="https://example.com/db.mmdb")
        self.assertEqual(mock_get.call_args.args[0], "https://example.com/db.mmdb")
        cached_path = os.path.join(self.tmp_dir, "parsedmarc", "ipinfo_lite.mmdb")
        self.assertEqual(parsedmarc.utils._IP_DB_PATH, cached_path)
        with open(cached_path, "rb") as f:
            self.assertEqual(f.read(), b"downloaded db bytes")

    def testDownloadFailureFallsBackToCachedCopy(self):
        """On a network error, a previously cached copy is selected"""
        cache_dir = os.path.join(self.tmp_dir, "parsedmarc")
        os.makedirs(cache_dir)
        cached_path = os.path.join(cache_dir, "ipinfo_lite.mmdb")
        with open(cached_path, "wb") as f:
            f.write(b"stale cached db")
        with patch(
            "parsedmarc.utils.requests.get",
            side_effect=requests.exceptions.ConnectionError("no network"),
        ):
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                parsedmarc.utils.load_ip_db()
        self.assertTrue(
            any("Failed to fetch IP database" in message for message in cm.output)
        )
        self.assertEqual(parsedmarc.utils._IP_DB_PATH, cached_path)

    def testDownloadFailureFallsBackToBundledCopy(self):
        """On a network error with no cached copy, the bundled db is used"""
        with patch(
            "parsedmarc.utils.requests.get",
            side_effect=requests.exceptions.ConnectionError("no network"),
        ):
            parsedmarc.utils.load_ip_db()
        bundled = str(files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb"))
        self.assertEqual(parsedmarc.utils._IP_DB_PATH, bundled)

    def testSaveFailureFallsBackToBundledCopy(self):
        """A download that cannot be written to disk logs a warning and
        falls back to the bundled db instead of crashing. The cache dir is
        made uncreatable by pointing gettempdir at a regular file."""
        blocker = os.path.join(self.tmp_dir, "blocker")
        with open(blocker, "wb") as f:
            f.write(b"not a directory")
        response = MagicMock()
        response.content = b"downloaded db bytes"
        response.raise_for_status.return_value = None
        with patch("parsedmarc.utils.tempfile.gettempdir", return_value=blocker):
            with patch("parsedmarc.utils.requests.get", return_value=response):
                with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                    parsedmarc.utils.load_ip_db()
        self.assertTrue(
            any("Failed to save IP database" in message for message in cm.output)
        )
        bundled = str(files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb"))
        self.assertEqual(parsedmarc.utils._IP_DB_PATH, bundled)


class TestConfigureIpinfoApiProbe(unittest.TestCase):
    """Tests for the configure_ipinfo_api() token probe."""

    def setUp(self):
        self.addCleanup(parsedmarc.utils.configure_ipinfo_api, None)

    @staticmethod
    def _response(status_code, json_body=None):
        response = MagicMock()
        response.status_code = status_code
        response.ok = 200 <= status_code < 300
        response.json.return_value = json_body if json_body is not None else {}
        return response

    def testProbeSuccessLogsConfigured(self):
        """A successful probe logs that the API is configured"""
        api_json = {"ip": "1.1.1.1", "asn": "AS13335", "country_code": "US"}
        with patch(
            "parsedmarc.utils.requests.get",
            return_value=self._response(200, api_json),
        ):
            with self.assertLogs("parsedmarc.log", level="INFO") as cm:
                parsedmarc.utils.configure_ipinfo_api("fake-token", probe=True)
        self.assertTrue(
            any("IPinfo API configured" in message for message in cm.output)
        )

    def testProbeNetworkErrorKeepsToken(self):
        """A probe network error logs a warning but keeps the token so
        per-request fallback can take over later"""
        with patch(
            "parsedmarc.utils.requests.get",
            side_effect=requests.exceptions.ConnectionError("no network"),
        ):
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                parsedmarc.utils.configure_ipinfo_api("fake-token", probe=True)
        self.assertTrue(
            any("IPinfo API probe failed" in message for message in cm.output)
        )
        self.assertEqual(parsedmarc.utils._IPINFO_API_TOKEN, "fake-token")

    def testProbeInvalidKeyRaises(self):
        """A 401 during the probe raises InvalidIPinfoAPIKey"""
        with patch("parsedmarc.utils.requests.get", return_value=self._response(401)):
            with self.assertRaises(parsedmarc.utils.InvalidIPinfoAPIKey):
                parsedmarc.utils.configure_ipinfo_api("bad-token", probe=True)


class TestIpinfoApiLookupFallbacks(unittest.TestCase):
    """API lookup failures other than 401/403 must fall back to the MMDB
    silently: network errors, non-JSON bodies, and non-dict payloads."""

    def setUp(self):
        parsedmarc.utils.configure_ipinfo_api("fake-token", probe=False)
        self.addCleanup(parsedmarc.utils.configure_ipinfo_api, None)

    def _assert_mmdb_fallback(self, response=None, side_effect=None):
        with patch(
            "parsedmarc.utils.requests.get",
            return_value=response,
            side_effect=side_effect,
        ):
            record = parsedmarc.utils.get_ip_address_db_record("8.8.8.8")
        # The bundled MMDB attributes 8.8.8.8 to Google's ASN.
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["asn"], 15169)

    def testNetworkErrorFallsBackToMmdb(self):
        self._assert_mmdb_fallback(
            side_effect=requests.exceptions.ConnectionError("no network")
        )

    def testNonJsonBodyFallsBackToMmdb(self):
        response = MagicMock()
        response.status_code = 200
        response.ok = True
        response.json.side_effect = ValueError("not JSON")
        self._assert_mmdb_fallback(response=response)

    def testNonDictPayloadFallsBackToMmdb(self):
        response = MagicMock()
        response.status_code = 200
        response.ok = True
        response.json.return_value = ["not", "a", "dict"]
        self._assert_mmdb_fallback(response=response)


class TestNormalizeIpRecord(unittest.TestCase):
    """_normalize_ip_record must produce the same internal shape from both
    the IPinfo API schema and the MaxMind MMDB schema."""

    def testMaxMindSchema(self):
        """MaxMind-style records (nested country iso_code, ASN under
        autonomous_system_number/organization) normalize correctly"""
        record = parsedmarc.utils._normalize_ip_record(
            {
                "country": {"iso_code": "US"},
                "autonomous_system_number": 15169,
                "autonomous_system_organization": "Google LLC",
            }
        )
        self.assertEqual(record["country"], "US")
        self.assertEqual(record["asn"], 15169)
        self.assertEqual(record["as_name"], "Google LLC")
        self.assertIsNone(record["as_domain"])

    def testIntegerAsnPassesThrough(self):
        """An already-integer asn field is stored as-is, and as_domain is
        lowercased on the way in"""
        record = parsedmarc.utils._normalize_ip_record(
            {"country_code": "US", "asn": 64496, "as_domain": "EXAMPLE.com"}
        )
        self.assertEqual(record["asn"], 64496)
        self.assertEqual(record["as_domain"], "example.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
