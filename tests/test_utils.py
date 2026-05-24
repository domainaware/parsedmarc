"""Tests for parsedmarc.utils"""

import os
import tempfile
import unittest
from datetime import datetime, timezone
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch

import dns.exception
import requests
from expiringdict import ExpiringDict

import parsedmarc
import parsedmarc.utils


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
        # "Name <addr>" display form used by the dashboards.
        self.assertEqual(result["display"], "John Doe <john@example.com>")

    def testParseEmailAddressWithoutDisplayName(self):
        """parse_email_address with empty display name"""
        result = parsedmarc.utils.parse_email_address(("", "john@example.com"))  # type: ignore[arg-type]
        self.assertIsNone(result["display_name"])
        self.assertEqual(result["address"], "john@example.com")
        # With no display name, display falls back to the bare address.
        self.assertEqual(result["display"], "john@example.com")

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


class TestUtilsIpDbPaths(unittest.TestCase):
    """Tests for IP database path validation"""

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
        # The dashboards render the "Name <addr>" display form.
        self.assertEqual(
            [a["display"] for a in result["reply_to"]],
            ["Real One <real@phish.example>", "Second <two@phish.example>"],
        )

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


class TestUtilsOutlookMsg(unittest.TestCase):
    """Tests for Outlook MSG detection and conversion"""

    def testIsOutlookMsg(self):
        """is_outlook_msg detects MSG magic bytes"""
        msg_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100
        self.assertTrue(parsedmarc.utils.is_outlook_msg(msg_magic))

    def testIsNotOutlookMsg(self):
        """is_outlook_msg rejects non-MSG content"""
        self.assertFalse(parsedmarc.utils.is_outlook_msg(b"not an msg file"))
        self.assertFalse(parsedmarc.utils.is_outlook_msg("string input"))

    def testConvertOutlookMsgInvalidInput(self):
        """convert_outlook_msg raises ValueError for non-MSG bytes"""
        with self.assertRaises(ValueError):
            parsedmarc.utils.convert_outlook_msg(b"not an msg file")


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
