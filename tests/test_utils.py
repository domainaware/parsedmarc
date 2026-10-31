"""Tests for parsedmarc.utils"""

import os
import shutil
import tempfile
import time
import traceback
import unittest
from datetime import datetime, timezone
from importlib.resources import files
from tempfile import NamedTemporaryFile
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import dns.exception
import dns.message
import dns.nameserver
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx
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
        # A mocked DB record whose as_domain is not in the reverse-DNS map
        # exercises the as_name fallback branch without depending on a
        # specific map state.
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
            resp.is_success = 200 <= status_code < 300
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
                "parsedmarc.utils.httpx.get",
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
                "parsedmarc.utils.httpx.get",
                return_value=_mock_response(401),
            ):
                configure_ipinfo_api("bad-token", probe=False)
                with self.assertRaises(InvalidIPinfoAPIKey):
                    get_ip_address_db_record("8.8.8.8")

            # Any other non-2xx (e.g. 500, 503) falls back to the MMDB silently.
            configure_ipinfo_api("fake-token", probe=False)
            with patch(
                "parsedmarc.utils.httpx.get",
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
        # A tab before the comment, and more than one comment, are stripped
        # too.
        self.assertEqual(
            parsedmarc.utils.human_timestamp_to_datetime(
                "Tue, 1 Jan 2019 00:00:00 +0000\t(GMT)"
            ),
            datetime(2019, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(
            parsedmarc.utils.human_timestamp_to_datetime(
                "Mon, 01 Jan 2024 00:00:00 +0000 (x) (y)"
            ),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        # RFC 5322 section 3.2.2 lets comments nest and contain quoted-pairs;
        # a regex cannot strip those, which is why a depth-counting scan does.
        self.assertEqual(
            parsedmarc.utils.human_timestamp_to_datetime(
                "Mon, 01 Jan 2024 00:00:00 +0000 (a (b) c)"
            ),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(
            parsedmarc.utils.human_timestamp_to_datetime(
                "Mon, 01 Jan 2024 00:00:00 +0000 (\\) x)"
            ),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

    def testHumanTimestampToDatetimeWhitespaceIsLinear(self):
        """A whitespace-padded timestamp is rejected in linear time.

        Comments were stripped with the regex ``\\s*\\(.*\\)\\s*``, whose
        leading ``\\s*`` was retried from every position in a whitespace run
        — quadratic, so 200,000 spaces took 18.6 s. The function runs on
        every message's Date header. The 5 s bound is not flaky: the
        depth-counting scan handles this input in milliseconds, orders of
        magnitude below both the bound and the old pattern's cost. The
        comment is left unclosed so the old pattern can never match: with a
        closing parenthesis its first attempt succeeded and the backtracking
        never happened."""
        start = time.perf_counter()
        # dateutil's ParserError subclasses ValueError.
        with self.assertRaises(ValueError):
            parsedmarc.utils.human_timestamp_to_datetime(" " * 200_000 + "(x")
        self.assertLess(time.perf_counter() - start, 5)

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
        result = parsedmarc.utils.get_filename_safe_string(None)
        self.assertEqual(result, "None")

    def testGetFilenameSafeStringTraversalSequencesCollapseToEmpty(self):
        """A subject made only of path separators and dots sanitizes to the
        empty string, so a caller's `or "sample"` fallback takes over rather
        than a relative path reaching os.path.join()

        Regression test for GHSA-c284-w5m6-jhjm: `../../../` and `/` are the
        reporter's proof-of-concept subjects."""
        for traversal in ("../../../", "/", "..", ".", "..\\..\\", "./../"):
            with self.subTest(traversal=traversal):
                self.assertEqual(
                    parsedmarc.utils.get_filename_safe_string(traversal), ""
                )

    def testGetFilenameSafeStringStripsNullByte(self):
        """A NUL byte is stripped, so the result cannot make open() raise
        ValueError: embedded null byte"""
        result = parsedmarc.utils.get_filename_safe_string("re\x00port")
        self.assertEqual(result, "report")

    def testGetFilenameSafeStringHasNoPathSeparators(self):
        """No os.sep or os.altsep survives a mixed-separator subject"""
        result = parsedmarc.utils.get_filename_safe_string("a/b\\c:d..\\..\\e/../f")
        self.assertEqual(result, "abcd....e..f")
        self.assertNotIn(os.sep, result)
        if os.altsep is not None:
            self.assertNotIn(os.altsep, result)

    def testGetFilenameSafeStringTruncatedNameHasNoTrailingDot(self):
        """Truncation happens before trailing dots are stripped, so a name
        cut off just after a dot does not end in one

        A trailing dot is silently dropped by Windows when the file is
        created, which would make two distinct subjects collide on one
        filename."""
        subject = f"{'a' * 99}.{'b' * 50}"
        result = parsedmarc.utils.get_filename_safe_string(subject)
        self.assertEqual(result, "a" * 99)
        self.assertFalse(result.endswith("."))

    def testGetFilenameSafeStringStripsTrailingSpaces(self):
        """Trailing spaces are stripped like trailing dots, and mixed runs of
        both, because Windows drops them when creating the file"""
        for subject, expected in (("report ", "report"), ("report . .", "report")):
            with self.subTest(subject=subject):
                self.assertEqual(
                    parsedmarc.utils.get_filename_safe_string(subject), expected
                )

    def testGetFilenameSafeStringLong(self):
        """get_filename_safe_string truncates to 100 chars"""
        result = parsedmarc.utils.get_filename_safe_string("a" * 200)
        self.assertEqual(len(result), 100)

    def testGetFilenameSafeStringBoundsUtf8Bytes(self):
        """Multi-byte names are truncated to at most 100 UTF-8 bytes, never
        splitting a character, so the name plus an extension can be created.

        Regression test for GHSA-j53g-34vj-g25q: the name was truncated to
        100 *characters*, but filesystems limit a name component to 255
        *bytes*, so 84 three-byte CJK characters or 63 four-byte emoji plus
        ``.eml`` (256 bytes) made ``save_output()`` fail with
        ``ENAMETOOLONG``."""
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        for subject, expected in (
            # 33 whole characters (99 bytes); the 34th would straddle byte 100.
            ("\u4e2d" * 84, "\u4e2d" * 33),
            # Exactly 25 four-byte characters fit in 100 bytes.
            ("\U0001f600" * 63, "\U0001f600" * 25),
        ):
            with self.subTest(subject=subject[:1]):
                result = parsedmarc.utils.get_filename_safe_string(subject)
                self.assertEqual(result, expected)
                encoded = result.encode("utf-8")
                self.assertLessEqual(len(encoded), 100)
                # A strict round trip proves no partial character survived.
                self.assertEqual(encoded.decode("utf-8"), result)
                path = os.path.join(tmpdir, result + ".eml")
                with open(path, "w") as f:
                    f.write("sample")
                self.assertTrue(os.path.isfile(path))

    def testGetFilenameSafeStringByteCutAfterDotIsStripped(self):
        """When the byte bound cuts the name just after a dot, the dot is
        still stripped: 33 CJK characters (99 bytes) and a dot fill exactly
        100 bytes, and the name stays under the 100-character bound."""
        subject = "\u4e2d" * 33 + "." + "\u4e2d" * 10
        result = parsedmarc.utils.get_filename_safe_string(subject)
        self.assertEqual(result, "\u4e2d" * 33)

    def testGetFilenameSafeStringDropsLoneSurrogates(self):
        """A lone surrogate cannot be encoded as UTF-8 (or used in a file
        name), so it is dropped rather than raising."""
        result = parsedmarc.utils.get_filename_safe_string("re\ud800port")
        self.assertEqual(result, "report")

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


class TestRedactUrlCredentials(unittest.TestCase):
    """Tests for parsedmarc.utils.redact_url_credentials()"""

    def testMasksUserinfoAndKeepsHost(self):
        cases = [
            ("https://user:secret@host", "https://user:***@host"),
            ("https://user:secret@host:9200/", "https://user:***@host:9200/"),
            ("localhost:9200", "localhost:9200"),
            ("127.0.0.1:9299", "127.0.0.1:9299"),
            ("user:secret@localhost:9200", "user:***@localhost:9200"),
            # A "://" in the path or query of a scheme-less value is not
            # the scheme separator; the userinfo at offset 0 is still masked
            (
                "user:secret@host:9200/x?r=http://y",
                "user:***@host:9200/x?r=http://y",
            ),
            ("user:secret@host?r=a://b", "user:***@host?r=a://b"),
            ("https://user:p@ss@host/x", "https://user:***@host/x"),
            ("https://user:p:w@[::1]:9200/", "https://user:***@[::1]:9200/"),
            ("https://[::1]:9200", "https://[::1]:9200"),
            ("//user:pw@host", "//user:***@host"),
            # Documented over-masking: with no "@" in the authority, an "@"
            # later in the value is masked through, since it may end a
            # password that contains "/", "?" or "#"
            ("http://host/path?e=a@b.com", "http://***@b.com"),
            ("https://host/path@file", "https://***@file"),
            ("https://host/?redirect=https://u:p@evil", "https://***@evil"),
            # Documented non-goal: with userinfo in the authority, credentials
            # inside a later query value are not masked
            (
                "https://a:b@host/?redirect=https://u:p@evil",
                "https://a:***@host/?redirect=https://u:p@evil",
            ),
            ("https://tok@host", "https://***@host"),
            ("user@host:9200", "***@host:9200"),
            ("https://user:@host", "https://user:***@host"),
            ("https://u%40x:p%3Aw@h", "https://u%40x:***@h"),
            ("not a url @ all", "***@ all"),
            ("", ""),
            ("::::", "::::"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    parsedmarc.utils.redact_url_credentials(value), expected
                )

    def testMasksPasswordContainingAuthorityDelimiter(self):
        """A password with an unencoded "/", "?" or "#" ends the authority
        before the "@" (RFC 3986 section 3.2), which used to leave the value
        unmasked; everything through the last "@" is masked instead."""
        cases = [
            ("https://admin:p4ssw0rd/extra@host:3100", "https://***@host:3100"),
            ("https://admin:p4ss?w0rd@host", "https://***@host"),
            ("https://admin:p4ss#w0rd@host", "https://***@host"),
            ("admin:p4ss/w0rd@host:9200", "***@host:9200"),
            ("//admin:p4ss/w0rd@host", "//***@host"),
            # The password may itself contain "@"; the last one is used
            ("https://admin:p4ss/w@rd@host:3100/x", "https://***@host:3100/x"),
            # A "://" after the "/" is not the scheme separator
            (
                "admin:p4ss/w0rd@host/x?r=http://y",
                "***@host/x?r=http://y",
            ),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                result = parsedmarc.utils.redact_url_credentials(value)
                self.assertEqual(result, expected)
                self.assertNotIn("p4ss", result)

    def testListMasksPasswordContainingAuthorityDelimiter(self):
        self.assertEqual(
            parsedmarc.utils.redact_url_credentials(
                ["https://admin:p4ss/w0rd@h1:9200", "https://h2:9200"]
            ),
            ["https://***@h1:9200", "https://h2:9200"],
        )

    def testListIsRedactedElementWiseIntoANewList(self):
        original = ["a:b@h1", "https://h2"]
        result = parsedmarc.utils.redact_url_credentials(original)
        self.assertEqual(result, ["a:***@h1", "https://h2"])
        self.assertIsNot(result, original)
        self.assertEqual(original, ["a:b@h1", "https://h2"])

    def testListKeepsNonStringItems(self):
        mixed = cast(list[str], ["a:b@h1", None])
        self.assertEqual(
            parsedmarc.utils.redact_url_credentials(mixed), ["a:***@h1", None]
        )

    def testNonStringInputIsReturnedUnchanged(self):
        for value in (None, 42):
            with self.subTest(value=value):
                self.assertEqual(
                    parsedmarc.utils.redact_url_credentials(cast(str, value)), value
                )

    def testLongInputsAreFast(self):
        """No regex is used, so adversarial input is linear. A 1 MB string
        of repeated openers and a 200,000-character run of '@' both finish
        in milliseconds."""
        for value in (
            "://" * 350_000,
            "@" * 200_000,
            "a:b@" * 250_000,
            "a:b/" * 250_000 + "@",
            "/@" * 500_000,
        ):
            with self.subTest(prefix=value[:8]):
                started = time.monotonic()
                parsedmarc.utils.redact_url_credentials(value)
                self.assertLess(time.monotonic() - started, 5)


class TestSanitizeForLog(unittest.TestCase):
    """Tests for parsedmarc.utils.sanitize_for_log()"""

    def testEscapesNonPrintableAndKeepsPrintable(self):
        cases = [
            ("plain ASCII", "plain ASCII"),
            ("", ""),
            ("line1\r\nINJECTED fake log", "line1\\r\\nINJECTED fake log"),
            ("a\tb", "a\\tb"),
            ("\x1b[31mred", "\\x1b[31mred"),
            ("a\u2028b", "a\\u2028b"),
            ("nul\x00byte", "nul\\x00byte"),
            ("\u65e5\u672c\u8a9e report", "\u65e5\u672c\u8a9e report"),
            ("ok \U0001f600", "ok \U0001f600"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(parsedmarc.utils.sanitize_for_log(value), expected)

    def testResultHasNoRawControlCharacters(self):
        result = parsedmarc.utils.sanitize_for_log("a\r\nb\nc\rd")
        self.assertNotIn("\r", result)
        self.assertNotIn("\n", result)


class TestDownloadUrlCredentialsNotLogged(unittest.TestCase):
    """A download URL with userinfo must not leak its password through the
    "Trying to fetch" debug line or the warning that embeds the httpx
    ``HTTPStatusError`` message (which quotes the full URL).

    The loaders run for real; only the network is replaced, with an
    ``httpx.MockTransport`` returning 401 so httpx itself builds the
    exception text.
    """

    URL = "https://dluser:DLSECRET@downloads.example.test/map.dat"

    @staticmethod
    def _transport_returning(handler):
        def get(url, **kwargs):
            with httpx.Client(transport=httpx.MockTransport(handler)) as client:
                return client.get(url, **kwargs)

        return get

    @classmethod
    def _status_getter(cls, reason_phrase=None):
        extensions = {}
        if reason_phrase is not None:
            extensions["reason_phrase"] = reason_phrase
        return cls._transport_returning(
            lambda request: httpx.Response(401, extensions=extensions)
        )

    @staticmethod
    def _connect_error_getter(url, **kwargs):
        def handler(request):
            raise httpx.ConnectError("connection refused", request=request)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return client.get(url, **kwargs)

    # Reason phrases containing URL delimiters used to defeat redaction of
    # the HTTPStatusError text, which puts the phrase before the URL.
    REASON_PHRASES = (
        None,
        b"Unauthorized/Expired",
        b"Unauthorized?",
        b"Gone#",
        b"Not @ home",
    )

    def _assert_redacted(self, logs):
        output = "\n".join(logs.output)
        self.assertNotIn("DLSECRET", output)
        self.assertTrue(
            any(
                line.startswith("DEBUG") and "downloads.example.test" in line
                for line in logs.output
            ),
            output,
        )
        warnings = [line for line in logs.output if line.startswith("WARNING")]
        self.assertTrue(
            any(
                "HTTP 401" in line
                and "'https://dluser:***@downloads.example.test/map.dat'" in line
                for line in warnings
            ),
            output,
        )

    def _run_psl(self, url=None):
        with self.assertLogs("parsedmarc.log", level="DEBUG") as logs:
            parsedmarc.utils.load_psl_overrides(url=url or self.URL)
        return logs

    def _run_ip_db(self, url=None):
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp_dir, ignore_errors=True)
        old_path = parsedmarc.utils._IP_DB_PATH
        self.addCleanup(setattr, parsedmarc.utils, "_IP_DB_PATH", old_path)
        parsedmarc.utils._IP_DB_PATH = None
        with (
            patch("parsedmarc.utils.tempfile.gettempdir", return_value=tmp_dir),
            self.assertLogs("parsedmarc.log", level="DEBUG") as logs,
        ):
            parsedmarc.utils.load_ip_db(url=url or self.URL)
        return logs

    def _run_reverse_dns_map(self, url=None):
        with self.assertLogs("parsedmarc.log", level="DEBUG") as logs:
            parsedmarc.utils.load_reverse_dns_map({}, url=url or self.URL)
        return logs

    def _check_loader(self, run):
        for phrase in self.REASON_PHRASES:
            with self.subTest(reason_phrase=phrase):
                with patch("parsedmarc.utils.httpx.get", self._status_getter(phrase)):
                    self._assert_redacted(run())

    def _check_transport_error(self, run):
        with patch("parsedmarc.utils.httpx.get", self._connect_error_getter):
            logs = run()
        output = "\n".join(logs.output)
        self.assertNotIn("DLSECRET", output)
        self.assertTrue(
            any(
                line.startswith("WARNING")
                and "ConnectError: connection refused" in line
                for line in logs.output
            ),
            output,
        )

    # The password holds an unencoded "/", "?" or "#", which RFC 3986 section
    # 3.2 ends the authority at, so the text after the colon is read as the
    # port. Real httpx raises InvalidURL("Invalid port: 'p4ssw0rd'") while
    # parsing, before any network I/O (httpx 0.28.1 _urlparse.py:
    # ``raise InvalidURL(f"Invalid port: {port!r}")``). InvalidURL is not an
    # httpx.HTTPError, and its message quotes part of the password.
    MALFORMED_URLS = (
        ("https://admin:p4ssw0rd/extra@downloads.example.test/map.dat", "p4ssw0rd"),
        ("https://admin:p4ss?w0rd@downloads.example.test/map.dat", "p4ss"),
        ("https://admin:p4ss#w0rd@downloads.example.test/map.dat", "p4ss"),
    )
    INVALID_URL_MESSAGE = (
        "invalid URL (details withheld because they may include credentials)"
    )

    def _check_invalid_url(self, run, source):
        for url, secret in self.MALFORMED_URLS:
            with self.subTest(url=url):
                requested = []
                real_get = httpx.get

                def recording_get(requested_url, **kwargs):
                    requested.append(requested_url)
                    if requested_url != url:
                        # e.g. the PSL overrides fetch that
                        # load_reverse_dns_map triggers; stay offline
                        raise httpx.ConnectError("offline")
                    return real_get(requested_url, **kwargs)

                with patch("parsedmarc.utils.httpx.get", recording_get):
                    logs = run(url)  # must return, not crash on InvalidURL
                # The loader still requested the real URL, not a redacted one
                self.assertIn(url, requested)
                output = "\n".join(logs.output)
                # Neither the warning nor the "Trying to fetch" debug line
                # may show any part of the password
                self.assertNotIn(secret, output)
                self.assertIn(
                    f"DEBUG:parsedmarc.log:Trying to fetch {source} from "
                    "https://***@downloads.example.test/map.dat...",
                    logs.output,
                )
                self.assertIn(
                    f"WARNING:parsedmarc.log:Failed to fetch {source}: "
                    f"{self.INVALID_URL_MESSAGE}",
                    logs.output,
                )
                self.assertNotIn("Not a valid CSV file", output)
                self.assertNotIn("Failed to save IP database", output)

    def test_psl_overrides_loader_invalid_url(self):
        """A malformed ``psl_overrides_url`` used to crash startup with the
        InvalidURL traceback; it now warns and falls back to the local file."""
        self._check_invalid_url(self._run_psl, "PSL overrides")
        self.assertIn(".linode.com", parsedmarc.utils.psl_overrides)

    def test_ip_db_loader_invalid_url(self):
        self._check_invalid_url(self._run_ip_db, "IP database")

    def test_reverse_dns_map_loader_invalid_url(self):
        self._check_invalid_url(self._run_reverse_dns_map, "reverse DNS map")

    def test_psl_overrides_loader(self):
        self._check_loader(self._run_psl)

    def test_ip_db_loader(self):
        self._check_loader(self._run_ip_db)

    def test_reverse_dns_map_loader(self):
        self._check_loader(self._run_reverse_dns_map)

    def test_psl_overrides_loader_transport_error(self):
        self._check_transport_error(self._run_psl)

    def test_ip_db_loader_transport_error(self):
        self._check_transport_error(self._run_ip_db)

    def test_reverse_dns_map_loader_transport_error(self):
        self._check_transport_error(self._run_reverse_dns_map)


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
            "parsedmarc.utils.httpx.get", return_value=mock_response
        ) as mock_get:
            result = parsedmarc.utils.load_psl_overrides(url="https://example.test/ov")
            self.assertEqual(result, ["-fetched-brand.com", ".cdn-fetched.net"])
            mock_get.assert_called_once()

    def test_url_failure_falls_back_to_local(self):
        """A network error falls back to the bundled copy."""
        with patch(
            "parsedmarc.utils.httpx.get",
            side_effect=httpx.ConnectError("nope"),
        ):
            result = parsedmarc.utils.load_psl_overrides(url="https://example.test/ov")
        # Bundled file still loaded.
        self.assertGreater(len(result), 0)
        self.assertIn(".linode.com", result)

    def test_always_use_local_skips_network(self):
        """always_use_local_file=True must not call httpx.get."""
        with patch("parsedmarc.utils.httpx.get") as mock_get:
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

    def _write_psl_overrides_file(self):
        """Write a temp PSL overrides file with a unique suffix and register
        cleanup, returning its path."""
        tf = tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        )
        tf.write(".internal.example-503.net\n")
        tf.close()
        self.addCleanup(os.unlink, tf.name)
        return tf.name

    def test_lazy_reverse_dns_map_load_applies_psl_overrides(self):
        """Regression test for GitHub issue #503: the lazy
        ``load_reverse_dns_map()`` call inside
        ``get_service_from_reverse_dns_base_domain`` previously omitted
        ``psl_overrides_path``/``psl_overrides_url``, so
        ``load_reverse_dns_map``'s unconditional ``load_psl_overrides()``
        call (utils.py) silently reloaded ``psl_overrides`` with the bundled
        defaults, discarding an operator-configured overrides file. This
        proves the lazy load now threads the caller's
        ``psl_overrides_path`` through: after calling with an empty
        ``reverse_dns_map`` (which forces the lazy load) and a custom
        ``psl_overrides_path``, the custom override must be in effect.
        """
        path = self._write_psl_overrides_file()
        parsedmarc.utils.get_service_from_reverse_dns_base_domain(
            "something.example",
            reverse_dns_map={},
            always_use_local_file=True,
            offline=True,
            psl_overrides_path=path,
        )
        self.assertEqual(
            parsedmarc.utils.get_base_domain("deep.sub.internal.example-503.net"),
            "internal.example-503.net",
        )

    def test_get_ip_address_info_lazy_load_applies_psl_overrides(self):
        """Regression test for GitHub issue #503, exercising the
        ASN-fallback lazy ``load_reverse_dns_map()`` call inside
        ``get_ip_address_info`` (used when no PTR record resolves). Before
        the fix, this lazy load also omitted ``psl_overrides_path``/
        ``psl_overrides_url``, so it clobbered operator-configured PSL
        overrides with the bundled defaults the same way. ``offline=True``
        forces the no-PTR path so this call reaches the ASN-fallback lazy
        load rather than the PTR-driven
        ``get_service_from_reverse_dns_base_domain`` call.
        """
        path = self._write_psl_overrides_file()
        parsedmarc.utils.get_ip_address_info(
            "192.0.2.1",
            offline=True,
            reverse_dns_map={},
            always_use_local_files=True,
            psl_overrides_path=path,
        )
        self.assertEqual(
            parsedmarc.utils.get_base_domain("deep.sub.internal.example-503.net"),
            "internal.example-503.net",
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
        the error names the expected bundled install location.

        The system-path fallback list in ``_get_ip_database_path()``
        includes real absolute paths like
        ``/usr/share/GeoIP/GeoLite2-Country.mmdb``. On a host that
        actually has a GeoIP package installed there (common on
        malware-analysis / network-tooling workstations, and the same
        file behind https://github.com/domainaware/parsedmarc/issues/810),
        that fallback silently succeeds and no FileNotFoundError is
        raised, regardless of the mocked bundled path or the temp cwd
        below. ``os.path.exists`` is patched to force every system path
        to look absent, so this test asserts the "nothing found
        anywhere" behavior regardless of what's actually installed on
        the machine running the suite.
        """
        tmp_dir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        self.addCleanup(lambda: (os.chdir(old_cwd), shutil.rmtree(tmp_dir)))
        os.chdir(tmp_dir)

        missing = os.path.join(tmp_dir, "does-not-exist.mmdb")
        with patch("parsedmarc.utils.files") as mock_files:
            mock_files.return_value.joinpath.return_value = missing
            with patch("parsedmarc.utils.os.path.exists", return_value=False):
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
        self.assertGreater(len(rdns_map), 0)

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
            "parsedmarc.utils.httpx.get",
            side_effect=httpx.ConnectError("no network"),
        ):
            parsedmarc.utils.load_reverse_dns_map(rdns_map)
        self.assertGreater(len(rdns_map), 0)

    def testLoadReverseDnsMapInvalidCsvFallback(self):
        """A fetch that returns a non-map CSV body logs a warning and
        falls back to the bundled map"""
        response = MagicMock()
        response.text = "not,the,map\nfoo,bar,baz\n"
        response.raise_for_status.return_value = None
        rdns_map = {}
        with patch("parsedmarc.utils.httpx.get", return_value=response):
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


def _dnspython_http_module():
    """Returns the HTTP library dnspython's DoH code imported: httpx2 on
    dnspython 2.9+, httpx on 2.7 and 2.8. Derived from dnspython rather than
    from parsedmarc's helper, so the tests below check the helper against
    what ``dns.query.https()`` actually accepts."""
    return getattr(dns.query, "httpx2", None) or httpx


class TestEncryptedDnsNameservers(unittest.TestCase):
    """Tests for the DNS over HTTPS and DNS over TLS transports selected by
    the form of each ``nameservers`` entry
    (https://github.com/domainaware/parsedmarc/issues/880). Most end-to-end
    tests mock at the dnspython SDK boundary (``dns.query.https`` /
    ``dns.query.tls``) and assert on the answer query_dns parses back out of
    a real DNS response message, so the whole chain — entry mapping,
    resolver, nameserver object, transport call — is exercised. The DoH
    session regression test (issue #935) runs the real ``dns.query.https``
    and fakes only the HTTP transport underneath it."""

    def setUp(self):
        # The DoH session is process-wide state; keep test ordering from
        # leaking a client (or a PID) between tests.
        self._old_session = parsedmarc.utils._DOH_SESSION
        self._old_pid = parsedmarc.utils._DOH_SESSION_PID
        parsedmarc.utils._DOH_SESSION = None
        parsedmarc.utils._DOH_SESSION_PID = None

        def restore():
            session = parsedmarc.utils._DOH_SESSION
            if session is not None and session is not self._old_session:
                session.close()
            parsedmarc.utils._DOH_SESSION = self._old_session
            parsedmarc.utils._DOH_SESSION_PID = self._old_pid

        self.addCleanup(restore)

    @staticmethod
    def _ptr_response(request: dns.message.Message, answer: str = "dns.example."):
        """Builds a response to ``request`` answering its PTR question with
        ``answer``."""
        response = dns.message.make_response(request)
        # find_rrset(create=True) rather than appending to response.answer,
        # so the message's rrset index is updated too — dnspython looks the
        # answer up through that index.
        rrset = response.find_rrset(
            response.answer,
            request.question[0].name,
            dns.rdataclass.IN,
            dns.rdatatype.PTR,
            create=True,
        )
        rrset.add(dns.rdata.from_text("IN", "PTR", answer), 300)
        return response

    @classmethod
    def _ptr_responder(cls, captured: list, answer: str = "dns.example."):
        """Builds a dns.query stand-in that answers any PTR query with
        ``answer``, recording the keyword arguments it was called with."""

        def responder(request, *args, **kwargs):
            captured.append(kwargs)
            return cls._ptr_response(request, answer)

        return responder

    def test_plain_ip_entries_are_passed_through_untouched(self):
        """An IP address is handed to dnspython as the same string object,
        leaving its own Do53 enrichment (and port defaulting) in charge."""
        entries = ["1.1.1.1", "2606:4700:4700::1111"]
        mapped = parsedmarc.utils._nameservers_to_resolver_input(entries)
        self.assertEqual(len(mapped), 2)
        for original, result in zip(entries, mapped):
            self.assertIs(result, original)

    def _map_doh(self, entry: str) -> parsedmarc.utils._SessionDoHNameserver:
        """Maps one entry and asserts it produced a DoH nameserver."""
        (mapped,) = parsedmarc.utils._nameservers_to_resolver_input([entry])
        self.assertIsInstance(mapped, parsedmarc.utils._SessionDoHNameserver)
        return cast(parsedmarc.utils._SessionDoHNameserver, mapped)

    def _map_dot(self, entry: str) -> dns.nameserver.DoTNameserver:
        """Maps one entry and asserts it produced a DoT nameserver."""
        (mapped,) = parsedmarc.utils._nameservers_to_resolver_input([entry])
        self.assertIsInstance(mapped, dns.nameserver.DoTNameserver)
        return cast(dns.nameserver.DoTNameserver, mapped)

    def test_https_entry_becomes_a_session_doh_nameserver(self):
        """An https:// entry maps to the DoH nameserver subclass that
        queries through parsedmarc's own httpx client."""
        url = "https://cloudflare-dns.com/dns-query"
        self.assertEqual(self._map_doh(url).url, url)

    def test_uppercase_scheme_is_recognized(self):
        """The scheme is compared as urlsplit reports it, which is
        lowercased, so HTTPS:// selects DoH rather than falling through to
        dnspython as an unusable string."""
        self._map_doh("HTTPS://cloudflare-dns.com/dns-query")

    def test_tls_entry_defaults_to_port_853_with_no_hostname(self):
        """tls://<ip> alone uses DoTNameserver's default port and performs
        no certificate-identity substitution."""
        mapped = self._map_dot("tls://9.9.9.9")
        self.assertEqual(mapped.address, "9.9.9.9")
        self.assertEqual(mapped.port, 853)
        self.assertIsNone(mapped.hostname)

    def test_tls_entry_port_and_hostname_are_parsed(self):
        """tls://ip:port#hostname sets both the port and the TLS
        certificate identity."""
        mapped = self._map_dot("tls://9.9.9.9:8853#dns.quad9.net")
        self.assertEqual(mapped.address, "9.9.9.9")
        self.assertEqual(mapped.port, 8853)
        self.assertEqual(mapped.hostname, "dns.quad9.net")

    def test_bracketed_ipv6_tls_entry_is_parsed(self):
        """An IPv6 address is bracketed so the colon before the port is
        unambiguous; the brackets are not part of the address."""
        mapped = self._map_dot("tls://[2620:fe::fe]:853#dns.quad9.net")
        self.assertEqual(mapped.address, "2620:fe::fe")
        self.assertEqual(mapped.port, 853)

    def test_mixed_list_preserves_order_and_types(self):
        """Transports can be mixed in one nameservers list, and the
        configured order is the failover order dnspython will use."""
        mapped = parsedmarc.utils._nameservers_to_resolver_input(
            [
                "1.1.1.1",
                "https://cloudflare-dns.com/dns-query",
                "tls://9.9.9.9#dns.quad9.net",
            ]
        )
        self.assertEqual(mapped[0], "1.1.1.1")
        self.assertIsInstance(mapped[1], parsedmarc.utils._SessionDoHNameserver)
        self.assertIsInstance(mapped[2], dns.nameserver.DoTNameserver)

    def test_tls_entry_without_a_host_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.utils._nameservers_to_resolver_input(["tls://"])
        self.assertIn("tls://", str(ctx.exception))

    def test_tls_entry_with_a_hostname_instead_of_an_ip_is_rejected(self):
        """DoTNameserver takes an IP address, not a name — it has no
        resolver of its own to bootstrap with. The certificate identity is
        supplied by the #hostname suffix instead."""
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.utils._nameservers_to_resolver_input(["tls://dns.quad9.net"])
        self.assertIn("tls://dns.quad9.net", str(ctx.exception))

    def test_tls_entry_with_an_invalid_port_is_rejected(self):
        """urlsplit only validates the port when it is read, so the
        ValueError it raises there is re-raised naming the entry."""
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.utils._nameservers_to_resolver_input(["tls://9.9.9.9:notaport"])
        self.assertIn("tls://9.9.9.9:notaport", str(ctx.exception))

    def test_tls_entry_with_a_path_is_rejected(self):
        """tls://9.9.9.9/dns.quad9.net — a plausible slash-for-# typo —
        must fail at configuration time naming the entry, not parse
        "successfully" with no TLS certificate identity and then fail at
        query time with an opaque certificate error. Userinfo and query
        components are rejected the same way, with the userinfo masked in
        the message (GHSA-hjr3-rx4c-24cv)."""
        for entry, shown in (
            ("tls://9.9.9.9/dns.quad9.net", "tls://9.9.9.9/dns.quad9.net"),
            ("tls://user@9.9.9.9", "tls://***@9.9.9.9"),
            (
                "tls://9.9.9.9?hostname=dns.quad9.net",
                "tls://9.9.9.9?hostname=dns.quad9.net",
            ),
        ):
            with self.subTest(entry=entry):
                with self.assertRaises(ValueError) as ctx:
                    parsedmarc.utils._nameservers_to_resolver_input([entry])
                self.assertIn(shown, str(ctx.exception))

    def test_unsplittable_entry_is_left_for_dnspython_to_reject(self):
        """urlsplit itself raises on some malformed input (an unbalanced
        IPv6 bracket). Such an entry is passed through rather than reported
        as a DoH/DoT problem, and dnspython rejects it with its own message
        about what a nameserver may be."""
        entry = "https://[::1"
        (mapped,) = parsedmarc.utils._nameservers_to_resolver_input([entry])
        self.assertIs(mapped, entry)
        with self.assertRaises(ValueError):
            dns.resolver.Resolver(configure=False).nameservers = [entry]

    def test_doh_query_returns_answers_through_a_shared_http_client(self):
        """An https:// nameserver resolves through dns.query.https, and the
        session it is given is the module's shared client, an instance of the
        Client class of the HTTP library dnspython imported (httpx2 on
        dnspython 2.9+, httpx before) with trust_env left on — the
        documented switch, in both libraries, for honoring
        HTTP_PROXY/HTTPS_PROXY/NO_PROXY and SSL_CERT_FILE, which is what a
        proxy-only network needs (issue #880). dnspython's stock DoH
        nameserver passes no session at all, and the client dns.query.https
        builds for itself has a custom transport, which disables environment
        proxies. Asserting identity with the shared client also observes the
        connection-reuse half of the claim: a fresh per-query client would
        satisfy every other assertion here."""
        captured: list = []
        with patch("dns.query.https", side_effect=self._ptr_responder(captured)):
            records = parsedmarc.utils.query_dns(
                "1.0.0.1.in-addr.arpa",
                "PTR",
                cache=ExpiringDict(max_len=10, max_age_seconds=60),
                nameservers=["https://dns.example/dns-query"],
                timeout=2,
            )
        self.assertEqual(records, ["dns.example"])
        self.assertEqual(len(captured), 1)
        session = captured[0]["session"]
        self.assertIsInstance(session, _dnspython_http_module().Client)
        self.assertIs(session.trust_env, True)
        self.assertIs(session, parsedmarc.utils._DOH_SESSION)

    def test_dot_query_returns_answers_and_passes_the_tls_hostname(self):
        """A tls:// nameserver resolves through dns.query.tls, and the
        #hostname suffix reaches it as server_hostname — the name the
        server's certificate is checked against."""
        captured: list = []
        with patch("dns.query.tls", side_effect=self._ptr_responder(captured)):
            records = parsedmarc.utils.query_dns(
                "1.0.0.1.in-addr.arpa",
                "PTR",
                cache=ExpiringDict(max_len=10, max_age_seconds=60),
                nameservers=["tls://9.9.9.9#dns.quad9.net"],
                timeout=2,
            )
        self.assertEqual(records, ["dns.example"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["server_hostname"], "dns.quad9.net")
        self.assertEqual(captured[0]["port"], 853)

    def test_doh_session_is_accepted_by_the_real_dns_query_https(self):
        """Regression test for issue #935: dnspython 2.9 moved DoH to
        httpx2, and ``dns.query.https()`` rejects a session of any other
        class before sending anything (dnspython 2.9.1 ``dns/query.py``
        line 551: ``if session and not isinstance(session, httpx2.Client):
        raise ValueError("session parameter must be an httpx2.Client")``;
        2.8.0 checks ``httpx.Client`` the same way at line 566). The old
        ``httpx.Client`` session therefore failed every DoH query under 2.9,
        and the resolver retried it until the lifetime ran out. Here the real
        ``dns.query.https`` runs, and only the network is faked, by patching
        the ``HTTPTransport`` of the library dnspython imported; a session
        of the wrong class raises LifetimeTimeout instead of returning the
        answer. The transport also observes the POSTed DNS query itself."""
        http_module = _dnspython_http_module()
        questions: list = []

        def handle_request(transport, request):
            query = dns.message.from_wire(request.read())
            questions.append(query.question[0].to_text())
            return http_module.Response(
                200,
                headers={"content-type": "application/dns-message"},
                # An iterator rather than bytes: a bytes body counts as read
                # already, so the client never closes the stream, and
                # ``response.elapsed``, which dns.query.https reads, is set
                # only on close
                content=iter([self._ptr_response(query).to_wire()]),
                request=request,
            )

        with patch.object(http_module.HTTPTransport, "handle_request", handle_request):
            records = parsedmarc.utils.query_dns(
                "1.0.0.1.in-addr.arpa",
                "PTR",
                nameservers=["https://dns.example/dns-query"],
                timeout=0.5,
            )
        self.assertEqual(records, ["dns.example"])
        self.assertEqual(questions, ["1.0.0.1.in-addr.arpa. IN PTR"])

    def test_doh_client_class_prefers_httpx2_when_dnspython_imported_it(self):
        """dnspython 2.9+ binds ``dns.query.httpx2``; its Client is the one
        ``dns.query.https()`` accepts, even with httpx importable too."""
        fake_httpx2 = SimpleNamespace(Client=type("Client", (), {}))
        with patch.dict(dns.query.__dict__, {"httpx2": fake_httpx2, "httpx": httpx}):
            self.assertIs(parsedmarc.utils._doh_client_class(), fake_httpx2.Client)

    def test_doh_client_class_uses_httpx_when_dnspython_imported_it(self):
        """dnspython 2.7 and 2.8 bind ``dns.query.httpx`` and no httpx2, so
        the class is ``httpx.Client`` — even if an unrelated httpx2 install
        exists, since dnspython 2.8 never checks against it."""
        fake_httpx = SimpleNamespace(Client=type("Client", (), {}))
        with patch.dict(dns.query.__dict__, {"httpx": fake_httpx}):
            dns.query.__dict__.pop("httpx2", None)
            self.assertIs(parsedmarc.utils._doh_client_class(), fake_httpx.Client)

    def test_doh_client_class_falls_back_to_httpx(self):
        """With neither library bound in dns.query (dnspython without its
        [doh] extra), the class falls back to ``httpx.Client``; dnspython
        (or httpx, if h2 is also missing) then raises its own error when a
        DoH query is made."""
        with patch.dict(dns.query.__dict__):
            dns.query.__dict__.pop("httpx2", None)
            dns.query.__dict__.pop("httpx", None)
            self.assertIs(parsedmarc.utils._doh_client_class(), httpx.Client)

    def test_doh_session_is_reused_within_a_process(self):
        """Consecutive calls hand back the same client, so DoH lookups
        reuse the connection instead of renegotiating TLS per query."""
        first = parsedmarc.utils._get_doh_session()
        self.assertIs(parsedmarc.utils._get_doh_session(), first)

    def test_doh_session_is_rebuilt_after_a_fork(self):
        """A forked worker (n_procs) inherits the module globals, including
        the parent's open sockets. Recording the creating PID makes the
        child build its own client rather than share the parent's."""
        parent_session = parsedmarc.utils._get_doh_session()
        parsedmarc.utils._DOH_SESSION_PID = os.getpid() + 1
        child_session = parsedmarc.utils._get_doh_session()
        self.addCleanup(parent_session.close)
        self.assertIsNot(child_session, parent_session)
        self.assertEqual(parsedmarc.utils._DOH_SESSION_PID, os.getpid())


class TestNameserverCredentialsNotLeaked(unittest.TestCase):
    """GHSA-hjr3-rx4c-24cv: nameserver URL credentials must not reach an
    exception message, its printed traceback, or the log."""

    def test_url_secrets_finds_the_password_and_its_port_like_prefix(self):
        """The secret is the userinfo after its first ":" (the whole
        userinfo when there is none). A "/", "?" or "#" in it ends the URL
        authority (RFC 3986 section 3.2), so urlsplit() reads the text
        before it as the port and quotes it in its error; that prefix is a
        secret too."""
        cases = [
            ("https://doh:p4ss@dns.example/q", ["p4ss"]),
            ("https://doh:p4ss/w0rd@dns.example/q", ["p4ss/w0rd", "p4ss"]),
            ("https://doh:p4ss?w0rd@dns.example/q", ["p4ss?w0rd", "p4ss"]),
            ("https://doh:p4ss#w0rd@dns.example/q", ["p4ss#w0rd", "p4ss"]),
            # The prefix ends at the first of the three delimiters
            ("https://doh:ab#cd/ef@dns.example/q", ["ab#cd/ef", "ab"]),
            ("https://doh:p:w@dns.example/q", ["p:w"]),
            ("https://doh:p@ss@dns.example/q", ["p@ss"]),
            ("https://S3CRETTOKEN@dns.example/q", ["S3CRETTOKEN"]),
            ("tls://dot:p4ss/w0rd@1.1.1.1", ["p4ss/w0rd", "p4ss"]),
            # Empty secrets are never returned: str.replace("", ...) would
            # insert the mask between every character
            ("https://doh:@dns.example/q", []),
            ("https://doh:/x@dns.example/q", ["/x"]),
            ("https://dns.example/dns-query", []),
            ("8.8.8.8", []),
            ("", []),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(parsedmarc.utils._url_secrets(value), expected)

    def test_mask_nameserver_secrets_masks_entries_passwords_and_prefixes(self):
        """Each configured entry is replaced by its redacted form, and each
        secret in it wherever it still appears, including the bare port-like
        prefix that urlsplit() and httpx quote."""
        mask = parsedmarc.utils._mask_nameserver_secrets
        url = "https://doh:p4ss/w0rd@dns.example/dns-query"
        text = (
            f"Server {url} answered x; "
            "Port could not be cast to integer value as 'p4ss'; "
            "Invalid port: 'p4ss/w0rd'"
        )
        self.assertEqual(
            mask(text, [url, "8.8.8.8"]),
            "Server https://***@dns.example/dns-query answered x; "
            "Port could not be cast to integer value as '***'; "
            "Invalid port: '***'",
        )
        self.assertEqual(
            mask(
                "Server https://u:PW123@h.example/q failed (PW123)",
                ["https://u:PW123@h.example/q"],
            ),
            "Server https://u:***@h.example/q failed (***)",
        )
        self.assertEqual(mask("abc", None), "abc")
        self.assertEqual(mask("abc", ["https://u:@h"]), "abc")

    def test_mask_nameserver_secrets_handles_unsplittable_entries(self):
        """urlsplit() raises ValueError for an entry such as ``https://[x``;
        the masking uses string methods only, so it still returns text."""
        text = "Server https://[x failed; Server https://u:PW@[x failed"
        self.assertEqual(
            parsedmarc.utils._mask_nameserver_secrets(
                text, ["https://[x", "https://u:PW@[x"]
            ),
            "Server https://[x failed; Server https://u:***@[x failed",
        )

    def test_malformed_https_and_tls_ports_are_reported_without_secrets(self):
        """A password containing "/", "?" or "#" makes urlsplit() read its
        start as the port, and its ValueError quotes that text; dnspython
        2.9.1 raised it from ``DoHNameserver.answer_port()`` only after a
        failed query (``dns/nameserver.py``). Both schemes are now rejected
        before any query, naming the entry with its credentials masked and
        with no chained exception repeating the urlsplit message."""
        for entry, shown in (
            (
                "https://doh:p4ss/w0rd@dns.example/dns-query",
                "Invalid DNS over HTTPS nameserver https://***@dns.example/dns-query",
            ),
            (
                "https://doh:p4ss?w0rd@dns.example/dns-query",
                "Invalid DNS over HTTPS nameserver https://***@dns.example/dns-query",
            ),
            (
                "tls://dot:p4ss#w0rd@1.1.1.1",
                "Invalid DNS over TLS nameserver tls://***@1.1.1.1",
            ),
            (
                "https://dns.example:notaport/dns-query",
                "Invalid DNS over HTTPS nameserver https://dns.example:notaport/",
            ),
        ):
            with self.subTest(entry=entry):
                with patch("dns.query.https", side_effect=AssertionError):
                    with self.assertRaises(ValueError) as ctx:
                        parsedmarc.utils.query_dns(
                            "1.0.0.1.in-addr.arpa",
                            "PTR",
                            nameservers=[entry],
                            timeout=0.2,
                        )
                trace = "".join(traceback.format_exception(ctx.exception))
                self.assertIn(shown, str(ctx.exception))
                self.assertIsNone(ctx.exception.__cause__)
                self.assertIsNone(ctx.exception.__context__)
                for secret in ("p4ss", "w0rd"):
                    self.assertNotIn(secret, trace)

    def test_dnspython_rejection_of_an_entry_is_masked(self):
        """dnspython rejects an entry urlsplit() cannot split with a message
        that quotes it as configured ("nameserver https://u:pw@[x is not a
        dns.nameserver.Nameserver instance ..."); query_dns() masks it."""
        entry = "https://doh:S3CRETPW@[dns.example/dns-query"
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.utils.query_dns(
                "1.0.0.1.in-addr.arpa", "PTR", nameservers=[entry], timeout=0.2
            )
        trace = "".join(traceback.format_exception(ctx.exception))
        self.assertIn("https://doh:***@[dns.example/dns-query", str(ctx.exception))
        self.assertNotIn("S3CRETPW", trace)

    def test_get_reverse_dns_debug_log_masks_nameserver_credentials(self):
        """get_reverse_dns() logs the DNS error it swallows at debug level,
        and LifetimeTimeout/NoNameservers quote each failing nameserver
        URL, so the configured credentials are masked there too."""
        url = "https://doh:S3CRETPW@dns.example/dns-query"

        def fail(*args, **kwargs):
            raise OSError(f"connection to {url} refused (S3CRETPW)")

        with patch("dns.query.https", side_effect=fail):
            with self.assertLogs("parsedmarc.log", level="DEBUG") as logs:
                result = parsedmarc.utils.get_reverse_dns(
                    "1.0.0.1", nameservers=[url], timeout=0.2, retries=0
                )
        self.assertIsNone(result)
        output = "\n".join(logs.output)
        self.assertIn("get_reverse_dns(1.0.0.1) exception:", output)
        self.assertIn("https://doh:***@dns.example/dns-query", output)
        self.assertNotIn("S3CRETPW", output)


class TestLoadIpDb(unittest.TestCase):
    """Tests for the load_ip_db() download/cache/bundled fallback chain,
    mocking at the httpx SDK boundary."""

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
        with patch("parsedmarc.utils.httpx.get") as mock_get:
            parsedmarc.utils.load_ip_db(local_file_path=local_path)
        mock_get.assert_not_called()
        self.assertEqual(parsedmarc.utils._IP_DB_PATH, local_path)

    def testDownloadSuccessWritesCacheFile(self):
        """A successful download is written to the cache path and selected"""
        response = MagicMock()
        response.content = b"downloaded db bytes"
        response.raise_for_status.return_value = None
        with patch("parsedmarc.utils.httpx.get", return_value=response) as mock_get:
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
            "parsedmarc.utils.httpx.get",
            side_effect=httpx.ConnectError("no network"),
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
            "parsedmarc.utils.httpx.get",
            side_effect=httpx.ConnectError("no network"),
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
            with patch("parsedmarc.utils.httpx.get", return_value=response):
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
        response.is_success = 200 <= status_code < 300
        response.json.return_value = json_body if json_body is not None else {}
        return response

    def testProbeSuccessLogsConfigured(self):
        """A successful probe logs that the API is configured"""
        api_json = {"ip": "1.1.1.1", "asn": "AS13335", "country_code": "US"}
        with patch(
            "parsedmarc.utils.httpx.get",
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
            "parsedmarc.utils.httpx.get",
            side_effect=httpx.ConnectError("no network"),
        ):
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                parsedmarc.utils.configure_ipinfo_api("fake-token", probe=True)
        self.assertTrue(
            any("IPinfo API probe failed" in message for message in cm.output)
        )
        self.assertEqual(parsedmarc.utils._IPINFO_API_TOKEN, "fake-token")

    def testProbeInvalidKeyRaises(self):
        """A 401 during the probe raises InvalidIPinfoAPIKey"""
        with patch("parsedmarc.utils.httpx.get", return_value=self._response(401)):
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
            "parsedmarc.utils.httpx.get",
            return_value=response,
            side_effect=side_effect,
        ):
            record = parsedmarc.utils.get_ip_address_db_record("8.8.8.8")
        # The bundled MMDB attributes 8.8.8.8 to Google's ASN.
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["asn"], 15169)

    def testNetworkErrorFallsBackToMmdb(self):
        self._assert_mmdb_fallback(side_effect=httpx.ConnectError("no network"))

    def testNonJsonBodyFallsBackToMmdb(self):
        response = MagicMock()
        response.status_code = 200
        response.is_success = True
        response.json.side_effect = ValueError("not JSON")
        self._assert_mmdb_fallback(response=response)

    def testNonDictPayloadFallsBackToMmdb(self):
        response = MagicMock()
        response.status_code = 200
        response.is_success = True
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
