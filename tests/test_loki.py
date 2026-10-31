"""Tests for parsedmarc.loki"""

import json
import os
import time
import traceback
import unittest
from typing import cast
from unittest.mock import MagicMock, patch

import httpx

import parsedmarc
from parsedmarc.loki import LokiClient, LokiError
from parsedmarc.types import AggregateReport, FailureReport, SMTPTLSReport
from parsedmarc.utils import human_timestamp_to_unix_timestamp

# Placeholders: the row conversion is patched in most tests.
AGGREGATE = cast(AggregateReport, {})
FAILURE = cast(FailureReport, {})
SMTP_TLS = cast(SMTPTLSReport, {})

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")

AGGREGATE_ROWS = [
    {
        "org_name": "google.com",
        "report_id": "r1",
        "begin_date": "2026-10-20 00:00:00",
        "end_date": "2026-10-20 23:59:59",
        "domain": "example.org",
        "source_ip_address": "192.0.2.1",
        "count": 3,
        "dmarc_aligned": True,
    },
    {
        "org_name": "google.com",
        "report_id": "r1",
        "begin_date": "2026-10-20 00:00:00",
        "end_date": "2026-10-20 23:59:59",
        "domain": "lists.example.org",
        "source_ip_address": "192.0.2.2",
        "count": 1,
        "dmarc_aligned": False,
    },
]
FAILURE_ROWS = [
    {
        "reported_domain": "example.org",
        "arrival_date_utc": "2026-10-20 09:20:27",
        "source_ip_address": "192.0.2.3",
    }
]
SMTP_TLS_ROWS = [
    {
        "organization_name": "Reporter",
        "begin_date": "2026-10-20T00:00:00Z",
        "policy_domain": "example.org",
        "failed_session_count": 1,
    }
]


def _ok_response(status_code=204):
    response = MagicMock()
    response.status_code = status_code
    response.text = ""
    return response


def _client(**kwargs):
    kwargs.setdefault("labels", {"host": "mail.example.org"})
    client = LokiClient("http://loki.example.org:3100", **kwargs)
    client.session = MagicMock()
    client.session.post.return_value = _ok_response()
    return client


def _session(client: LokiClient) -> MagicMock:
    return cast(MagicMock, client.session)


def _pushes(client):
    """The JSON bodies of every push request, in order."""
    return [json.loads(c.kwargs["content"]) for c in client.session.post.call_args_list]


def _entries(client):
    """(labels, timestamp_ns, line dict) of every pushed entry."""
    out = []
    for body in _pushes(client):
        for stream in body["streams"]:
            for ts, line in stream["values"]:
                out.append((stream["stream"], int(ts), json.loads(line)))
    return out


class TestLokiClientInit(unittest.TestCase):
    def test_push_path_appended_to_base_url(self):
        for url in ("http://loki:3100", "http://loki:3100/"):
            client = LokiClient(url)
            self.assertEqual(client.url, "http://loki:3100/loki/api/v1/push")

    def test_push_path_appended_before_query_string(self):
        for url in (
            "https://gw.example.org?route=logs",
            "https://gw.example.org/?route=logs",
        ):
            client = LokiClient(url)
            self.assertEqual(
                client.url, "https://gw.example.org/loki/api/v1/push?route=logs"
            )

    def test_explicit_push_path_kept(self):
        client = LokiClient("https://gw.example.org/custom/push")
        self.assertEqual(client.url, "https://gw.example.org/custom/push")

    def test_default_labels_job_and_fqdn_host(self):
        with patch("parsedmarc.loki.socket.getfqdn", return_value="mx1.example.org"):
            client = LokiClient("http://loki:3100")
        self.assertEqual(
            client.labels, {"job": "parsedmarc", "host": "mx1.example.org"}
        )

    def test_configured_labels_override_and_extend_defaults(self):
        client = LokiClient("http://loki:3100", labels={"host": "mail2", "env": "prod"})
        self.assertEqual(client.labels["host"], "mail2")
        self.assertEqual(client.labels["env"], "prod")
        self.assertEqual(client.labels["job"], "parsedmarc")

    def test_default_label_fields(self):
        self.assertEqual(
            LokiClient("http://loki:3100").label_fields, ["report_type", "domain"]
        )

    def test_invalid_label_names_rejected(self):
        with self.assertRaises(ValueError):
            LokiClient("http://loki:3100", labels={"bad-name": "x"})
        with self.assertRaises(ValueError):
            LokiClient("http://loki:3100", label_fields=["1field"])

    def test_invalid_timestamp_mode_rejected(self):
        with self.assertRaises(ValueError):
            LokiClient("http://loki:3100", timestamp="report_end")

    def test_token_and_basic_auth_are_exclusive(self):
        with self.assertRaises(ValueError):
            LokiClient("http://loki:3100", username="u", password="p", token="t")

    def test_headers(self):
        client = LokiClient("http://loki:3100", token="secret", tenant_id="fosdem")
        headers = client.session.headers
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn("parsedmarc", headers["User-Agent"])
        self.assertEqual(headers["Authorization"], "Bearer secret")
        self.assertEqual(headers["X-Scope-OrgID"], "fosdem")

    def test_no_auth_headers_by_default(self):
        headers = LokiClient("http://loki:3100").session.headers
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("X-Scope-OrgID", headers)

    def test_basic_auth(self):
        client = LokiClient("http://loki:3100", username="u", password="p")
        self.assertIsInstance(client.session.auth, httpx.BasicAuth)


class TestLokiInvalidUrlDoesNotLeakPassword(unittest.TestCase):
    """GHSA-hjr3-rx4c-24cv: a password with an unencoded "/", "?" or "#"
    ends the URL's authority early (RFC 3986 section 3.2), so httpx reads the
    text after the colon as the port and raises
    ``InvalidURL("Invalid port: 'p4ssw0rd'")`` (httpx 0.28.1 _urlparse.py:
    ``raise InvalidURL(f"Invalid port: {port!r}")``). Its implicit
    ``__context__`` is a ValueError that repeats that part of the password
    too."""

    MALFORMED = (
        ("https://admin:p4ssw0rd/extra@loki.example.org:3100", "p4ssw0rd"),
        ("https://admin:p4ss?w0rd@loki.example.org:3100", "p4ss"),
        ("https://admin:p4ss#w0rd@loki.example.org:3100", "p4ss"),
    )

    def test_invalid_url_raises_fixed_message_without_password(self):
        for url, secret in self.MALFORMED:
            with self.subTest(url=url):
                with self.assertRaises(ValueError) as ctx:
                    LokiClient(url)
                self.assertEqual(
                    str(ctx.exception),
                    "Invalid Loki URL (details withheld because they may "
                    "include credentials)",
                )
                self.assertIsNone(ctx.exception.__cause__)
                self.assertTrue(ctx.exception.__suppress_context__)
                trace = "".join(traceback.format_exception(ctx.exception))
                self.assertNotIn(secret, trace)

    def test_valid_url_keeps_userinfo_for_requests(self):
        client = LokiClient("https://admin:p4ssw0rd@loki.example.org:3100")
        self.assertEqual(
            client.url,
            "https://admin:p4ssw0rd@loki.example.org:3100/loki/api/v1/push",
        )


@patch(
    "parsedmarc.loki.parsed_aggregate_reports_to_csv_rows", return_value=AGGREGATE_ROWS
)
class TestLokiAggregate(unittest.TestCase):
    def test_one_line_per_record_with_report_type(self, _rows):
        client = _client()
        client.save_aggregate_report_to_loki(AGGREGATE)
        lines = [line for _, _, line in _entries(client)]
        self.assertEqual(len(lines), 2)
        for line, row in zip(lines, AGGREGATE_ROWS):
            self.assertEqual(line, {**row, "report_type": "aggregate"})

    def test_streams_split_by_label_fields(self, _rows):
        client = _client()
        client.save_aggregate_report_to_loki(AGGREGATE)
        streams = sorted(
            (s["stream"] for s in _pushes(client)[0]["streams"]),
            key=lambda s: s["domain"],
        )
        self.assertEqual(
            streams,
            [
                {
                    "job": "parsedmarc",
                    "host": "mail.example.org",
                    "report_type": "aggregate",
                    "domain": "example.org",
                },
                {
                    "job": "parsedmarc",
                    "host": "mail.example.org",
                    "report_type": "aggregate",
                    "domain": "lists.example.org",
                },
            ],
        )

    def test_custom_label_fields(self, _rows):
        client = _client(label_fields=["org_name"])
        client.save_aggregate_report_to_loki(AGGREGATE)
        streams = _pushes(client)[0]["streams"]
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0]["stream"]["org_name"], "google.com")
        self.assertNotIn("domain", streams[0]["stream"])

    def test_empty_or_missing_label_values_are_left_out(self, rows):
        rows.return_value = [{"domain": "", "org_name": None}]
        client = _client(label_fields=["domain", "org_name", "nope"])
        client.save_aggregate_report_to_loki(AGGREGATE)
        labels = _pushes(client)[0]["streams"][0]["stream"]
        self.assertEqual(set(labels), {"job", "host"})

    def test_ingest_timestamps_are_now_and_unique(self, _rows):
        client = _client()
        with patch("parsedmarc.loki.time.time_ns", return_value=1_000_000_000_000):
            client.save_aggregate_report_to_loki(AGGREGATE)
        stamps = sorted(ts for _, ts, _ in _entries(client))
        self.assertEqual(stamps, [1_000_000_000_000, 1_000_000_000_001])

    def test_report_begin_timestamps(self, _rows):
        client = _client(timestamp="report_begin")
        client.save_aggregate_report_to_loki(AGGREGATE)
        begin = (
            human_timestamp_to_unix_timestamp("2026-10-20 00:00:00", assume_utc=True)
            * 10**9
        )
        stamps = sorted(ts for _, ts, _ in _entries(client))
        self.assertEqual(stamps, [begin, begin + 1])

    def test_report_begin_falls_back_to_ingest_time(self, rows):
        rows.return_value = [{"domain": "example.org", "begin_date": "garbage"}]
        client = _client(timestamp="report_begin")
        with patch("parsedmarc.loki.time.time_ns", return_value=42):
            client.save_aggregate_report_to_loki(AGGREGATE)
        self.assertEqual([ts for _, ts, _ in _entries(client)], [42])

    def test_timestamps_are_strings(self, _rows):
        client = _client()
        client.save_aggregate_report_to_loki(AGGREGATE)
        for stream in _pushes(client)[0]["streams"]:
            for ts, line in stream["values"]:
                self.assertIsInstance(ts, str)
                self.assertIsInstance(line, str)

    def test_large_reports_split_into_batches(self, rows):
        rows.return_value = [
            dict(AGGREGATE_ROWS[0], report_id=str(i)) for i in range(5)
        ]
        client = _client(batch_size=2)
        client.save_aggregate_report_to_loki(AGGREGATE)
        sizes = [
            sum(len(s["values"]) for s in body["streams"]) for body in _pushes(client)
        ]
        self.assertEqual(sizes, [2, 2, 1])
        self.assertEqual(len({ts for _, ts, _ in _entries(client)}), 5)

    def test_nothing_sent_without_rows(self, rows):
        rows.return_value = []
        client = _client()
        client.save_aggregate_report_to_loki([])
        _session(client).post.assert_not_called()

    def test_posts_to_push_url_with_timeout(self, _rows):
        client = _client(timeout=12)
        client.save_aggregate_report_to_loki(AGGREGATE)
        call = _session(client).post.call_args
        self.assertEqual(call.args[0], "http://loki.example.org:3100/loki/api/v1/push")
        self.assertEqual(call.kwargs["timeout"], 12)


class TestLokiOrdering(unittest.TestCase):
    def test_report_begin_entries_sent_in_timestamp_order(self):
        """Loki rejects entries more than max_chunk_age/2 behind the newest
        line of a stream (too_far_behind), so entries must be pushed oldest
        first even though normalized multi-day aggregate rows arrive
        source-major: all days of one source, then back to day 1 for the
        next source."""
        rows = [
            {"source_ip_address": ip, "begin_date": f"2024-01-{day:02d} 00:00:00"}
            for ip in ("192.0.2.1", "192.0.2.2")
            for day in (1, 2, 3)
        ]
        client = _client(timestamp="report_begin", batch_size=2)
        with patch(
            "parsedmarc.loki.parsed_aggregate_reports_to_csv_rows", return_value=rows
        ):
            client.save_aggregate_report_to_loki(cast(AggregateReport, {}))
        stamps = [ts for _, ts, _ in _entries(client)]
        self.assertEqual(len(stamps), 6)
        self.assertEqual(len(_session(client).post.call_args_list), 3)
        self.assertEqual(stamps, sorted(stamps))


class TestLokiOtherReportTypes(unittest.TestCase):
    @patch(
        "parsedmarc.loki.parsed_failure_reports_to_csv_rows", return_value=FAILURE_ROWS
    )
    def test_failure_domain_label_and_utc_begin(self, _rows):
        client = _client(timestamp="report_begin")
        client.save_failure_report_to_loki(FAILURE)
        [(labels, ts, line)] = _entries(client)
        self.assertEqual(labels["report_type"], "failure")
        self.assertEqual(labels["domain"], "example.org")
        self.assertEqual(line["domain"], "example.org")
        expected = human_timestamp_to_unix_timestamp(
            "2026-10-20 09:20:27", assume_utc=True
        )
        self.assertEqual(ts, expected * 10**9)

    @patch(
        "parsedmarc.loki.parsed_smtp_tls_reports_to_csv_rows",
        return_value=SMTP_TLS_ROWS,
    )
    def test_smtp_tls_domain_label_and_begin(self, _rows):
        client = _client(timestamp="report_begin")
        client.save_smtp_tls_report_to_loki(SMTP_TLS)
        [(labels, ts, line)] = _entries(client)
        self.assertEqual(labels["report_type"], "smtp_tls")
        self.assertEqual(labels["domain"], "example.org")
        self.assertEqual(line["policy_domain"], "example.org")
        self.assertEqual(
            ts, human_timestamp_to_unix_timestamp("2026-10-20T00:00:00Z") * 10**9
        )

    @patch(
        "parsedmarc.loki.parsed_aggregate_reports_to_csv_rows",
        return_value=[{"domain": "a.example", "report_type": "x"}],
    )
    def test_existing_fields_are_not_overwritten_except_report_type(self, _rows):
        client = _client()
        client.save_aggregate_report_to_loki(AGGREGATE)
        [(_, _, line)] = _entries(client)
        self.assertEqual(line["domain"], "a.example")
        self.assertEqual(line["report_type"], "aggregate")


@patch(
    "parsedmarc.loki.parsed_aggregate_reports_to_csv_rows", return_value=AGGREGATE_ROWS
)
class TestLokiErrors(unittest.TestCase):
    """A failed push must raise: the CLI then keeps the mailbox messages
    for a retry instead of archiving reports that were never stored."""

    def test_error_status_raises_with_status_and_body(self, _rows):
        client = _client()
        response = _ok_response(400)
        response.text = "entry too far behind"
        _session(client).post.return_value = response
        with self.assertRaises(LokiError) as ctx:
            client.save_aggregate_report_to_loki(AGGREGATE)
        self.assertIn("400", str(ctx.exception))
        self.assertIn("entry too far behind", str(ctx.exception))

    def test_server_error_raises(self, _rows):
        client = _client()
        _session(client).post.return_value = _ok_response(503)
        with self.assertRaises(LokiError):
            client.save_aggregate_report_to_loki(AGGREGATE)

    def test_network_error_raises(self, _rows):
        client = _client()
        _session(client).post.side_effect = httpx.ConnectError("refused")
        with self.assertRaises(LokiError) as ctx:
            client.save_aggregate_report_to_loki(AGGREGATE)
        self.assertIn("refused", str(ctx.exception))

    def test_errors_mask_url_password(self, _rows):
        """GHSA-hjr3-rx4c-24cv: the URL keeps its userinfo, and the CLI
        logs LokiError text, so the password must be masked in it."""
        secret = "s3cretPW"
        client = LokiClient(f"http://u:{secret}@loki.example.org:3100")
        client.session = MagicMock()
        _session(client).post.return_value = _ok_response(500)
        with self.assertRaises(LokiError) as status_ctx:
            client.save_aggregate_report_to_loki(AGGREGATE)
        _session(client).post.side_effect = httpx.ConnectError("refused")
        with self.assertRaises(LokiError) as network_ctx:
            client.save_aggregate_report_to_loki(AGGREGATE)
        for ctx in (status_ctx, network_ctx):
            with self.subTest(error=str(ctx.exception)):
                self.assertNotIn(secret, str(ctx.exception))
                self.assertIn("http://u:***@loki.example.org:3100", str(ctx.exception))
        # Redaction is message-only: the request still goes to the real URL
        self.assertEqual(
            _session(client).post.call_args.args[0],
            f"http://u:{secret}@loki.example.org:3100/loki/api/v1/push",
        )

    def test_blocked_ingestion_status_raises(self, _rows):
        """Loki returns 260 (block_ingestion_status_code default) and drops
        the logs when ingestion is blocked; that must not read as success."""
        client = _client()
        response = _ok_response(260)
        response.text = "ingestion blocked"
        _session(client).post.return_value = response
        with self.assertRaises(LokiError) as ctx:
            client.save_aggregate_report_to_loki(AGGREGATE)
        self.assertIn("260", str(ctx.exception))

    def test_redirect_raises_and_is_not_followed(self, _rows):
        """httpx turns a redirected POST into a GET, which the target would
        answer 200 without storing anything; a 3xx must raise instead."""
        requested = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            if request.url.host == "loki.example.org":
                return httpx.Response(
                    301, headers={"Location": "http://elsewhere.example.org/ok"}
                )
            return httpx.Response(200)

        real_client = httpx.Client

        def client_factory(**kwargs):
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        with patch("parsedmarc.loki.httpx.Client", side_effect=client_factory):
            client = LokiClient("http://loki.example.org:3100")
        with self.assertRaises(LokiError) as ctx:
            client.save_aggregate_report_to_loki(AGGREGATE)
        self.assertIn("301", str(ctx.exception))
        self.assertEqual(requested, ["http://loki.example.org:3100/loki/api/v1/push"])

    def test_success_statuses(self, _rows):
        for status in (200, 204):
            client = _client()
            _session(client).post.return_value = _ok_response(status)
            client.save_aggregate_report_to_loki(AGGREGATE)


class TestLokiRealReports(unittest.TestCase):
    """End to end through parsedmarc's own row conversion."""

    @unittest.skipUnless(hasattr(time, "tzset"), "needs time.tzset")
    def test_report_begin_is_utc_in_a_non_utc_timezone(self):
        """The aggregate row's interval_begin is naive UTC, so the pushed
        timestamp must equal the XML <begin> epoch whatever the local zone
        (it was 4h late under America/New_York when read as local time)."""
        old_tz = os.environ.get("TZ")

        def restore():
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

        self.addCleanup(restore)
        os.environ["TZ"] = "America/New_York"
        time.tzset()
        path = os.path.join(
            SAMPLES, "aggregate", "!example.com!1538204542!1538463818.xml"
        )
        report = parsedmarc.parse_report_file(path, offline=True)["report"]
        client = _client(timestamp="report_begin")
        client.save_aggregate_report_to_loki(cast(AggregateReport, report))
        # <begin> of the sample is 1538413632; a one-day report is one record
        # bucket, so every pushed entry starts at that epoch
        stamps = {ts for _, ts, _ in _entries(client)}
        self.assertEqual(stamps, {1538413632 * 10**9})

    def test_aggregate_sample(self):
        sample = os.path.join(
            SAMPLES, "aggregate", "!example.com!1538204542!1538463818.xml"
        )
        report = cast(
            AggregateReport,
            parsedmarc.parse_report_file(sample, offline=True)["report"],
        )
        client = _client()
        client.save_aggregate_report_to_loki(report)
        [(labels, _, line)] = _entries(client)
        self.assertEqual(labels["domain"], "example.com")
        self.assertEqual(line["source_ip_address"], "12.20.127.122")
        self.assertEqual(line["report_type"], "aggregate")


class TestLokiClose(unittest.TestCase):
    def test_close_closes_session(self):
        client = _client()
        session = _session(client)
        client.close()
        session.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
