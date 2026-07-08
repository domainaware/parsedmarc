"""Tests for parsedmarc.splunk"""

import json
import os
import time
import unittest
from unittest.mock import MagicMock

from parsedmarc.splunk import HECClient, SplunkError


def _aggregate_report():
    return {
        "report_metadata": {
            "org_name": "TestOrg",
            "org_email": "dmarc@example.com",
            "report_id": "agg-1",
            "begin_date": "2024-01-01 00:00:00",
            "end_date": "2024-01-02 00:00:00",
        },
        "policy_published": {"domain": "example.com", "p": "none"},
        "records": [
            {
                "interval_begin": "2024-01-01 00:00:00",
                "interval_end": "2024-01-02 00:00:00",
                "normalized_timespan": False,
                "source": {
                    "ip_address": "192.0.2.1",
                    "country": "US",
                    "reverse_dns": None,
                    "base_domain": None,
                    "name": None,
                    "type": None,
                    "asn": 64496,
                    "as_name": "Example AS",
                    "as_domain": "example.net",
                },
                "count": 4,
                "alignment": {"spf": True, "dkim": True, "dmarc": True},
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                    "policy_override_reasons": [],
                },
                "identifiers": {
                    "header_from": "example.com",
                    "envelope_from": "example.com",
                    "envelope_to": None,
                },
                "auth_results": {
                    "dkim": [
                        {
                            "domain": "example.com",
                            "selector": "s",
                            "result": "pass",
                            "human_result": None,
                        }
                    ],
                    "spf": [
                        {
                            "domain": "example.com",
                            "scope": "mfrom",
                            "result": "pass",
                            "human_result": None,
                        }
                    ],
                },
            }
        ],
    }


def _failure_report():
    return {
        "feedback_type": "auth-failure",
        "user_agent": "test/1.0",
        "version": "1",
        "original_envelope_id": None,
        "original_mail_from": "x@example.com",
        "original_rcpt_to": None,
        "arrival_date": "Thu, 1 Jan 2024 00:00:00 +0000",
        "arrival_date_utc": "2024-01-01 00:00:00",
        "authentication_results": None,
        "delivery_result": "other",
        "auth_failure": ["dmarc"],
        "authentication_mechanisms": [],
        "dkim_domain": None,
        "reported_domain": "example.com",
        "sample_headers_only": True,
        "source": {
            "ip_address": "192.0.2.5",
            "country": "US",
            "reverse_dns": None,
            "base_domain": None,
            "name": None,
            "type": None,
            "asn": 64496,
            "as_name": "Example AS",
            "as_domain": "example.net",
        },
        "sample": "...",
        "parsed_sample": {"subject": "Test"},
    }


def _smtp_tls_report():
    return {
        "organization_name": "example.com",
        "begin_date": "2024-02-03T00:00:00Z",
        "end_date": "2024-02-04T00:00:00Z",
        "contact_info": "tls@example.com",
        "report_id": "tls-1",
        "policies": [
            {
                "policy_domain": "example.com",
                "policy_type": "sts",
                "successful_session_count": 100,
                "failed_session_count": 0,
            }
        ],
    }


def _ok_response():
    """Splunk HEC success response shape: {"code": 0, ...}."""
    r = MagicMock()
    r.json.return_value = {"code": 0, "text": "Success"}
    return r


def _client():
    return HECClient(
        url="https://splunk.example.com:8088",
        access_token="abc-token-uuid",
        index="dmarc",
    )


class TestHECClientInit(unittest.TestCase):
    """The HEC URL is rebuilt from the user-supplied URL into the
    /services/collector/event/1.0 endpoint, and the Authorization
    header is set to `Splunk <token>`."""

    def test_url_rewritten_to_collector_endpoint(self):
        """A user may supply any URL on the Splunk host; the client
        rewrites to the documented HEC path."""
        client = HECClient(
            url="https://splunk.example.com:8088/some/random/path",
            access_token="t",
            index="dmarc",
        )
        self.assertEqual(
            client.url, "https://splunk.example.com:8088/services/collector/event/1.0"
        )

    def test_authorization_header_uses_splunk_prefix(self):
        client = HECClient(url="https://h:8088", access_token="my-token", index="dmarc")
        self.assertEqual(client.session.headers["Authorization"], "Splunk my-token")

    def test_user_agent_header_is_set(self):
        client = HECClient(url="https://h:8088", access_token="my-token", index="dmarc")
        self.assertIn("parsedmarc", client.session.headers["User-Agent"])

    def test_token_with_splunk_prefix_is_normalized(self):
        """If a user pastes `Splunk <token>` from the Splunk UI into
        config, the constructor strips the prefix so the resulting
        Authorization header isn't `Splunk Splunk <token>`."""
        client = HECClient(
            url="https://h:8088",
            access_token="Splunk abc-token-uuid",
            index="dmarc",
        )
        self.assertEqual(client.access_token, "abc-token-uuid")

    def test_token_without_prefix_is_unchanged(self):
        """The lstrip("Splunk ") implementation has character-set
        semantics, not prefix semantics — it happens to work for the
        UUID-shaped tokens HEC issues (none of S/p/l/u/n/k/space
        appear in a UUID's hex character set). A token containing
        only hex digits and dashes is unchanged."""
        client = HECClient(
            url="https://h:8088",
            access_token="abc-token-uuid",
            index="dmarc",
        )
        self.assertEqual(client.access_token, "abc-token-uuid")

    def test_common_data_carries_host_source_and_index(self):
        """Splunk events inherit these three top-level fields. A
        regression here would mis-route events to the wrong index."""
        client = HECClient(
            url="https://h:8088", access_token="t", index="dmarc", source="my-source"
        )
        self.assertEqual(client._common_data["index"], "dmarc")
        self.assertEqual(client._common_data["source"], "my-source")
        # host defaults to socket.getfqdn(); non-empty is enough.
        self.assertTrue(client._common_data["host"])


class TestSaveAggregateReportsToSplunk(unittest.TestCase):
    """Each record is emitted as a separate Splunk event, with the
    record's interval_begin as the event timestamp, the report's
    metadata flattened onto the event, and sourcetype dmarc:aggregate."""

    def test_sends_one_event_per_record(self):
        """Two-record report → two newline-separated events in the POST body."""
        client = _client()
        report = _aggregate_report()
        report["records"].append(report["records"][0].copy())
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_aggregate_reports_to_splunk(report)
        body = client.session.post.call_args.kwargs["data"]
        events = [json.loads(line) for line in body.strip().split("\n")]
        self.assertEqual(len(events), 2)
        for event in events:
            self.assertEqual(event["sourcetype"], "dmarc:aggregate")
            self.assertEqual(event["index"], "dmarc")

    def test_event_payload_carries_source_metadata(self):
        """The flattened event includes source attribution fields a
        Splunk dashboard would filter on."""
        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_aggregate_reports_to_splunk(_aggregate_report())
        body = client.session.post.call_args.kwargs["data"]
        event = json.loads(body.strip())["event"]
        self.assertEqual(event["source_ip_address"], "192.0.2.1")
        self.assertEqual(event["header_from"], "example.com")
        self.assertEqual(event["message_count"], 4)
        self.assertEqual(event["passed_dmarc"], True)
        self.assertEqual(event["org_name"], "TestOrg")

    def test_event_includes_published_policy(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_aggregate_reports_to_splunk(_aggregate_report())
        event = json.loads(client.session.post.call_args.kwargs["data"].strip())[
            "event"
        ]
        self.assertEqual(
            event["published_policy"], {"domain": "example.com", "p": "none"}
        )

    def test_dict_input_normalized_to_list(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_aggregate_reports_to_splunk(_aggregate_report())
        client.session.post.assert_called_once()

    def test_empty_list_is_a_noop(self):
        client = _client()
        client.session = MagicMock()
        client.save_aggregate_reports_to_splunk([])
        client.session.post.assert_not_called()

    def test_post_uses_session_verify_and_timeout(self):
        client = HECClient(
            url="https://h:8088",
            access_token="t",
            index="dmarc",
            verify=False,
            timeout=15,
        )
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_aggregate_reports_to_splunk(_aggregate_report())
        kwargs = client.session.post.call_args.kwargs
        self.assertEqual(kwargs["verify"], False)
        self.assertEqual(kwargs["timeout"], 15)

    def test_non_zero_response_code_raises_splunk_error(self):
        """HEC returns code=0 on success and non-zero codes for
        token/index/format errors. The error text from HEC carries
        the diagnosis and is propagated."""
        client = _client()
        client.session = MagicMock()
        bad = MagicMock()
        bad.json.return_value = {"code": 4, "text": "Invalid token"}
        client.session.post.return_value = bad
        with self.assertRaises(SplunkError) as ctx:
            client.save_aggregate_reports_to_splunk(_aggregate_report())
        self.assertIn("Invalid token", str(ctx.exception))

    def test_post_exception_translates_to_splunk_error(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.side_effect = OSError("network")
        with self.assertRaises(SplunkError) as ctx:
            client.save_aggregate_reports_to_splunk(_aggregate_report())
        self.assertIn("network", str(ctx.exception))


class TestSaveFailureReportsToSplunk(unittest.TestCase):
    def test_sends_one_event_per_report(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_failure_reports_to_splunk([_failure_report(), _failure_report()])
        events = [
            json.loads(line)
            for line in client.session.post.call_args.kwargs["data"].strip().split("\n")
        ]
        self.assertEqual(len(events), 2)
        for event in events:
            self.assertEqual(event["sourcetype"], "dmarc:failure")

    def test_event_payload_is_the_report_dict(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_failure_reports_to_splunk(_failure_report())
        event = json.loads(client.session.post.call_args.kwargs["data"].strip())[
            "event"
        ]
        self.assertEqual(event["reported_domain"], "example.com")

    def test_empty_list_is_a_noop(self):
        client = _client()
        client.session = MagicMock()
        client.save_failure_reports_to_splunk([])
        client.session.post.assert_not_called()

    @unittest.skipUnless(hasattr(time, "tzset"), "requires POSIX time.tzset()")
    def test_event_time_treats_arrival_date_utc_as_utc(self):
        """arrival_date_utc is a UTC wall-clock string; the HEC event
        `time` must be its true UTC epoch regardless of the host
        timezone. Regression test for
        https://github.com/domainaware/parsedmarc/issues/811 (bug 1):
        the naive parse used to shift the epoch by the host's UTC
        offset (-3600 s under Europe/Warsaw in January)."""
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "Europe/Warsaw"
        time.tzset()

        def restore():
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

        self.addCleanup(restore)

        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_failure_reports_to_splunk(_failure_report())
        event = json.loads(client.session.post.call_args.kwargs["data"].strip())
        # Fixture arrival_date_utc is 2024-01-01 00:00:00 UTC.
        self.assertEqual(event["time"], 1704067200)

    def test_non_zero_response_code_raises_splunk_error(self):
        client = _client()
        client.session = MagicMock()
        bad = MagicMock()
        bad.json.return_value = {"code": 6, "text": "Invalid data format"}
        client.session.post.return_value = bad
        with self.assertRaises(SplunkError):
            client.save_failure_reports_to_splunk(_failure_report())

    def test_post_exception_translates_to_splunk_error(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.side_effect = RuntimeError("conn refused")
        with self.assertRaises(SplunkError):
            client.save_failure_reports_to_splunk(_failure_report())

    def test_verify_false_logs_skip_message(self):
        """verify=False should leave a debug breadcrumb so operators
        can spot misconfigured TLS in their logs."""
        client = HECClient(
            url="https://h:8088", access_token="t", index="dmarc", verify=False
        )
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        with self.assertLogs("parsedmarc.log", level="DEBUG") as cm:
            client.save_failure_reports_to_splunk(_failure_report())
        self.assertTrue(
            any("Skipping certificate verification" in m for m in cm.output)
        )


class TestSaveSmtpTlsReportsToSplunk(unittest.TestCase):
    def test_sends_one_event_per_report(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_smtp_tls_reports_to_splunk([_smtp_tls_report()])
        events = [
            json.loads(line)
            for line in client.session.post.call_args.kwargs["data"].strip().split("\n")
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["sourcetype"], "smtp:tls")

    def test_dict_input_normalized_to_list(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        client.save_smtp_tls_reports_to_splunk(_smtp_tls_report())
        client.session.post.assert_called_once()

    def test_empty_list_is_a_noop(self):
        client = _client()
        client.session = MagicMock()
        client.save_smtp_tls_reports_to_splunk([])
        client.session.post.assert_not_called()

    def test_non_zero_response_code_raises_splunk_error(self):
        client = _client()
        client.session = MagicMock()
        bad = MagicMock()
        bad.json.return_value = {"code": 7, "text": "Incorrect index"}
        client.session.post.return_value = bad
        with self.assertRaises(SplunkError):
            client.save_smtp_tls_reports_to_splunk(_smtp_tls_report())

    def test_post_exception_translates_to_splunk_error(self):
        client = _client()
        client.session = MagicMock()
        client.session.post.side_effect = RuntimeError("conn refused")
        with self.assertRaises(SplunkError):
            client.save_smtp_tls_reports_to_splunk(_smtp_tls_report())

    def test_verify_false_logs_skip_message(self):
        client = HECClient(
            url="https://h:8088", access_token="t", index="dmarc", verify=False
        )
        client.session = MagicMock()
        client.session.post.return_value = _ok_response()
        with self.assertLogs("parsedmarc.log", level="DEBUG") as cm:
            client.save_smtp_tls_reports_to_splunk(_smtp_tls_report())
        self.assertTrue(
            any("Skipping certificate verification" in m for m in cm.output)
        )


class TestHECClientClose(unittest.TestCase):
    def test_close_closes_session(self):
        client = _client()
        client.session = MagicMock()
        client.close()
        client.session.close.assert_called_once()


class TestSplunkBackwardCompatAlias(unittest.TestCase):
    def test_forensic_alias_points_to_failure_method(self):
        self.assertIs(
            HECClient.save_forensic_reports_to_splunk,
            HECClient.save_failure_reports_to_splunk,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
