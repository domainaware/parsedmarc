"""Tests for parsedmarc.gsecops"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

import parsedmarc
from parsedmarc.gsecops import (
    GoogleSecOpsClient,
    GoogleSecOpsError,
    aggregate_report_to_udm_events,
    failure_report_to_udm_events,
    smtp_tls_report_to_udm_events,
)
from parsedmarc.types import AggregateReport, FailureReport, SMTPTLSReport


def _parse_sample(path: str) -> Any:
    result = parsedmarc.parse_report_file(
        path, always_use_local_files=True, offline=True
    )
    return result["report"]


def _aggregate_report() -> AggregateReport:
    return cast(
        AggregateReport,
        _parse_sample("samples/aggregate/!example.com!1538204542!1538463818.xml"),
    )


def _failure_report() -> FailureReport:
    return cast(
        FailureReport,
        _parse_sample(
            "samples/failure/DMARC Failure Report for domain.de "
            "(mail-from=sharepoint@domain.de, ip=10.10.10.10).eml"
        ),
    )


def _smtp_tls_report() -> SMTPTLSReport:
    return cast(SMTPTLSReport, _parse_sample("samples/smtp_tls/mail.ru.json"))


class TestAggregateUdmEvents(unittest.TestCase):
    """Aggregate reports map to EMAIL_TRANSACTION events whose fields a
    UDM search or dashboard would actually filter on."""

    def test_event_shape(self):
        events = aggregate_report_to_udm_events(_aggregate_report())
        self.assertEqual(len(events), 1)
        udm = events[0]["udm"]
        metadata = udm["metadata"]
        self.assertEqual(metadata["eventType"], "EMAIL_TRANSACTION")
        # RFC 3339: the record interval start, not ingest time
        self.assertEqual(metadata["eventTimestamp"], "2018-10-01T17:07:12Z")
        self.assertEqual(metadata["vendorName"], "parsedmarc")
        self.assertEqual(metadata["productName"], "parsedmarc")
        self.assertEqual(metadata["productEventType"], "aggregate")
        self.assertEqual(metadata["productLogId"], "example.com:1538463741")
        self.assertEqual(udm["principal"]["ip"], ["12.20.127.122"])
        self.assertEqual(udm["principal"]["location"]["countryOrRegion"], "US")
        self.assertEqual(udm["target"]["hostname"], "example.com")
        # aggregate reports only carry the From domain
        self.assertEqual(udm["network"]["email"]["from"], "example.com")

    def test_security_result(self):
        events = aggregate_report_to_udm_events(_aggregate_report())
        (security_result,) = events[0]["udm"]["securityResult"]
        # disposition "none" -> ALLOW; action and category are repeated
        # fields in the UDM SecurityResult message
        self.assertEqual(security_result["action"], ["ALLOW"])
        # dmarc_aligned is False in this sample -> AUTH_VIOLATION
        self.assertEqual(security_result["category"], ["AUTH_VIOLATION"])

    def test_additional_preserves_native_json_types(self):
        """additional is a protobuf Struct, so numbers and booleans must
        arrive as native JSON types for range queries and boolean filters —
        parsedmarc's "store numbers as numbers" rule."""
        events = aggregate_report_to_udm_events(_aggregate_report())
        additional = events[0]["udm"]["additional"]
        self.assertIs(additional["count"], 1)
        self.assertEqual(additional["source_asn"], 7018)
        self.assertIs(additional["dmarc_aligned"], False)
        self.assertIs(additional["spf_aligned"], False)
        # renamed keys match the CBN parser in google_secops_parser/ so
        # searches port between the two delivery paths
        self.assertEqual(additional["dmarc_policy"], "none")
        self.assertEqual(additional["dmarc_subdomain_policy"], "reject")
        self.assertEqual(additional["dmarc_pct"], "100")
        self.assertEqual(additional["source_name"], "AT&T")

    def test_additional_drops_empty_values(self):
        """Absent report fields are empty strings in the flat rows; they
        must not appear as empty additional entries."""
        events = aggregate_report_to_udm_events(_aggregate_report())
        additional = events[0]["udm"]["additional"]
        for key, value in additional.items():
            self.assertNotEqual(value, "", f"empty value for {key}")
        # this sample publishes no np/fo/testing and no DKIM results
        self.assertNotIn("dmarc_np_policy", additional)
        self.assertNotIn("dmarc_fo", additional)
        self.assertNotIn("dmarc_testing", additional)
        self.assertNotIn("dkim_domains", additional)


class TestFailureUdmEvents(unittest.TestCase):
    def test_event_shape(self):
        events = failure_report_to_udm_events(_failure_report())
        self.assertEqual(len(events), 1)
        udm = events[0]["udm"]
        metadata = udm["metadata"]
        self.assertEqual(metadata["eventType"], "EMAIL_TRANSACTION")
        self.assertEqual(metadata["eventTimestamp"], "2018-10-01T09:20:27Z")
        self.assertEqual(metadata["productEventType"], "failure")
        self.assertEqual(udm["principal"]["ip"], ["10.10.10.10"])
        self.assertEqual(udm["target"]["hostname"], "domain.de")
        email = udm["network"]["email"]
        self.assertEqual(email["from"], "sharepoint@domain.de")
        # to and subject are repeated fields in the UDM Email message
        self.assertEqual(email["to"], ["peter.pan@domain.de"])
        self.assertEqual(email["subject"], ["Subject"])
        self.assertEqual(email["mailId"], metadata["productLogId"])

    def test_security_result(self):
        events = failure_report_to_udm_events(_failure_report())
        (security_result,) = events[0]["udm"]["securityResult"]
        self.assertEqual(security_result["category"], ["AUTH_VIOLATION"])
        # delivery_result "policy" has no direct action mapping
        self.assertEqual(security_result["action"], ["UNKNOWN_ACTION"])

    def test_additional_drops_null_enrichment(self):
        """Failure rows carry None for offline enrichment fields
        (source_name, dkim_domain, ...); None must never reach the API."""
        events = failure_report_to_udm_events(_failure_report())
        additional = events[0]["udm"]["additional"]
        for key, value in additional.items():
            self.assertIsNotNone(value, f"null value for {key}")
            self.assertNotEqual(value, "", f"empty value for {key}")
        self.assertEqual(additional["auth_failure"], "dmarc")
        self.assertEqual(additional["delivery_result"], "policy")
        self.assertNotIn("source_name", additional)
        self.assertNotIn("dkim_domain", additional)


class TestSmtpTlsUdmEvents(unittest.TestCase):
    def test_success_and_failure_rows(self):
        events = smtp_tls_report_to_udm_events(_smtp_tls_report())
        # mail.ru sample: one policy summary row + two failure details
        self.assertEqual(len(events), 3)
        for event in events:
            udm = event["udm"]
            self.assertEqual(udm["metadata"]["eventType"], "GENERIC_EVENT")
            self.assertEqual(udm["metadata"]["eventTimestamp"], "2024-02-22T00:00:00Z")
            # the policy domain is the noun on every row, including
            # failure details (requires the paired serializer fix)
            self.assertEqual(udm["target"]["hostname"], "example.com")
            self.assertEqual(udm["additional"]["policy_type"], "sts")
        success, failure = events[0]["udm"], events[1]["udm"]
        # summary rows carry counts (as numbers) and no security_result
        self.assertNotIn("securityResult", success)
        self.assertEqual(success["additional"]["successful_session_count"], 0)
        self.assertEqual(success["additional"]["failed_session_count"], 1)
        # failure rows carry the result_type and a FAIL security_result
        (security_result,) = failure["securityResult"]
        self.assertEqual(security_result["action"], ["FAIL"])
        self.assertEqual(security_result["category"], ["POLICY_VIOLATION"])
        self.assertEqual(failure["additional"]["result_type"], "sts-policy-fetch-error")
        self.assertEqual(
            failure["additional"]["failure_reason_code"],
            "bad https response code: 404",
        )


def _client() -> tuple[GoogleSecOpsClient, MagicMock]:
    """Builds a client with mocked Google credentials and returns it along
    with the mocked AuthorizedSession instance."""
    with (
        patch(
            "parsedmarc.gsecops.google.auth.default",
            return_value=(MagicMock(), "some-project"),
        ),
        patch("parsedmarc.gsecops.AuthorizedSession") as mock_session_cls,
    ):
        client = GoogleSecOpsClient(
            project_id="my-project", instance_id="my-instance", region="europe"
        )
    return client, mock_session_cls.return_value


def _response(status_code: int, text: str = "") -> MagicMock:
    return MagicMock(status_code=status_code, text=text)


def _event(name: str) -> dict:
    return {"udm": {"metadata": {"productLogId": name}}}


class TestGoogleSecOpsClient(unittest.TestCase):
    def test_missing_required_settings_raises(self):
        with self.assertRaises(GoogleSecOpsError):
            GoogleSecOpsClient(project_id="", instance_id="my-instance")
        with self.assertRaises(GoogleSecOpsError):
            GoogleSecOpsClient(project_id="my-project", instance_id="")

    def test_url_uses_region_and_parent(self):
        client, _ = _client()
        self.assertEqual(
            client.url,
            "https://chronicle.europe.rep.googleapis.com/v1/"
            "projects/my-project/locations/europe/instances/my-instance"
            "/events:import",
        )

    def test_service_account_file_credentials(self):
        with (
            patch(
                "parsedmarc.gsecops.service_account.Credentials"
                ".from_service_account_file"
            ) as mock_from_file,
            patch("parsedmarc.gsecops.AuthorizedSession"),
        ):
            GoogleSecOpsClient(
                project_id="my-project",
                instance_id="my-instance",
                credentials_file="/path/to/key.json",
            )
        self.assertEqual(mock_from_file.call_args.args[0], "/path/to/key.json")

    def test_save_events_posts_inline_source_envelope(self):
        client, session = _client()
        session.post.return_value = _response(200)
        events = [_event("a"), _event("b")]
        client.save_events(events)
        session.post.assert_called_once()
        call = session.post.call_args
        self.assertEqual(call.args[0], client.url)
        self.assertEqual(call.kwargs["timeout"], 60)
        self.assertEqual(call.kwargs["json"], {"inlineSource": {"events": events}})

    def test_save_events_batches_at_1000(self):
        client, session = _client()
        session.post.return_value = _response(200)
        client.save_events([_event(str(i)) for i in range(1500)])
        self.assertEqual(session.post.call_count, 2)
        first, second = session.post.call_args_list
        self.assertEqual(len(first.kwargs["json"]["inlineSource"]["events"]), 1000)
        self.assertEqual(len(second.kwargs["json"]["inlineSource"]["events"]), 500)

    def test_http_400_bisects_and_delivers_valid_events(self):
        """events.import is all-or-nothing: one invalid event rejects the
        whole request. The client must bisect a rejected batch so every
        valid event is still delivered, and report the drop."""
        client, session = _client()
        bad_event = _event("bad")

        def post(url, *, json, timeout):
            batch = json["inlineSource"]["events"]
            if bad_event in batch:
                return _response(400, "invalid event")
            return _response(200)

        session.post.side_effect = post
        events = [_event("a"), bad_event, _event("c")]
        with self.assertRaises(GoogleSecOpsError) as raised:
            client.save_events(events)
        self.assertIn("1 of 3", str(raised.exception))
        delivered = []
        for call in session.post.call_args_list:
            batch = call.kwargs["json"]["inlineSource"]["events"]
            if bad_event not in batch:
                delivered += batch
        self.assertIn(_event("a"), delivered)
        self.assertIn(_event("c"), delivered)

    def test_http_500_raises(self):
        client, session = _client()
        session.post.return_value = _response(500, "boom")
        with self.assertRaises(GoogleSecOpsError) as raised:
            client.save_events([_event("a"), _event("b")])
        self.assertIn("500", str(raised.exception))
        # a non-400 error must not trigger the bisect fallback
        self.assertEqual(session.post.call_count, 1)

    def test_publish_results_honors_save_flags(self):
        client, session = _client()
        session.post.return_value = _response(200)
        results = {
            "aggregate_reports": [_aggregate_report()],
            "failure_reports": [_failure_report()],
            "smtp_tls_reports": [_smtp_tls_report()],
        }
        client.publish_results(results, True, True, True)
        (call,) = session.post.call_args_list
        batch = call.kwargs["json"]["inlineSource"]["events"]
        # 1 aggregate row + 1 failure row + 3 SMTP TLS rows
        self.assertEqual(len(batch), 5)
        event_types = [e["udm"]["metadata"]["productEventType"] for e in batch]
        self.assertEqual(
            event_types, ["aggregate", "failure", "smtp_tls", "smtp_tls", "smtp_tls"]
        )

    def test_publish_results_skips_disabled_types(self):
        client, session = _client()
        session.post.return_value = _response(200)
        results = {
            "aggregate_reports": [_aggregate_report()],
            "failure_reports": [_failure_report()],
            "smtp_tls_reports": [_smtp_tls_report()],
        }
        client.publish_results(results, False, False, False)
        session.post.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
