"""Tests for parsedmarc.gelf"""

import logging
import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from parsedmarc.gelf import ContextFilter, GelfClient, log_context_data
from parsedmarc.types import AggregateReport, FailureReport, SMTPTLSReport


def _sample_aggregate_report() -> AggregateReport:
    """Minimal aggregate report shape acceptable to
    parsed_aggregate_reports_to_csv_rows."""
    report = {
        "xml_schema": "draft",
        "xml_namespace": None,
        "report_metadata": {
            "org_name": "example.com",
            "org_email": "dmarc@example.com",
            "org_extra_contact_info": None,
            "report_id": "agg-1",
            "begin_date": "2024-01-01 00:00:00",
            "end_date": "2024-01-02 00:00:00",
            "timespan_requires_normalization": False,
            "original_timespan_seconds": 86400,
            "errors": [],
            "generator": None,
        },
        "policy_published": {
            "domain": "example.com",
            "adkim": "r",
            "aspf": "r",
            "p": "none",
            "sp": "none",
            "pct": None,
            "fo": None,
            "np": None,
            "testing": None,
            "discovery_method": None,
        },
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
                "count": 7,
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
                            "selector": "s1",
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
    return cast(AggregateReport, report)


class _Handler(logging.Handler):
    """Capture the (record, extra) of every log emit, so tests can
    assert on what GelfClient actually pushed."""

    def __init__(self):
        super().__init__()
        self.records: list[tuple[str, Any]] = []

    def emit(self, record):
        # ContextFilter has run by this point so `record.parsedmarc` is
        # whatever payload GelfClient set via log_context_data.
        self.records.append((record.getMessage(), getattr(record, "parsedmarc", None)))


class TestGelfClientInit(unittest.TestCase):
    """GelfClient.__init__ wires a pygelf handler for the requested
    transport. The mode lookup is a real failure surface: a typo in the
    config (`udb` instead of `udp`) should KeyError loudly, not silently
    pick the wrong transport."""

    def test_init_udp_picks_udp_handler(self):
        with (
            patch("parsedmarc.gelf.GelfUdpHandler") as mock_udp,
            patch("parsedmarc.gelf.GelfTcpHandler"),
            patch("parsedmarc.gelf.GelfTlsHandler"),
        ):
            GelfClient(host="graylog.example.com", port=12201, mode="udp")
        mock_udp.assert_called_once_with(
            host="graylog.example.com", port=12201, include_extra_fields=True
        )

    def test_init_tcp_picks_tcp_handler(self):
        with (
            patch("parsedmarc.gelf.GelfTcpHandler") as mock_tcp,
            patch("parsedmarc.gelf.GelfUdpHandler"),
            patch("parsedmarc.gelf.GelfTlsHandler"),
        ):
            GelfClient(host="g", port=12201, mode="tcp")
        mock_tcp.assert_called_once_with(
            host="g", port=12201, include_extra_fields=True
        )

    def test_init_tls_picks_tls_handler(self):
        with (
            patch("parsedmarc.gelf.GelfTlsHandler") as mock_tls,
            patch("parsedmarc.gelf.GelfUdpHandler"),
            patch("parsedmarc.gelf.GelfTcpHandler"),
        ):
            GelfClient(host="g", port=12201, mode="tls")
        mock_tls.assert_called_once_with(
            host="g", port=12201, include_extra_fields=True
        )

    def test_init_unknown_mode_raises_keyerror(self):
        """An unknown mode in config should be a loud failure, not silent."""
        with (
            patch("parsedmarc.gelf.GelfUdpHandler"),
            patch("parsedmarc.gelf.GelfTcpHandler"),
            patch("parsedmarc.gelf.GelfTlsHandler"),
        ):
            with self.assertRaises(KeyError):
                GelfClient(host="g", port=12201, mode="udb")


def _install_capturing_handler(client):
    """Replace the real pygelf handler with one that records emitted
    log records and their `parsedmarc` payload. Returns the handler
    so the test can inspect captured records."""
    client.logger.removeHandler(client.handler)
    h = _Handler()
    client.logger.addHandler(h)
    client.handler = h
    return h


def _gelf_client():
    # The parsedmarc_gelf logger is module-level — each new client adds
    # another handler. Clear stale handlers from prior tests so the
    # logger only carries this client's handler.
    logging.getLogger("parsedmarc_gelf").handlers.clear()
    with (
        patch("parsedmarc.gelf.GelfUdpHandler"),
        patch("parsedmarc.gelf.GelfTcpHandler"),
        patch("parsedmarc.gelf.GelfTlsHandler"),
    ):
        return GelfClient(host="g", port=12201, mode="udp")


class TestGelfClientSaveAggregate(unittest.TestCase):
    """save_aggregate_report_to_gelf emits one log record per
    aggregate CSV row, with the row payload on `record.parsedmarc`.
    Verifying the payload — not just "log was called" — catches future
    regressions in the row-builder or filter wiring."""

    def test_emits_one_record_per_csv_row_with_payload(self):
        client = _gelf_client()
        handler = _install_capturing_handler(client)
        client.save_aggregate_report_to_gelf([_sample_aggregate_report()])
        # One row in the sample report → one log record.
        self.assertEqual(len(handler.records), 1)
        message, payload = handler.records[0]
        self.assertEqual(message, "parsedmarc aggregate report")
        # The payload is the flattened CSV row; verify the key fields a
        # Graylog dashboard would actually filter on.
        self.assertEqual(payload["source_ip_address"], "192.0.2.1")
        self.assertEqual(payload["header_from"], "example.com")
        self.assertEqual(payload["count"], 7)

    def test_clears_context_after_emit(self):
        """The thread-local payload is reset to None after the loop so
        a later unrelated log call on the same thread doesn't carry
        stale DMARC data."""
        client = _gelf_client()
        _install_capturing_handler(client)
        client.save_aggregate_report_to_gelf([_sample_aggregate_report()])
        self.assertIsNone(log_context_data.parsedmarc)


class TestGelfClientSaveFailure(unittest.TestCase):
    """save_failure_report_to_gelf operates on already-parsed failure
    reports. Build one through the CSV-row helper to verify GelfClient
    surfaces the right fields."""

    def _sample_failure_report(self) -> FailureReport:
        report = {
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
        return cast(FailureReport, report)

    def test_emits_one_record_per_failure_report(self):
        client = _gelf_client()
        handler = _install_capturing_handler(client)
        client.save_failure_report_to_gelf([self._sample_failure_report()])
        self.assertEqual(len(handler.records), 1)
        message, payload = handler.records[0]
        self.assertEqual(message, "parsedmarc failure report")
        self.assertEqual(payload["source_ip_address"], "192.0.2.5")
        self.assertEqual(payload["reported_domain"], "example.com")


class TestGelfClientSaveSmtpTls(unittest.TestCase):
    def _sample_smtp_tls(self) -> SMTPTLSReport:
        report = {
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
        return cast(SMTPTLSReport, report)

    def test_emits_one_record_per_policy(self):
        client = _gelf_client()
        handler = _install_capturing_handler(client)
        client.save_smtp_tls_report_to_gelf([self._sample_smtp_tls()])
        self.assertEqual(len(handler.records), 1)
        message, payload = handler.records[0]
        self.assertEqual(message, "parsedmarc smtptls report")
        self.assertEqual(payload["policy_domain"], "example.com")
        self.assertEqual(payload["successful_session_count"], 100)


class TestContextFilter(unittest.TestCase):
    """ContextFilter copies log_context_data.parsedmarc onto the log
    record so pygelf can include it as an extra field. Failure mode:
    if the filter raises (or removes itself), GELF output goes dark."""

    def test_filter_copies_thread_local_onto_record(self):
        log_context_data.parsedmarc = {"hello": "world"}
        try:
            f = ContextFilter()
            record = logging.LogRecord(
                name="x",
                level=logging.INFO,
                pathname=__file__,
                lineno=1,
                msg="msg",
                args=(),
                exc_info=None,
            )
            result = f.filter(record)
            self.assertTrue(result)
            self.assertEqual(record.parsedmarc, {"hello": "world"})  # type: ignore[attr-defined]
        finally:
            log_context_data.parsedmarc = None


class TestGelfClientClose(unittest.TestCase):
    def test_close_removes_and_closes_handler(self):
        client = _gelf_client()
        handler = MagicMock()
        client.logger.removeHandler(client.handler)
        client.logger.addHandler(handler)
        client.handler = handler
        client.close()
        handler.close.assert_called_once()
        # Handler should no longer be attached after close().
        self.assertNotIn(handler, client.logger.handlers)


class TestGelfClientBackwardCompatAlias(unittest.TestCase):
    def test_forensic_alias_points_to_failure_method(self):
        self.assertIs(
            GelfClient.save_forensic_report_to_gelf,
            GelfClient.save_failure_report_to_gelf,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
