"""Tests for parsedmarc.syslog"""

import json
import logging
import socket
import unittest
from unittest.mock import MagicMock, patch

from typing import cast

from parsedmarc.syslog import SyslogClient
from parsedmarc.types import AggregateReport, FailureReport, SMTPTLSReport


def _sample_aggregate_report() -> AggregateReport:
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
                "count": 9,
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
                "auth_results": {"dkim": [], "spf": []},
            }
        ],
    }
    return cast(AggregateReport, report)


class _CapturingHandler(logging.Handler):
    """Records the messages emitted by SyslogClient.logger."""

    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _fresh_logger():
    """Reset the module-level parsedmarc_syslog logger before each test."""
    logging.getLogger("parsedmarc_syslog").handlers.clear()


class TestSyslogClientInitUdp(unittest.TestCase):
    """UDP is the default protocol — back-compat for every existing
    deployment. The handler must be SOCK_DGRAM, not SOCK_STREAM."""

    def test_udp_uses_dgram_socket(self):
        _fresh_logger()
        with patch("parsedmarc.syslog.logging.handlers.SysLogHandler") as mock_handler:
            SyslogClient(server_name="syslog.example.com", server_port=514)
        mock_handler.assert_called_once_with(
            address=("syslog.example.com", 514),
            socktype=socket.SOCK_DGRAM,
        )

    def test_udp_is_default(self):
        """Explicit protocol='udp' and default produce the same call."""
        _fresh_logger()
        with patch("parsedmarc.syslog.logging.handlers.SysLogHandler") as mock_handler:
            SyslogClient("s", 514, protocol="udp")
        kwargs = mock_handler.call_args.kwargs
        self.assertEqual(kwargs["socktype"], socket.SOCK_DGRAM)


class TestSyslogClientInitTcp(unittest.TestCase):
    """TCP path applies the configured timeout to the underlying socket
    and uses SOCK_STREAM. Wrong socket type would silently fail to
    deliver messages."""

    def test_tcp_uses_stream_socket(self):
        _fresh_logger()
        with patch("parsedmarc.syslog.logging.handlers.SysLogHandler") as mock_handler:
            mock_handler.return_value.socket = MagicMock()
            SyslogClient("s", 6514, protocol="tcp")
        kwargs = mock_handler.call_args.kwargs
        self.assertEqual(kwargs["socktype"], socket.SOCK_STREAM)

    def test_tcp_applies_timeout_to_socket(self):
        _fresh_logger()
        sock = MagicMock()
        with patch("parsedmarc.syslog.logging.handlers.SysLogHandler") as mock_handler:
            mock_handler.return_value.socket = sock
            SyslogClient("s", 6514, protocol="tcp", timeout=12.5)
        sock.settimeout.assert_called_once_with(12.5)


class TestSyslogClientInitTls(unittest.TestCase):
    """TLS path: TLS ≥1.2 minimum, optional CA + client cert, retry on
    connection failure. Each has user-facing security consequences."""

    def _patch_handler_and_ssl(self):
        handler_patch = patch("parsedmarc.syslog.logging.handlers.SysLogHandler")
        ssl_patch = patch("parsedmarc.syslog.ssl.create_default_context")
        return handler_patch, ssl_patch

    def test_tls_enforces_tls_1_2_minimum(self):
        """The lowest version security teams accept is TLS 1.2."""
        _fresh_logger()
        import ssl

        handler_p, ssl_p = self._patch_handler_and_ssl()
        with handler_p as mock_h, ssl_p as mock_ctx_factory:
            mock_h.return_value.socket = MagicMock()
            ctx = mock_ctx_factory.return_value
            SyslogClient("s", 6514, protocol="tls")
        mock_ctx_factory.assert_called_once_with()
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_tls_loads_ca_when_cafile_provided(self):
        _fresh_logger()
        handler_p, ssl_p = self._patch_handler_and_ssl()
        with handler_p as mock_h, ssl_p as mock_ctx_factory:
            mock_h.return_value.socket = MagicMock()
            SyslogClient("s", 6514, protocol="tls", cafile_path="/etc/ca.pem")
        mock_ctx_factory.return_value.load_verify_locations.assert_called_once_with(
            cafile="/etc/ca.pem"
        )

    def test_tls_loads_client_cert_when_both_paths_provided(self):
        _fresh_logger()
        handler_p, ssl_p = self._patch_handler_and_ssl()
        with handler_p as mock_h, ssl_p as mock_ctx_factory:
            mock_h.return_value.socket = MagicMock()
            SyslogClient(
                "s",
                6514,
                protocol="tls",
                certfile_path="/etc/c.pem",
                keyfile_path="/etc/k.pem",
            )
        mock_ctx_factory.return_value.load_cert_chain.assert_called_once_with(
            certfile="/etc/c.pem",
            keyfile="/etc/k.pem",
        )

    def test_tls_warns_when_only_certfile_provided(self):
        """Half-configured client auth (cert without key, or vice
        versa) is a config bug that disables client auth silently.
        The code warns instead."""
        _fresh_logger()
        handler_p, ssl_p = self._patch_handler_and_ssl()
        with handler_p as mock_h, ssl_p:
            mock_h.return_value.socket = MagicMock()
            with self.assertLogs("parsedmarc_syslog", level="WARNING") as cm:
                SyslogClient("s", 6514, protocol="tls", certfile_path="/etc/c.pem")
        self.assertTrue(
            any("Both certfile_path and keyfile_path" in m for m in cm.output)
        )

    def test_tls_wraps_socket_with_server_hostname(self):
        """server_name is used as TLS SNI / certificate-verification hostname."""
        _fresh_logger()
        wrapped_sock = MagicMock()
        handler_p, ssl_p = self._patch_handler_and_ssl()
        with handler_p as mock_h, ssl_p as mock_ctx_factory:
            raw_sock = MagicMock()
            mock_h.return_value.socket = raw_sock
            mock_ctx_factory.return_value.wrap_socket.return_value = wrapped_sock
            SyslogClient("syslog.example.com", 6514, protocol="tls")
        mock_ctx_factory.return_value.wrap_socket.assert_called_once_with(
            raw_sock, server_hostname="syslog.example.com"
        )

    def test_tls_retries_then_succeeds(self):
        """Transient connection failures should retry up to
        retry_attempts before raising."""
        _fresh_logger()
        attempts = {"n": 0}

        def flaky_handler(*args, **kwargs):
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise OSError("network down")
            h = MagicMock()
            h.socket = MagicMock()
            return h

        with (
            patch(
                "parsedmarc.syslog.logging.handlers.SysLogHandler",
                side_effect=flaky_handler,
            ),
            patch("parsedmarc.syslog.ssl.create_default_context"),
            patch("parsedmarc.syslog.time.sleep") as mock_sleep,
        ):
            SyslogClient("s", 6514, protocol="tls", retry_attempts=3, retry_delay=1)
        self.assertEqual(attempts["n"], 2)
        mock_sleep.assert_called_with(1)

    def test_tls_raises_after_exhausting_retries(self):
        _fresh_logger()
        with (
            patch(
                "parsedmarc.syslog.logging.handlers.SysLogHandler",
                side_effect=OSError("network down"),
            ),
            patch("parsedmarc.syslog.ssl.create_default_context"),
            patch("parsedmarc.syslog.time.sleep"),
        ):
            with self.assertRaises(OSError):
                SyslogClient("s", 6514, protocol="tls", retry_attempts=2, retry_delay=0)


class TestSyslogClientInitInvalidProtocol(unittest.TestCase):
    """Typos in the protocol field should fail loudly."""

    def test_invalid_protocol_raises_value_error(self):
        _fresh_logger()
        with self.assertRaises(ValueError) as ctx:
            SyslogClient("s", 514, protocol="udb")
        self.assertIn("udb", str(ctx.exception))
        self.assertIn("'udp', 'tcp', or 'tls'", str(ctx.exception))

    def test_zero_retry_attempts_raises_value_error(self):
        """retry_attempts < 1 means the TCP/TLS connect loop never runs.
        Before the fix, _create_syslog_handler fell through and returned
        None, which was then passed to logger.addHandler(); now it raises
        ValueError instead of silently configuring a broken client."""
        _fresh_logger()
        with patch("parsedmarc.syslog.logging.handlers.SysLogHandler") as handler_cls:
            with self.assertRaises(ValueError) as ctx:
                SyslogClient("s", 514, protocol="tcp", retry_attempts=0)
        handler_cls.assert_not_called()
        self.assertIn("retry_attempts", str(ctx.exception))


class TestSyslogClientSave(unittest.TestCase):
    """save_* methods emit one syslog message per CSV row, each as a
    JSON-encoded payload. Wrong format would break downstream parsers."""

    def _client_with_capture(self):
        _fresh_logger()
        with patch("parsedmarc.syslog.logging.handlers.SysLogHandler"):
            client = SyslogClient("s", 514)
        client.logger.removeHandler(client.log_handler)
        cap = _CapturingHandler()
        client.logger.addHandler(cap)
        return client, cap

    def test_save_aggregate_emits_json_per_row(self):
        client, cap = self._client_with_capture()
        client.save_aggregate_report_to_syslog([_sample_aggregate_report()])
        self.assertEqual(len(cap.messages), 1)
        payload = json.loads(cap.messages[0])
        self.assertEqual(payload["source_ip_address"], "192.0.2.1")
        self.assertEqual(payload["count"], 9)
        self.assertEqual(payload["org_name"], "example.com")

    def test_save_failure_emits_json_per_report(self):
        client, cap = self._client_with_capture()
        failure_report = {
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
        client.save_failure_report_to_syslog([cast(FailureReport, failure_report)])
        self.assertEqual(len(cap.messages), 1)
        payload = json.loads(cap.messages[0])
        self.assertEqual(payload["reported_domain"], "example.com")
        self.assertEqual(payload["source_ip_address"], "192.0.2.5")

    def test_save_smtp_tls_emits_json_per_policy(self):
        client, cap = self._client_with_capture()
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
        client.save_smtp_tls_report_to_syslog([cast(SMTPTLSReport, report)])
        self.assertEqual(len(cap.messages), 1)
        payload = json.loads(cap.messages[0])
        self.assertEqual(payload["policy_domain"], "example.com")


class TestSyslogClientClose(unittest.TestCase):
    def test_close_removes_and_closes_handler(self):
        _fresh_logger()
        with patch("parsedmarc.syslog.logging.handlers.SysLogHandler") as mock_handler:
            client = SyslogClient("s", 514)
        client.close()
        mock_handler.return_value.close.assert_called_once()
        self.assertNotIn(mock_handler.return_value, client.logger.handlers)


class TestSyslogBackwardCompatAlias(unittest.TestCase):
    def test_forensic_alias_points_to_failure_method(self):
        self.assertIs(
            SyslogClient.save_forensic_report_to_syslog,
            SyslogClient.save_failure_report_to_syslog,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
