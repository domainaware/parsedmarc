"""Tests for parsedmarc.loganalytics"""

import json
import unittest
from unittest.mock import MagicMock, patch

from azure.core.exceptions import (
    AzureError,
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)

from parsedmarc.loganalytics import (
    MAX_UPLOAD_ITEM_BYTES,
    LogAnalyticsClient,
    LogAnalyticsConfig,
    LogAnalyticsException,
)


def _valid_kwargs(**overrides):
    base = dict(
        client_id="cid",
        client_secret="csec",
        tenant_id="tid",
        dce="https://dce.example.com",
        dcr_immutable_id="dcr-123",
        dcr_aggregate_stream="agg-stream",
        dcr_failure_stream="fail-stream",
        dcr_smtp_tls_stream="tls-stream",
    )
    base.update(overrides)
    return base


def _json_size(report):
    """The size LogsIngestionClient.upload() measures a report at."""
    return len(json.dumps(report).encode("utf-8"))


def _aggregate_report(org_name, report_id, size=None):
    """An aggregate report, padded with records to ``size`` bytes of JSON."""
    report = {
        "report_metadata": {"org_name": org_name, "report_id": report_id},
        "policy_published": {"domain": "example.com"},
        "records": [],
    }
    if size is not None:
        padding = size - _json_size(report)
        # One record of the required length: ``"x"`` is 3 bytes of JSON,
        # and each extra character of the string adds one
        report["records"].append("x" * (padding - 2))
    return report


class TestLogAnalyticsConfig(unittest.TestCase):
    """The config dataclass holds every credential and stream needed
    to push to Log Analytics. A typo on any attribute would silently
    drop data into the wrong stream."""

    def test_config_stores_every_field(self):
        config = LogAnalyticsConfig(**_valid_kwargs())
        self.assertEqual(config.client_id, "cid")
        self.assertEqual(config.client_secret, "csec")
        self.assertEqual(config.tenant_id, "tid")
        self.assertEqual(config.dce, "https://dce.example.com")
        self.assertEqual(config.dcr_immutable_id, "dcr-123")
        self.assertEqual(config.dcr_aggregate_stream, "agg-stream")
        self.assertEqual(config.dcr_failure_stream, "fail-stream")
        self.assertEqual(config.dcr_smtp_tls_stream, "tls-stream")


class TestLogAnalyticsClientInit(unittest.TestCase):
    """The constructor's validation guards against a half-configured
    deployment that would otherwise fail late inside Azure SDK calls
    with confusing errors."""

    def test_init_accepts_complete_config(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        self.assertEqual(client.conf.client_id, "cid")
        self.assertEqual(client.conf.dcr_immutable_id, "dcr-123")

    def test_missing_client_id_raises(self):
        with self.assertRaises(LogAnalyticsException):
            LogAnalyticsClient(**_valid_kwargs(client_id=""))

    def test_missing_client_secret_raises(self):
        with self.assertRaises(LogAnalyticsException):
            LogAnalyticsClient(**_valid_kwargs(client_secret=""))

    def test_missing_tenant_id_raises(self):
        with self.assertRaises(LogAnalyticsException):
            LogAnalyticsClient(**_valid_kwargs(tenant_id=""))

    def test_missing_dce_raises(self):
        with self.assertRaises(LogAnalyticsException):
            LogAnalyticsClient(**_valid_kwargs(dce=""))

    def test_missing_dcr_immutable_id_raises(self):
        with self.assertRaises(LogAnalyticsException):
            LogAnalyticsClient(**_valid_kwargs(dcr_immutable_id=""))


class TestPublishJson(unittest.TestCase):
    """publish_json wraps logs_client.upload and translates Azure
    HttpResponseError into the module's own exception type so the CLI
    error reporter can handle it uniformly."""

    def test_publish_json_forwards_to_logs_client(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        logs_client = MagicMock()
        client.publish_json([{"a": 1}], logs_client, "agg-stream")
        logs_client.upload.assert_called_once_with("dcr-123", "agg-stream", [{"a": 1}])

    def test_publish_json_translates_http_error(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        logs_client = MagicMock()
        logs_client.upload.side_effect = HttpResponseError("forbidden")
        with self.assertRaises(LogAnalyticsException) as ctx:
            client.publish_json([{"a": 1}], logs_client, "stream")
        self.assertIn("forbidden", str(ctx.exception))


class TestPublishJsonSizeLimit(unittest.TestCase):
    """The Logs Ingestion API rejects a call over 1 MB, and the SDK sends a
    report larger than its 1 MiB chunk as a call of its own, so one
    oversize report used to fail the upload of every report in the batch
    (GHSA-rg4h-58fm-8pc9). Such a report is now left out with a warning."""

    def test_oversize_report_is_skipped_and_the_rest_uploaded(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        logs_client = MagicMock()
        big = _aggregate_report("Big Sender", "big-1", size=1_200_000)
        small = _aggregate_report("Small Sender", "small-1")
        self.assertGreater(_json_size(big), MAX_UPLOAD_ITEM_BYTES)
        with self.assertLogs("parsedmarc.log", level="WARNING") as logs:
            published = client.publish_json([big, small], logs_client, "agg-stream")
        logs_client.upload.assert_called_once_with("dcr-123", "agg-stream", [small])
        self.assertEqual(published, 1)
        self.assertEqual(len(logs.output), 1)
        self.assertIn(f"{_json_size(big)} bytes", logs.output[0])
        self.assertIn("agg-stream", logs.output[0])
        self.assertIn("Big Sender", logs.output[0])
        self.assertIn("big-1", logs.output[0])

    def test_all_reports_oversize_uploads_nothing(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        logs_client = MagicMock()
        reports = [
            _aggregate_report("Sender A", "a-1", size=1_100_000),
            _aggregate_report("Sender B", "b-1", size=1_100_000),
        ]
        for report in reports:
            self.assertGreater(_json_size(report), MAX_UPLOAD_ITEM_BYTES)
        with self.assertLogs("parsedmarc.log", level="WARNING") as logs:
            published = client.publish_json(reports, logs_client, "agg-stream")
        logs_client.upload.assert_not_called()
        self.assertEqual(published, 0)
        self.assertEqual(len(logs.output), 2)
        self.assertIn("a-1", logs.output[0])
        self.assertIn("b-1", logs.output[1])

    def test_report_just_under_the_limit_is_uploaded(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        logs_client = MagicMock()
        report = _aggregate_report("Sender", "r-1", size=MAX_UPLOAD_ITEM_BYTES - 1)
        self.assertEqual(_json_size(report), MAX_UPLOAD_ITEM_BYTES - 1)
        client.publish_json([report], logs_client, "agg-stream")
        logs_client.upload.assert_called_once_with("dcr-123", "agg-stream", [report])

    def test_report_one_byte_over_the_limit_is_skipped(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        logs_client = MagicMock()
        report = _aggregate_report("Sender", "r-1", size=MAX_UPLOAD_ITEM_BYTES + 1)
        self.assertEqual(_json_size(report), MAX_UPLOAD_ITEM_BYTES + 1)
        with self.assertLogs("parsedmarc.log", level="WARNING"):
            client.publish_json([report], logs_client, "agg-stream")
        logs_client.upload.assert_not_called()

    def test_warning_names_smtp_tls_and_failure_reports(self):
        """SMTP TLS reports are named by organization and report ID, and
        failure reports by reported domain and arrival date; a CR/LF a
        sender planted in a name is escaped so it cannot forge a line."""
        client = LogAnalyticsClient(**_valid_kwargs())
        logs_client = MagicMock()
        padding = "x" * 1_100_000
        tls = {
            "organization_name": "TLS\r\nForged line",
            "report_id": "tls-1",
            "policies": [padding],
        }
        failure = {
            "reported_domain": "example.org",
            "arrival_date_utc": "2026-11-10 12:00:00",
            "sample": padding,
        }
        with self.assertLogs("parsedmarc.log", level="WARNING") as logs:
            client.publish_json([tls], logs_client, "tls-stream")
            client.publish_json([failure], logs_client, "fail-stream")
        logs_client.upload.assert_not_called()
        self.assertIn("organization_name TLS\\r\\nForged line", logs.output[0])
        self.assertNotIn("\n", logs.output[0])
        self.assertIn("report_id tls-1", logs.output[0])
        self.assertIn("reported_domain example.org", logs.output[1])
        self.assertIn("arrival_date_utc 2026-11-10 12:00:00", logs.output[1])


class TestPublishResults(unittest.TestCase):
    """publish_results gates each report type behind both a config flag
    (save_aggregate / save_failure / save_smtp_tls) and a configured
    stream name. Both gates need to work — a missing stream is skipped
    silently (a partially configured client is normal), while an
    explicit save_*=False means the operator opted out."""

    def _publish_with(self, results, **flags):
        flags.setdefault("save_aggregate", True)
        flags.setdefault("save_failure", True)
        flags.setdefault("save_smtp_tls", True)
        client = LogAnalyticsClient(**_valid_kwargs())
        with (
            patch("parsedmarc.loganalytics.ClientSecretCredential"),
            patch("parsedmarc.loganalytics.LogsIngestionClient") as mock_client_cls,
        ):
            mock_logs_client = mock_client_cls.return_value
            client.publish_results(results, **flags)
        return mock_logs_client

    def test_aggregate_published_to_aggregate_stream(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [{"id": "a"}],
                "failure_reports": [],
                "smtp_tls_reports": [],
            }
        )
        logs_client.upload.assert_called_once_with(
            "dcr-123", "agg-stream", [{"id": "a"}]
        )

    def test_failure_published_to_failure_stream(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [],
                "failure_reports": [{"id": "f"}],
                "smtp_tls_reports": [],
            }
        )
        logs_client.upload.assert_called_once_with(
            "dcr-123", "fail-stream", [{"id": "f"}]
        )

    def test_smtp_tls_published_to_smtp_tls_stream(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [],
                "failure_reports": [],
                "smtp_tls_reports": [{"id": "t"}],
            }
        )
        logs_client.upload.assert_called_once_with(
            "dcr-123", "tls-stream", [{"id": "t"}]
        )

    def test_all_three_published_together(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [{"id": "a"}],
                "failure_reports": [{"id": "f"}],
                "smtp_tls_reports": [{"id": "t"}],
            }
        )
        self.assertEqual(logs_client.upload.call_count, 3)
        streams_uploaded = {call.args[1] for call in logs_client.upload.call_args_list}
        self.assertEqual(streams_uploaded, {"agg-stream", "fail-stream", "tls-stream"})

    def test_save_aggregate_false_skips_aggregate(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [{"id": "a"}],
                "failure_reports": [],
                "smtp_tls_reports": [],
            },
            save_aggregate=False,
        )
        logs_client.upload.assert_not_called()

    def test_save_failure_false_skips_failure(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [],
                "failure_reports": [{"id": "f"}],
                "smtp_tls_reports": [],
            },
            save_failure=False,
        )
        logs_client.upload.assert_not_called()

    def test_save_smtp_tls_false_skips_smtp_tls(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [],
                "failure_reports": [],
                "smtp_tls_reports": [{"id": "t"}],
            },
            save_smtp_tls=False,
        )
        logs_client.upload.assert_not_called()

    def test_empty_results_publishes_nothing(self):
        logs_client = self._publish_with(
            {
                "aggregate_reports": [],
                "failure_reports": [],
                "smtp_tls_reports": [],
            }
        )
        logs_client.upload.assert_not_called()

    def test_stream_whose_reports_are_all_oversize_logs_no_success(self):
        """A stream whose every report is over the size limit uploads
        nothing, so it must not log "Successfully pushed" (it used to,
        after the per-report warnings), while the other streams still
        upload and log their success."""
        big = _aggregate_report("Big Sender", "big-1", size=1_100_000)
        with self.assertLogs("parsedmarc.log", level="INFO") as logs:
            logs_client = self._publish_with(
                {
                    "aggregate_reports": [big],
                    "failure_reports": [{"id": "f"}],
                    "smtp_tls_reports": [{"id": "t"}],
                }
            )
        streams_uploaded = [call.args[1] for call in logs_client.upload.call_args_list]
        self.assertEqual(streams_uploaded, ["fail-stream", "tls-stream"])
        messages = [record.getMessage() for record in logs.records]
        self.assertNotIn("Successfully pushed aggregate reports.", messages)
        self.assertIn("Successfully pushed failure reports.", messages)
        self.assertIn("Successfully pushed SMTP TLS reports.", messages)
        self.assertTrue(any("big-1" in message for message in messages))

    def _publish_failing(
        self, failing_streams, error_class: type[AzureError] = HttpResponseError
    ):
        """Publishes one report of each kind with upload() raising
        ``error_class`` for the streams in ``failing_streams``."""

        def upload(rule_id, stream_name, logs):
            if stream_name in failing_streams:
                raise error_class(f"rejected by {stream_name}")

        client = LogAnalyticsClient(**_valid_kwargs())
        with (
            patch("parsedmarc.loganalytics.ClientSecretCredential"),
            patch("parsedmarc.loganalytics.LogsIngestionClient") as mock_client_cls,
        ):
            mock_logs_client = mock_client_cls.return_value
            mock_logs_client.upload.side_effect = upload
            with self.assertRaises(LogAnalyticsException) as ctx:
                client.publish_results(
                    {
                        "aggregate_reports": [{"id": "a"}],
                        "failure_reports": [{"id": "f"}],
                        "smtp_tls_reports": [{"id": "t"}],
                    },
                    save_aggregate=True,
                    save_failure=True,
                    save_smtp_tls=True,
                )
        streams = [call.args[1] for call in mock_logs_client.upload.call_args_list]
        return streams, str(ctx.exception)

    def test_failed_aggregate_upload_does_not_stop_other_streams(self):
        """GHSA-rg4h-58fm-8pc9: a failed aggregate upload returned before
        the failure and SMTP TLS streams were sent."""
        streams, message = self._publish_failing({"agg-stream"})
        self.assertEqual(streams, ["agg-stream", "fail-stream", "tls-stream"])
        self.assertIn("aggregate reports", message)
        self.assertIn("rejected by agg-stream", message)
        self.assertNotIn("failure reports", message)
        self.assertNotIn("SMTP TLS reports", message)

    def test_connection_error_does_not_stop_other_streams(self):
        """upload() re-raises any exception, and a connection reset or
        timeout is a ServiceRequestError or ServiceResponseError: an
        AzureError but not an HttpResponseError, so it escaped
        publish_results at the first stream and the other two were never
        attempted."""
        for error_class in (ServiceRequestError, ServiceResponseError):
            with self.subTest(error_class=error_class.__name__):
                streams, message = self._publish_failing(
                    {"agg-stream"}, error_class=error_class
                )
                self.assertEqual(streams, ["agg-stream", "fail-stream", "tls-stream"])
                self.assertEqual(
                    message, "aggregate reports: Upload failed: rejected by agg-stream"
                )

    def test_two_failed_streams_raise_one_exception_naming_both(self):
        streams, message = self._publish_failing({"agg-stream", "tls-stream"})
        self.assertEqual(streams, ["agg-stream", "fail-stream", "tls-stream"])
        self.assertIn(
            "aggregate reports: Upload failed: rejected by agg-stream", message
        )
        self.assertIn(
            "SMTP TLS reports: Upload failed: rejected by tls-stream", message
        )
        self.assertNotIn("failure reports", message)

    def test_failed_failure_upload_does_not_stop_smtp_tls_stream(self):
        streams, message = self._publish_failing({"fail-stream"})
        self.assertEqual(streams, ["agg-stream", "fail-stream", "tls-stream"])
        self.assertEqual(
            message, "failure reports: Upload failed: rejected by fail-stream"
        )

    def test_missing_aggregate_stream_skips_aggregate(self):
        """If the operator hasn't configured a stream for one of the
        report types, the corresponding publish branch is skipped
        silently — matching the existing CLI deployment pattern where
        a single client object handles whatever streams are set."""
        client = LogAnalyticsClient(**_valid_kwargs(dcr_aggregate_stream=""))
        with (
            patch("parsedmarc.loganalytics.ClientSecretCredential"),
            patch("parsedmarc.loganalytics.LogsIngestionClient") as mock_client_cls,
        ):
            mock_logs_client = mock_client_cls.return_value
            client.publish_results(
                {
                    "aggregate_reports": [{"id": "a"}],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
                save_aggregate=True,
                save_failure=True,
                save_smtp_tls=True,
            )
        mock_logs_client.upload.assert_not_called()

    def test_credential_built_from_config(self):
        """ClientSecretCredential is constructed with the conf's three
        identity fields — a rename or order shuffle would auth as the
        wrong principal."""
        client = LogAnalyticsClient(**_valid_kwargs())
        with (
            patch("parsedmarc.loganalytics.ClientSecretCredential") as mock_cred,
            patch("parsedmarc.loganalytics.LogsIngestionClient"),
        ):
            client.publish_results(
                {
                    "aggregate_reports": [],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
                save_aggregate=True,
                save_failure=True,
                save_smtp_tls=True,
            )
        mock_cred.assert_called_once_with(
            tenant_id="tid", client_id="cid", client_secret="csec"
        )

    def test_logs_ingestion_client_built_from_dce_and_credential(self):
        client = LogAnalyticsClient(**_valid_kwargs())
        with (
            patch("parsedmarc.loganalytics.ClientSecretCredential") as mock_cred,
            patch("parsedmarc.loganalytics.LogsIngestionClient") as mock_client_cls,
        ):
            client.publish_results(
                {
                    "aggregate_reports": [],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
                save_aggregate=True,
                save_failure=True,
                save_smtp_tls=True,
            )
        mock_client_cls.assert_called_once_with(
            "https://dce.example.com", credential=mock_cred.return_value
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
