"""Tests for parsedmarc.loganalytics"""

import unittest
from unittest.mock import MagicMock, patch

from azure.core.exceptions import HttpResponseError

from parsedmarc.loganalytics import (
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


class TestPublishResults(unittest.TestCase):
    """publish_results gates each report type behind both a config flag
    (save_aggregate / save_failure / save_smtp_tls) and a configured
    stream name. Both gates need to work — a missing stream alone is a
    config bug that should be silent, but an explicit save_*=False
    means the operator opted out."""

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
