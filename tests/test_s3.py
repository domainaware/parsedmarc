"""Tests for parsedmarc.s3"""

import json
import unittest
from unittest.mock import MagicMock, patch

from parsedmarc.s3 import S3Client


def _sample_aggregate_report():
    """Minimal aggregate report shape used by S3Client.save_*_to_s3."""
    return {
        "report_metadata": {
            "org_name": "example.com",
            "org_email": "dmarc@example.com",
            "report_id": "agg-123",
            "begin_date": "2024-01-15 00:00:00",
            "end_date": "2024-01-16 00:00:00",
            # not in S3Client.metadata_keys; should NOT appear on the S3 object
            "errors": [],
        },
        "policy_published": {"domain": "example.com", "p": "none"},
        "records": [],
    }


def _sample_smtp_tls_report():
    """Minimal SMTP TLS report shape as parse_smtp_tls_report_json
    produces it — flat, with ISO-string begin_date / end_date pulled
    directly from the report JSON."""
    return {
        "organization_name": "example.com",
        "begin_date": "2024-02-03T00:00:00Z",
        "end_date": "2024-02-04T00:00:00Z",
        "report_id": "tls-456",
        "contact_info": "tls-admin@example.com",
        "policies": [],
    }


class TestS3ClientInit(unittest.TestCase):
    """S3Client.__init__ delegates to boto3.resource() with the supplied
    credentials and endpoint. A regression in argument names or order
    would silently send reports to the wrong bucket or auth as the wrong
    principal."""

    def test_init_forwards_credentials_to_boto3(self):
        with patch("parsedmarc.s3.boto3.resource") as mock_resource:
            S3Client(
                bucket_name="my-bucket",
                bucket_path="dmarc",
                region_name="us-east-1",
                endpoint_url="https://s3.example.com",
                access_key_id="AKIA-test",
                secret_access_key="secret-test",
            )
        mock_resource.assert_called_once_with(
            "s3",
            region_name="us-east-1",
            endpoint_url="https://s3.example.com",
            aws_access_key_id="AKIA-test",
            aws_secret_access_key="secret-test",
        )

    def test_init_caches_bucket_handle(self):
        """self.bucket is the Bucket(bucket_name) on the boto3 resource,
        so subsequent save_* calls go to the right bucket."""
        with patch("parsedmarc.s3.boto3.resource") as mock_resource:
            mock_resource.return_value.Bucket.return_value = "bucket-handle"
            client = S3Client(
                bucket_name="my-bucket",
                bucket_path="dmarc",
                region_name="us-east-1",
                endpoint_url="https://s3.example.com",
                access_key_id="k",
                secret_access_key="s",
            )
        mock_resource.return_value.Bucket.assert_called_once_with("my-bucket")
        self.assertEqual(client.bucket, "bucket-handle")


class TestS3ClientSavePathsAndMetadata(unittest.TestCase):
    """The S3 key is built from the report's begin_date and report_id.
    Wrong format = unfindable reports; wrong metadata filtering = secret
    leakage onto the S3 object."""

    def _client_with_mock_bucket(self):
        with patch("parsedmarc.s3.boto3.resource"):
            client = S3Client(
                bucket_name="b",
                bucket_path="dmarc",
                region_name="us-east-1",
                endpoint_url="https://s3.example.com",
                access_key_id="k",
                secret_access_key="s",
            )
        client.bucket = MagicMock()
        return client

    def test_aggregate_dispatches_with_aggregate_in_key_path(self):
        """save_aggregate_report_to_s3 puts the object under
        <bucket_path>/aggregate/year=YYYY/month=MM/day=DD/<report_id>.json."""
        client = self._client_with_mock_bucket()
        client.save_aggregate_report_to_s3(_sample_aggregate_report())
        client.bucket.put_object.assert_called_once()
        call = client.bucket.put_object.call_args
        self.assertEqual(
            call.kwargs["Key"],
            "dmarc/aggregate/year=2024/month=01/day=15/agg-123.json",
        )

    def test_failure_dispatches_with_failure_in_key_path(self):
        client = self._client_with_mock_bucket()
        report = _sample_aggregate_report()
        report["report_metadata"]["report_id"] = "fail-789"
        client.save_failure_report_to_s3(report)
        key = client.bucket.put_object.call_args.kwargs["Key"]
        self.assertEqual(key, "dmarc/failure/year=2024/month=01/day=15/fail-789.json")

    def test_smtp_tls_uses_report_begin_date(self):
        """SMTP TLS reports are flat — no report_metadata — and
        begin_date is the ISO string produced by parse_smtp_tls_report_json.
        The S3 path-builder parses that string into a datetime for the
        year=/month=/day= key segments.

        Regression: an earlier version assumed ALL reports carried a
        report_metadata sub-object, which crashed with KeyError on every
        SMTP TLS save. The CLI swallowed the error and only logged it,
        so the bug was invisible in production."""
        client = self._client_with_mock_bucket()
        client.save_smtp_tls_report_to_s3(_sample_smtp_tls_report())
        key = client.bucket.put_object.call_args.kwargs["Key"]
        self.assertEqual(key, "dmarc/smtp_tls/year=2024/month=02/day=03/tls-456.json")

    def test_smtp_tls_metadata_comes_from_flat_report_fields(self):
        """SMTP TLS object metadata is built from the flat report
        instead of report_metadata. organization_name is renamed to
        org_name (the S3 metadata key) for consistency with DMARC."""
        client = self._client_with_mock_bucket()
        client.save_smtp_tls_report_to_s3(_sample_smtp_tls_report())
        meta = client.bucket.put_object.call_args.kwargs["Metadata"]
        self.assertEqual(meta["org_name"], "example.com")
        self.assertEqual(meta["report_id"], "tls-456")
        self.assertEqual(meta["begin_date"], "2024-02-03T00:00:00Z")
        self.assertEqual(meta["end_date"], "2024-02-04T00:00:00Z")

    def test_object_body_is_json_serialized_report(self):
        client = self._client_with_mock_bucket()
        report = _sample_aggregate_report()
        client.save_aggregate_report_to_s3(report)
        body = client.bucket.put_object.call_args.kwargs["Body"]
        # Round-trip the JSON to make sure it actually deserializes and
        # carries every top-level key the source report had.
        self.assertEqual(json.loads(body), report)

    def test_metadata_filtered_to_documented_keys_only(self):
        """report_metadata fields outside `metadata_keys` must not be
        attached to the S3 object — they could leak large or sensitive
        payloads (errors lists, internal IDs) into object metadata."""
        client = self._client_with_mock_bucket()
        report = _sample_aggregate_report()
        report["report_metadata"]["errors"] = ["a", "b"]
        report["report_metadata"]["internal_diag"] = "secret"
        client.save_aggregate_report_to_s3(report)
        meta = client.bucket.put_object.call_args.kwargs["Metadata"]
        self.assertEqual(
            set(meta.keys()),
            {"org_name", "org_email", "report_id", "begin_date", "end_date"},
        )
        self.assertNotIn("errors", meta)
        self.assertNotIn("internal_diag", meta)


class TestS3ClientClose(unittest.TestCase):
    """close() must release the underlying boto3 client; a slow leak
    here matters for long-running watch-mode processes."""

    def test_close_calls_underlying_client_close(self):
        with patch("parsedmarc.s3.boto3.resource") as mock_resource:
            client = S3Client(
                bucket_name="b",
                bucket_path="p",
                region_name="r",
                endpoint_url="https://s3.example.com",
                access_key_id="k",
                secret_access_key="s",
            )
        client.close()
        mock_resource.return_value.meta.client.close.assert_called_once()

    def test_close_swallows_exceptions_from_underlying_client(self):
        """close() is called during shutdown/reload; if boto3 raises
        from the close path, we don't want it to propagate and prevent
        clean exit. The except is defensive but deliberate."""
        with patch("parsedmarc.s3.boto3.resource") as mock_resource:
            mock_resource.return_value.meta.client.close.side_effect = RuntimeError(
                "boom"
            )
            client = S3Client(
                bucket_name="b",
                bucket_path="p",
                region_name="r",
                endpoint_url="https://s3.example.com",
                access_key_id="k",
                secret_access_key="s",
            )
        # Should not raise.
        client.close()


class TestS3ClientBackwardCompatAlias(unittest.TestCase):
    def test_forensic_alias_points_to_failure_method(self):
        self.assertIs(
            S3Client.save_forensic_report_to_s3,  # type: ignore[attr-defined]
            S3Client.save_failure_report_to_s3,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
