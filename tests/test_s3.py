"""Tests for parsedmarc.s3"""

import copy
import hashlib
import json
import os
import re
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import unquote

from botocore.exceptions import ParamValidationError
from botocore.stub import ANY, Stubber

import parsedmarc
from parsedmarc.s3 import S3Client

_SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
_HASH_SUFFIX = r"_[0-9a-f]{16}\.json"


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


def _client_with_mock_bucket(bucket_path="dmarc"):
    with patch("parsedmarc.s3.boto3.resource"):
        client = S3Client(
            bucket_name="b",
            bucket_path=bucket_path,
            region_name="us-east-1",
            endpoint_url="https://s3.example.com",
            access_key_id="k",
            secret_access_key="s",
        )
    client.bucket = MagicMock()
    return client


def _saved_key(client):
    return client.bucket.put_object.call_args.kwargs["Key"]


def _saved_metadata(client):
    return client.bucket.put_object.call_args.kwargs["Metadata"]


def _aggregate_key(report, bucket_path="dmarc"):
    client = _client_with_mock_bucket(bucket_path)
    client.save_aggregate_report_to_s3(report)
    return _saved_key(client)


def _aggregate_key_segment(report_id):
    """The last key segment for an aggregate report with ``report_id``."""
    report = _sample_aggregate_report()
    report["report_metadata"]["report_id"] = report_id
    return _aggregate_key(report).rsplit("/", 1)[1]


class TestS3ClientSavePathsAndMetadata(unittest.TestCase):
    """The S3 key is built from the report's begin_date, report_id, and a
    hash of the fields that identify the report. Wrong format = unfindable
    reports; wrong metadata filtering = secret leakage onto the S3 object."""

    def test_aggregate_dispatches_with_aggregate_in_key_path(self):
        """save_aggregate_report_to_s3 puts the object under
        <bucket_path>/aggregate/year=YYYY/month=MM/day=DD/<report_id>_<hash>.json."""
        client = _client_with_mock_bucket()
        client.save_aggregate_report_to_s3(_sample_aggregate_report())
        client.bucket.put_object.assert_called_once()
        self.assertRegex(
            _saved_key(client),
            r"\Admarc/aggregate/year=2024/month=01/day=15/agg-123"
            + _HASH_SUFFIX
            + r"\Z",
        )

    def test_smtp_tls_uses_report_begin_date(self):
        """SMTP TLS reports are flat — no report_metadata — and
        begin_date is the ISO string produced by parse_smtp_tls_report_json.
        The S3 path-builder parses that string into a datetime for the
        year=/month=/day= key segments.

        Regression: an earlier version assumed ALL reports carried a
        report_metadata sub-object, which crashed with KeyError on every
        SMTP TLS save. The CLI swallowed the error and only logged it,
        so the bug was invisible in production."""
        client = _client_with_mock_bucket()
        client.save_smtp_tls_report_to_s3(_sample_smtp_tls_report())
        self.assertRegex(
            _saved_key(client),
            r"\Admarc/smtp_tls/year=2024/month=02/day=03/tls-456"
            + _HASH_SUFFIX
            + r"\Z",
        )

    def test_smtp_tls_metadata_comes_from_flat_report_fields(self):
        """SMTP TLS object metadata is built from the flat report
        instead of report_metadata. organization_name is renamed to
        org_name (the S3 metadata key) for consistency with DMARC."""
        client = _client_with_mock_bucket()
        client.save_smtp_tls_report_to_s3(_sample_smtp_tls_report())
        self.assertEqual(
            _saved_metadata(client),
            {
                "org_name": "example.com",
                "report_id": "tls-456",
                "begin_date": "2024-02-03T00:00:00Z",
                "end_date": "2024-02-04T00:00:00Z",
            },
        )

    def test_object_body_is_json_serialized_report(self):
        client = _client_with_mock_bucket()
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
        client = _client_with_mock_bucket()
        report = _sample_aggregate_report()
        report["report_metadata"]["errors"] = ["a", "b"]
        report["report_metadata"]["internal_diag"] = "secret"
        client.save_aggregate_report_to_s3(report)
        meta = _saved_metadata(client)
        self.assertEqual(
            set(meta.keys()),
            {"org_name", "org_email", "report_id", "begin_date", "end_date"},
        )
        self.assertNotIn("errors", meta)
        self.assertNotIn("internal_diag", meta)


class TestS3ClientKeyHash(unittest.TestCase):
    """Every key ends in ``_<hash>.json``, where the hash covers the fields
    that identify the report, so two different reports that share a report
    ID (by accident, or because a sender reuses another reporter's ID) are
    saved to different objects, while a retry of the same report
    overwrites its own object."""

    def test_normal_report_id_prefix_and_id_unchanged(self):
        """Report IDs real reporters use keep their punctuation, so
        existing key prefixes and IDs stay readable."""
        for report_id in (
            "agg-123",
            "example.com:1538463741",
            "x@mail.ru",
            "2024-01-09T00:00:00Z_example.com",
        ):
            with self.subTest(report_id=report_id):
                report = _sample_aggregate_report()
                report["report_metadata"]["report_id"] = report_id
                key = _aggregate_key(report)
                self.assertTrue(
                    key.startswith("dmarc/aggregate/year=2024/month=01/day=15/")
                )
                self.assertRegex(
                    key.rsplit("/", 1)[1],
                    r"\A" + re.escape(report_id) + _HASH_SUFFIX + r"\Z",
                )

    def test_key_hash_pinned_for_fixed_report(self):
        """The hash recipe is pinned. Changing it moves every object to a
        new key, so a batch retried across the upgrade is saved twice;
        that is a compatibility event that needs a changelog entry, not a
        silent refactor.

        The golden value is the first 16 hex characters of
        sha256('["aggregate","example.com","agg-123","example.com",
        "2024-01-15 00:00:00","2024-01-16 00:00:00"]'): report type, then
        org_name, report_id, policy_published.domain, begin_date, end_date,
        as compact JSON. It is recomputed independently below."""
        canonical = json.dumps(
            [
                "aggregate",
                "example.com",
                "agg-123",
                "example.com",
                "2024-01-15 00:00:00",
                "2024-01-16 00:00:00",
            ],
            separators=(",", ":"),
        )
        self.assertEqual(
            hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16],
            "f80ea35e1b3f6ad4",
        )
        self.assertEqual(
            _aggregate_key(_sample_aggregate_report()),
            "dmarc/aggregate/year=2024/month=01/day=15/agg-123_f80ea35e1b3f6ad4.json",
        )

    def test_key_hash_ignores_enrichment(self):
        """A report retried later may get different reverse DNS or GeoIP
        results; only fields from the report itself are hashed, so the
        retry still overwrites the same object."""
        first = _sample_aggregate_report()
        first["records"] = [
            {"source": {"ip_address": "192.0.2.1", "reverse_dns": None}}
        ]
        second = copy.deepcopy(first)
        second["records"][0]["source"]["reverse_dns"] = "mail.example.net"
        second["records"][0]["source"]["country"] = "US"
        self.assertEqual(_aggregate_key(first), _aggregate_key(second))

    def test_key_hash_separates_reports_sharing_report_id(self):
        """Reports with the same org_name and report_id but a different
        policy domain, begin_date (same day), end_date, or org_name are
        different reports and must not overwrite each other."""
        base_key = _aggregate_key(_sample_aggregate_report())
        variants = {
            "domain": ("policy_published", "domain", "other.example"),
            "begin_date": ("report_metadata", "begin_date", "2024-01-15 06:00:00"),
            "end_date": ("report_metadata", "end_date", "2024-01-17 00:00:00"),
            "org_name": ("report_metadata", "org_name", "attacker.example"),
        }
        for name, (section, field, value) in variants.items():
            with self.subTest(field=name):
                report = _sample_aggregate_report()
                report[section][field] = value
                key = _aggregate_key(report)
                # Same directory and report ID; only the hash differs.
                self.assertEqual(key.rsplit("_", 1)[0], base_key.rsplit("_", 1)[0])
                self.assertNotEqual(key, base_key)

    def test_smtp_tls_hash_includes_policy_domains(self):
        """Two SMTP TLS reports sharing organization, report ID, and dates
        but covering different policy domains get different keys; the
        policy order inside one report does not matter."""

        def key_for(*domains):
            client = _client_with_mock_bucket()
            report = _sample_smtp_tls_report()
            report["policies"] = [{"policy_domain": d} for d in domains]
            client.save_smtp_tls_report_to_s3(report)
            return _saved_key(client)

        self.assertNotEqual(key_for("a.example"), key_for("b.example"))
        self.assertEqual(
            key_for("a.example", "b.example"), key_for("b.example", "a.example")
        )


class TestS3ClientKeySanitization(unittest.TestCase):
    """The report ID is sender-controlled. It is percent-encoded into one
    key segment so it cannot add path segments, carry characters AWS says
    to avoid, or push the key past S3's 1,024-byte limit
    (https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html)."""

    def test_traversal_report_id_stays_one_segment(self):
        report = _sample_aggregate_report()
        report["report_metadata"]["report_id"] = "../../etc/passwd"
        key = _aggregate_key(report)
        normal_key = _aggregate_key(_sample_aggregate_report())
        self.assertEqual(key.count("/"), normal_key.count("/"))
        self.assertTrue(key.startswith("dmarc/aggregate/year=2024/month=01/day=15/"))
        self.assertRegex(
            key.rsplit("/", 1)[1], r"\A\.\.%2F\.\.%2Fetc%2Fpasswd" + _HASH_SUFFIX
        )

    def test_report_id_backslash_percent_control_nonascii_encoded(self):
        """ "/", every printable character in the AWS "characters to avoid"
        list, control characters, and non-ASCII characters are encoded.
        quote() never encodes "~" on its own, so it is checked too."""
        cases = {
            "a/b": "a%2Fb",
            "a{b}": "a%7Bb%7D",
            "a^b": "a%5Eb",
            "a[b]": "a%5Bb%5D",
            'a"b': "a%22b",
            "a<b>": "a%3Cb%3E",
            "a~b": "a%7Eb",
            "a#b": "a%23b",
            "a|b": "a%7Cb",
            "a`b": "a%60b",
            "a\\b": "a%5Cb",
            "a%b": "a%25b",
            "a\r\nb": "a%0D%0Ab",
            "a\x00b": "a%00b",
            "a\x7fb": "a%7Fb",
            "café": "caf%C3%A9",
        }
        for report_id, encoded in cases.items():
            with self.subTest(report_id=report_id):
                segment = _aggregate_key_segment(report_id)
                self.assertRegex(
                    segment, r"\A" + re.escape(encoded) + _HASH_SUFFIX + r"\Z"
                )
                # The encoding is reversible.
                self.assertEqual(unquote(segment.rsplit("_", 1)[0]), report_id)

    def test_empty_dot_dotdot_report_id(self):
        """The hash suffix keeps the last segment from ever being empty or
        period-only, which AWS says to avoid."""
        for report_id, expected in (("", ""), (".", "."), ("..", "..")):
            with self.subTest(report_id=report_id):
                self.assertRegex(
                    _aggregate_key_segment(report_id),
                    r"\A" + re.escape(expected) + _HASH_SUFFIX + r"\Z",
                )

    def test_oversized_report_id_key_within_1024_bytes(self):
        """A 5,000-character multibyte report ID under a long bucket_path
        is shortened between whole characters so the key fits in 1,024
        bytes, the hash suffix is intact, and no %XX triplet or UTF-8
        sequence is split."""
        report = _sample_aggregate_report()
        report_id = "€" * 5000  # 3 UTF-8 bytes -> 9 encoded characters
        report["report_metadata"]["report_id"] = report_id
        key = _aggregate_key(report, bucket_path="p" * 300)
        self.assertLessEqual(len(key.encode("utf-8")), 1024)
        # Only a partial character's worth of room may be left unused.
        self.assertGreater(len(key.encode("utf-8")), 1024 - 9)
        segment = key.rsplit("/", 1)[1]
        self.assertRegex(segment, r"\A(%E2%82%AC)+" + _HASH_SUFFIX + r"\Z")
        decoded = unquote(segment.rsplit("_", 1)[0], errors="strict")
        self.assertTrue(report_id.startswith(decoded))

    def test_oversized_tilde_report_id_counts_encoded_length(self):
        """ "~" grows to "%7E" after quote() returns, and the shortening
        counts the encoded length, so the key still fits in 1,024 bytes
        and ends on a whole triplet."""
        report = _sample_aggregate_report()
        report["report_metadata"]["report_id"] = "~" * 2000
        key = _aggregate_key(report)
        self.assertLessEqual(len(key.encode("utf-8")), 1024)
        self.assertGreater(len(key.encode("utf-8")), 1024 - 3)
        self.assertRegex(key.rsplit("/", 1)[1], r"\A(%7E)+" + _HASH_SUFFIX + r"\Z")

    def test_bucket_path_longer_than_key_limit_leaves_id_empty(self):
        """If bucket_path alone uses up the 1,024 bytes, the report ID is
        dropped rather than sliced with a negative length; the hash still
        identifies the report and S3 reports the over-long key."""
        key = _aggregate_key(_sample_aggregate_report(), bucket_path="p" * 1100)
        self.assertRegex(key, r"/year=2024/month=01/day=15/" + _HASH_SUFFIX + r"\Z")


class TestS3ClientMetadataSanitization(unittest.TestCase):
    """S3 user-defined metadata must be ASCII (botocore rejects anything
    else before sending) and is limited to 2 KB in total, counted as the
    UTF-8 bytes of every key and value
    (https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html).
    Values are percent-encoded so they round-trip through unquote()."""

    def _stubbed_client(self):
        """A real S3Client whose boto3 client is stubbed, so botocore's
        own parameter handlers, including the ASCII metadata check, run."""
        client = S3Client(
            bucket_name="b",
            bucket_path="dmarc",
            region_name="us-east-1",
            endpoint_url="https://s3.example.com",
            access_key_id="k",
            secret_access_key="s",
        )
        self.addCleanup(client.close)
        meta = client.s3.meta
        assert meta is not None
        stubber = Stubber(meta.client)
        stubber.activate()
        self.addCleanup(stubber.deactivate)
        return client, stubber

    def test_metadata_non_ascii_org_name_accepted_by_botocore(self):
        client, stubber = self._stubbed_client()
        report = _sample_aggregate_report()
        report["report_metadata"]["org_name"] = "Ünïcode Org"
        stubber.add_response(
            "put_object",
            {},
            expected_params={
                "Bucket": "b",
                "Key": ANY,
                "Body": ANY,
                "Metadata": {
                    "org_name": "%C3%9Cn%C3%AFcode Org",
                    "org_email": "dmarc@example.com",
                    "report_id": "agg-123",
                    "begin_date": "2024-01-15 00:00:00",
                    "end_date": "2024-01-16 00:00:00",
                },
            },
        )
        client.save_aggregate_report_to_s3(report)
        stubber.assert_no_pending_responses()
        self.assertEqual(unquote("%C3%9Cn%C3%AFcode Org"), "Ünïcode Org")

        # The SMTP TLS path goes through the same encoding.
        tls_report = _sample_smtp_tls_report()
        tls_report["organization_name"] = "Ünïcode Org"
        stubber.add_response(
            "put_object",
            {},
            expected_params={
                "Bucket": "b",
                "Key": ANY,
                "Body": ANY,
                "Metadata": {
                    "org_name": "%C3%9Cn%C3%AFcode Org",
                    "report_id": "tls-456",
                    "begin_date": "2024-02-03T00:00:00Z",
                    "end_date": "2024-02-04T00:00:00Z",
                },
            },
        )
        client.save_smtp_tls_report_to_s3(tls_report)
        stubber.assert_no_pending_responses()

        # The validator is live under the Stubber: the raw value that the
        # unfixed code sent is rejected before any request is made.
        stubber.add_response("put_object", {})
        with self.assertRaises(ParamValidationError):
            client.bucket.put_object(
                Body="{}", Key="k.json", Metadata={"org_name": "Ünïcode Org"}
            )

    def test_metadata_crlf_and_percent_round_trip(self):
        client = _client_with_mock_bucket()
        report = _sample_aggregate_report()
        org_name = "Org\r\nX-Injected: 1 100%"
        report["report_metadata"]["org_name"] = org_name
        client.save_aggregate_report_to_s3(report)
        value = _saved_metadata(client)["org_name"]
        self.assertEqual(value, "Org%0D%0AX-Injected: 1 100%25")
        self.assertEqual(unquote(value), org_name)

    def test_metadata_values_capped_total_under_2kb(self):
        """Each value is at most 256 characters, cut between whole
        characters, so the metadata sent stays under 2 KB, counting the
        x-amz-meta- header names."""
        client = _client_with_mock_bucket()
        report = _sample_aggregate_report()
        # begin_date is parsed for the key, so it stays a real date.
        for field in ("org_name", "org_email", "report_id"):
            report["report_metadata"][field] = "x" * 10_000
        # 255 ASCII characters, then one that encodes to 6: it must be
        # dropped whole, not cut to "%C3" or "%C3%9".
        report["report_metadata"]["end_date"] = "a" * 255 + "Ü"
        client.save_aggregate_report_to_s3(report)
        meta = _saved_metadata(client)
        self.assertEqual(meta["end_date"], "a" * 255)
        for value in meta.values():
            self.assertLessEqual(len(value), 256)
        total = sum(
            len(f"x-amz-meta-{k}".encode("utf-8")) + len(v.encode("utf-8"))
            for k, v in meta.items()
        )
        self.assertLess(total, 2048)

    def test_smtp_tls_lone_surrogate_does_not_raise(self):
        """A lone surrogate has no UTF-8 encoding; it becomes "?" instead
        of raising UnicodeEncodeError and failing the batch."""
        client = _client_with_mock_bucket()
        report = _sample_smtp_tls_report()
        report["organization_name"] = "Org\ud800"
        report["report_id"] = "id\udfff"
        client.save_smtp_tls_report_to_s3(report)
        self.assertEqual(_saved_metadata(client)["org_name"], "Org?")
        self.assertEqual(_saved_metadata(client)["report_id"], "id?")
        self.assertRegex(_saved_key(client), r"/id\?" + _HASH_SUFFIX + r"\Z")


class TestS3ClientFailureReports(unittest.TestCase):
    """Failure reports (FailureReport in parsedmarc/types.py) have no
    report_metadata and no report ID. Saving one used to raise KeyError
    on report_metadata, so no failure report was ever saved to S3."""

    @classmethod
    def setUpClass(cls):
        parsed = parsedmarc.parse_report_file(
            os.path.join(_SAMPLES_DIR, "failure", "dmarc_ruf_report_linkedin.eml"),
            offline=True,
        )
        assert parsed["report_type"] == "failure"
        cls.report = parsed["report"]

    def _save(self, report):
        client = _client_with_mock_bucket()
        client.save_failure_report_to_s3(report)
        return client

    def test_failure_report_key_from_arrival_date_and_reported_domain(self):
        client = self._save(copy.deepcopy(self.report))
        key = _saved_key(client)
        self.assertRegex(
            key,
            r"\Admarc/failure/year=2019/month=04/day=30/example\.com"
            + _HASH_SUFFIX
            + r"\Z",
        )
        self.assertEqual(
            _saved_metadata(client),
            {
                "reported_domain": "example.com",
                "arrival_date": "2019-04-30 02:09:00",
            },
        )
        body = json.loads(client.bucket.put_object.call_args.kwargs["Body"])
        self.assertEqual(body["reported_domain"], "example.com")

        # A different sample is a different report.
        other = copy.deepcopy(self.report)
        other["sample"] = other["sample"] + "\n"
        self.assertNotEqual(_saved_key(self._save(other)), key)

        # Different enrichment of the same report is the same report.
        enriched = copy.deepcopy(self.report)
        enriched["source"]["reverse_dns"] = "mail.example.net"
        enriched["source"]["country"] = "US"
        self.assertEqual(_saved_key(self._save(enriched)), key)


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
            S3Client.save_forensic_report_to_s3,
            S3Client.save_failure_report_to_s3,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
