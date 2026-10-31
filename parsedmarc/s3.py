# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import quote

import boto3

from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime

# Printable ASCII (0x20-0x7E) except "%", which is always encoded so that
# urllib.parse.unquote() reverses the encoding exactly. AWS allows Unicode
# metadata values but recommends US-ASCII for REST, and botocore rejects a
# non-ASCII metadata key or value with ParamValidationError. A bare CR or LF
# in a value makes botocore raise "Invalid header value" before sending,
# while CR or LF followed by a space or tab (an obs-fold) is sent as-is.
_METADATA_SAFE = "".join(chr(c) for c in range(0x20, 0x7F) if chr(c) != "%")
# The same, minus "/" (the key delimiter) and every printable character in
# the AWS object key "characters to avoid" list, so a report ID always stays
# one key segment. After encoding, "%" appears in a key segment only as the
# escape character. The "might require special handling" characters that
# real report IDs use (such as ":" and "@") are kept.
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html
_KEY_AVOID = '/\\{}^[]"<>~#|`'
_KEY_SEGMENT_SAFE = "".join(c for c in _METADATA_SAFE if c not in _KEY_AVOID)
# User-defined metadata is limited to 2 KB, counted as the UTF-8 bytes of
# every key and value. At most seven metadata keys exist; 7 * 256 bytes plus
# the names (with their "x-amz-meta-" prefixes) is 1,940 bytes.
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html
_MAX_METADATA_VALUE_LENGTH = 256
# An object key is at most 1,024 bytes of UTF-8, prefix included.
_MAX_KEY_LENGTH = 1024
# Hex characters of the SHA-256 digest appended to each key (64 bits).
_KEY_HASH_LENGTH = 16


def _percent_encode(value: str, safe: str, max_length: int) -> str:
    """Percent-encode ``value`` as UTF-8, keeping only ``safe`` characters
    as-is, and cut the result to at most ``max_length`` characters.

    The result is ASCII, so its length in characters is its length in
    bytes. It is cut between whole input characters, so neither a ``%XX``
    triplet nor a multibyte UTF-8 sequence is ever split. A lone surrogate,
    which has no UTF-8 encoding, becomes ``?``. A ``max_length`` of zero or
    less returns an empty string.
    """
    pieces: list[str] = []
    length = 0
    # Every input character encodes to at least one output character, so
    # no more than max_length input characters can fit.
    for char in value[: max(max_length, 0)]:
        piece = quote(char, safe=safe, errors="replace")
        if "~" not in safe:
            # quote() never encodes "~" (RFC 3986 unreserved), whatever
            # the safe set says.
            piece = piece.replace("~", "%7E")
        if length + len(piece) > max_length:
            break
        pieces.append(piece)
        length += len(piece)
    return "".join(pieces)


def _metadata_value(value: object) -> str:
    """Return ``value`` as an S3 metadata value: printable ASCII other
    than ``%`` is kept, everything else is percent-encoded, and the result
    is at most 256 characters long."""
    return _percent_encode(str(value), _METADATA_SAFE, _MAX_METADATA_VALUE_LENGTH)


def _report_hash(report_type: str, fields: list[object]) -> str:
    """Return the first 16 hex characters of the SHA-256 digest of the
    report type and the fields that identify the report.

    Only fields taken from the report itself are hashed, never enrichment
    (reverse DNS, GeoIP, ...), so the same report retried later is saved
    to the same key. Changing this recipe moves every object.
    """
    canonical = json.dumps(
        [report_type, *fields],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest[:_KEY_HASH_LENGTH]


class S3Client(object):
    """A client for interacting with Amazon S3"""

    def __init__(
        self,
        bucket_name: str,
        bucket_path: str,
        region_name: str,
        endpoint_url: str,
        access_key_id: str,
        secret_access_key: str,
    ):
        """
        Initializes the S3Client
        Args:
            bucket_name (str): The S3 Bucket
            bucket_path (str): The path to save reports
            region_name (str): The region name
            endpoint_url (str): The endpoint URL
            access_key_id (str): The access key id
            secret_access_key (str): The secret access key
        """
        self.bucket_name = bucket_name
        self.bucket_path = bucket_path
        self.metadata_keys = [
            "org_name",
            "org_email",
            "report_id",
            "begin_date",
            "end_date",
            "reported_domain",
            "arrival_date",
        ]

        # https://github.com/boto/boto3/blob/1.24.7/boto3/session.py#L312
        self.s3 = boto3.resource(
            "s3",
            region_name=region_name,
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )
        self.bucket = self.s3.Bucket(self.bucket_name)  # type: ignore

    def save_aggregate_report_to_s3(self, report: dict[str, Any]):
        self.save_report_to_s3(report, "aggregate")

    def save_failure_report_to_s3(self, report: dict[str, Any]):
        self.save_report_to_s3(report, "failure")

    def save_smtp_tls_report_to_s3(self, report: dict[str, Any]):
        self.save_report_to_s3(report, "smtp_tls")

    def save_report_to_s3(self, report: dict[str, Any], report_type: str):
        metadata_source: dict[str, Any]
        if report_type == "smtp_tls":
            # SMTP TLS reports (RFC 8460) are flat — they have no
            # `report_metadata` sub-object — and parse_smtp_tls_report_json
            # stores begin_date as the ISO string from the report JSON
            # (per SMTPTLSReport's TypedDict).
            report_date = human_timestamp_to_datetime(report["begin_date"])
            report_id = report["report_id"]
            hash_fields: list[object] = [
                report.get("organization_name"),
                report.get("report_id"),
                report.get("begin_date"),
                report.get("end_date"),
                sorted(
                    str(policy.get("policy_domain"))
                    for policy in report.get("policies") or []
                ),
            ]
            metadata_source = {
                "org_name": report.get("organization_name"),
                "report_id": report.get("report_id"),
                "begin_date": str(report.get("begin_date")),
                "end_date": str(report.get("end_date")),
            }
        elif report_type == "failure":
            # Failure reports (RFC 9991) have no report_metadata and no
            # report ID (see FailureReport in types.py): the arrival date
            # and the reported domain stand in for the begin date and the
            # report ID. arrival_date_utc is a UTC wall-clock string.
            report_date = human_timestamp_to_datetime(
                report["arrival_date_utc"], assume_utc=True
            )
            report_id = report["reported_domain"]
            source = report.get("source") or {}
            hash_fields = [
                report.get("arrival_date_utc"),
                report.get("reported_domain"),
                report.get("original_mail_from"),
                report.get("original_rcpt_to"),
                report.get("original_envelope_id"),
                source.get("ip_address"),
                report.get("sample"),
            ]
            metadata_source = {
                "reported_domain": report.get("reported_domain"),
                "arrival_date": report.get("arrival_date_utc"),
            }
        else:
            report_metadata = report["report_metadata"]
            report_date = human_timestamp_to_datetime(report_metadata["begin_date"])
            report_id = report_metadata["report_id"]
            hash_fields = [
                report_metadata.get("org_name"),
                report_metadata.get("report_id"),
                (report.get("policy_published") or {}).get("domain"),
                report_metadata.get("begin_date"),
                report_metadata.get("end_date"),
            ]
            metadata_source = report_metadata
        prefix = (
            f"{self.bucket_path}/{report_type}/year={report_date.year}/"
            f"month={report_date.month:02d}/day={report_date.day:02d}/"
        )
        suffix = f"_{_report_hash(report_type, hash_fields)}.json"
        # The report ID is percent-encoded into a single key segment and
        # shortened so the whole key fits in S3's 1,024-byte limit.
        budget = _MAX_KEY_LENGTH - len(prefix.encode("utf-8")) - len(suffix)
        segment = _percent_encode(str(report_id), _KEY_SEGMENT_SAFE, budget)
        object_path = f"{prefix}{segment}{suffix}"
        logger.debug(
            f"Saving {report_type} report to s3://{self.bucket_name}/{object_path}"
        )
        object_metadata = {
            k: _metadata_value(v)
            for k, v in metadata_source.items()
            if k in self.metadata_keys and v is not None
        }
        self.bucket.put_object(
            Body=json.dumps(report, default=str),
            Key=object_path,
            Metadata=object_metadata,
        )

    def close(self):
        """Clean up the boto3 resource."""
        try:
            if self.s3.meta is not None:
                self.s3.meta.client.close()
        except Exception:
            # Best-effort: this runs during shutdown/cleanup, and a
            # failure to close the underlying boto3 client isn't
            # actionable here.
            pass

    # Backward-compatible alias
    save_forensic_report_to_s3 = save_failure_report_to_s3
