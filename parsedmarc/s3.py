from __future__ import annotations

# Standard Library
import json
from typing import Any

# Installed
import boto3

# Package
from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime


class S3Client:
    """A client for a Amazon S3"""

    def __init__(
        self,
        bucket_name: str,
        bucket_path: str,
        region_name: str | None = None,
        endpoint_url: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
    ):
        """
        Args:
            bucket_name: The S3 Bucket
            bucket_path: The path to save reports
            region_name: The region name
            endpoint_url: The endpoint URL
            access_key_id: The access key id
            secret_access_key: The secret access key
        """
        self.bucket_name = bucket_name
        self.bucket_path = bucket_path
        self.metadata_keys = [
            "org_name",
            "org_email",
            "report_id",
            "begin_date",
            "end_date",
        ]

        # https://github.com/boto/boto3/blob/1.24.7/boto3/session.py#L312
        self.s3 = boto3.resource(
            "s3",
            region_name=region_name,
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )
        self.bucket = self.s3.Bucket(self.bucket_name)
        return

    def save_aggregate_report_to_s3(self, report: dict[str, Any]) -> None:
        self.save_report_to_s3(report, "aggregate")
        return

    def save_forensic_report_to_s3(self, report: dict[str, Any]) -> None:
        self.save_report_to_s3(report, "forensic")
        return

    def save_report_to_s3(self, report: dict[str, Any], report_type: str):
        report_date = human_timestamp_to_datetime(report["report_metadata"]["begin_date"])
        report_id = report["report_metadata"]["report_id"]
        path_template = "{0}/{1}/year={2}/month={3:02d}/day={4:02d}/{5}.json"
        object_path = path_template.format(
            self.bucket_path,
            report_type,
            report_date.year,
            report_date.month,
            report_date.day,
            report_id,
        )
        logger.debug("Saving {report_type} report to s3://{self.bucket_name}/{object_path}")
        object_metadata = {
            k: v for k, v in report["report_metadata"].items() if k in self.metadata_keys
        }
        self.bucket.put_object(Body=json.dumps(report), Key=object_path, Metadata=object_metadata)
