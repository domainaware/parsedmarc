# -*- coding: utf-8 -*-

import json
import boto3

from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime


class S3Client(object):
    """A client for a Amazon S3"""

    def __init__(
        self,
        bucket_name,
        bucket_path,
        region_name,
        endpoint_url,
        access_key_id,
        secret_access_key,
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

    def save_aggregate_report_to_s3(self, report):
        self.save_report_to_s3(report, "aggregate")

    def save_forensic_report_to_s3(self, report):
        self.save_report_to_s3(report, "forensic")

    def save_smtp_tls_report_to_s3(self, report):
        self.save_report_to_s3(report, "smtp_tls")

    def save_report_to_s3(self, report, report_type):
        if report_type == "smtp_tls":
            report_date = report["begin_date"]
            report_id = report["report_id"]
        else:
            report_date = human_timestamp_to_datetime(
                report["report_metadata"]["begin_date"]
            )
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
        logger.debug(
            "Saving {0} report to s3://{1}/{2}".format(
                report_type, self.bucket_name, object_path
            )
        )
        object_metadata = {
            k: v
            for k, v in report["report_metadata"].items()
            if k in self.metadata_keys
        }
        self.bucket.put_object(
            Body=json.dumps(report), Key=object_path, Metadata=object_metadata
        )
