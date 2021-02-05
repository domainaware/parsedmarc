# -*- coding: utf-8 -*-

import logging
import json
import boto3

from parsedmarc.utils import human_timestamp_to_datetime

logger = logging.getLogger("parsedmarc")


class S3Client(object):
    """A client for a Amazon S3"""

    def __init__(self, bucket_name, bucket_path):
        """
        Initializes the S3Client
        Args:
            bucket_name (str): The S3 Bucket
            bucket_path (str): The path to save reports
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

        self.s3 = boto3.resource('s3')
        self.bucket = self.s3.Bucket(self.bucket_name)

    def save_aggregate_report_to_s3(self, report):
        self.save_report_to_s3(report, 'aggregate')

    def save_forensic_report_to_s3(self, report):
        self.save_report_to_s3(report, 'forensic')

    def save_report_to_s3(self, report, report_type):
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
            report_id
        )
        logger.debug("Saving {0} report to s3://{1}/{2}".format(
            report_type,
            self.bucket_name,
            object_path))
        object_metadata = {
            k: v
            for k, v in report["report_metadata"].items()
            if k in self.metadata_keys
        }
        self.bucket.put_object(
            Body=json.dumps(report),
            Key=object_path,
            Metadata=object_metadata
        )
