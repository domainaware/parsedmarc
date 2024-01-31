from __future__ import annotations

# Standard Library
from collections import OrderedDict
import json
from ssl import SSLContext, create_default_context

# Installed
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable, UnknownTopicOrPartitionError

# Package
from parsedmarc import __version__
from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime


class KafkaError(RuntimeError):
    """Raised when a Kafka error occurs"""

    def __init__(self, message: str | Exception):
        if isinstance(message, Exception):
            message = repr(message)
        super().__init__(f"Kafka Error: {message}")
        return


class KafkaClient:
    def __init__(
        self,
        kafka_hosts: list[str],
        ssl: bool = False,
        username: str | None = None,
        password: str | None = None,
        ssl_context: SSLContext | None = None,
    ):
        """
        Args:
            kafka_hosts: A list of Kafka hostnames (with optional port numbers)
            ssl: Use a SSL/TLS connection. This is implied `True` if `username` or `password` is supplied.
            username: An optional username
            password:  An optional password
            ssl_context: SSL context options

        Note:
            When using Azure Event Hubs, the `username` is literally `$ConnectionString`, and the `password` is the
            Azure Event Hub connection string.
        """
        config = dict(
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            bootstrap_servers=kafka_hosts,
            client_id=f"parsedmarc-{__version__}",
        )
        if ssl or username or password:
            config["security_protocol"] = "SSL"
            config["ssl_context"] = ssl_context or create_default_context()
            if username or password:
                config["sasl_plain_username"] = username or ""
                config["sasl_plain_password"] = password or ""
        try:
            self.producer = KafkaProducer(**config)
        except NoBrokersAvailable:
            raise KafkaError("No Kafka brokers available")

    @staticmethod
    def strip_metadata(report):
        """
        Duplicates org_name, org_email and report_id into JSON root
        and removes report_metadata key to bring it more inline
        with Elastic output.
        """
        report["org_name"] = report["report_metadata"]["org_name"]
        report["org_email"] = report["report_metadata"]["org_email"]
        report["report_id"] = report["report_metadata"]["report_id"]
        report.pop("report_metadata")

        return report

    @staticmethod
    def generate_daterange(report):
        """
        Creates a date_range timestamp with format YYYY-MM-DD-T-HH:MM:SS
        based on begin and end dates for easier parsing in Kibana.

        Move to utils to avoid duplication w/ elastic?
        """

        metadata = report["report_metadata"]
        begin_date = human_timestamp_to_datetime(metadata["begin_date"])
        end_date = human_timestamp_to_datetime(metadata["end_date"])
        begin_date_human = begin_date.strftime("%Y-%m-%dT%H:%M:%S")
        end_date_human = end_date.strftime("%Y-%m-%dT%H:%M:%S")
        date_range = [begin_date_human, end_date_human]
        logger.debug(f"date_range is {date_range}")
        return date_range

    def save_aggregate_reports_to_kafka(
        self, aggregate_reports: OrderedDict | list[OrderedDict], aggregate_topic: str
    ) -> None:
        """
        Saves aggregate DMARC reports to Kafka

        Args:
            aggregate_reports:  Aggregate reports to save to Kafka
            aggregate_topic: The name of the Kafka topic

        """
        if isinstance(aggregate_reports, dict):
            aggregate_reports = [aggregate_reports]

        if not aggregate_reports:
            return

        for report in aggregate_reports:
            report["date_range"] = self.generate_daterange(report)
            report = self.strip_metadata(report)

            for slice in report["records"]:
                slice["date_range"] = report["date_range"]
                slice["org_name"] = report["org_name"]
                slice["org_email"] = report["org_email"]
                slice["policy_published"] = report["policy_published"]
                slice["report_id"] = report["report_id"]
                logger.debug("Sending slice.")
                try:
                    logger.debug("Saving aggregate report to Kafka")
                    self.producer.send(aggregate_topic, slice)
                except UnknownTopicOrPartitionError:
                    raise KafkaError("Unknown topic or partition on broker")
                except Exception as e:
                    raise KafkaError(e)
                try:
                    self.producer.flush()
                except Exception as e:
                    raise KafkaError(e)
        return

    def save_forensic_reports_to_kafka(
        self, forensic_reports: OrderedDict | list[OrderedDict], forensic_topic: str
    ) -> None:
        """
        Saves forensic DMARC reports to Kafka, sends individual
        records (slices) since Kafka requires messages to be <= 1MB
        by default.

        Args:
            forensic_reports:  Forensic reports to save to Kafka
            forensic_topic: The name of the Kafka topic

        """
        if isinstance(forensic_reports, dict):
            forensic_reports = [forensic_reports]

        if not forensic_reports:
            return

        try:
            logger.debug("Saving forensic reports to Kafka")
            self.producer.send(forensic_topic, forensic_reports)
        except UnknownTopicOrPartitionError:
            raise KafkaError("Unknown topic or partition on broker")
        except Exception as e:
            raise KafkaError(e)
        try:
            self.producer.flush()
        except Exception as e:
            raise KafkaError(e)
        return
