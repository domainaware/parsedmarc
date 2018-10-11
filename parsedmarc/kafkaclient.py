# -*- coding: utf-8 -*-

import logging
import json

from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable, UnknownTopicOrPartitionError


logger = logging.getLogger("parsedmarc")


class KafkaError(RuntimeError):
    """Raised when a Kafka error occurs"""


class KafkaClient(object):
    def __init__(self, kafka_hosts):
        try:
            self.producer = KafkaProducer(
                          value_serializer=lambda v: json.dumps(v).encode(
                              'utf-8'),
                          bootstrap_servers=kafka_hosts)
        except NoBrokersAvailable:
            raise KafkaError("No Kafka brokers available")

    def save_aggregate_reports_to_kafka(self, aggregate_reports,
                                        aggregate_topic):
        """
        Saves aggregate DMARC reports to Kafka

        Args:
            aggregate_reports (list):  A list of aggregate report dictionaries
            to save to Kafka
            aggregate_topic (str): The name of the Kafka topic

        """
        if type(aggregate_reports) == dict:
            aggregate_reports = [aggregate_reports]

        if len(aggregate_reports) < 1:
            return

        try:
            logger.debug("Saving aggregate reports to Kafka")
            self.producer.send(aggregate_topic, aggregate_reports)
        except UnknownTopicOrPartitionError:
                raise KafkaError(
                    "Kafka error: Unknown topic or partition on broker")
        except Exception as e:
            raise KafkaError(
                "Kafka error: {0}".format(e.__str__()))
        try:
            self.producer.flush()
        except Exception as e:
            raise KafkaError(
                "Kafka error: {0}".format(e.__str__()))

    def save_forensic_reports_to_kafka(self, forensic_reports, forensic_topic):
            """
            Saves forensic DMARC reports to Kafka

            Args:
                forensic_reports (list):  A list of forensic report dicts
                to save to Kafka
                forensic_topic (str): The name of the Kafka topic

            """
            if type(forensic_reports) == dict:
                forensic_reports = [forensic_reports]

            if len(forensic_reports) < 1:
                return

            try:
                logger.debug("Saving forensic reports to Kafka")
                self.producer.send(forensic_topic, forensic_reports)
            except UnknownTopicOrPartitionError:
                raise KafkaError(
                    "Kafka error: Unknown topic or partition on broker")
            except Exception as e:
                raise KafkaError(
                    "Kafka error: {0}".format(e.__str__()))
            try:
                self.producer.flush()
            except Exception as e:
                raise KafkaError(
                    "Kafka error: {0}".format(e.__str__()))
