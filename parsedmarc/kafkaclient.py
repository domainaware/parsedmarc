#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable, UnknownTopicOrPartitionError
import json


class KafkaError(RuntimeError):
    """Raised when a Kafka error occurs"""


class KafkaClient(object):
    def __init__(self, kafka_hosts):
        try:
            def serializer(v): lambda v: json.dumps(v).encode('utf-8')
            self.producer = KafkaProducer(
                          value_serializer=serializer,
                          bootstrap_servers=kafka_hosts)
        except NoBrokersAvailable:
            raise KafkaError("No Kafka brokers availabe")

    def save_aggregate_reports_to_kafka(self, aggregate_reports,
                                        aggregate_topic):
        """
        Saves aggregate DMARC reports to Kafka

        Args:
            aggregate_reports (list):  A list of aggregate report dictionaries
            to save to kafka

        """
        if type(aggregate_reports) == dict:
            aggregate_reports = [aggregate_reports]

        if len(aggregate_reports) < 1:
            return

        try:
            self.producer.send(aggregate_topic, aggregate_reports)
        except UnknownTopicOrPartitionError:
                raise KafkaError("Unknown topic or partition on broker")
        self.producer.flush()

    def save_forensic_reports_to_kafka(self, forensic_reports, forensic_topic):
            """
            Saves forensic DMARC reports to Kafka

            Args:
                forensic_reports (list):  A list of forensic report dicts
                to save to kafka

            """
            if type(forensic_reports) == dict:
                forensic_reports = [forensic_reports]

            if len(forensic_reports) < 1:
                return

            try:
                self.producer.send(forensic_topic, forensic_reports)
            except UnknownTopicOrPartitionError:
                raise KafkaError("Unknown topic or partition on broker")
            self.producer.flush()
