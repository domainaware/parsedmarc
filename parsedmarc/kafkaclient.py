#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kafka import KafkaProducer
from collections import OrderedDict
import json

class KafkaError(RuntimeError):
    """Raised when a Kafka error occurs"""

class KafkaClient(object):
  def __init__(self, kafka_hosts):
    self.producer = KafkaProducer(value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                                    bootstrap_servers=kafka_hosts)

  def save_aggregate_reports_to_kafka(self, aggregate_reports, aggregate_topic):
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

        for record in aggregate_reports['records']:
            buffer = OrderedDict([('xml_schema', aggregate_reports['xml_schema']),
                                ('report_metadata',aggregate_reports['report_metadata']),
                                ('records', record)])
            self.producer.send(aggregate_topic, buffer)
        self.producer.flush()


  def save_forensic_reports_to_kafka(self, forensic_reports, forensic_topic):
            """
            Saves forensic DMARC reports to Kafka

            Args:
                forensic_reports (list):  A list of forensic report dictionaries
                to save to kafka

            """
            if type(forensic_reports) == dict:
                forensic_reports = [forensic_reports]

            if len(forensic_reports) < 1:
                return

            for report in forensic_reports:
                self.producer.send(forensic_topic, json.dumps(report))
                self.producer.flush()
