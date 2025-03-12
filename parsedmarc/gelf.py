# -*- coding: utf-8 -*-

import logging
import logging.handlers
import json
import threading

from parsedmarc import (
    parsed_aggregate_reports_to_csv_rows,
    parsed_forensic_reports_to_csv_rows,
    parsed_smtp_tls_reports_to_csv_rows,
)
from pygelf import GelfTcpHandler, GelfUdpHandler, GelfTlsHandler


log_context_data = threading.local()


class ContextFilter(logging.Filter):
    def filter(self, record):
        record.parsedmarc = log_context_data.parsedmarc
        return True


class GelfClient(object):
    """A client for the Graylog Extended Log Format"""

    def __init__(self, host, port, mode):
        """
        Initializes the GelfClient
        Args:
            host (str): The GELF host
            port (int): The GELF port
            mode (str): The GELF transport mode
        """
        self.host = host
        self.port = port
        self.logger = logging.getLogger("parsedmarc_syslog")
        self.logger.setLevel(logging.INFO)
        self.logger.addFilter(ContextFilter())
        self.gelf_mode = {
            "udp": GelfUdpHandler,
            "tcp": GelfTcpHandler,
            "tls": GelfTlsHandler,
        }
        self.handler = self.gelf_mode[mode](
            host=self.host, port=self.port, include_extra_fields=True
        )
        self.logger.addHandler(self.handler)

    def save_aggregate_report_to_gelf(self, aggregate_reports):
        rows = parsed_aggregate_reports_to_csv_rows(aggregate_reports)
        for row in rows:
            log_context_data.parsedmarc = row
            self.logger.info("parsedmarc aggregate report")

        log_context_data.parsedmarc = None

    def save_forensic_report_to_gelf(self, forensic_reports):
        rows = parsed_forensic_reports_to_csv_rows(forensic_reports)
        for row in rows:
            self.logger.info(json.dumps(row))

    def save_smtp_tls_report_to_gelf(self, smtp_tls_reports):
        rows = parsed_smtp_tls_reports_to_csv_rows(smtp_tls_reports)
        for row in rows:
            self.logger.info(json.dumps(row))
