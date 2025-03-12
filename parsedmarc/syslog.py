# -*- coding: utf-8 -*-

import logging
import logging.handlers
import json

from parsedmarc import (
    parsed_aggregate_reports_to_csv_rows,
    parsed_forensic_reports_to_csv_rows,
    parsed_smtp_tls_reports_to_csv_rows,
)


class SyslogClient(object):
    """A client for Syslog"""

    def __init__(self, server_name, server_port):
        """
        Initializes the SyslogClient
        Args:
            server_name (str): The Syslog server
            server_port (int): The Syslog UDP port
        """
        self.server_name = server_name
        self.server_port = server_port
        self.logger = logging.getLogger("parsedmarc_syslog")
        self.logger.setLevel(logging.INFO)
        log_handler = logging.handlers.SysLogHandler(address=(server_name, server_port))
        self.logger.addHandler(log_handler)

    def save_aggregate_report_to_syslog(self, aggregate_reports):
        rows = parsed_aggregate_reports_to_csv_rows(aggregate_reports)
        for row in rows:
            self.logger.info(json.dumps(row))

    def save_forensic_report_to_syslog(self, forensic_reports):
        rows = parsed_forensic_reports_to_csv_rows(forensic_reports)
        for row in rows:
            self.logger.info(json.dumps(row))

    def save_smtp_tls_report_to_syslog(self, smtp_tls_reports):
        rows = parsed_smtp_tls_reports_to_csv_rows(smtp_tls_reports)
        for row in rows:
            self.logger.info(json.dumps(row))
