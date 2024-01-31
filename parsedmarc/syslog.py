# Standard Library
import json
import logging
import logging.handlers

# Package
from parsedmarc import (
    parsed_aggregate_reports_to_csv_rows,
    parsed_forensic_reports_to_csv_rows,
)


class SyslogClient:
    """A client for Syslog"""

    def __init__(self, server_name: str, server_port: int):
        """
        Args:
            server_name: The Syslog server
            server_port: The Syslog UDP port
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
