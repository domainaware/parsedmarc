# -*- coding: utf-8 -*-


from __future__ import annotations

import json
import logging
import logging.handlers
import socket
import ssl
import time
from typing import Any, Optional

from parsedmarc import (
    parsed_aggregate_reports_to_csv_rows,
    parsed_forensic_reports_to_csv_rows,
    parsed_smtp_tls_reports_to_csv_rows,
)


class SyslogClient(object):
    """A client for Syslog"""

    def __init__(
        self,
        server_name: str,
        server_port: int,
        protocol: str = "udp",
        cafile_path: Optional[str] = None,
        certfile_path: Optional[str] = None,
        keyfile_path: Optional[str] = None,
        timeout: float = 5.0,
        retry_attempts: int = 3,
        retry_delay: int = 5,
    ):
        """
        Initializes the SyslogClient
        Args:
            server_name (str): The Syslog server
            server_port (int): The Syslog port
            protocol (str): The protocol to use: "udp", "tcp", or "tls" (Default: "udp")
            cafile_path (str): Path to CA certificate file for TLS server verification (Optional)
            certfile_path (str): Path to client certificate file for TLS authentication (Optional)
            keyfile_path (str): Path to client private key file for TLS authentication (Optional)
            timeout (float): Connection timeout in seconds for TCP/TLS (Default: 5.0)
            retry_attempts (int): Number of retry attempts for failed connections (Default: 3)
            retry_delay (int): Delay in seconds between retry attempts (Default: 5)
        """
        self.server_name = server_name
        self.server_port = server_port
        self.protocol = protocol.lower()
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay

        self.logger = logging.getLogger("parsedmarc_syslog")
        self.logger.setLevel(logging.INFO)

        # Create the appropriate syslog handler based on protocol
        log_handler = self._create_syslog_handler(
            server_name,
            server_port,
            self.protocol,
            cafile_path,
            certfile_path,
            keyfile_path,
            timeout,
            retry_attempts,
            retry_delay,
        )

        self.logger.addHandler(log_handler)

    def _create_syslog_handler(
        self,
        server_name: str,
        server_port: int,
        protocol: str,
        cafile_path: Optional[str],
        certfile_path: Optional[str],
        keyfile_path: Optional[str],
        timeout: float,
        retry_attempts: int,
        retry_delay: int,
    ) -> logging.handlers.SysLogHandler:
        """
        Creates a SysLogHandler with the specified protocol and TLS settings
        """
        if protocol == "udp":
            # UDP protocol (default, backward compatible)
            return logging.handlers.SysLogHandler(
                address=(server_name, server_port),
                socktype=socket.SOCK_DGRAM,
            )
        elif protocol in ["tcp", "tls"]:
            # TCP or TLS protocol with retry logic
            for attempt in range(1, retry_attempts + 1):
                try:
                    if protocol == "tcp":
                        # TCP without TLS
                        handler = logging.handlers.SysLogHandler(
                            address=(server_name, server_port),
                            socktype=socket.SOCK_STREAM,
                        )
                        # Set timeout on the socket
                        if hasattr(handler, "socket") and handler.socket:
                            handler.socket.settimeout(timeout)
                        return handler
                    else:
                        # TLS protocol
                        # Create SSL context
                        ssl_context = ssl.create_default_context()

                        # Configure server certificate verification
                        if cafile_path:
                            ssl_context.load_verify_locations(cafile=cafile_path)

                        # Configure client certificate authentication
                        if certfile_path and keyfile_path:
                            ssl_context.load_cert_chain(
                                certfile=certfile_path,
                                keyfile=keyfile_path,
                            )
                        elif certfile_path or keyfile_path:
                            # Warn if only one of the two required parameters is provided
                            self.logger.warning(
                                "Both certfile_path and keyfile_path are required for "
                                "client certificate authentication. Client authentication "
                                "will not be used."
                            )

                        # Create TCP handler first
                        handler = logging.handlers.SysLogHandler(
                            address=(server_name, server_port),
                            socktype=socket.SOCK_STREAM,
                        )

                        # Wrap socket with TLS
                        if hasattr(handler, "socket") and handler.socket:
                            handler.socket = ssl_context.wrap_socket(
                                handler.socket,
                                server_hostname=server_name,
                            )
                            handler.socket.settimeout(timeout)

                        return handler

                except Exception as e:
                    if attempt < retry_attempts:
                        self.logger.warning(
                            f"Syslog connection attempt {attempt}/{retry_attempts} failed: {e}. "
                            f"Retrying in {retry_delay} seconds..."
                        )
                        time.sleep(retry_delay)
                    else:
                        self.logger.error(
                            f"Syslog connection failed after {retry_attempts} attempts: {e}"
                        )
                        raise
        else:
            raise ValueError(
                f"Invalid protocol '{protocol}'. Must be 'udp', 'tcp', or 'tls'."
            )

    def save_aggregate_report_to_syslog(self, aggregate_reports: list[dict[str, Any]]):
        rows = parsed_aggregate_reports_to_csv_rows(aggregate_reports)
        for row in rows:
            self.logger.info(json.dumps(row))

    def save_forensic_report_to_syslog(self, forensic_reports: list[dict[str, Any]]):
        rows = parsed_forensic_reports_to_csv_rows(forensic_reports)
        for row in rows:
            self.logger.info(json.dumps(row))

    def save_smtp_tls_report_to_syslog(self, smtp_tls_reports: list[dict[str, Any]]):
        rows = parsed_smtp_tls_reports_to_csv_rows(smtp_tls_reports)
        for row in rows:
            self.logger.info(json.dumps(row))
