# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from typing import Any

from azure.core.exceptions import AzureError
from azure.identity import ClientSecretCredential
from azure.monitor.ingestion import LogsIngestionClient

from parsedmarc.log import logger
from parsedmarc.utils import sanitize_for_log

# The Logs Ingestion API rejects a call larger than 1 MB, compressed or
# not ("Maximum size of API call: 1 MB", Logs Ingestion API section of
# https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits).
# LogsIngestionClient.upload() packs whole reports into chunks of up to
# 1 MiB of JSON and never splits a report, so a report larger than that
# is sent as a call of its own and rejected. The documented decimal limit
# is used here because it is the smaller of the two.
MAX_UPLOAD_ITEM_BYTES = 1_000_000


class LogAnalyticsException(Exception):
    """Raised when a Log Analytics error occurs"""


def _describe_report(report: dict[str, Any]) -> str:
    """Names a parsed report for a log line, from the keys of
    ``AggregateReport``, ``SMTPTLSReport`` or ``FailureReport``.

    Args:
        report (dict): A parsed report

    Returns:
        str: The report's sender and ID (or arrival date for a failure
        report), with non-printable characters escaped
    """
    if "report_metadata" in report:
        metadata = report.get("report_metadata") or {}
        sender = metadata.get("org_name")
        report_id = metadata.get("report_id")
        return (
            f"org_name {sanitize_for_log(str(sender))}, "
            f"report_id {sanitize_for_log(str(report_id))}"
        )
    if "organization_name" in report:
        return (
            f"organization_name "
            f"{sanitize_for_log(str(report.get('organization_name')))}, "
            f"report_id {sanitize_for_log(str(report.get('report_id')))}"
        )
    return (
        f"reported_domain {sanitize_for_log(str(report.get('reported_domain')))}, "
        f"arrival_date_utc {sanitize_for_log(str(report.get('arrival_date_utc')))}"
    )


class LogAnalyticsConfig:
    """
    The LogAnalyticsConfig class is used to define the configuration
    for the Log Analytics Client.

    Properties:
        client_id (str):
            The client ID of the service principal.
        client_secret (str):
            The client secret of the service principal.
        tenant_id (str):
            The tenant ID where
            the service principal resides.
        dce (str):
            The Data Collection Endpoint (DCE)
            used by the Data Collection Rule (DCR).
        dcr_immutable_id (str):
            The immutable ID of
            the Data Collection Rule (DCR).
        dcr_aggregate_stream (str):
            The Stream name where
            the Aggregate DMARC reports
            need to be pushed.
        dcr_failure_stream (str):
            The Stream name where
            the Failure DMARC reports
            need to be pushed.
        dcr_smtp_tls_stream (str):
            The Stream name where
            the SMTP TLS Reports
            need to be pushed.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        dce: str,
        dcr_immutable_id: str,
        dcr_aggregate_stream: str,
        dcr_failure_stream: str,
        dcr_smtp_tls_stream: str,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.dce = dce
        self.dcr_immutable_id = dcr_immutable_id
        self.dcr_aggregate_stream = dcr_aggregate_stream
        self.dcr_failure_stream = dcr_failure_stream
        self.dcr_smtp_tls_stream = dcr_smtp_tls_stream


class LogAnalyticsClient(object):
    """
    The LogAnalyticsClient is used to push
    the generated DMARC reports to Log Analytics
    via Data Collection Rules.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        dce: str,
        dcr_immutable_id: str,
        dcr_aggregate_stream: str,
        dcr_failure_stream: str,
        dcr_smtp_tls_stream: str,
    ):
        self.conf = LogAnalyticsConfig(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            dce=dce,
            dcr_immutable_id=dcr_immutable_id,
            dcr_aggregate_stream=dcr_aggregate_stream,
            dcr_failure_stream=dcr_failure_stream,
            dcr_smtp_tls_stream=dcr_smtp_tls_stream,
        )
        if (
            not self.conf.client_id
            or not self.conf.client_secret
            or not self.conf.tenant_id
            or not self.conf.dce
            or not self.conf.dcr_immutable_id
        ):
            raise LogAnalyticsException(
                "Invalid configuration. " + "One or more required settings are missing."
            )

    def publish_json(
        self,
        results,
        logs_client: LogsIngestionClient,
        dcr_stream: str,
    ) -> int:
        """
        Publishes the given reports to the specified
        Data Collection Rule stream.

        A report whose JSON is larger than ``MAX_UPLOAD_ITEM_BYTES`` would
        be sent as an API call of its own and rejected by the service, so
        it is left out with a warning and the other reports are uploaded.

        Args:
            results (list):
                The parsed reports generated by parsedmarc.
            logs_client (LogsIngestionClient):
                The client used to send the reports.
            dcr_stream (str):
                The stream name where the reports need to be pushed.

        Returns:
            int: The number of reports uploaded (0 when every report was
            left out).

        Raises:
            LogAnalyticsException: The upload failed
        """
        reports = []
        for report in results:
            # Measured as LogsIngestionClient.upload() measures it when it
            # splits the reports into chunks (json.dumps with its defaults)
            size = len(json.dumps(report).encode("utf-8"))
            if size > MAX_UPLOAD_ITEM_BYTES:
                logger.warning(
                    f"Not publishing a report of {size} bytes to the "
                    f"{dcr_stream} stream: larger than the 1,000,000-byte "
                    f"limit of one Logs Ingestion API call "
                    f"({_describe_report(report)})"
                )
                continue
            reports.append(report)
        if not reports:
            return 0
        try:
            logs_client.upload(self.conf.dcr_immutable_id, dcr_stream, reports)
        except AzureError as e:
            raise LogAnalyticsException(f"Upload failed: {e}")
        return len(reports)

    def publish_results(
        self,
        results: dict[str, Any],
        save_aggregate: bool,
        save_failure: bool,
        save_smtp_tls: bool,
    ):
        """
        Function to publish DMARC and/or SMTP TLS reports to Log Analytics
        via Data Collection Rules (DCR).
        See:
        https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview

        Args:
            results (dict):
                The parsing results (aggregate, failure, and SMTP TLS reports)
            save_aggregate (bool):
                Whether aggregate reports can be saved into Log Analytics
            save_failure (bool):
                Whether failure reports can be saved into Log Analytics
            save_smtp_tls (bool):
                Whether SMTP TLS reports can be saved into Log Analytics
        """
        conf = self.conf
        credential = ClientSecretCredential(
            tenant_id=conf.tenant_id,
            client_id=conf.client_id,
            client_secret=conf.client_secret,
        )
        logs_client = LogsIngestionClient(conf.dce, credential=credential)
        errors = []
        if (
            results["aggregate_reports"]
            and conf.dcr_aggregate_stream
            and len(results["aggregate_reports"]) > 0
            and save_aggregate
        ):
            logger.info("Publishing aggregate reports.")
            try:
                published = self.publish_json(
                    results["aggregate_reports"], logs_client, conf.dcr_aggregate_stream
                )
                # Oversize reports were already warned about one by one
                if published:
                    logger.info("Successfully pushed aggregate reports.")
            except LogAnalyticsException as e:
                errors.append(f"aggregate reports: {e}")
        if (
            results["failure_reports"]
            and conf.dcr_failure_stream
            and len(results["failure_reports"]) > 0
            and save_failure
        ):
            logger.info("Publishing failure reports.")
            try:
                published = self.publish_json(
                    results["failure_reports"], logs_client, conf.dcr_failure_stream
                )
                # Oversize reports were already warned about one by one
                if published:
                    logger.info("Successfully pushed failure reports.")
            except LogAnalyticsException as e:
                errors.append(f"failure reports: {e}")
        if (
            results["smtp_tls_reports"]
            and conf.dcr_smtp_tls_stream
            and len(results["smtp_tls_reports"]) > 0
            and save_smtp_tls
        ):
            logger.info("Publishing SMTP TLS reports.")
            try:
                published = self.publish_json(
                    results["smtp_tls_reports"], logs_client, conf.dcr_smtp_tls_stream
                )
                # Oversize reports were already warned about one by one
                if published:
                    logger.info("Successfully pushed SMTP TLS reports.")
            except LogAnalyticsException as e:
                errors.append(f"SMTP TLS reports: {e}")
        if errors:
            raise LogAnalyticsException("; ".join(errors))
