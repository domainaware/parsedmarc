# -*- coding: utf-8 -*-

"""Google SecOps (Chronicle) output.

Sends parsed reports to a Google SecOps instance as Unified Data Model (UDM)
events via the GA v1 Chronicle API ``events.import`` method:

    POST https://chronicle.{region}.rep.googleapis.com/v1/{parent}/events:import
    parent = projects/{project}/locations/{region}/instances/{instance}

Because the events are already normalized, they bypass SecOps's server-side
parsing (CBN) layer entirely. The UDM mapping mirrors the CBN parser shipped
in ``google_secops_parser/`` — the same ``additional`` keys are used by both
delivery paths so searches and dashboards port between them:

  * DMARC aggregate report record -> EMAIL_TRANSACTION
  * DMARC failure report record   -> EMAIL_TRANSACTION
  * SMTP TLS report record        -> GENERIC_EVENT

API references:
  https://docs.cloud.google.com/chronicle/docs/reference/ingestion-methods
  https://docs.cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.events/import

Authentication uses standard Google Cloud credentials (a service account key
file, or Application Default Credentials when no file is configured). The
account needs the Chronicle API Editor IAM role — specifically the
``chronicle.events.import`` permission — in the Google Cloud project that was
linked to the SecOps instance at onboarding; a correctly-permissioned account
in any other project will fail to authenticate.
"""

from __future__ import annotations

from typing import Any

import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

from parsedmarc import (
    parsed_aggregate_reports_to_csv_rows,
    parsed_failure_reports_to_csv_rows,
    parsed_smtp_tls_reports_to_csv_rows,
)
from parsedmarc.log import logger
from parsedmarc.types import AggregateReport, FailureReport, SMTPTLSReport

# https://docs.cloud.google.com/chronicle/docs/reference/rest/v1/projects.locations.instances.events/import
# also accepts the narrower https://www.googleapis.com/auth/chronicle scope;
# cloud-platform is what Google's own secops SDK requests.
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

# Documented API behavior and best practices: 4 MB maximum request size,
# ~1,000 log lines and ~2 MB per batch optimal, 60 second request timeout.
# https://docs.cloud.google.com/chronicle/docs/reference/ingestion-methods
_MAX_EVENTS_PER_BATCH = 1000
_REQUEST_TIMEOUT = 60

_VENDOR = "parsedmarc"

_DISPOSITION_TO_ACTION = {
    "none": "ALLOW",
    "quarantine": "QUARANTINE",
    "reject": "BLOCK",
}

_DELIVERY_RESULT_TO_ACTION = {
    "delivered": "ALLOW",
    "quarantine": "QUARANTINE",
    "reject": "BLOCK",
}


class GoogleSecOpsError(Exception):
    """Raised when a Google SecOps API error occurs"""


def _rfc3339(timestamp: str) -> str:
    """Converts parsedmarc's ``YYYY-MM-DD HH:MM:SS`` UTC wall-clock strings to
    RFC 3339 (proto Timestamp JSON). SMTP TLS timestamps are already RFC 3339
    and pass through unchanged."""
    timestamp = timestamp.replace(" ", "T")
    if not timestamp.endswith("Z"):
        timestamp += "Z"
    return timestamp


def _metadata(
    event_type: str, product_event_type: str, timestamp: str, log_id: Any
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "eventTimestamp": _rfc3339(timestamp),
        "eventType": event_type,
        "vendorName": _VENDOR,
        "productName": _VENDOR,
        "productEventType": product_event_type,
    }
    if log_id:
        metadata["productLogId"] = log_id
    return metadata


def _source_noun(row: dict[str, Any]) -> dict[str, Any]:
    """principal: the sending source (machine details only)."""
    noun: dict[str, Any] = {}
    if row.get("source_ip_address"):
        noun["ip"] = [row["source_ip_address"]]
    if row.get("source_reverse_dns"):
        noun["hostname"] = row["source_reverse_dns"]
    if row.get("source_country"):
        noun["location"] = {"countryOrRegion": row["source_country"]}
    return noun


def _additional(row: dict[str, Any], keys: dict[str, str]) -> dict[str, Any]:
    """Builds the ``additional`` Struct from row values.

    ``keys`` maps row keys to their ``additional`` key names (matching the
    CBN parser's key names so searches port between the two delivery paths).
    Because ``additional`` is a protobuf Struct, native JSON types survive:
    booleans stay booleans and counts stay numbers, so SecOps can filter and
    range-query them directly. Empty strings and ``None`` (absent in the
    source report) are dropped.
    """
    additional: dict[str, Any] = {}
    for row_key, additional_key in keys.items():
        value = row.get(row_key)
        if value is None or value == "":
            continue
        # parsedmarc writes the literal "none" when there are no overrides
        if row_key.startswith("policy_override_") and value == "none":
            continue
        additional[additional_key] = value
    return additional


_AGGREGATE_ADDITIONAL_KEYS = {
    "org_name": "org_name",
    "org_email": "org_email",
    "org_extra_contact_info": "org_extra_contact_info",
    "errors": "errors",
    "begin_date": "begin_date",
    "end_date": "end_date",
    "count": "count",
    "p": "dmarc_policy",
    "sp": "dmarc_subdomain_policy",
    "np": "dmarc_np_policy",
    "pct": "dmarc_pct",
    "fo": "dmarc_fo",
    "adkim": "dkim_alignment_mode",
    "aspf": "spf_alignment_mode",
    "testing": "dmarc_testing",
    "discovery_method": "discovery_method",
    "normalized_timespan": "normalized_timespan",
    "dmarc_aligned": "dmarc_aligned",
    "spf_aligned": "spf_aligned",
    "dkim_aligned": "dkim_aligned",
    "disposition": "disposition",
    "dkim_domains": "dkim_domains",
    "dkim_selectors": "dkim_selectors",
    "dkim_results": "dkim_results",
    "spf_domains": "spf_domains",
    "spf_scopes": "spf_scopes",
    "spf_results": "spf_results",
    "policy_override_reasons": "policy_override_reasons",
    "policy_override_comments": "policy_override_comments",
    "source_base_domain": "source_base_domain",
    "source_name": "source_name",
    "source_type": "source_type",
    "source_asn": "source_asn",
    "source_as_name": "source_as_name",
    "source_as_domain": "source_as_domain",
    "envelope_from": "envelope_from",
    "envelope_to": "envelope_to",
}

_FAILURE_ADDITIONAL_KEYS = {
    "feedback_type": "feedback_type",
    "auth_failure": "auth_failure",
    "delivery_result": "delivery_result",
    "authentication_results": "authentication_results",
    "authentication_mechanisms": "authentication_mechanisms",
    "user_agent": "user_agent",
    "dkim_domain": "dkim_domain",
    "arrival_date": "arrival_date",
    "source_base_domain": "source_base_domain",
    "source_name": "source_name",
    "source_type": "source_type",
    "source_asn": "source_asn",
    "source_as_name": "source_as_name",
    "source_as_domain": "source_as_domain",
}

_SMTP_TLS_ADDITIONAL_KEYS = {
    "organization_name": "organization_name",
    "begin_date": "begin_date",
    "end_date": "end_date",
    "policy_domain": "policy_domain",
    "policy_type": "policy_type",
    "policy_strings": "policy_strings",
    "mx_host_patterns": "mx_host_patterns",
    "successful_session_count": "successful_session_count",
    "failed_session_count": "failed_session_count",
    "result_type": "result_type",
    "failure_reason_code": "failure_reason_code",
    "receiving_mx_hostname": "receiving_mx_hostname",
    "receiving_mx_helo": "receiving_mx_helo",
    "additional_info_uri": "additional_info_uri",
}


def aggregate_report_to_udm_events(
    report: AggregateReport,
) -> list[dict[str, Any]]:
    """Converts a parsed aggregate report to UDM EMAIL_TRANSACTION events,
    one per record row"""
    events = []
    for row in parsed_aggregate_reports_to_csv_rows(report):
        udm: dict[str, Any] = {
            "metadata": _metadata(
                "EMAIL_TRANSACTION", "aggregate", row["begin_date"], row["report_id"]
            )
        }
        principal = _source_noun(row)
        if principal:
            udm["principal"] = principal
        if row.get("domain"):
            udm["target"] = {"hostname": row["domain"]}
        if row.get("header_from"):
            # aggregate reports only carry the From domain, so this is a bare
            # domain rather than a full address (documented in the CBN
            # parser's README as caveat 5)
            udm["network"] = {"email": {"from": row["header_from"]}}
        security_result: dict[str, Any] = {
            "summary": "DMARC aggregate report",
            "action": [
                _DISPOSITION_TO_ACTION.get(row["disposition"], "UNKNOWN_ACTION")
            ],
        }
        if row["dmarc_aligned"] is False:
            security_result["category"] = ["AUTH_VIOLATION"]
        udm["securityResult"] = [security_result]
        udm["additional"] = _additional(row, _AGGREGATE_ADDITIONAL_KEYS)
        events.append({"udm": udm})
    return events


def failure_report_to_udm_events(report: FailureReport) -> list[dict[str, Any]]:
    """Converts a parsed failure report to UDM EMAIL_TRANSACTION events"""
    events = []
    for row in parsed_failure_reports_to_csv_rows(report):
        udm: dict[str, Any] = {
            "metadata": _metadata(
                "EMAIL_TRANSACTION",
                "failure",
                row["arrival_date_utc"],
                row.get("message_id"),
            )
        }
        principal = _source_noun(row)
        if principal:
            udm["principal"] = principal
        if row.get("reported_domain"):
            udm["target"] = {"hostname": row["reported_domain"]}
        email: dict[str, Any] = {}
        if row.get("original_mail_from"):
            email["from"] = row["original_mail_from"]
        if row.get("original_rcpt_to"):
            # to and subject are repeated fields in the UDM Email message
            email["to"] = [row["original_rcpt_to"]]
        if row.get("subject"):
            email["subject"] = [row["subject"]]
        if row.get("message_id"):
            email["mailId"] = row["message_id"]
        if email:
            udm["network"] = {"email": email}
        udm["securityResult"] = [
            {
                "summary": "DMARC failure report",
                "category": ["AUTH_VIOLATION"],
                "action": [
                    _DELIVERY_RESULT_TO_ACTION.get(
                        row.get("delivery_result") or "", "UNKNOWN_ACTION"
                    )
                ],
            }
        ]
        udm["additional"] = _additional(row, _FAILURE_ADDITIONAL_KEYS)
        events.append({"udm": udm})
    return events


def smtp_tls_report_to_udm_events(report: SMTPTLSReport) -> list[dict[str, Any]]:
    """Converts a parsed SMTP TLS report to UDM GENERIC_EVENT events, one per
    policy summary row and one per failure-detail row"""
    events = []
    for row in parsed_smtp_tls_reports_to_csv_rows(report):
        udm: dict[str, Any] = {
            "metadata": _metadata(
                "GENERIC_EVENT", "smtp_tls", row["begin_date"], row["report_id"]
            )
        }
        target: dict[str, Any] = {}
        if row.get("policy_domain"):
            target["hostname"] = row["policy_domain"]
        elif row.get("receiving_mx_hostname"):
            target["hostname"] = row["receiving_mx_hostname"]
        if row.get("receiving_ip"):
            target["ip"] = [row["receiving_ip"]]
        if target:
            udm["target"] = target
        if row.get("sending_mta_ip"):
            udm["principal"] = {"ip": [row["sending_mta_ip"]]}
        if row.get("result_type"):
            udm["securityResult"] = [
                {
                    "summary": "SMTP TLS report failure",
                    "category": ["POLICY_VIOLATION"],
                    "action": ["FAIL"],
                }
            ]
        udm["additional"] = _additional(row, _SMTP_TLS_ADDITIONAL_KEYS)
        events.append({"udm": udm})
    return events


class GoogleSecOpsClient(object):
    """A client for the Google SecOps (Chronicle) v1 events.import method"""

    def __init__(
        self,
        project_id: str,
        instance_id: str,
        region: str = "us",
        credentials_file: str | None = None,
    ):
        """
        Initializes the GoogleSecOpsClient

        Args:
            project_id (str): The Google Cloud project linked to the SecOps
                instance at onboarding
            instance_id (str): The SecOps instance (customer) GUID
            region (str): The SecOps instance region, e.g. ``us`` or
                ``europe`` (Default: ``us``)
            credentials_file (str): Path to a service account JSON key file.
                When not set, Application Default Credentials are used.
        """
        if not project_id or not instance_id:
            raise GoogleSecOpsError(
                "Invalid configuration. project_id and instance_id are required."
            )
        parent = "projects/{0}/locations/{1}/instances/{2}".format(
            project_id, region, instance_id
        )
        self.url = (
            "https://chronicle.{0}.rep.googleapis.com/v1/{1}/events:import".format(
                region, parent
            )
        )
        if credentials_file:
            credentials = service_account.Credentials.from_service_account_file(
                credentials_file, scopes=_SCOPES
            )
        else:
            credentials, _ = google.auth.default(scopes=_SCOPES)
        self.session = AuthorizedSession(credentials)
        self._dropped = 0

    def _import_events(self, events: list[dict[str, Any]]) -> None:
        """Imports a batch of UDM events, bisecting on HTTP 400.

        The v1 ``events.import`` method is all-or-nothing: one invalid event
        rejects the entire request. Splitting a rejected batch isolates the
        invalid events so the valid remainder is still delivered; each
        invalid event is logged and counted rather than aborting the batch.
        """
        response = self.session.post(
            self.url,
            json={"inlineSource": {"events": events}},
            timeout=_REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            return
        if response.status_code == 400 and len(events) > 1:
            middle = len(events) // 2
            self._import_events(events[:middle])
            self._import_events(events[middle:])
            return
        if response.status_code == 400:
            logger.error(
                "Google SecOps rejected event {0}: {1}".format(events[0], response.text)
            )
            self._dropped += 1
            return
        raise GoogleSecOpsError(
            "Import failed with HTTP {0}: {1}".format(
                response.status_code, response.text
            )
        )

    def save_events(self, events: list[dict[str, Any]]) -> None:
        """Imports UDM events in documented-best-practice batch sizes"""
        self._dropped = 0
        for start in range(0, len(events), _MAX_EVENTS_PER_BATCH):
            self._import_events(events[start : start + _MAX_EVENTS_PER_BATCH])
        if self._dropped:
            raise GoogleSecOpsError(
                "{0} of {1} events were rejected by Google SecOps "
                "(see error log for details)".format(self._dropped, len(events))
            )

    def publish_results(
        self,
        results: dict[str, Any],
        save_aggregate: bool,
        save_failure: bool,
        save_smtp_tls: bool,
    ) -> None:
        """
        Publishes DMARC and/or SMTP TLS reports to Google SecOps as UDM
        events

        Args:
            results (dict): Parsing results from parsedmarc
            save_aggregate (bool): Whether to save aggregate reports
            save_failure (bool): Whether to save failure reports
            save_smtp_tls (bool): Whether to save SMTP TLS reports
        """
        events: list[dict[str, Any]] = []
        if save_aggregate:
            for report in results["aggregate_reports"]:
                events += aggregate_report_to_udm_events(report)
        if save_failure:
            for report in results["failure_reports"]:
                events += failure_report_to_udm_events(report)
        if save_smtp_tls:
            for report in results["smtp_tls_reports"]:
                events += smtp_tls_report_to_udm_events(report)
        if len(events) > 0:
            logger.info(
                "Publishing {0} UDM events to Google SecOps".format(len(events))
            )
            self.save_events(events)
            logger.info("Successfully published UDM events to Google SecOps")
