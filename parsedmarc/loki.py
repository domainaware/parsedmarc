# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
import socket
import time
from collections.abc import Callable
from typing import Any

import httpx

from parsedmarc import (
    parsed_aggregate_reports_to_csv_rows,
    parsed_failure_reports_to_csv_rows,
    parsed_smtp_tls_reports_to_csv_rows,
)
from parsedmarc.constants import USER_AGENT
from parsedmarc.log import logger
from parsedmarc.types import AggregateReport, FailureReport, SMTPTLSReport
from parsedmarc.utils import human_timestamp_to_unix_timestamp

PUSH_PATH = "/loki/api/v1/push"
TIMESTAMP_MODES = ("ingest", "report_begin")
DEFAULT_LABEL_FIELDS = ["report_type", "domain"]

_LABEL_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Per report type: the row field holding the domain the report is about,
# and the row field with its begin time (and whether that value is UTC
# without an offset; aggregate rows carry the record's interval_begin,
# which parsedmarc builds as naive UTC wall-clock time).
_REPORT_TYPES: dict[str, tuple[str, str, bool]] = {
    "aggregate": ("domain", "begin_date", True),
    "failure": ("reported_domain", "arrival_date_utc", True),
    "smtp_tls": ("policy_domain", "begin_date", False),
}


class LokiError(RuntimeError):
    """Raised when pushing to Loki fails"""


class LokiClient(object):
    """A client for the Grafana Loki push API"""

    def __init__(
        self,
        url: str,
        *,
        labels: dict[str, str] | None = None,
        label_fields: list[str] | None = None,
        timestamp: str = "ingest",
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        tenant_id: str | None = None,
        verify: bool = True,
        timeout: float = 60,
        batch_size: int = 1000,
    ):
        """
        Initializes the LokiClient

        Every report record becomes one JSON log line. Streams are labeled
        with ``labels`` plus the record fields named in ``label_fields``;
        keep those to fields with few distinct values.

        Args:
            url (str): Loki base URL (``/loki/api/v1/push`` is appended when
                the URL has no path) or the full push URL
            labels (dict): Static stream labels, merged over the defaults
                ``job=parsedmarc`` and ``host=<FQDN>``
            label_fields (list): Record fields used as stream labels
                (Default: ``report_type``, ``domain``)
            timestamp (str): ``ingest`` (time of the push) or
                ``report_begin`` (begin of the reported period; Loki rejects
                entries older than its ``reject_old_samples_max_age``)
            username (str): Basic auth user
            password (str): Basic auth password
            token (str): Bearer token, instead of basic auth
            tenant_id (str): Sent as ``X-Scope-OrgID``
            verify (bool): Verify TLS certificates
            timeout (float): Request timeout in seconds
            batch_size (int): Maximum log lines per push request
        """
        if timestamp not in TIMESTAMP_MODES:
            raise ValueError(
                f"Invalid Loki timestamp '{timestamp}'. "
                f"Must be one of: {', '.join(TIMESTAMP_MODES)}"
            )
        if token and (username or password):
            raise ValueError("Loki token and username/password are exclusive")

        self.labels = {"job": "parsedmarc", "host": socket.getfqdn()}
        self.labels.update(labels or {})
        self.label_fields = list(
            DEFAULT_LABEL_FIELDS if label_fields is None else label_fields
        )
        for name in list(self.labels) + self.label_fields:
            if not _LABEL_NAME.match(name):
                raise ValueError(f"Invalid Loki label name '{name}'")

        stripped = url.rstrip("/")
        self.url = stripped + PUSH_PATH if httpx.URL(url).path in ("", "/") else url
        self.timestamp = timestamp
        self.timeout = timeout
        self.batch_size = max(1, int(batch_size))

        headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if tenant_id:
            headers["X-Scope-OrgID"] = tenant_id
        auth = httpx.BasicAuth(username or "", password or "") if username else None
        self.session = httpx.Client(
            headers=headers, auth=auth, verify=verify, follow_redirects=True
        )

    def save_aggregate_report_to_loki(
        self, aggregate_reports: AggregateReport | list[AggregateReport]
    ):
        self._save("aggregate", parsed_aggregate_reports_to_csv_rows, aggregate_reports)

    def save_failure_report_to_loki(
        self, failure_reports: FailureReport | list[FailureReport]
    ):
        self._save("failure", parsed_failure_reports_to_csv_rows, failure_reports)

    def save_smtp_tls_report_to_loki(
        self, smtp_tls_reports: SMTPTLSReport | list[SMTPTLSReport]
    ):
        self._save("smtp_tls", parsed_smtp_tls_reports_to_csv_rows, smtp_tls_reports)

    def _save(self, report_type: str, to_rows: Callable, reports: Any):
        rows = to_rows(reports)
        if not rows:
            return
        logger.debug(f"Saving {len(rows)} {report_type} records to Loki")
        domain_field, begin_field, begin_is_utc = _REPORT_TYPES[report_type]
        now = time.time_ns()
        entries = []
        for i, row in enumerate(rows):
            line = dict(row)
            line["report_type"] = report_type
            line.setdefault("domain", row.get(domain_field))
            ts = now
            if self.timestamp == "report_begin":
                try:
                    begin = human_timestamp_to_unix_timestamp(
                        str(row[begin_field]), assume_utc=begin_is_utc
                    )
                    ts = begin * 10**9
                except Exception:
                    logger.debug(f"Unparsable {begin_field}, using ingest time")
            entries.append((self._stream_labels(line), ts + i, line))

        for start in range(0, len(entries), self.batch_size):
            self._push(entries[start : start + self.batch_size])

    def _stream_labels(self, line: dict[str, Any]) -> tuple[tuple[str, str], ...]:
        labels = dict(self.labels)
        for field in self.label_fields:
            value = line.get(field)
            if value is not None and value != "":
                labels[field] = str(value)
        return tuple(labels.items())

    def _push(self, entries: list):
        streams: dict[tuple, list[list[str]]] = {}
        for labels, ts, line in entries:
            streams.setdefault(labels, []).append(
                [str(ts), json.dumps(line, ensure_ascii=False, default=str)]
            )
        body = {
            "streams": [
                {"stream": dict(labels), "values": values}
                for labels, values in streams.items()
            ]
        }
        try:
            response = self.session.post(
                self.url, content=json.dumps(body), timeout=self.timeout
            )
        except httpx.HTTPError as error_:
            raise LokiError(f"Loki push to {self.url} failed: {error_}") from error_
        # Loki answers 204 when it stored the push; 200 is also accepted.
        # Other 2xx codes are not success: with block_ingestion_until set it
        # returns a custom 260 and discards the logs
        # (block_ingestion_status_code).
        if response.status_code not in (200, 204):
            raise LokiError(
                f"Loki push to {self.url} failed with HTTP "
                f"{response.status_code}: {response.text[:500]}"
            )

    def close(self):
        """Close the underlying HTTP session."""
        self.session.close()

    # Backward-compatible alias
    save_forensic_report_to_loki = save_failure_report_to_loki
