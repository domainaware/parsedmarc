# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Any

import httpx

from parsedmarc import logger
from parsedmarc.constants import USER_AGENT


class WebhookClient(object):
    """A client for webhooks"""

    def __init__(
        self,
        aggregate_url: str,
        failure_url: str,
        smtp_tls_url: str,
        timeout: int | None = 60,
    ):
        """
        Initializes the WebhookClient
        Args:
            aggregate_url (str): The aggregate report webhook url
            failure_url (str): The failure report webhook url
            smtp_tls_url (str): The smtp_tls report webhook url
            timeout (int): The timeout to use when calling the webhooks
        """
        self.aggregate_url = aggregate_url
        self.failure_url = failure_url
        self.smtp_tls_url = smtp_tls_url
        self.timeout = timeout
        self.session = httpx.Client(
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
            follow_redirects=True,
        )

    def save_failure_report_to_webhook(self, report: str):
        self._send_to_webhook(self.failure_url, report)

    def save_smtp_tls_report_to_webhook(self, report: str):
        self._send_to_webhook(self.smtp_tls_url, report)

    def save_aggregate_report_to_webhook(self, report: str):
        self._send_to_webhook(self.aggregate_url, report)

    def _send_to_webhook(self, webhook_url: str, payload: bytes | str | dict[str, Any]):
        # All HTTP / network errors are swallowed and logged: a failing
        # webhook should never abort the surrounding parse-and-output
        # batch. The outer save_* methods previously wrapped this in a
        # redundant try/except — removed because _send_to_webhook
        # already catches every Exception itself.
        try:
            if isinstance(payload, dict):
                # requests form-encoded dict payloads via data=; httpx does
                # the same only via data=
                self.session.post(webhook_url, data=payload, timeout=self.timeout)
            else:
                self.session.post(webhook_url, content=payload, timeout=self.timeout)
        except Exception as error_:
            logger.error("Webhook Error: {0}".format(error_.__str__()))

    def close(self):
        """Close the underlying HTTP session."""
        self.session.close()

    # Backward-compatible alias
    save_forensic_report_to_webhook = save_failure_report_to_webhook
