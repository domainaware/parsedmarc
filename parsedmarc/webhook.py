import requests

from parsedmarc import logger
from parsedmarc.constants import USER_AGENT


class WebhookClient(object):
    """A client for webhooks"""

    def __init__(self, aggregate_url, forensic_url, smtp_tls_url, timeout=60):
        """
        Initializes the WebhookClient
        Args:
            aggregate_url (str): The aggregate report webhook url
            forensic_url (str): The forensic report webhook url
            smtp_tls_url (str): The smtp_tls report webhook url
            timeout (int): The timeout to use when calling the webhooks
        """
        self.aggregate_url = aggregate_url
        self.forensic_url = forensic_url
        self.smtp_tls_url = smtp_tls_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
        }

    def save_forensic_report_to_webhook(self, report):
        try:
            self._send_to_webhook(self.forensic_url, report)
        except Exception as error_:
            logger.error("Webhook Error: {0}".format(error_.__str__()))

    def save_smtp_tls_report_to_webhook(self, report):
        try:
            self._send_to_webhook(self.smtp_tls_url, report)
        except Exception as error_:
            logger.error("Webhook Error: {0}".format(error_.__str__()))

    def save_aggregate_report_to_webhook(self, report):
        try:
            self._send_to_webhook(self.aggregate_url, report)
        except Exception as error_:
            logger.error("Webhook Error: {0}".format(error_.__str__()))

    def _send_to_webhook(self, webhook_url, payload):
        try:
            self.session.post(webhook_url, data=payload, timeout=self.timeout)
        except Exception as error_:
            logger.error("Webhook Error: {0}".format(error_.__str__()))
