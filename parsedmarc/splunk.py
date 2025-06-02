from urllib.parse import urlparse
import socket
import json

import urllib3
import requests

from parsedmarc.constants import USER_AGENT
from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_unix_timestamp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkError(RuntimeError):
    """Raised when a Splunk API error occurs"""


class HECClient(object):
    """A client for a Splunk HTTP Events Collector (HEC)"""

    # http://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHEC
    # http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#services.2Fcollector

    def __init__(
        self, url, access_token, index, source="parsedmarc", verify=True, timeout=60
    ):
        """
        Initializes the HECClient

        Args:
            url (str): The URL of the HEC
            access_token (str): The HEC access token
            index (str): The name of the index
            source (str): The source name
            verify (bool): Verify SSL certificates
            timeout (float): Number of seconds to wait for the server to send
                data before giving up
        """
        url = urlparse(url)
        self.url = "{0}://{1}/services/collector/event/1.0".format(
            url.scheme, url.netloc
        )
        self.access_token = access_token.lstrip("Splunk ")
        self.index = index
        self.host = socket.getfqdn()
        self.source = source
        self.session = requests.Session()
        self.timeout = timeout
        self.session.verify = verify
        self._common_data = dict(host=self.host, source=self.source, index=self.index)

        self.session.headers = {
            "User-Agent": USER_AGENT,
            "Authorization": "Splunk {0}".format(self.access_token),
        }

    def save_aggregate_reports_to_splunk(self, aggregate_reports):
        """
        Saves aggregate DMARC reports to Splunk

        Args:
            aggregate_reports: A list of aggregate report dictionaries
                to save in Splunk

        """
        logger.debug("Saving aggregate reports to Splunk")
        if isinstance(aggregate_reports, dict):
            aggregate_reports = [aggregate_reports]

        if len(aggregate_reports) < 1:
            return

        data = self._common_data.copy()
        json_str = ""
        for report in aggregate_reports:
            for record in report["records"]:
                new_report = dict()
                for metadata in report["report_metadata"]:
                    new_report[metadata] = report["report_metadata"][metadata]
                new_report["published_policy"] = report["policy_published"]
                new_report["source_ip_address"] = record["source"]["ip_address"]
                new_report["source_country"] = record["source"]["country"]
                new_report["source_reverse_dns"] = record["source"]["reverse_dns"]
                new_report["source_base_domain"] = record["source"]["base_domain"]
                new_report["source_type"] = record["source"]["type"]
                new_report["source_name"] = record["source"]["name"]
                new_report["message_count"] = record["count"]
                new_report["disposition"] = record["policy_evaluated"]["disposition"]
                new_report["spf_aligned"] = record["alignment"]["spf"]
                new_report["dkim_aligned"] = record["alignment"]["dkim"]
                new_report["passed_dmarc"] = record["alignment"]["dmarc"]
                new_report["header_from"] = record["identifiers"]["header_from"]
                new_report["envelope_from"] = record["identifiers"]["envelope_from"]
                if "dkim" in record["auth_results"]:
                    new_report["dkim_results"] = record["auth_results"]["dkim"]
                if "spf" in record["auth_results"]:
                    new_report["spf_results"] = record["auth_results"]["spf"]

                data["sourcetype"] = "dmarc:aggregate"
                timestamp = human_timestamp_to_unix_timestamp(new_report["begin_date"])
                data["time"] = timestamp
                data["event"] = new_report.copy()
                json_str += "{0}\n".format(json.dumps(data))

        if not self.session.verify:
            logger.debug("Skipping certificate verification for Splunk HEC")
        try:
            response = self.session.post(self.url, data=json_str, timeout=self.timeout)
            response = response.json()
        except Exception as e:
            raise SplunkError(e.__str__())
        if response["code"] != 0:
            raise SplunkError(response["text"])

    def save_forensic_reports_to_splunk(self, forensic_reports):
        """
        Saves forensic DMARC reports to Splunk

        Args:
            forensic_reports (list): A list of forensic report dictionaries
                to save in Splunk
        """
        logger.debug("Saving forensic reports to Splunk")
        if isinstance(forensic_reports, dict):
            forensic_reports = [forensic_reports]

        if len(forensic_reports) < 1:
            return

        json_str = ""
        for report in forensic_reports:
            data = self._common_data.copy()
            data["sourcetype"] = "dmarc:forensic"
            timestamp = human_timestamp_to_unix_timestamp(report["arrival_date_utc"])
            data["time"] = timestamp
            data["event"] = report.copy()
            json_str += "{0}\n".format(json.dumps(data))

        if not self.session.verify:
            logger.debug("Skipping certificate verification for Splunk HEC")
        try:
            response = self.session.post(self.url, data=json_str, timeout=self.timeout)
            response = response.json()
        except Exception as e:
            raise SplunkError(e.__str__())
        if response["code"] != 0:
            raise SplunkError(response["text"])

    def save_smtp_tls_reports_to_splunk(self, reports):
        """
        Saves aggregate DMARC reports to Splunk

        Args:
            reports: A list of SMTP TLS report dictionaries
                to save in Splunk

        """
        logger.debug("Saving SMTP TLS reports to Splunk")
        if isinstance(reports, dict):
            reports = [reports]

        if len(reports) < 1:
            return

        data = self._common_data.copy()
        json_str = ""
        for report in reports:
            data["sourcetype"] = "smtp:tls"
            timestamp = human_timestamp_to_unix_timestamp(report["begin_date"])
            data["time"] = timestamp
            data["event"] = report.copy()
            json_str += "{0}\n".format(json.dumps(data))

        if not self.session.verify:
            logger.debug("Skipping certificate verification for Splunk HEC")
        try:
            response = self.session.post(self.url, data=json_str, timeout=self.timeout)
            response = response.json()
        except Exception as e:
            raise SplunkError(e.__str__())
        if response["code"] != 0:
            raise SplunkError(response["text"])
