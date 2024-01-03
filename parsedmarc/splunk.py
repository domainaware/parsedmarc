# Standard Library
import json
import socket
from typing import Any, Dict, List, Union
from urllib.parse import urlparse

# Installed
import requests
import urllib3

# Package
from parsedmarc import __version__
from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_timestamp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkError(RuntimeError):
    """Raised when a Splunk API error occurs"""

    def __init__(self, message: Union[str, Exception]):
        if isinstance(message, Exception):
            message = repr(message)
        super().__init__(f"Splunk Error: {message}")
        return


class HECClient(object):
    """A client for a Splunk HTTP Events Collector (HEC)"""

    # http://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHEC
    # http://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTinput#services.2Fcollector

    def __init__(
        self,
        url: str,
        access_token: str,
        index: str,
        source: str = "parsedmarc",
        verify: bool = True,
        timeout: int = 60,
    ):
        """
        Args:
            url: The URL of the HEC
            access_token: The HEC access token
            index: The name of the index
            source: The source name
            verify: Verify SSL certificates
            timeout: Number of seconds to wait for the server to send data before giving up
        """
        parsed = urlparse(url)
        self.url = f"{parsed.scheme}://{parsed.netloc}/services/collector/event/1.0"
        self.access_token = access_token.lstrip("Splunk ")
        self.index = index
        self.host = socket.getfqdn()
        self.source = source
        self.session = requests.Session()
        self.timeout = timeout
        self.session.verify = verify
        self._common_data: Dict[str, Any] = dict(
            host=self.host, source=self.source, index=self.index
        )

        self.session.headers = {
            "User-Agent": f"parsedmarc/{__version__}",
            "Authorization": f"Splunk {self.access_token}",
        }
        return

    def save_aggregate_reports_to_splunk(
        self, aggregate_reports: Union[Dict, List[Dict[str, Any]]]
    ):
        """Save aggregate DMARC reports to Splunk

        Args:
            aggregate_reports: Aggregate reports to save in Splunk
        """
        logger.debug("Saving aggregate reports to Splunk")
        if isinstance(aggregate_reports, dict):
            aggregate_reports = [aggregate_reports]

        if not aggregate_reports:
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
                timestamp = human_timestamp_to_timestamp(new_report["begin_date"])
                data["time"] = timestamp
                data["event"] = new_report.copy()
                json_str += json.dumps(data) + "\n"

        if not self.session.verify:
            logger.debug("Skipping certificate verification for Splunk HEC")
        try:
            response = self.session.post(self.url, data=json_str, timeout=self.timeout).json()
        except Exception as e:
            raise SplunkError(e)
        if response["code"] != 0:
            raise SplunkError(response["text"])
        return

    def save_forensic_reports_to_splunk(self, forensic_reports: Union[Dict, List[Dict[str, Any]]]):
        """Save forensic DMARC reports to Splunk

        Args:
            forensic_reports: Forensic reports to save in Splunk
        """
        logger.debug("Saving forensic reports to Splunk")
        if isinstance(forensic_reports, dict):
            forensic_reports = [forensic_reports]

        if not forensic_reports:
            return

        json_str = ""
        for report in forensic_reports:
            data = self._common_data.copy()
            data["sourcetype"] = "dmarc:forensic"
            timestamp = human_timestamp_to_timestamp(report["arrival_date_utc"])
            data["time"] = timestamp
            data["event"] = report.copy()
            json_str += json.dumps(data) + "\n"

        if not self.session.verify:
            logger.debug("Skipping certificate verification for Splunk HEC")
        try:
            response = self.session.post(self.url, data=json_str, timeout=self.timeout).json()
        except Exception as e:
            raise SplunkError(e)
        if response["code"] != 0:
            raise SplunkError(response["text"])
        return
