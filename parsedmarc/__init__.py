# -*- coding: utf-8 -*-

"""A Python package for parsing DMARC reports"""

import logging
import os
import xml.parsers.expat as expat
import json
from datetime import datetime
from collections import OrderedDict
from datetime import timedelta
from io import BytesIO, StringIO
from gzip import GzipFile
import tarfile
import zipfile
from csv import DictWriter
import re
from base64 import b64decode
import binascii
import shutil
import email
import tempfile
import subprocess
import socket
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
import smtplib
import ssl
import time

import publicsuffix
import xmltodict
import dns.reversename
import dns.resolver
import dns.exception
from requests import get
import geoip2.database
import geoip2.errors
import imapclient
import imapclient.exceptions
import dateparser
import mailparser

__version__ = "3.9.7"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

feedback_report_regex = re.compile(r"^([\w\-]+): (.+)$", re.MULTILINE)

MAGIC_ZIP = b"\x50\x4B\x03\x04"
MAGIC_GZIP = b"\x1F\x8B"
MAGIC_XML = b"\x3c\x3f\x78\x6d\x6c\x20"


class ParserError(RuntimeError):
    """Raised whenever the parser fails for some reason"""


class IMAPError(RuntimeError):
    """Raised when an IMAP error occurs"""


class SMTPError(RuntimeError):
    """Raised when a SMTP error occurs"""


class InvalidDMARCReport(ParserError):
    """Raised when an invalid DMARC report is encountered"""


class InvalidAggregateReport(InvalidDMARCReport):
    """Raised when an invalid DMARC aggregate report is encountered"""


class InvalidForensicReport(InvalidDMARCReport):
    """Raised when an invalid DMARC forensic report is encountered"""


def _get_base_domain(domain):
    """
    Gets the base domain name for the given domain

    .. note::
        Results are based on a list of public domain suffixes at
        https://publicsuffix.org/list/public_suffix_list.dat.

        This file is saved to the current working directory,
        where it is used as a cache file for 24 hours.

    Args:
        domain (str): A domain or subdomain

    Returns:
        str: The base domain of the given domain

    """
    psl_path = ".public_suffix_list.dat"

    def download_psl():
        fresh_psl = publicsuffix.fetch().read()
        with open(psl_path, "w", encoding="utf-8") as fresh_psl_file:
            fresh_psl_file.write(fresh_psl)

    if not os.path.exists(psl_path):
        download_psl()
    else:
        psl_age = datetime.now() - datetime.fromtimestamp(
            os.stat(psl_path).st_mtime)
        if psl_age > timedelta(hours=24):
            try:
                download_psl()
            except Exception as error:
                logger.warning("Failed to download an updated PSL - \
                               {0}".format(error))
    with open(psl_path, encoding="utf-8") as psl_file:
        psl = publicsuffix.PublicSuffixList(psl_file)

    return psl.get_public_suffix(domain)


def _query_dns(domain, record_type, nameservers=None, timeout=6.0):
    """
    Queries DNS

    Args:
        domain (str): The domain or subdomain to query about
        record_type (str): The record type to query for
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        list: A list of answers
    """
    resolver = dns.resolver.Resolver()
    timeout = float(timeout)
    if nameservers is None:
        nameservers = ["1.1.1.1", "1.0.0.1",
                       "2606:4700:4700::1111", "2606:4700:4700::1001",
                       ]
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return list(map(
        lambda r: r.to_text().replace(' "', '').replace('"', '').rstrip("."),
        resolver.query(domain, record_type, tcp=True)))


def _get_reverse_dns(ip_address, nameservers=None, timeout=6.0):
    """
    Resolves an IP address to a hostname using a reverse DNS query

    Args:
        ip_address (str): The IP address to resolve
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS query timeout in seconds

    Returns:
        str: The reverse DNS hostname (if any)
    """
    hostname = None
    try:
        address = dns.reversename.from_address(ip_address)
        hostname = _query_dns(address, "PTR",
                              nameservers=nameservers,
                              timeout=timeout)[0]

    except dns.exception.DNSException:
        pass

    return hostname


def _timestamp_to_datetime(timestamp):
    """
    Converts a UNIX/DMARC timestamp to a Python ``DateTime`` object

    Args:
        timestamp (int): The timestamp

    Returns:
        DateTime: The converted timestamp as a Python ``DateTime`` object
    """
    return datetime.fromtimestamp(int(timestamp))


def _timestamp_to_human(timestamp):
    """
    Converts a UNIX/DMARC timestamp to a human-readable string

    Args:
        timestamp: The timestamp

    Returns:
        str: The converted timestamp in ``YYYY-MM-DD HH:MM:SS`` format
    """
    return _timestamp_to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def human_timestamp_to_datetime(human_timestamp):
    """
    Converts a human-readable timestamp into a Python ``DateTime`` object

    Args:
        human_timestamp (str): A timestamp in `YYYY-MM-DD HH:MM:SS`` format

    Returns:
        DateTime: The converted timestamp
    """
    return datetime.strptime(human_timestamp, "%Y-%m-%d %H:%M:%S")


def _get_ip_address_country(ip_address):
    """
    Uses the MaxMind Geolite2 Country database to return the ISO code for the
    country associated with the given IPv4 or IPv6 address

    Args:
        ip_address (str): The IP address to query for

    Returns:
        str: And ISO country code associated with the given IP address
    """
    db_filename = ".GeoLite2-Country.mmdb"

    def download_country_database(location=".GeoLite2-Country.mmdb"):
        """Downloads the MaxMind Geolite2 Country database

        Args:
            location (str): Local location for the database file
        """
        url = "https://geolite.maxmind.com/download/geoip/database/" \
              "GeoLite2-Country.tar.gz"
        original_filename = "GeoLite2-Country.mmdb"
        tar_file = tarfile.open(fileobj=BytesIO(get(url).content), mode="r:gz")
        tar_dir = tar_file.getnames()[0]
        tar_path = "{0}/{1}".format(tar_dir, original_filename)
        tar_file.extract(tar_path)
        shutil.move(tar_path, location)
        shutil.rmtree(tar_dir)

    system_paths = ["/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
                    "/usr/share/GeoIP/GeoLite2-Country.mmdb"]
    db_path = ""

    for system_path in system_paths:
        if os.path.exists(system_path):
            db_path = system_path
            break

    if db_path == "":
        if not os.path.exists(db_filename):
            download_country_database(db_filename)
        else:
            db_age = datetime.now() - datetime.fromtimestamp(
                os.stat(db_filename).st_mtime)
            if db_age > timedelta(days=60):
                download_country_database()
        db_path = db_filename

    db_reader = geoip2.database.Reader(db_path)

    country = None

    try:
        country = db_reader.country(ip_address).country.iso_code
    except geoip2.errors.AddressNotFoundError:
        pass

    return country


def _get_ip_address_info(ip_address, nameservers=None, timeout=6.0):
    """
    Returns reverse DNS and country information for the given IP address

    Args:
        ip_address (str): The IP address to check
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: ``ip_address``, ``reverse_dns``

    """
    ip_address = ip_address.lower()
    info = OrderedDict()
    info["ip_address"] = ip_address
    reverse_dns = _get_reverse_dns(ip_address,
                                   nameservers=nameservers,
                                   timeout=timeout)
    country = _get_ip_address_country(ip_address)
    info["country"] = country
    info["reverse_dns"] = reverse_dns
    info["base_domain"] = None
    if reverse_dns is not None:
        base_domain = _get_base_domain(reverse_dns)
        info["base_domain"] = base_domain

    return info


def _parse_report_record(record, nameservers=None, timeout=6.0):
    """
    Converts a record from a DMARC aggregate report into a more consistent
    format

    Args:
        record (OrderedDict): The record to convert
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: The converted record
    """
    if nameservers is None:
        nameservers = ["8.8.8.8", "4.4.4.4"]
    record = record.copy()
    new_record = OrderedDict()
    new_record["source"] = _get_ip_address_info(record["row"]["source_ip"],
                                                nameservers=nameservers,
                                                timeout=timeout)
    new_record["count"] = int(record["row"]["count"])
    policy_evaluated = record["row"]["policy_evaluated"].copy()
    new_policy_evaluated = OrderedDict([("disposition", "none"),
                                        ("dkim", "fail"),
                                        ("spf", "fail"),
                                        ("policy_override_reasons", [])
                                        ])
    if "disposition" in policy_evaluated:
        new_policy_evaluated["disposition"] = policy_evaluated["disposition"]
    if "dkim" in policy_evaluated:
        new_policy_evaluated["dkim"] = policy_evaluated["dkim"]
    if "spf" in policy_evaluated:
        new_policy_evaluated["spf"] = policy_evaluated["spf"]
    reasons = []
    if "reason" in policy_evaluated:
        if type(policy_evaluated["reason"]) == list:
            reasons = policy_evaluated["reason"]
        else:
            reasons = [policy_evaluated["reason"]]
    for reason in reasons:
        if "comment" not in reason:
            reason["comment"] = "none"
            reasons.append(reason)
    new_policy_evaluated["policy_override_reasons"] = reasons
    new_record["policy_evaluated"] = new_policy_evaluated
    new_record["identifiers"] = record["identifiers"].copy()
    new_record["auth_results"] = OrderedDict([("dkim", []), ("spf", [])])
    if record["auth_results"] is not None:
        auth_results = record["auth_results"].copy()
    else:
        auth_results = new_record["auth_results"].copy()
    if "dkim" in auth_results:
        if type(auth_results["dkim"]) != list:
            auth_results["dkim"] = [auth_results["dkim"]]
        for result in auth_results["dkim"]:
            if "domain" in result and result["domain"] is not None:
                new_result = OrderedDict([("domain", result["domain"])])
                if "selector" in result and result["selector"] is not None:
                    new_result["selector"] = result["selector"]
                else:
                    new_result["selector"] = "none"
                if "result" in result and result["result"] is not None:
                    new_result["result"] = result["result"]
                else:
                    new_result["result"] = "none"
                new_record["auth_results"]["dkim"].append(new_result)
    if type(auth_results["spf"]) != list:
        auth_results["spf"] = [auth_results["spf"]]
    for result in auth_results["spf"]:
        new_result = OrderedDict([("domain", result["domain"])])
        if "scope" in result and result["scope"] is not None:
            new_result["scope"] = result["scope"]
        else:
            new_result["scope"] = "mfrom"
        if "result" in result and result["result"] is not None:
            new_result["result"] = result["result"]
        else:
            new_result["result"] = "none"
        new_record["auth_results"]["spf"].append(new_result)

    if "envelope_from" not in new_record["identifiers"]:
        envelope_from = new_record["auth_results"]["spf"][-1]["domain"]
        if envelope_from is not None:
            envelope_from = str(envelope_from).lower()
        new_record["identifiers"]["envelope_from"] = envelope_from

    elif new_record["identifiers"]["envelope_from"] is None:
        envelope_from = new_record["auth_results"]["spf"][-1]["domain"]
        if envelope_from is not None:
            envelope_from = str(envelope_from).lower()
        new_record["identifiers"]["envelope_from"] = envelope_from

    envelope_to = None
    if "envelope_to" in new_record["identifiers"]:
        envelope_to = new_record["identifiers"]["envelope_to"]
        del new_record["identifiers"]["envelope_to"]

    new_record["identifiers"]["envelope_to"] = envelope_to

    return new_record


def parse_aggregate_report_xml(xml, nameservers=None, timeout=6.0):
    """Parses a DMARC XML report string and returns a consistent OrderedDict

    Args:
        xml (str): A string of DMARC aggregate report XML
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: The parsed aggregate DMARC report
    """
    try:
        report = xmltodict.parse(xml)["feedback"]
        report_metadata = report["report_metadata"]
        schema = "draft"
        if "version" in report:
            schema = report["version"]
        new_report = OrderedDict([("xml_schema", schema)])
        new_report_metadata = OrderedDict()
        org_name = _get_base_domain(report_metadata["org_name"])
        new_report_metadata["org_name"] = org_name
        new_report_metadata["org_email"] = report_metadata["email"]
        extra = None
        if "extra_contact_info" in report_metadata:
            extra = report_metadata["extra_contact_info"]
        new_report_metadata["org_extra_contact_info"] = extra
        new_report_metadata["report_id"] = report_metadata["report_id"]
        report_id = new_report_metadata["report_id"]
        report_id = report_id.replace("<",
                                      "").replace(">", "").split("@")[0]
        new_report_metadata["report_id"] = report_id
        date_range = report["report_metadata"]["date_range"]
        date_range["begin"] = _timestamp_to_human(date_range["begin"])
        date_range["end"] = _timestamp_to_human(date_range["end"])
        new_report_metadata["begin_date"] = date_range["begin"]
        new_report_metadata["end_date"] = date_range["end"]
        errors = []
        if "error" in report["report_metadata"]:
            if type(report["report_metadata"]["error"]) != list:
                errors = [report["report_metadata"]["error"]]
            else:
                errors = report["report_metadata"]["error"]
        new_report_metadata["errors"] = errors
        new_report["report_metadata"] = new_report_metadata
        records = []
        policy_published = report["policy_published"]
        new_policy_published = OrderedDict()
        new_policy_published["domain"] = policy_published["domain"]
        adkim = "r"
        if "adkim" in policy_published:
            if policy_published["adkim"] is not None:
                adkim = policy_published["adkim"]
        new_policy_published["adkim"] = adkim
        aspf = "r"
        if "aspf" in policy_published:
            if policy_published["aspf"] is not None:
                aspf = policy_published["aspf"]
        new_policy_published["aspf"] = aspf
        new_policy_published["p"] = policy_published["p"]
        sp = new_policy_published["p"]
        if "sp" in policy_published:
            if policy_published["sp"] is not None:
                sp = report["policy_published"]["sp"]
        new_policy_published["sp"] = sp
        pct = "100"
        if "pct" in policy_published:
            if policy_published["pct"] is not None:
                pct = report["policy_published"]["pct"]
        new_policy_published["pct"] = pct
        fo = "0"
        if "fo" in policy_published:
            if policy_published["fo"] is not None:
                fo = report["policy_published"]["fo"]
        new_policy_published["fo"] = fo
        new_report["policy_published"] = new_policy_published

        if type(report["record"]) == list:
            for record in report["record"]:
                records.append(_parse_report_record(record,
                                                    nameservers=nameservers,
                                                    timeout=timeout))

        else:
            records.append(_parse_report_record(report["record"],
                           nameservers=nameservers))

        new_report["records"] = records

        return new_report

    except expat.ExpatError as error:
        raise InvalidAggregateReport("Invalid XML: "
                                     "{0}".format(error.__str__()))

    except KeyError as error:
        raise InvalidAggregateReport("Missing field: "
                                     "{0}".format(error.__str__()))
    except AttributeError:
        raise InvalidAggregateReport("Report missing required section")

    except Exception as error:
        raise InvalidAggregateReport("Unexpected error: "
                                     "{0}".format(error.__str__()))


def extract_xml(input_):
    """
    Extracts xml from a zip or gzip file at the given path, file-like object,
    or bytes.

    Args:
        input_: A path to a file, a file like object, or bytes

    Returns:
        str: The extracted XML

    """
    if type(input_) == str:
        file_object = open(input_, "rb")
    elif type(input_) == bytes:
        file_object = BytesIO(input_)
    else:
        file_object = input_
    try:
        header = file_object.read(6)
        file_object.seek(0)
        if header.startswith(MAGIC_ZIP):
            _zip = zipfile.ZipFile(file_object)
            xml = _zip.open(_zip.namelist()[0]).read().decode()
        elif header.startswith(MAGIC_GZIP):
            xml = GzipFile(fileobj=file_object).read().decode()
        elif header.startswith(MAGIC_XML):
            xml = file_object.read().decode()
        else:
            file_object.close()
            raise InvalidAggregateReport("Not a valid zip, gzip, or xml file")

        file_object.close()

    except UnicodeDecodeError:
        raise InvalidAggregateReport("File objects must be opened in binary "
                                     "(rb) mode")
    except Exception as error:
        raise InvalidAggregateReport("Invalid archive file: "
                                     "{0}".format(error.__str__()))

    return xml


def parse_aggregate_report_file(_input, nameservers=None, timeout=6.0):
    """Parses a file at the given path, a file-like object. or bytes as a
    aggregate DMARC report

    Args:
        _input: A path to a file, a file like object, or bytes
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: The parsed DMARC aggregate report
    """
    xml = extract_xml(_input)

    return parse_aggregate_report_xml(xml,
                                      nameservers=nameservers,
                                      timeout=timeout)


def parsed_aggregate_reports_to_csv(reports):
    """
    Converts one or more parsed aggregate reports to flat CSV format, including
    headers

    Args:
        reports: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        str: Parsed aggregate report data in flat CSV format, including headers
    """

    def to_str(obj):
        return str(obj).lower()

    fields = ["xml_schema", "org_name", "org_email",
              "org_extra_contact_info", "report_id", "begin_date", "end_date",
              "errors", "domain", "adkim", "aspf", "p", "sp", "pct", "fo",
              "source_ip_address", "source_country", "source_reverse_dns",
              "source_base_domain", "count", "disposition", "dkim_alignment",
              "spf_alignment", "policy_override_reasons",
              "policy_override_comments", "envelope_from", "header_from",
              "envelope_to", "dkim_domains", "dkim_selectors", "dkim_results",
              "spf_domains", "spf_scopes", "spf_results"]

    csv_file_object = StringIO()
    writer = DictWriter(csv_file_object, fields)
    writer.writeheader()

    if type(reports) == OrderedDict:
        reports = [reports]

    for report in reports:
        xml_schema = report["xml_schema"]
        org_name = report["report_metadata"]["org_name"]
        org_email = report["report_metadata"]["org_email"]
        org_extra_contact = report["report_metadata"]["org_extra_contact_info"]
        report_id = report["report_metadata"]["report_id"]
        begin_date = report["report_metadata"]["begin_date"]
        end_date = report["report_metadata"]["end_date"]
        errors = "|".join(report["report_metadata"]["errors"])
        domain = report["policy_published"]["domain"]
        adkim = report["policy_published"]["adkim"]
        aspf = report["policy_published"]["aspf"]
        p = report["policy_published"]["p"]
        sp = report["policy_published"]["sp"]
        pct = report["policy_published"]["pct"]
        fo = report["policy_published"]["fo"]

        report_dict = dict(xml_schema=xml_schema, org_name=org_name,
                           org_email=org_email,
                           org_extra_contact_info=org_extra_contact,
                           report_id=report_id, begin_date=begin_date,
                           end_date=end_date, errors=errors, domain=domain,
                           adkim=adkim, aspf=aspf, p=p, sp=sp, pct=pct, fo=fo)

        for record in report["records"]:
            row = report_dict
            row["source_ip_address"] = record["source"]["ip_address"]
            row["source_country"] = record["source"]["country"]
            row["source_reverse_dns"] = record["source"]["reverse_dns"]
            row["source_base_domain"] = record["source"]["base_domain"]
            row["count"] = record["count"]
            row["disposition"] = record["policy_evaluated"]["disposition"]
            row["spf_alignment"] = record["policy_evaluated"]["spf"]
            row["dkim_alignment"] = record["policy_evaluated"]["dkim"]
            policy_override_reasons = list(map(lambda r: r["type"],
                                               record["policy_evaluated"]
                                               ["policy_override_reasons"]))
            policy_override_comments = list(map(lambda r: r["comment"],
                                                record["policy_evaluated"]
                                                ["policy_override_reasons"]))
            row["policy_override_reasons"] = ",".join(
                policy_override_reasons)
            row["policy_override_comments"] = "|".join(
                policy_override_comments)
            row["envelope_from"] = record["identifiers"]["envelope_from"]
            row["header_from"] = record["identifiers"]["header_from"]
            envelope_to = record["identifiers"]["envelope_to"]
            row["envelope_to"] = envelope_to
            dkim_domains = []
            dkim_selectors = []
            dkim_results = []
            for dkim_result in record["auth_results"]["dkim"]:
                dkim_domains.append(dkim_result["domain"])
                if "selector" in dkim_result:
                    dkim_selectors.append(dkim_result["selector"])
                dkim_results.append(dkim_result["result"])
            row["dkim_domains"] = ",".join(map(to_str, dkim_domains))
            row["dkim_selectors"] = ",".join(map(to_str, dkim_selectors))
            row["dkim_results"] = ",".join(map(to_str, dkim_results))
            spf_domains = []
            spf_scopes = []
            spf_results = []
            for spf_result in record["auth_results"]["spf"]:
                spf_domains.append(spf_result["domain"])
                spf_scopes.append(spf_result["scope"])
                spf_results.append(spf_result["result"])
            row["spf_domains"] = ",".join(map(to_str, spf_domains))
            row["spf_scopes"] = ",".join(map(to_str, spf_scopes))
            row["spf_results"] = ",".join(map(to_str, dkim_results))

            writer.writerow(row)
            csv_file_object.flush()

    return csv_file_object.getvalue()


def parse_forensic_report(feedback_report, sample, sample_headers_only,
                          nameservers=None, timeout=6.0):
    """
    Converts a DMARC forensic report and sample to a ``OrderedDict``

    Args:
        feedback_report (str): A message's feedback report as a string
        sample (str): The RFC 822 headers or RFC 822 message sample
        sample_headers_only (bool): Set true if the sample is only headers
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: An parsed report and sample
    """

    def convert_address(original_address):
        if original_address[0] == "":
            display_name = None
        else:
            display_name = original_address[0]
        address = original_address[1]

        return OrderedDict([("display_name", display_name),
                            ("address", address)])

    def get_filename_safe_subject(_subject):
        """
        Converts a message subject to a string that is safe for a filename
        Args:
            _subject (str): A message subject

        Returns:
            str: A string safe for a filename
        """
        invalid_filename_chars = ['\\', '/', ':', '"', '*', '?', '|', '\n',
                                  '\r']
        if _subject is None:
            _subject = "No Subject"
        for char in invalid_filename_chars:
            _subject = _subject.replace(char, "")
        _subject = _subject.rstrip(".")

        return _subject

    try:
        parsed_report = OrderedDict()
        report_values = feedback_report_regex.findall(feedback_report)
        for report_value in report_values:
            key = report_value[0].lower().replace("-", "_")
            parsed_report[key] = report_value[1]
            if key == "arrival_date":
                arrival_utc = dateparser.parse(parsed_report["arrival_date"],
                                               settings={"TO_TIMEZONE": "UTC"})
                arrival_utc = arrival_utc.strftime("%Y-%m-%d %H:%M:%S")
                parsed_report["arrival_date_utc"] = arrival_utc

        if "arrival_date_utc" not in parsed_report:
            raise InvalidForensicReport("Missing Arrival-Date")

        ip_address = parsed_report["source_ip"]
        parsed_report["source"] = _get_ip_address_info(ip_address,
                                                       nameservers=nameservers,
                                                       timeout=timeout)
        del parsed_report["source_ip"]

        if "identity_alignment" not in parsed_report:
            parsed_report["authentication_mechanisms"] = []
        elif parsed_report["identity_alignment"] == "none":
            parsed_report["authentication_mechanisms"] = []
            del parsed_report["identity_alignment"]
        else:
            auth_mechanisms = parsed_report["identity_alignment"]
            auth_mechanisms = auth_mechanisms.split(",")
            parsed_report["authentication_mechanisms"] = auth_mechanisms
            del parsed_report["identity_alignment"]

        if "auth_failure" not in parsed_report:
            parsed_report["auth_failure"] = "dmarc"
        auth_failure = parsed_report["auth_failure"].split(",")
        parsed_report["auth_failure"] = auth_failure

        optional_fields = ["original_envelope_id", "dkim_domain",
                           "original_mail_from", "original_rcpt_to"]
        for optional_field in optional_fields:
            if optional_field not in parsed_report:
                parsed_report[optional_field] = None

        parsed_mail = mailparser.parse_from_string(sample)
        parsed_headers = json.loads(parsed_mail.headers_json)
        parsed_message = json.loads(parsed_mail.mail_json)
        parsed_sample = OrderedDict([("headers", parsed_headers)])
        for key in parsed_message:
            parsed_sample[key] = parsed_message[key]

        parsed_sample["date"] = parsed_sample["date"].replace("T", " ")
        if "received" in parsed_message:
            for received in parsed_message["received"]:
                if "date_utc" in received:
                    received["date_utc"] = received["date_utc"].replace("T",
                                                                        " ")
        parsed_sample["from"] = convert_address(parsed_sample["from"][0])

        if "reply_to" in parsed_sample:
            parsed_sample["reply_to"] = list(map(lambda x: convert_address(x),
                                                 parsed_sample["reply_to"]))
        else:
            parsed_sample["reply_to"] = []

        if "to" in parsed_sample:
            parsed_sample["to"] = list(map(lambda x: convert_address(x),
                                           parsed_sample["to"]))
        else:
            parsed_sample["to"] = []

        if "cc" in parsed_sample:
            parsed_sample["cc"] = list(map(lambda x: convert_address(x),
                                           parsed_sample["cc"]))
        else:
            parsed_sample["cc"] = []

        if "bcc" in parsed_sample:
            parsed_sample["bcc"] = list(map(lambda x: convert_address(x),
                                            parsed_sample["bcc"]))
        else:
            parsed_sample["bcc"] = []

        if "delivered_to" in parsed_sample:
            parsed_sample["delivered_to"] = list(
                map(lambda x: convert_address(x),
                    parsed_sample["delivered_to"])
            )

        if "attachments" not in parsed_sample:
            parsed_sample["attachments"] = []

        if "subject" not in parsed_sample:
            parsed_sample["subject"] = None

        parsed_sample["filename_safe_subject"] = get_filename_safe_subject(
            parsed_sample["subject"])

        if "body" not in parsed_sample:
            parsed_sample["body"] = None

        if sample_headers_only and parsed_sample["has_defects"]:
            del parsed_sample["defects"]
            del parsed_sample["defects_categories"]
            del parsed_sample["has_defects"]
        parsed_report["sample_headers_only"] = sample_headers_only
        parsed_report["sample"] = sample
        parsed_report["parsed_sample"] = parsed_sample

        return parsed_report

    except KeyError as error:
        raise InvalidForensicReport("Missing value: {0}".format(
            error.__str__()))

    except Exception as error:
        raise InvalidForensicReport("Unexpected error: "
                                    "{0}".format(error.__str__()))


def parsed_forensic_reports_to_csv(reports):
    """
    Converts one or more parsed forensic reports to flat CSV format, including
    headers

    Args:
        reports: A parsed forensic report or list of parsed forensic reports

    Returns:
        str: Parsed forensic report data in flat CSV format, including headers
        """
    fields = ["feedback_type", "user_agent", "version", "original_envelope_id",
              "original_mail_from", "original_rcpt_to", "arrival_date",
              "arrival_date_utc", "subject", "message_id",
              "authentication_results", "dkim_domain", "source_ip_address",
              "source_country", "source_reverse_dns", "source_base_domain",
              "delivery_result", "auth_failure", "reported_domain",
              "authentication_mechanisms", "sample_headers_only"]

    if type(reports) == OrderedDict:
        reports = [reports]
    csv_file = StringIO()
    csv_writer = DictWriter(csv_file, fieldnames=fields)
    csv_writer.writeheader()
    for report in reports:
        row = report.copy()
        row["source_ip_address"] = report["source"]["ip_address"]
        row["source_reverse_dns"] = report["source"]["reverse_dns"]
        row["source_base_domain"] = report["source"]["base_domain"]
        row["source_country"] = report["source"]["country"]
        del row["source"]
        row["subject"] = report["parsed_sample"]["subject"]
        row["auth_failure"] = ",".join(report["auth_failure"])
        authentication_mechanisms = report["authentication_mechanisms"]
        row["authentication_mechanisms"] = ",".join(
            authentication_mechanisms)
        del row["sample"]
        del row["parsed_sample"]
        csv_writer.writerow(row)

    return csv_file.getvalue()


def parse_report_email(input_, nameservers=None, timeout=6.0):
    """
    Parses a DMARC report from an email

    Args:
        input_: An emailed DMARC report in RFC 822 format, as bytes or a string
        nameservers (list): A list of one or more nameservers to use
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict:
        * ``report_type``: ``aggregate`` or ``forensic``
        * ``report``: The parsed report
    """

    def is_outlook_msg(suspect_bytes):
        """Checks if the given content is a Outlook msg OLE file"""
        return suspect_bytes.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")

    def convert_outlook_msg(msg_bytes):
        """
        Uses the ``msgconvert`` Perl utility to convert an Outlook MS file to
        standard RFC 822 format

        Args:
            msg_bytes (bytes): the content of the .msg file

        Returns:
            A RFC 822 string
        """
        if not is_outlook_msg(msg_bytes):
            raise ValueError("The supplied bytes are not an Outlook MSG file")
        orig_dir = os.getcwd()
        tmp_dir = tempfile.mkdtemp()
        os.chdir(tmp_dir)
        with open("sample.msg", "wb") as msg_file:
            msg_file.write(msg_bytes)
        try:
            subprocess.check_call(["msgconvert", "sample.msg"])
            eml_path = "sample.eml"
            with open(eml_path, "rb") as eml_file:
                rfc822 = eml_file.read()
        except FileNotFoundError:
            raise FileNotFoundError(
                "msgconvert not found. Please ensure it is installed\n"
                "sudo apt install libemail-outlook-message-perl\n"
                "https://github.com/mvz/email-outlook-message-perl")
        finally:
            os.chdir(orig_dir)
            shutil.rmtree(tmp_dir)

        return rfc822

    def decode_header(header):
        """Decodes a RFC 822 email header"""
        header = header.replace("\r", "").replace("\n", "")
        decoded_header = email.header.decode_header(header)
        header = ""
        for header_part in decoded_header:
            if type(header_part[0]) == bytes:
                encoding = header_part[1] or "ascii"
                header_part = header_part[0].decode(encoding=encoding,
                                                    errors="replace")
            else:
                header_part = header_part[0]
            header += header_part
        header = header.replace("\r", " ").replace("\n", " ")

        return header

    if type(input_) == bytes:
        if is_outlook_msg(input_):
            input_ = convert_outlook_msg(input_)
        input_ = input_.decode("utf-8", errors="replace")
    result = None
    msg = email.message_from_string(input_)
    subject = None
    feedback_report = None
    sample_headers_only = False
    sample = None
    if "subject" in msg:
        subject = decode_header(msg["subject"])
    for part in msg.walk():
        content_type = part.get_content_type()
        payload = part.get_payload()
        if type(payload) == list:
            payload = payload[0].__str__()
        if content_type == "message/feedback-report":
            try:
                if "Feedback-Type" in payload:
                    feedback_report = payload
                else:
                    feedback_report = b64decode(payload).__str__()
                feedback_report = feedback_report.lstrip("b'").rstrip("'")
                feedback_report = feedback_report.replace("\\r", "")
                feedback_report = feedback_report.replace("\\n", "\n")
            except (ValueError, TypeError, binascii.Error):
                feedback_report = payload

        elif content_type == "text/rfc822-headers":
            sample = payload
            sample_headers_only = True
        elif content_type == "message/rfc822":
            sample = payload
            sample_headers_only = False
        if feedback_report and sample:
            forensic_report = parse_forensic_report(feedback_report,
                                                    sample,
                                                    sample_headers_only,
                                                    nameservers=nameservers,
                                                    timeout=timeout)

            result = OrderedDict([("report_type", "forensic"),
                                  ("report", forensic_report)])
            return result
        try:
            payload = b64decode(payload)
            if payload.startswith(MAGIC_ZIP) or \
                    payload.startswith(MAGIC_GZIP) or \
                    payload.startswith(MAGIC_XML):
                ns = nameservers
                aggregate_report = parse_aggregate_report_file(payload,
                                                               nameservers=ns,
                                                               timeout=timeout)
                result = OrderedDict([("report_type", "aggregate"),
                                      ("report", aggregate_report)])
        except (TypeError, ValueError, binascii.Error):
            pass

        except InvalidAggregateReport as e:
            error = 'Message with subject "{0}" ' \
                    'is not a valid ' \
                    'aggregate DMARC report: {1}'.format(subject, e)
            raise InvalidAggregateReport(error)

        except InvalidForensicReport as e:
            error = 'Message with subject "{0}" ' \
                    'is not a valid ' \
                    'forensic DMARC report: {1}'.format(subject, e)
            raise InvalidForensicReport(error)

        except FileNotFoundError as e:
            error = 'Unable to parse message with subject "{0}": {1}' .format(
                subject, e)
            raise InvalidDMARCReport(error)

    if result is None:
        error = 'Message with subject "{0}" is ' \
                'not a valid DMARC report'.format(subject)
        raise InvalidDMARCReport(error)

    return result


def parse_report_file(input_, nameservers=None, timeout=6.0):
    """Parses a DMARC aggregate or forensic file at the given path, a
    file-like object. or bytes

    Args:
        input_: A path to a file, a file like object, or bytes
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: The parsed DMARC report
    """
    if type(input_) == str:
        file_object = open(input_, "rb")
    elif type(input_) == bytes:
        file_object = BytesIO(input_)
    else:
        file_object = input_

    content = file_object.read()
    try:
        report = parse_aggregate_report_file(content, nameservers=nameservers,
                                             timeout=timeout)
        results = OrderedDict([("report_type", "aggregate"),
                               ("report", report)])
    except InvalidAggregateReport:
        try:
            results = parse_report_email(content,
                                         nameservers=nameservers,
                                         timeout=timeout)
        except InvalidDMARCReport:
            raise InvalidDMARCReport("Not a valid aggregate or forensic "
                                     "report")
    return results


def get_imap_capabilities(server):
    """
    Returns a list of an IMAP server's capabilities

    Args:
        server (imapclient.IMAPClient): An instance of imapclient.IMAPClient

    Returns (list): A list of capabilities
    """

    capabilities = list(map(str, list(server.capabilities())))
    for i in range(len(capabilities)):
        capabilities[i] = str(capabilities[i]).replace("b'",
                                                       "").replace("'",
                                                                   "")
    logger.debug("IMAP server supports: {0}".format(capabilities))

    return capabilities


def get_dmarc_reports_from_inbox(host=None, user=None, password=None,
                                 connection=None,
                                 move_supported=None,
                                 reports_folder="INBOX",
                                 archive_folder="Archive",
                                 delete=False, test=False,
                                 nameservers=None,
                                 dns_timeout=6.0):
    """
    Fetches and parses DMARC reports from sn inbox

    Args:
        host: The mail server hostname or IP address
        user: The mail server user
        password: The mail server password
        connection: An IMAPCLient connection to reuse
        move_supported: Indicate if the IMAP server supports the MOVE command
        (autodetect if None)
        reports_folder: The IMAP folder where reports can be found
        archive_folder: The folder to move processed mail to
        delete (bool): Delete  messages after processing them
        test (bool): Do not move or delete messages after processing them
        nameservers (list): A list of DNS nameservers to query
        dns_timeout (float): Set the DNS query timeout

    Returns:
        OrderedDict: Lists of ``aggregate_reports`` and ``forensic_reports``
    """

    def chunks(l, n):
        """Yield successive n-sized chunks from l."""
        for i in range(0, len(l), n):
            yield l[i:i + n]

    if delete and test:
        raise ValueError("delete and test options are mutually exclusive")

    if connection is None and (user is None or password is None):
        raise ValueError("Must supply a connection, or a username and "
                         "password")

    aggregate_reports = []
    forensic_reports = []
    aggregate_report_msg_uids = []
    forensic_report_msg_uids = []
    aggregate_reports_folder = "{0}/Aggregate".format(archive_folder)
    forensic_reports_folder = "{0}/Forensic".format(archive_folder)
    invalid_reports_folder = "{0}/Invalid".format(archive_folder)

    try:
        if connection:
            server = connection
        else:
            server = imapclient.IMAPClient(host, use_uid=True)
            server.login(user, password)

        if move_supported is not None:
            server_capabilities = get_imap_capabilities(server)
            move_supported = "MOVE" in server_capabilities

        def delete_messages(msg_uids):
            if type(msg_uids) == str:
                msg_uids = [msg_uids]

            server.add_flags(msg_uids, [imapclient.DELETED])
            server.expunge()

        def move_messages(msg_uids, folder):
            if type(msg_uids) == str:
                msg_uids = [msg_uids]
            for chunk in chunks(msg_uids, 100):
                if move_supported:
                    server.move(chunk, folder)
                else:
                    server.copy(msg_uids, folder)
                    delete_messages(msg_uids)

        if not server.folder_exists(archive_folder):
            server.create_folder(archive_folder)
        try:
            # Test subfolder creation
            if not server.folder_exists(aggregate_reports_folder):
                server.create_folder(aggregate_reports_folder)
        except imapclient.exceptions.IMAPClientError:
            #  Only replace / with . when . doesn't work
            # This usually indicates a dovecot IMAP server
            aggregate_reports_folder = aggregate_reports_folder.replace("/",
                                                                        ".")
            forensic_reports_folder = forensic_reports_folder.replace("/",
                                                                      ".")

        if not server.folder_exists(aggregate_reports_folder):
            server.create_folder(aggregate_reports_folder)
        if not server.folder_exists(forensic_reports_folder):
            server.create_folder(forensic_reports_folder)
        if not server.folder_exists(invalid_reports_folder):
            server.create_folder(invalid_reports_folder)
        server.select_folder(reports_folder)
        messages = server.search()
        for message_uid in messages:
            raw_msg = server.fetch(message_uid,
                                   ["RFC822"])[message_uid][b"RFC822"]
            msg_content = raw_msg.decode("utf-8", errors="replace")

            try:
                parsed_email = parse_report_email(msg_content,
                                                  nameservers=nameservers,
                                                  timeout=dns_timeout)
                if parsed_email["report_type"] == "aggregate":
                    aggregate_reports.append(parsed_email["report"])
                    aggregate_report_msg_uids.append(message_uid)
                elif parsed_email["report_type"] == "forensic":
                    forensic_reports.append(parsed_email["report"])
                    forensic_report_msg_uids.append(message_uid)
            except InvalidDMARCReport as error:
                logger.warning(error.__str__())
                if not test:
                    if delete:
                        delete_messages([message_uid])
                    else:
                        move_messages([message_uid], invalid_reports_folder)
            if not test:
                if delete:
                    processed_messages = aggregate_report_msg_uids + \
                                         forensic_report_msg_uids
                    delete_messages(processed_messages)
                else:
                    if len(aggregate_report_msg_uids) > 0:
                        move_messages(aggregate_report_msg_uids,
                                      aggregate_reports_folder)
                    if len(forensic_report_msg_uids) > 0:
                        move_messages(forensic_report_msg_uids,
                                      forensic_reports_folder)

        results = OrderedDict([("aggregate_reports", aggregate_reports),
                               ("forensic_reports", forensic_reports)])

        return results
    except imapclient.exceptions.IMAPClientError as error:
        error = error.__str__().lstrip("b'").rstrip("'").rstrip(".")
        raise IMAPError(error)
    except socket.gaierror:
        raise IMAPError("DNS resolution failed")
    except ConnectionRefusedError:
        raise IMAPError("Connection refused")
    except ConnectionResetError:
        raise IMAPError("Connection reset")
    except ConnectionAbortedError:
        raise IMAPError("Connection aborted")
    except TimeoutError:
        raise IMAPError("Connection timed out")
    except ssl.SSLError as error:
        raise IMAPError("SSL error: {0}".format(error.__str__()))
    except ssl.CertificateError as error:
        raise IMAPError("Certificate error: {0}".format(error.__str__()))


def save_output(results, output_directory="output"):
    """
    Save report data in the given directory

    Args:
        results (OrderedDict): Parsing results
        output_directory: The patch to the directory to save in
    """

    aggregate_reports = results["aggregate_reports"]
    forensic_reports = results["forensic_reports"]

    if os.path.exists(output_directory):
        if not os.path.isdir(output_directory):
            raise ValueError("{0} is not a directory".format(output_directory))
    else:
        os.makedirs(output_directory)

    with open("{0}".format(os.path.join(output_directory, "aggregate.json")),
              "w", newline="\n", encoding="utf-8") as agg_json:
        agg_json.write(json.dumps(aggregate_reports, ensure_ascii=False,
                                  indent=2))

    with open("{0}".format(os.path.join(output_directory, "aggregate.csv")),
              "w", newline="\n", encoding="utf-8") as agg_csv:
        csv = parsed_aggregate_reports_to_csv(aggregate_reports)
        agg_csv.write(csv)

    with open("{0}".format(os.path.join(output_directory, "forensic.json")),
              "w", newline="\n", encoding="utf-8") as for_json:
        for_json.write(json.dumps(forensic_reports, ensure_ascii=False,
                                  indent=2))

    with open("{0}".format(os.path.join(output_directory, "forensic.csv")),
              "w", newline="\n", encoding="utf-8") as for_csv:
        csv = parsed_forensic_reports_to_csv(forensic_reports)
        for_csv.write(csv)

    samples_directory = os.path.join(output_directory, "samples")
    if not os.path.exists(samples_directory):
        os.makedirs(samples_directory)

    sample_filenames = []
    for forensic_report in forensic_reports:
        sample = forensic_report["sample"]
        message_count = 0
        parsed_sample = forensic_report["parsed_sample"]
        subject = parsed_sample["filename_safe_subject"]
        filename = subject

        while filename in sample_filenames:
            message_count += 1
            filename = "{0} ({1})".format(subject, message_count)

        sample_filenames.append(filename)

        filename = "{0}.eml".format(filename)
        path = os.path.join(samples_directory, filename)
        with open(path, "w", newline="\n", encoding="utf-8") as sample_file:
            sample_file.write(sample)


def get_report_zip(results):
    """
    Creates a zip file of parsed report output

    Args:
        results (OrderedDict): The parsed results

    Returns:
        bytes: zip file bytes
    """
    def add_subdir(root_path, subdir):
        subdir_path = os.path.join(root_path, subdir)
        for subdir_root, subdir_dirs, subdir_files in os.walk(subdir_path):
            for subdir_file in subdir_files:
                subdir_file_path = os.path.join(root_path, subdir, subdir_file)
                if os.path.isfile(subdir_file_path):
                    rel_path = os.path.relpath(subdir_root, subdir_file_path)
                    subdir_arc_name = os.path.join(rel_path, subdir_file)
                    zip_file.write(subdir_file_path, subdir_arc_name)
            for subdir in subdir_dirs:
                add_subdir(subdir_path, subdir)

    storage = BytesIO()
    tmp_dir = tempfile.mkdtemp()
    try:
        save_output(results, tmp_dir)
        with zipfile.ZipFile(storage, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(tmp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        arcname = os.path.join(os.path.relpath(root, tmp_dir),
                                               file)
                        zip_file.write(file_path, arcname)
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    if os.path.isdir(dir_path):
                        zip_file.write(dir_path, directory)
                        add_subdir(root, directory)
    finally:
        shutil.rmtree(tmp_dir)

    return storage.getvalue()


def email_results(results, host, mail_from, mail_to, port=0, starttls=True,
                  use_ssl=False, user=None, password=None, subject=None,
                  attachment_filename=None, message=None, ssl_context=None):
    """
    Emails parsing results as a zip file

    Args:
        results (OrderedDict): Parsing results
        host: Mail server hostname or IP address
        mail_from: The value of the message from header
        mail_to : A list of addresses to mail to
        port (int): Port to use
        starttls (bool): use STARTTLS
        use_ssl (bool): Require a SSL connection from the start
        user: An optional username
        password: An optional password
        subject: Overrides the default message subject
        attachment_filename: Override the default attachment filename
        message: Override the default plain text body
        ssl_context: SSL context options
    """
    date_string = datetime.now().strftime("%Y-%m-%d")
    if attachment_filename:
        if not attachment_filename.lower().endswith(".zip"):
            attachment_filename += ".zip"
        filename = attachment_filename
    else:
        filename = "DMARC-{0}.zip".format(date_string)

    assert isinstance(mail_to, list)

    msg = MIMEMultipart()
    msg['From'] = mail_from
    msg['To'] = ", ".join(mail_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject or "DMARC results for {0}".format(date_string)
    text = message or "Please see the attached zip file\n"

    msg.attach(MIMEText(text))

    zip_bytes = get_report_zip(results)
    part = MIMEApplication(zip_bytes, Name=filename)

    part['Content-Disposition'] = 'attachment; filename="{0}"'.format(filename)
    msg.attach(part)

    try:
        if ssl_context is None:
            ssl_context = ssl.create_default_context()
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port=port, context=ssl_context)
            server.helo()
        else:
            server = smtplib.SMTP(host, port=port)
            server.ehlo()
            if starttls:
                server.starttls(context=ssl_context)
                server.helo()
        if user and password:
            server.login(user, password)
        server.sendmail(mail_from, mail_to, msg.as_string())
    except smtplib.SMTPException as error:
        error = error.__str__().lstrip("b'").rstrip("'").rstrip(".")
        raise SMTPError(error)
    except socket.gaierror:
        raise SMTPError("DNS resolution failed")
    except ConnectionRefusedError:
        raise SMTPError("Connection refused")
    except ConnectionResetError:
        raise SMTPError("Connection reset")
    except ConnectionAbortedError:
        raise SMTPError("Connection aborted")
    except TimeoutError:
        raise SMTPError("Connection timed out")
    except ssl.SSLError as error:
        raise SMTPError("SSL error: {0}".format(error.__str__()))
    except ssl.CertificateError as error:
        raise SMTPError("Certificate error: {0}".format(error.__str__()))


def watch_inbox(host, username, password, callback, reports_folder="INBOX",
                archive_folder="Archive", delete=False, test=False, wait=30,
                nameservers=None, dns_timeout=6.0):
    """
    Use an IDLE IMAP connection to parse incoming emails, and pass the results
    to a callback function

    Args:
        host: The mail server hostname or IP address
        username: The mail server username
        password: The mail server password
        callback: The callback function to receive the parsing results
        reports_folder: The IMAP folder where reports can be found
        archive_folder: The folder to move processed mail to
        delete (bool): Delete  messages after processing them
        test (bool): Do not move or delete messages after processing them
        wait (int): Number of seconds to wait for a IMAP IDLE response
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Set the DNS query timeout
    """
    rf = reports_folder
    af = archive_folder
    ns = nameservers
    dt = dns_timeout
    server = imapclient.IMAPClient(host)

    try:
        server.login(username, password)
        imap_capabilities = get_imap_capabilities(server)
        if "IDLE" not in imap_capabilities:
            raise IMAPError("Cannot watch inbox: IMAP server does not support "
                            "the IDLE command")

        ms = "MOVE" in imap_capabilities
        server.select_folder(rf)
        idle_start_time = time.monotonic()
        server.idle()

    except imapclient.exceptions.IMAPClientError as error:
        error = error.__str__().lstrip("b'").rstrip("'").rstrip(".")
        raise IMAPError(error)
    except socket.gaierror:
        raise IMAPError("DNS resolution failed")
    except ConnectionRefusedError:
        raise IMAPError("Connection refused")
    except ConnectionResetError:
        raise IMAPError("Connection reset")
    except ConnectionAbortedError:
        raise IMAPError("Connection aborted")
    except TimeoutError:
        raise IMAPError("Connection timed out")
    except ssl.SSLError as error:
        raise IMAPError("SSL error: {0}".format(error.__str__()))
    except ssl.CertificateError as error:
        raise IMAPError("Certificate error: {0}".format(error.__str__()))
    except BrokenPipeError:
        logger.debug("IMAP error: Broken pipe")
        logger.debug("Reconnecting watcher")
        server = imapclient.IMAPClient(host)
        server.select_folder(rf)
        idle_start_time = time.monotonic()
        ms = "MOVE" in get_imap_capabilities(server)
        res = get_dmarc_reports_from_inbox(connection=server,
                                           move_supported=ms,
                                           reports_folder=rf,
                                           archive_folder=af,
                                           delete=delete,
                                           test=test,
                                           nameservers=ns,
                                           dns_timeout=dt)
        callback(res)
        server.idle()

    while True:
        try:
            # Refresh the IDLE session every 5 minutes to stay connected
            if time.monotonic() - idle_start_time > 5 * 60:
                logger.debug("IMAP: Refreshing IDLE session")
                server.idle_done()
                server.idle()
                idle_start_time = time.monotonic()
            responses = server.idle_check(timeout=wait)
            if responses is not None:
                for response in responses:
                    if response[1] == b'RECENT' and response[0] > 0:
                        server.idle_done()
                        res = get_dmarc_reports_from_inbox(connection=server,
                                                           move_supported=ms,
                                                           reports_folder=rf,
                                                           archive_folder=af,
                                                           delete=delete,
                                                           test=test,
                                                           nameservers=ns,
                                                           dns_timeout=dt)
                        callback(res)
                        server.idle()
                        idle_start_time = time.monotonic()
                        break
        except imapclient.exceptions.IMAPClientError as error:
            error = error.__str__().lstrip("b'").rstrip("'").rstrip(".")
            raise IMAPError(error)
        except socket.gaierror:
            raise IMAPError("DNS resolution failed")
        except ConnectionRefusedError:
            raise IMAPError("Connection refused")
        except ConnectionResetError:
            raise IMAPError("Connection reset")
        except ConnectionAbortedError:
            raise IMAPError("Connection aborted")
        except TimeoutError:
            raise IMAPError("Connection timed out")
        except ssl.SSLError as error:
            raise IMAPError("SSL error: {0}".format(error.__str__()))
        except ssl.CertificateError as error:
            raise IMAPError("Certificate error: {0}".format(error.__str__()))
        except BrokenPipeError:
            logger.debug("IMAP error: Broken pipe")
            logger.debug("Reconnecting watcher")
            server = imapclient.IMAPClient(host)
            server.select_folder(rf)
            idle_start_time = time.monotonic()
            res = get_dmarc_reports_from_inbox(connection=server,
                                               move_supported=ms,
                                               reports_folder=rf,
                                               archive_folder=af,
                                               delete=delete,
                                               test=test,
                                               nameservers=ns,
                                               dns_timeout=dt)
            callback(res)
            server.idle()
        except KeyboardInterrupt:
            break

    try:
        server.idle_done()
        server.logout()
    except BrokenPipeError:
        pass
