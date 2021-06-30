# -*- coding: utf-8 -*-

"""A Python package for parsing DMARC reports"""

import logging
import os
import shutil
import xml.parsers.expat as expat
import json
from datetime import datetime
from time import sleep
from collections import OrderedDict
from io import BytesIO, StringIO
from gzip import GzipFile
from socket import timeout
import zipfile
from csv import DictWriter
import re
from base64 import b64decode
import binascii
import email
import tempfile
import email.utils
import mailbox

import mailparser
from expiringdict import ExpiringDict
import xmltodict
from lxml import etree
from mailsuite.imap import IMAPClient
from mailsuite.smtp import send_email
from imapclient.exceptions import IMAPClientError

from parsedmarc.utils import get_base_domain, get_ip_address_info
from parsedmarc.utils import is_outlook_msg, convert_outlook_msg
from parsedmarc.utils import timestamp_to_human, human_timestamp_to_datetime
from parsedmarc.utils import parse_email

__version__ = "7.0.1"

logging.basicConfig(
    format='%(levelname)8s:%(filename)s:%(lineno)d:'
           '%(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S')

logger = logging.getLogger("parsedmarc")
logger.debug("parsedmarc v{0}".format(__version__))

feedback_report_regex = re.compile(r"^([\w\-]+): (.+)$", re.MULTILINE)
xml_header_regex = re.compile(r"^<\?xml .*?>", re.MULTILINE)
xml_schema_regex = re.compile(r"</??xs:schema.*>", re.MULTILINE)

MAGIC_ZIP = b"\x50\x4B\x03\x04"
MAGIC_GZIP = b"\x1F\x8B"
MAGIC_XML = b"\x3c\x3f\x78\x6d\x6c\x20"

IP_ADDRESS_CACHE = ExpiringDict(max_len=10000, max_age_seconds=1800)


class ParserError(RuntimeError):
    """Raised whenever the parser fails for some reason"""


class InvalidDMARCReport(ParserError):
    """Raised when an invalid DMARC report is encountered"""


class InvalidAggregateReport(InvalidDMARCReport):
    """Raised when an invalid DMARC aggregate report is encountered"""


class InvalidForensicReport(InvalidDMARCReport):
    """Raised when an invalid DMARC forensic report is encountered"""


def _parse_report_record(record, offline=False, nameservers=None,
                         dns_timeout=2.0, parallel=False):
    """
    Converts a record from a DMARC aggregate report into a more consistent
    format

    Args:
        record (OrderedDict): The record to convert
        offline (bool): Do not query online for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: The converted record
    """
    record = record.copy()
    new_record = OrderedDict()
    new_record_source = get_ip_address_info(record["row"]["source_ip"],
                                            cache=IP_ADDRESS_CACHE,
                                            offline=offline,
                                            nameservers=nameservers,
                                            timeout=dns_timeout,
                                            parallel=parallel)
    new_record["source"] = new_record_source
    new_record["count"] = int(record["row"]["count"])
    policy_evaluated = record["row"]["policy_evaluated"].copy()
    new_policy_evaluated = OrderedDict([("disposition", "none"),
                                        ("dkim", "fail"),
                                        ("spf", "fail"),
                                        ("policy_override_reasons", [])
                                        ])
    if "disposition" in policy_evaluated:
        new_policy_evaluated["disposition"] = policy_evaluated["disposition"]
        if new_policy_evaluated["disposition"].strip().lower() == "pass":
            new_policy_evaluated["disposition"] = "none"
    if "dkim" in policy_evaluated:
        new_policy_evaluated["dkim"] = policy_evaluated["dkim"]
    if "spf" in policy_evaluated:
        new_policy_evaluated["spf"] = policy_evaluated["spf"]
    reasons = []
    spf_aligned = policy_evaluated["spf"] is not None and policy_evaluated[
        "spf"].lower() == "pass"
    dkim_aligned = policy_evaluated["dkim"] is not None and policy_evaluated[
        "dkim"].lower() == "pass"
    dmarc_aligned = spf_aligned or dkim_aligned
    new_record["alignment"] = dict()
    new_record["alignment"]["spf"] = spf_aligned
    new_record["alignment"]["dkim"] = dkim_aligned
    new_record["alignment"]["dmarc"] = dmarc_aligned
    if "reason" in policy_evaluated:
        if type(policy_evaluated["reason"]) == list:
            reasons = policy_evaluated["reason"]
        else:
            reasons = [policy_evaluated["reason"]]
    for reason in reasons:
        if "comment" not in reason:
            reason["comment"] = None
    new_policy_evaluated["policy_override_reasons"] = reasons
    new_record["policy_evaluated"] = new_policy_evaluated
    new_record["identifiers"] = record["identifiers"].copy()
    new_record["auth_results"] = OrderedDict([("dkim", []), ("spf", [])])
    if type(new_record["identifiers"]["header_from"]) == str:
        lowered_from = new_record["identifiers"]["header_from"].lower()
    else:
        lowered_from = ''
    new_record["identifiers"]["header_from"] = lowered_from
    if record["auth_results"] is not None:
        auth_results = record["auth_results"].copy()
        if "spf" not in auth_results:
            auth_results["spf"] = []
        if "dkim" not in auth_results:
            auth_results["dkim"] = []
    else:
        auth_results = new_record["auth_results"].copy()

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
        envelope_from = None
        if len(auth_results["spf"]) > 0:
            envelope_from = new_record["auth_results"]["spf"][-1]["domain"]
        if envelope_from is not None:
            envelope_from = str(envelope_from).lower()
        new_record["identifiers"]["envelope_from"] = envelope_from

    elif new_record["identifiers"]["envelope_from"] is None:
        if len(auth_results["spf"]) > 0:
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


def parse_aggregate_report_xml(xml, offline=False, nameservers=None,
                               timeout=2.0, parallel=False, server=None):
    """Parses a DMARC XML report string and returns a consistent OrderedDict

    Args:
        xml (str): A string of DMARC aggregate report XML
        offline (bool): Do not query online for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds
        parallel (bool): Parallel processing
        server (IMAPClient): Connection object

    Returns:
        OrderedDict: The parsed aggregate DMARC report
    """
    errors = []
    # Parse XML and recover from errors
    try:
        xmltodict.parse(xml)["feedback"]
    except Exception as e:
        errors.append("Invalid XML: {0}".format(e.__str__()))
        tree = etree.parse(BytesIO(xml.encode('utf-8')),
                           etree.XMLParser(recover=True))
        s = etree.tostring(tree)
        xml = '' if s is None else s.decode('utf-8')

    try:
        # Replace XML header (sometimes they are invalid)
        xml = xml_header_regex.sub("<?xml version=\"1.0\"?>", xml)

        # Remove invalid schema tags
        xml = xml_schema_regex.sub('', xml)

        report = xmltodict.parse(xml)["feedback"]
        report_metadata = report["report_metadata"]
        schema = "draft"
        if "version" in report:
            schema = report["version"]
        new_report = OrderedDict([("xml_schema", schema)])
        new_report_metadata = OrderedDict()
        if report_metadata["org_name"] is None:
            if report_metadata["email"] is not None:
                report_metadata["org_name"] = report_metadata[
                    "email"].split("@")[-1]
        org_name = report_metadata["org_name"]
        if org_name is not None and " " not in org_name:
            org_name = get_base_domain(org_name)
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
        date_range["begin"] = timestamp_to_human(date_range["begin"])
        date_range["end"] = timestamp_to_human(date_range["end"])
        new_report_metadata["begin_date"] = date_range["begin"]
        new_report_metadata["end_date"] = date_range["end"]
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
            for i in range(len(report["record"])):
                if server is not None and i > 0 and i % 20 == 0:
                    logger.debug("Sending noop cmd")
                    server.noop()
                    logger.debug("Processed {0}/{1}".format(
                        i, len(report["record"])))
                report_record = _parse_report_record(report["record"][i],
                                                     offline=offline,
                                                     nameservers=nameservers,
                                                     dns_timeout=timeout,
                                                     parallel=parallel)
                records.append(report_record)

        else:
            report_record = _parse_report_record(report["record"],
                                                 offline=offline,
                                                 nameservers=nameservers,
                                                 dns_timeout=timeout,
                                                 parallel=parallel)
            records.append(report_record)

        new_report["records"] = records

        return new_report

    except expat.ExpatError as error:
        raise InvalidAggregateReport(
            "Invalid XML: {0}".format(error.__str__()))

    except KeyError as error:
        raise InvalidAggregateReport(
            "Missing field: {0}".format(error.__str__()))
    except AttributeError:
        raise InvalidAggregateReport("Report missing required section")

    except Exception as error:
        raise InvalidAggregateReport(
            "Unexpected error: {0}".format(error.__str__()))


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
            xml = _zip.open(_zip.namelist()[0]).read().decode(errors='ignore')
        elif header.startswith(MAGIC_GZIP):
            xml = GzipFile(fileobj=file_object).read().decode(errors='ignore')
        elif header.startswith(MAGIC_XML):
            xml = file_object.read().decode(errors='ignore')
        else:
            file_object.close()
            raise InvalidAggregateReport("Not a valid zip, gzip, or xml file")

        file_object.close()

    except UnicodeDecodeError:
        raise InvalidAggregateReport("File objects must be opened in binary "
                                     "(rb) mode")
    except Exception as error:
        raise InvalidAggregateReport(
            "Invalid archive file: {0}".format(error.__str__()))

    return xml


def parse_aggregate_report_file(_input, offline=False, nameservers=None,
                                dns_timeout=2.0,
                                parallel=False,
                                server=None):
    """Parses a file at the given path, a file-like object. or bytes as a
    aggregate DMARC report

    Args:
        _input: A path to a file, a file like object, or bytes
        offline (bool): Do not query online for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        parallel (bool): Parallel processing
        server (IMAPClient): Connection object

    Returns:
        OrderedDict: The parsed DMARC aggregate report
    """
    xml = extract_xml(_input)

    return parse_aggregate_report_xml(xml,
                                      offline=offline,
                                      nameservers=nameservers,
                                      timeout=dns_timeout,
                                      parallel=parallel,
                                      server=server)


def parsed_aggregate_reports_to_csv_rows(reports):
    """
    Converts one or more parsed aggregate reports to list of dicts in flat CSV
    format

    Args:
        reports: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        list: Parsed aggregate report data as a list of dicts in flat CSV
        format
    """

    def to_str(obj):
        return str(obj).lower()

    if type(reports) == OrderedDict:
        reports = [reports]

    rows = []

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
            row = report_dict.copy()
            row["source_ip_address"] = record["source"]["ip_address"]
            row["source_country"] = record["source"]["country"]
            row["source_reverse_dns"] = record["source"]["reverse_dns"]
            row["source_base_domain"] = record["source"]["base_domain"]
            row["count"] = record["count"]
            row["spf_aligned"] = record["alignment"]["spf"]
            row["dkim_aligned"] = record["alignment"]["dkim"]
            row["dmarc_aligned"] = record["alignment"]["dmarc"]
            row["disposition"] = record["policy_evaluated"]["disposition"]
            policy_override_reasons = list(map(
                lambda r: r["type"],
                record["policy_evaluated"]
                ["policy_override_reasons"]))
            policy_override_comments = list(map(
                lambda r: r["comment"] or "none",
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
            row["spf_results"] = ",".join(map(to_str, spf_results))
            rows.append(row)

    for r in rows:
        for k, v in r.items():
            if type(v) not in [str, int, bool]:
                r[k] = ''

    return rows


def parsed_aggregate_reports_to_csv(reports):
    """
    Converts one or more parsed aggregate reports to flat CSV format, including
    headers

    Args:
        reports: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        str: Parsed aggregate report data in flat CSV format, including headers
    """

    fields = ["xml_schema", "org_name", "org_email",
              "org_extra_contact_info", "report_id", "begin_date", "end_date",
              "errors", "domain", "adkim", "aspf", "p", "sp", "pct", "fo",
              "source_ip_address", "source_country", "source_reverse_dns",
              "source_base_domain", "count", "spf_aligned",
              "dkim_aligned", "dmarc_aligned", "disposition",
              "policy_override_reasons",  "policy_override_comments",
              "envelope_from", "header_from",
              "envelope_to", "dkim_domains", "dkim_selectors", "dkim_results",
              "spf_domains", "spf_scopes", "spf_results"]

    csv_file_object = StringIO(newline="\n")
    writer = DictWriter(csv_file_object, fields)
    writer.writeheader()

    rows = parsed_aggregate_reports_to_csv_rows(reports)

    for row in rows:
        writer.writerow(row)
        csv_file_object.flush()

    return csv_file_object.getvalue()


def parse_forensic_report(feedback_report, sample, msg_date,
                          offline=False, nameservers=None, dns_timeout=2.0,
                          strip_attachment_payloads=False,
                          parallel=False):
    """
    Converts a DMARC forensic report and sample to a ``OrderedDict``

    Args:
        feedback_report (str): A message's feedback report as a string
        offline (bool): Do not query online for geolocation or DNS
        sample (str): The RFC 822 headers or RFC 822 message sample
        msg_date (str): The message's date header
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        strip_attachment_payloads (bool): Remove attachment payloads from
        forensic report results
        parallel (bool): Parallel processing

    Returns:
        OrderedDict: A parsed report and sample
    """
    delivery_results = ["delivered", "spam", "policy", "reject", "other"]

    try:
        parsed_report = OrderedDict()
        report_values = feedback_report_regex.findall(feedback_report)
        for report_value in report_values:
            key = report_value[0].lower().replace("-", "_")
            parsed_report[key] = report_value[1]

        if "arrival_date" not in parsed_report:
            if msg_date is None:
                raise InvalidForensicReport(
                    "Forensic sample is not a valid email")
            parsed_report["arrival_date"] = msg_date.isoformat()

        if "version" not in parsed_report:
            parsed_report["version"] = 1

        if "user_agent" not in parsed_report:
            parsed_report["user_agent"] = None

        if "delivery_result" not in parsed_report:
            parsed_report["delivery_result"] = None
        else:
            for delivery_result in delivery_results:
                if delivery_result in parsed_report["delivery_result"].lower():
                    parsed_report["delivery_result"] = delivery_result
                    break
        if parsed_report["delivery_result"] not in delivery_results:
            parsed_report["delivery_result"] = "other"

        arrival_utc = human_timestamp_to_datetime(
            parsed_report["arrival_date"], to_utc=True)
        arrival_utc = arrival_utc.strftime("%Y-%m-%d %H:%M:%S")
        parsed_report["arrival_date_utc"] = arrival_utc

        ip_address = re.split(r'\s', parsed_report["source_ip"]).pop(0)
        parsed_report_source = get_ip_address_info(ip_address,
                                                   offline=offline,
                                                   nameservers=nameservers,
                                                   timeout=dns_timeout,
                                                   parallel=parallel)
        parsed_report["source"] = parsed_report_source
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

        parsed_sample = parse_email(
            sample,
            strip_attachment_payloads=strip_attachment_payloads)

        if "reported_domain" not in parsed_report:
            parsed_report["reported_domain"] = parsed_sample["from"]["domain"]

        sample_headers_only = False
        number_of_attachments = len(parsed_sample["attachments"])
        if number_of_attachments < 1 and parsed_sample["body"] is None:
            sample_headers_only = True
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
        raise InvalidForensicReport(
            "Unexpected error: {0}".format(error.__str__()))


def parsed_forensic_reports_to_csv_rows(reports):
    """
    Converts one or more parsed forensic reports to a list of dicts in flat CSV
    format

    Args:
        reports: A parsed forensic report or list of parsed forensic reports

    Returns:
        list: Parsed forensic report data as a list of dicts in flat CSV format
    """
    if type(reports) == OrderedDict:
        reports = [reports]

    rows = []

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
        rows.append(row)

    return rows


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

    csv_file = StringIO()
    csv_writer = DictWriter(csv_file, fieldnames=fields)
    csv_writer.writeheader()

    rows = parsed_forensic_reports_to_csv_rows(reports)

    for row in rows:
        new_row = {}
        for key in new_row.keys():
            new_row[key] = row[key]
        csv_writer.writerow(new_row)

    return csv_file.getvalue()


def parse_report_email(input_, offline=False, nameservers=None,
                       dns_timeout=2.0, strip_attachment_payloads=False,
                       parallel=False, server=None):
    """
    Parses a DMARC report from an email

    Args:
        input_: An emailed DMARC report in RFC 822 format, as bytes or a string
        offline (bool): Do not query online for geolocation on DNS
        nameservers (list): A list of one or more nameservers to use
        dns_timeout (float): Sets the DNS timeout in seconds
        strip_attachment_payloads (bool): Remove attachment payloads from
        forensic report results
        parallel (bool): Parallel processing
        server (IMAPClient): Connection object

    Returns:
        OrderedDict:
        * ``report_type``: ``aggregate`` or ``forensic``
        * ``report``: The parsed report
    """
    result = None

    try:
        if is_outlook_msg(input_):
            input_ = convert_outlook_msg(input_)
        if type(input_) == bytes:
            input_ = input_.decode(encoding="utf8", errors="replace")
        msg = mailparser.parse_from_string(input_)
        msg_headers = json.loads(msg.headers_json)
        date = email.utils.format_datetime(datetime.utcnow())
        if "Date" in msg_headers:
            date = human_timestamp_to_datetime(
                msg_headers["Date"])
        msg = email.message_from_string(input_)

    except Exception as e:
        raise InvalidDMARCReport(e.__str__())
    subject = None
    feedback_report = None
    sample = None
    if "From" in msg_headers:
        logger.info("Parsing mail from {0}".format(msg_headers["From"]))
    if "Subject" in msg_headers:
        subject = msg_headers["Subject"]
    for part in msg.walk():
        content_type = part.get_content_type()
        payload = part.get_payload()
        if type(payload) != list:
            payload = [payload]
        payload = payload[0].__str__()
        if content_type == "message/feedback-report":
            try:
                if "Feedback-Type" in payload:
                    feedback_report = payload
                else:
                    feedback_report = b64decode(payload).__str__()
                feedback_report = feedback_report.lstrip(
                    "b'").rstrip("'")
                feedback_report = feedback_report.replace("\\r", "")
                feedback_report = feedback_report.replace("\\n", "\n")
            except (ValueError, TypeError, binascii.Error):
                feedback_report = payload

        elif content_type == "text/rfc822-headers":
            sample = payload
        elif content_type == "message/rfc822":
            sample = payload
        else:
            try:
                payload = b64decode(payload)
                if payload.startswith(MAGIC_ZIP) or \
                        payload.startswith(MAGIC_GZIP) or \
                        payload.startswith(MAGIC_XML):
                    ns = nameservers
                    aggregate_report = parse_aggregate_report_file(
                        payload,
                        offline=offline,
                        nameservers=ns,
                        dns_timeout=dns_timeout,
                        parallel=parallel,
                        server=server)
                    result = OrderedDict([("report_type", "aggregate"),
                                          ("report", aggregate_report)])
                    return result

            except (TypeError, ValueError, binascii.Error):
                pass

            except InvalidAggregateReport as e:
                error = 'Message with subject "{0}" ' \
                        'is not a valid ' \
                        'aggregate DMARC report: {1}'.format(subject, e)
                raise InvalidAggregateReport(error)

            except FileNotFoundError as e:
                error = 'Unable to parse message with ' \
                        'subject "{0}": {1}'.format(subject, e)
                raise InvalidDMARCReport(error)

    if feedback_report and sample:
        try:
            forensic_report = parse_forensic_report(
                feedback_report,
                sample,
                date,
                offline=offline,
                nameservers=nameservers,
                dns_timeout=dns_timeout,
                strip_attachment_payloads=strip_attachment_payloads,
                parallel=parallel)
        except InvalidForensicReport as e:
            error = 'Message with subject "{0}" ' \
                    'is not a valid ' \
                    'forensic DMARC report: {1}'.format(subject, e)
            raise InvalidForensicReport(error)
        except Exception as e:
            raise InvalidForensicReport(e.__str__())

        result = OrderedDict([("report_type", "forensic"),
                              ("report", forensic_report)])
        return result

    if result is None:
        error = 'Message with subject "{0}" is ' \
                'not a valid DMARC report'.format(subject)
        raise InvalidDMARCReport(error)


def parse_report_file(input_, nameservers=None, dns_timeout=2.0,
                      strip_attachment_payloads=False,
                      offline=False, parallel=False, server=None):
    """Parses a DMARC aggregate or forensic file at the given path, a
    file-like object. or bytes

    Args:
        input_: A path to a file, a file like object, or bytes
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        strip_attachment_payloads (bool): Remove attachment payloads from
        forensic report results
        offline (bool): Do not make online queries for geolocation or DNS
        parallel (bool): Parallel processing
        server (IMAPClient): Connection object

    Returns:
        OrderedDict: The parsed DMARC report
    """
    if type(input_) == str:
        logger.debug("Parsing {0}".format(input_))
        file_object = open(input_, "rb")
    elif type(input_) == bytes:
        file_object = BytesIO(input_)
    else:
        file_object = input_

    content = file_object.read()
    file_object.close()
    try:
        report = parse_aggregate_report_file(content,
                                             offline=offline,
                                             nameservers=nameservers,
                                             dns_timeout=dns_timeout,
                                             parallel=parallel,
                                             server=server)
        results = OrderedDict([("report_type", "aggregate"),
                               ("report", report)])
    except InvalidAggregateReport:
        try:
            sa = strip_attachment_payloads
            results = parse_report_email(content,
                                         offline=offline,
                                         nameservers=nameservers,
                                         dns_timeout=dns_timeout,
                                         strip_attachment_payloads=sa,
                                         parallel=parallel,
                                         server=server)
        except InvalidDMARCReport:
            raise InvalidDMARCReport("Not a valid aggregate or forensic "
                                     "report")
    return results


def get_dmarc_reports_from_mbox(input_, nameservers=None, dns_timeout=2.0,
                                strip_attachment_payloads=False,
                                offline=False, parallel=False):
    """Parses a mailbox in mbox format containing e-mails with attached
    DMARC reports

    Args:
        input_: A path to a mbox file
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        strip_attachment_payloads (bool): Remove attachment payloads from
        forensic report results
        offline (bool): Do not make online queries for geolocation or DNS
        parallel (bool): Parallel processing

    Returns:
        OrderedDict: Lists of  ``aggregate_reports`` and ``forensic_reports``

    """
    aggregate_reports = []
    forensic_reports = []
    try:
        mbox = mailbox.mbox(input_)
        message_keys = mbox.keys()
        total_messages = len(message_keys)
        logger.debug("Found {0} messages in {1}".format(total_messages,
                                                        input_))
        for i in range(len(message_keys)):
            message_key = message_keys[i]
            logger.info("Processing message {0} of {1}".format(
                i+1, total_messages
            ))
            msg_content = mbox.get_string(message_key)
            try:
                sa = strip_attachment_payloads
                parsed_email = parse_report_email(msg_content,
                                                  offline=offline,
                                                  nameservers=nameservers,
                                                  dns_timeout=dns_timeout,
                                                  strip_attachment_payloads=sa,
                                                  parallel=parallel)
                if parsed_email["report_type"] == "aggregate":
                    aggregate_reports.append(parsed_email["report"])
                elif parsed_email["report_type"] == "forensic":
                    forensic_reports.append(parsed_email["report"])
            except InvalidDMARCReport as error:
                logger.warning(error.__str__())
    except mailbox.NoSuchMailboxError:
        raise InvalidDMARCReport("Mailbox {0} does not exist".format(input_))
    return OrderedDict([("aggregate_reports", aggregate_reports),
                        ("forensic_reports", forensic_reports)])


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


def get_dmarc_reports_from_inbox(connection=None,
                                 host=None,
                                 user=None,
                                 password=None,
                                 port=None,
                                 ssl=True,
                                 verify=True,
                                 timeout=30,
                                 max_retries=4,
                                 reports_folder="INBOX",
                                 archive_folder="Archive",
                                 delete=False,
                                 test=False,
                                 offline=False,
                                 nameservers=None,
                                 dns_timeout=6.0,
                                 strip_attachment_payloads=False,
                                 results=None,
                                 batch_size=None):
    """
    Fetches and parses DMARC reports from an inbox

    Args:
        connection: An IMAPClient connection to reuse
        host: The mail server hostname or IP address
        user: The mail server user
        password: The mail server password
        port: The mail server port
        ssl (bool): Use SSL/TLS
        verify (bool): Verify SSL/TLS certificate
        timeout (float): IMAP timeout in seconds
        max_retries (int): The maximum number of retries after a timeout
        reports_folder: The IMAP folder where reports can be found
        archive_folder: The folder to move processed mail to
        delete (bool): Delete  messages after processing them
        test (bool): Do not move or delete messages after processing them
        offline (bool): Do not query onfline for geolocation or DNS
        nameservers (list): A list of DNS nameservers to query
        dns_timeout (float): Set the DNS query timeout
        strip_attachment_payloads (bool): Remove attachment payloads from
        forensic report results
        results (dict): Results from the previous run
        batch_size (int): Number of messages to read and process before saving

    Returns:
        OrderedDict: Lists of ``aggregate_reports`` and ``forensic_reports``
    """
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

    if results:
        aggregate_reports = results["aggregate_reports"].copy()
        forensic_reports = results["forensic_reports"].copy()

    if connection:
        server = connection
    else:
        server = IMAPClient(host, user, password, port=port,
                            ssl=ssl, verify=verify,
                            timeout=timeout,
                            max_retries=max_retries,
                            initial_folder=reports_folder)

    if not test:
        server.create_folder(archive_folder)
        server.create_folder(aggregate_reports_folder)
        server.create_folder(forensic_reports_folder)
        server.create_folder(invalid_reports_folder)

    messages = server.search()
    total_messages = len(messages)
    logger.debug("Found {0} messages in {1}".format(len(messages),
                                                    reports_folder))

    if batch_size:
        message_limit = min(total_messages, batch_size)
    else:
        message_limit = total_messages

    logger.debug("Processing {0} messages".format(message_limit))

    for i in range(message_limit):
        msg_uid = messages[i]
        logger.debug("Processing message {0} of {1}: UID {2}".format(
            i+1, message_limit, msg_uid
        ))
        msg_content = server.fetch_message(msg_uid, parse=False)
        sa = strip_attachment_payloads
        try:
            parsed_email = parse_report_email(msg_content,
                                              nameservers=nameservers,
                                              dns_timeout=dns_timeout,
                                              offline=offline,
                                              strip_attachment_payloads=sa,
                                              server=server)
            if parsed_email["report_type"] == "aggregate":
                aggregate_reports.append(parsed_email["report"])
                aggregate_report_msg_uids.append(msg_uid)
            elif parsed_email["report_type"] == "forensic":
                forensic_reports.append(parsed_email["report"])
                forensic_report_msg_uids.append(msg_uid)
        except InvalidDMARCReport as error:
            logger.warning(error.__str__())
            if not test:
                if delete:
                    logger.debug(
                        "Deleting message UID {0}".format(msg_uid))
                    server.delete_messages([msg_uid])
                else:
                    logger.debug(
                        "Moving message UID {0} to {1}".format(
                            msg_uid, invalid_reports_folder))
                    server.move_messages([msg_uid], invalid_reports_folder)

    if not test:
        if delete:
            processed_messages = aggregate_report_msg_uids + \
                                 forensic_report_msg_uids

            number_of_processed_msgs = len(processed_messages)
            for i in range(number_of_processed_msgs):
                msg_uid = processed_messages[i]
                logger.debug(
                    "Deleting message {0} of {1}: UID {2}".format(
                        i + 1, number_of_processed_msgs, msg_uid))
                try:
                    server.delete_messages([msg_uid])

                except Exception as e:
                    message = "Error deleting message UID"
                    e = "{0} {1}: " "{2}".format(message, msg_uid, e)
                    logger.error("IMAP error: {0}".format(e))
        else:
            if len(aggregate_report_msg_uids) > 0:
                log_message = "Moving aggregate report messages from"
                logger.debug(
                    "{0} {1} to {2}".format(
                        log_message, reports_folder,
                        aggregate_reports_folder))
                number_of_agg_report_msgs = len(aggregate_report_msg_uids)
                for i in range(number_of_agg_report_msgs):
                    msg_uid = aggregate_report_msg_uids[i]
                    logger.debug(
                        "Moving message {0} of {1}: UID {2}".format(
                            i+1, number_of_agg_report_msgs, msg_uid))
                    try:
                        server.move_messages([msg_uid],
                                             aggregate_reports_folder)
                    except Exception as e:
                        message = "Error moving message UID"
                        e = "{0} {1}: {2}".format(message, msg_uid, e)
                        logger.error("IMAP error: {0}".format(e))
            if len(forensic_report_msg_uids) > 0:
                message = "Moving forensic report messages from"
                logger.debug(
                    "{0} {1} to {2}".format(message,
                                            reports_folder,
                                            forensic_reports_folder))
                number_of_forensic_msgs = len(forensic_report_msg_uids)
                for i in range(number_of_forensic_msgs):
                    msg_uid = forensic_report_msg_uids[i]
                    message = "Moving message"
                    logger.debug("{0} {1} of {2}: UID {3}".format(
                        message,
                        i + 1, number_of_forensic_msgs, msg_uid))
                    try:
                        server.move_messages([msg_uid],
                                             forensic_reports_folder)
                    except Exception as e:
                        e = "Error moving message UID {0}: {1}".format(
                            msg_uid, e)
                        logger.error("IMAP error: {0}".format(e))
    results = OrderedDict([("aggregate_reports", aggregate_reports),
                           ("forensic_reports", forensic_reports)])

    total_messages = len(server.search())

    if not test and not batch_size and total_messages > 0:
        # Process emails that came in during the last run
        results = get_dmarc_reports_from_inbox(
            connection=server,
            reports_folder=reports_folder,
            archive_folder=archive_folder,
            delete=delete,
            test=test,
            nameservers=nameservers,
            dns_timeout=dns_timeout,
            strip_attachment_payloads=strip_attachment_payloads,
            results=results,
            offline=offline
        )

    return results


def watch_inbox(host, username, password, callback, port=None, ssl=True,
                verify=True, reports_folder="INBOX",
                archive_folder="Archive", delete=False, test=False,
                idle_timeout=30, offline=False, nameservers=None,
                dns_timeout=6.0, strip_attachment_payloads=False,
                batch_size=None):
    """
    Use an IDLE IMAP connection to parse incoming emails, and pass the results
    to a callback function
    Args:
        host: The mail server hostname or IP address
        username: The mail server username
        password: The mail server password
        callback: The callback function to receive the parsing results
        port: The mail server port
        ssl (bool): Use SSL/TLS
        verify (bool): Verify the TLS/SSL certificate
        reports_folder: The IMAP folder where reports can be found
        archive_folder: The folder to move processed mail to
        delete (bool): Delete  messages after processing them
        test (bool): Do not move or delete messages after processing them
        idle_timeout (int): Number of seconds to wait for a IMAP IDLE response
        offline (bool): Do not query online for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
        (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Set the DNS query timeout
        strip_attachment_payloads (bool): Replace attachment payloads in
        forensic report samples with None
        batch_size (int): Number of messages to read and process before saving
    """
    sa = strip_attachment_payloads

    def idle_callback(connection):
        res = get_dmarc_reports_from_inbox(connection=connection,
                                           reports_folder=reports_folder,
                                           archive_folder=archive_folder,
                                           delete=delete,
                                           test=test,
                                           offline=offline,
                                           nameservers=nameservers,
                                           dns_timeout=dns_timeout,
                                           strip_attachment_payloads=sa,
                                           batch_size=batch_size)
        callback(res)

    while True:
        try:
            IMAPClient(host=host, username=username, password=password,
                       port=port, ssl=ssl, verify=verify,
                       initial_folder=reports_folder,
                       idle_callback=idle_callback,
                       idle_timeout=idle_timeout)
        except (timeout, IMAPClientError):
            logger.warning("IMAP connection timeout. Reconnecting...")
            sleep(5)
        except Exception as e:
            logger.warning("IMAP connection error. {0}. "
                           "Reconnecting...".format(e))
            sleep(5)


def save_output(results, output_directory="output",
                aggregate_json_filename="aggregate.json",
                forensic_json_filename="forensic.json",
                aggregate_csv_filename="aggregate.csv",
                forensic_csv_filename="forensic.csv"):
    """
    Save report data in the given directory

    Args:
        results (OrderedDict): Parsing results
        output_directory (str): The patch to the directory to save in
        aggregate_json_filename (str): Filename for the aggregate JSON file
        forensic_json_filename (str): Filename for the forensic JSON file
        aggregate_csv_filename (str): Filename for the aggregate CSV file
        forensic_csv_filename (str): Filename for the forensic CSV file
    """

    aggregate_reports = results["aggregate_reports"]
    forensic_reports = results["forensic_reports"]

    if os.path.exists(output_directory):
        if not os.path.isdir(output_directory):
            raise ValueError("{0} is not a directory".format(output_directory))
    else:
        os.makedirs(output_directory)

    with open("{0}"
              .format(os.path.join(output_directory,
                                   aggregate_json_filename)),
              "w", newline="\n", encoding="utf-8") as agg_json:
        agg_json.write(json.dumps(aggregate_reports, ensure_ascii=False,
                                  indent=2))

    with open("{0}"
              .format(os.path.join(output_directory,
                                   aggregate_csv_filename)),
              "w", newline="\n", encoding="utf-8") as agg_csv:
        csv = parsed_aggregate_reports_to_csv(aggregate_reports)
        agg_csv.write(csv)

    with open("{0}"
              .format(os.path.join(output_directory,
                                   forensic_json_filename)),
              "w", newline="\n", encoding="utf-8") as for_json:
        for_json.write(json.dumps(forensic_reports, ensure_ascii=False,
                                  indent=2))

    with open("{0}"
              .format(os.path.join(output_directory,
                                   forensic_csv_filename)),
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


def email_results(results, host, mail_from, mail_to,
                  mail_cc=None, mail_bcc=None, port=0,
                  require_encryption=False, verify=True,
                  username=None, password=None, subject=None,
                  attachment_filename=None, message=None):
    """
    Emails parsing results as a zip file

    Args:
        results (OrderedDict): Parsing results
        host: Mail server hostname or IP address
        mail_from: The value of the message from header
        mail_to (list): A list of addresses to mail to
        mail_cc (list): A list of addresses to CC
        mail_bcc (list): A list addresses to BCC
        port (int): Port to use
        require_encryption (bool): Require a secure connection from the start
        verify (bool): verify the SSL/TLS certificate
        username (str): An optional username
        password (str): An optional password
        subject (str): Overrides the default message subject
        attachment_filename (str): Override the default attachment filename
        message (str: Override the default plain text body
    """
    logging.debug("Emailing report to: {0}".format(",".join(mail_to)))
    date_string = datetime.now().strftime("%Y-%m-%d")
    if attachment_filename:
        if not attachment_filename.lower().endswith(".zip"):
            attachment_filename += ".zip"
        filename = attachment_filename
    else:
        filename = "DMARC-{0}.zip".format(date_string)

    assert isinstance(mail_to, list)

    if subject is None:
        subject = "DMARC results for {0}".format(date_string)
    if message is None:
        message = "DMARC results for {0}".format(date_string)
    zip_bytes = get_report_zip(results)
    attachments = [(filename, zip_bytes)]

    send_email(host, mail_from, mail_to, message_cc=mail_cc,
               message_bcc=mail_bcc, port=port,
               require_encryption=require_encryption, verify=verify,
               username=username, password=password, subject=subject,
               attachments=attachments, plain_message=message)
