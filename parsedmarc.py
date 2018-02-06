#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""A Python module and CLI for parsing aggregate DMARC reports"""

from __future__ import unicode_literals, print_function, absolute_import

import logging
from sys import version_info
from os import path, stat
import json
from datetime import datetime
from collections import OrderedDict
from datetime import timedelta
from io import BytesIO, StringIO
from gzip import GzipFile
import tarfile
from zipfile import ZipFile
from csv import DictWriter
import shutil
from argparse import ArgumentParser
from glob import glob

import publicsuffix
import xmltodict
import dns.reversename
import dns.resolver
import dns.exception
from requests import get
import geoip2.database
import geoip2.errors

__version__ = "1.0.1"

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


#  Python 2 comparability hack
if version_info[0] >= 3:
    unicode = str


class InvalidAggregateReport(Exception):
    """Raised when an invalid DMARC aggregate report is encountered"""


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
    psl_path = "public_suffix_list.dat"

    def download_psl():
        fresh_psl = publicsuffix.fetch()
        with open(psl_path, "w", encoding="utf-8") as fresh_psl_file:
            fresh_psl_file.write(fresh_psl.read())

        return publicsuffix.PublicSuffixList(fresh_psl)

    if not path.exists(psl_path):
        psl = download_psl()
    else:
        psl_age = datetime.now() - datetime.fromtimestamp(
            stat(psl_path).st_mtime)
        if psl_age > timedelta(hours=24):
            psl = download_psl()
        else:
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
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        list: A list of answers
    """
    resolver = dns.resolver.Resolver()
    timeout = float(timeout)
    if nameservers:
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
        nameservers (list): A list of nameservers to query
        timeout (float): Sets the DNS query timeout in seconds

    Returns:

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
        timestamp: The timestamp

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


def _human_timestamp_to_datetime(human_timestamp):
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
    db_filename = "GeoLite2-Country.mmdb"

    def download_country_database():
        """Downloads the MaxMind Geolite2 Country database to the current
        working directory"""
        url = "https://geolite.maxmind.com/download/geoip/database/" \
              "GeoLite2-Country.tar.gz"
        tar_file = tarfile.open(fileobj=BytesIO(get(url).content), mode="r:gz")
        tar_dir = tar_file.getnames()[0]
        tar_path = "{0}/{1}".format(tar_dir, db_filename)
        tar_file.extract(tar_path)
        shutil.move(tar_path, ".")
        shutil.rmtree(tar_dir)

    system_paths = ["/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
                    "/usr/share/GeoIP/GeoLite2-Country.mmdb"]
    db_path = ""

    for system_path in system_paths:
        if path.exists(system_path):
            db_path = system_path
            break

    if db_path == "":
        if not path.exists(db_filename):
            download_country_database()
        else:
            db_age = datetime.now() - datetime.fromtimestamp(
                stat(db_filename).st_mtime)
            if db_age > timedelta(days=60):
                shutil.rmtree(db_path)
                download_country_database()
        db_path = db_filename

    db_reader = geoip2.database.Reader(db_path)

    country = None

    try:
        country = db_reader.country(ip_address).country.iso_code
    except geoip2.errors.AddressNotFoundError:
        pass

    return country


def _parse_report_record(record, nameservers=None, timeout=6.0):
    """
    Converts a record from a DMARC aggregate report into a more consistent
    format

    Args:
        record (OrderedDict): The record to convert
        nameservers (list): A list of one or more nameservers to use
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: The converted record
    """
    record = record.copy()
    new_record = OrderedDict()
    new_record["source"] = OrderedDict()
    new_record["source"]["ip_address"] = record["row"]["source_ip"]
    reverse_dns = _get_reverse_dns(new_record["source"]["ip_address"],
                                   nameservers=nameservers,
                                   timeout=timeout)
    country = _get_ip_address_country(new_record["source"]["ip_address"])
    new_record["source"]["country"] = country
    new_record["source"]["reverse_dns"] = reverse_dns
    new_record["source"]["base_domain"] = None
    if new_record["source"]["reverse_dns"] is not None:
        base_domain = _get_base_domain(new_record["source"]["reverse_dns"])
        new_record["source"]["base_domain"] = base_domain
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
    auth_results = record["auth_results"].copy()
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
        envelope_from = new_record["auth_results"]["spf"][-1]["domain"].lower()
        new_record["identifiers"]["envelope_from"] = envelope_from

    elif new_record["identifiers"]["envelope_from"] is None:
        envelope_from = new_record["auth_results"]["spf"][-1]["domain"].lower()
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
        new_report_metadata["org_name"] = report_metadata["org_name"]
        new_report_metadata["org_email"] = report_metadata["email"]
        extra = None
        if "extra_contact_info" in report_metadata:
            extra = report_metadata["extra_contact_info"]
        new_report_metadata["org_extra_contact_info"] = extra
        new_report_metadata["report_id"] = report_metadata["report_id"]
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
            records.append(_parse_report_record(report["record"]))

        new_report["records"] = records

        return new_report

    except KeyError as error:
        raise InvalidAggregateReport("Missing field: "
                                     "{0}".format(error.__str__()))


def parse_aggregate_report_file(_input, nameservers=None, timeout=6.0):
    """Parses a file at the given path, a file-like object. or bytes as a
    aggregate DMARC report

    Args:
        _input: A path to a file, a file like object, or bytes
        nameservers (list): A list of one or more nameservers to use
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: The parsed DMARC aggregate report
    """
    if type(_input) == str or type(_input) == unicode:
        file_object = open(_input, "rb")
    elif type(_input) == bytes:
        file_object = BytesIO(_input)
    else:
        file_object = _input
    try:
        header = file_object.read(6)
        file_object.seek(0)
        if header.startswith(b"\x50\x4B\x03\x04"):
            _zip = ZipFile(file_object)
            xml = _zip.open(_zip.namelist()[0]).read().decode()
        elif header.startswith(b"\x1F\x8B"):
            xml = GzipFile(fileobj=file_object).read().decode()
        elif header.startswith(b"\x3c\x3f\x78\x6d\x6c\x20"):
            xml = file_object.read().decode()
        else:
            file_object.close()
            raise InvalidAggregateReport("Not a valid zip, gzip, or xml file")

        file_object.close()
    except UnicodeDecodeError:
        raise InvalidAggregateReport("File objects must be opened in binary "
                                     "(rb) mode")

    return parse_aggregate_report_xml(xml,
                                      nameservers=nameservers,
                                      timeout=timeout)


def parsed_aggregate_report_to_csv(_input):
    """
    Converts one or more parsed aggregate reports to flat CSV format, including
    headers

    Args:
        _input: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        str: Parsed aggregate report data in flat CSV format, including headers
    """
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

    if type(_input) == OrderedDict:
        _input = [_input]

    for report in _input:
        xml_schema = report["xml_schema"]
        org_name = report["report_metadata"]["org_name"]
        org_email = report["report_metadata"]["org_email"]
        org_extra_contact = report["report_metadata"]["org_extra_contact_info"]
        report_id = report["report_metadata"]["report_id"]
        begin_date = report["report_metadata"]["begin_date"]
        end_date = report["report_metadata"]["end_date"]
        errors = report["report_metadata"]["errors"]
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
            row["dkim_domains"] = ",".join(dkim_domains)
            row["dkim_selectors"] = ",".join(dkim_selectors)
            row["dkim_results"] = ",".join(dkim_results)
            spf_domains = []
            spf_scopes = []
            spf_results = []
            for spf_result in record["auth_results"]["spf"]:
                spf_domains.append(spf_result["domain"])
                spf_scopes.append(spf_result["scope"])
                spf_results.append(spf_result["result"])
            row["spf_domains"] = ",".join(spf_domains)
            row["spf_scopes"] = ",".join(spf_scopes)
            row["spf_results"] = ",".join(spf_results)

            writer.writerow(row)
            csv_file_object.flush()

    return csv_file_object.getvalue()


def _main():
    """Called when the module in executed"""
    arg_parser = ArgumentParser(description="Parses aggregate DMARC reports")
    arg_parser.add_argument("file_path", nargs="+",
                            help="one or more paths of aggregate report "
                                 "files (compressed or uncompressed)")
    arg_parser.add_argument("-f", "--format", default="json",
                            help="specify JSON or CSV output format")
    arg_parser.add_argument("-o", "--output",
                            help="output to a file path rather than "
                                 "printing to the screen")
    arg_parser.add_argument("-n", "--nameserver", nargs="+",
                            help="nameservers to query")
    arg_parser.add_argument("-t", "--timeout",
                            help="number of seconds to wait for an answer "
                                 "from DNS (default 6.0)",
                            type=float,
                            default=6.0)
    arg_parser.add_argument("-v", "--version", action="version",
                            version=__version__)

    args = arg_parser.parse_args()
    file_paths = []
    for file_path in args.file_path:
        file_paths += glob(file_path)
    file_paths = list(set(file_paths))

    parsed_reports = []
    for file_path in file_paths:
        try:
            report = parse_aggregate_report_file(file_path,
                                                 nameservers=args.nameserver,
                                                 timeout=args.timeout)
            parsed_reports.append(report)
        except InvalidAggregateReport as error:
            logger.error("Unable to parse {0}: {1}".format(file_path,
                                                           error.__str__()))
    output = ""
    if args.format.lower() == "json":
        if len(parsed_reports) == 1:
            parsed_reports = parsed_reports[0]
        output = json.dumps(parsed_reports,
                            ensure_ascii=False,
                            indent=2)
    elif args.format.lower() == "csv":
        output = parsed_aggregate_report_to_csv(parsed_reports)
    else:
        logger.error("Invalid output format: {0}".format(args.format))
        exit(-1)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as file:
            file.write(output)
    else:
        print(output)


if __name__ == "__main__":
    _main()
