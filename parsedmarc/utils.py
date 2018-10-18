"""Utility functions that might be useful for other projects"""

import logging
import os
from datetime import datetime
from datetime import timedelta
from collections import OrderedDict
from io import BytesIO
import tarfile
import tempfile
import subprocess
import shutil
import mailparser
import json
import hashlib
import base64

import dateparser
import dns.reversename
import dns.resolver
import dns.exception
import geoip2.database
import geoip2.errors
import requests
import publicsuffix

from parsedmarc.__version__ import USER_AGENT


logger = logging.getLogger("parsedmarc")


class EmailParserError(RuntimeError):
    """Raised when an error parsing the email occurs"""


def decode_base64(data):
    """
    Decodes a base64 string, with padding being optional

    Args:
        data: A base64 encoded string

    Returns:
        bytes: The decoded bytes

    """
    data = str(data)
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b'=' * (4 - missing_padding)
    return base64.b64decode(data)


def get_base_domain(domain):
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
        url = "https://publicsuffix.org/list/public_suffix_list.dat"
        # Use a browser-like user agent string to bypass some proxy blocks
        headers = {"User-Agent": USER_AGENT}
        fresh_psl = requests.get(url, headers=headers).text
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
                logger.warning(
                    "Failed to download an updated PSL {0}".format(error))
    with open(psl_path, encoding="utf-8") as psl_file:
        psl = publicsuffix.PublicSuffixList(psl_file)

    return psl.get_public_suffix(domain)


def query_dns(domain, record_type, nameservers=None, timeout=2.0):
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
    if record_type == "TXT":
        resource_records = list(map(
            lambda r: r.strings,
            resolver.query(domain, record_type, tcp=True)))
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records if resource_record]
        return [r.decode() for r in _resource_record]
    else:
        return list(map(
            lambda r: r.to_text().replace('"', '').rstrip("."),
            resolver.query(domain, record_type, tcp=True)))


def get_reverse_dns(ip_address, nameservers=None, timeout=2.0):
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
        hostname = query_dns(address, "PTR",
                             nameservers=nameservers,
                             timeout=timeout)[0]

    except dns.exception.DNSException:
        pass

    return hostname


def timestamp_to_datetime(timestamp):
    """
    Converts a UNIX/DMARC timestamp to a Python ``DateTime`` object

    Args:
        timestamp (int): The timestamp

    Returns:
        DateTime: The converted timestamp as a Python ``DateTime`` object
    """
    return datetime.fromtimestamp(int(timestamp))


def timestamp_to_human(timestamp):
    """
    Converts a UNIX/DMARC timestamp to a human-readable string

    Args:
        timestamp: The timestamp

    Returns:
        str: The converted timestamp in ``YYYY-MM-DD HH:MM:SS`` format
    """
    return timestamp_to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def human_timestamp_to_datetime(human_timestamp, to_utc=False):
    """
    Converts a human-readable timestamp into a Python ``DateTime`` object

    Args:
        human_timestamp (str): A timestamp string
        to_utc (bool): Convert the timestamp to UTC

    Returns:
        DateTime: The converted timestamp
    """

    settings = {}

    if to_utc:
        settings = {"TO_TIMEZONE": "UTC"}

    return dateparser.parse(human_timestamp, settings=settings)


def human_timestamp_to_timestamp(human_timestamp):
    """
    Converts a human-readable timestamp into a into a UNIX timestamp

    Args:
        human_timestamp (str): A timestamp in `YYYY-MM-DD HH:MM:SS`` format

    Returns:
        float: The converted timestamp
    """
    human_timestamp = human_timestamp.replace("T", " ")
    return human_timestamp_to_datetime(human_timestamp).timestamp()


def get_ip_address_country(ip_address):
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
        # Use a browser-like user agent string to bypass some proxy blocks
        headers = {"User-Agent": USER_AGENT}
        original_filename = "GeoLite2-Country.mmdb"
        tar_bytes = requests.get(url, headers=headers).content
        tar_file = tarfile.open(fileobj=BytesIO(tar_bytes), mode="r:gz")
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


def get_ip_address_info(ip_address, nameservers=None, timeout=2.0):
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
    reverse_dns = get_reverse_dns(ip_address,
                                  nameservers=nameservers,
                                  timeout=timeout)
    country = get_ip_address_country(ip_address)
    info["country"] = country
    info["reverse_dns"] = reverse_dns
    info["base_domain"] = None
    if reverse_dns is not None:
        base_domain = get_base_domain(reverse_dns)
        info["base_domain"] = base_domain

    return info


def parse_email_address(original_address):
    if original_address[0] == "":
        display_name = None
    else:
        display_name = original_address[0]
    address = original_address[1]
    address_parts = address.split("@")
    local = None
    domain = None
    if len(address_parts) > 1:
        local = address_parts[0].lower()
        domain = address_parts[-1].lower()

    return OrderedDict([("display_name", display_name),
                        ("address", address),
                        ("local", local),
                        ("domain", domain)])


def get_filename_safe_string(string):
    """
    Converts a string to a string that is safe for a filename
    Args:
        string (str): A string to make safe for a filename

    Returns:
        str: A string safe for a filename
    """
    invalid_filename_chars = ['\\', '/', ':', '"', '*', '?', '|', '\n',
                              '\r']
    if string is None:
        string = "None"
    for char in invalid_filename_chars:
        string = string.replace(char, "")
    string = string.rstrip(".")

    return string


def is_outlook_msg(content):
    """
    Checks if the given content is a Outlook msg OLE file

    Args:
        content: Content to check

    Returns:
        bool: A flag the indicates if a file is a Outlook MSG file
    """
    return type(content) == bytes and content.startswith(
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")


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
        raise EmailParserError(
            "Failed to convert Outlook MSG: msgconvert utility not found")
    finally:
        os.chdir(orig_dir)
        shutil.rmtree(tmp_dir)

    return rfc822


def parse_email(data, strip_attachment_payloads=False):
    """
    A simplified email parser

    Args:
        data: The RFC 822 message string, or MSG binary
        strip_attachment_payloads (bool): Remove attachment payloads

    Returns (dict): Parsed email data
    """

    if type(data) == bytes:
        if is_outlook_msg(data):
            data = convert_outlook_msg(data)
        data = data.decode("utf-8", errors="replace")
    parsed_email = mailparser.parse_from_string(data)
    headers = json.loads(parsed_email.headers_json).copy()
    parsed_email = json.loads(parsed_email.mail_json).copy()
    parsed_email["headers"] = headers
    if "received" in parsed_email:
        for received in parsed_email["received"]:
            if "date_utc" in received:
                received["date_utc"] = received["date_utc"].replace("T",
                                                                    " ")

    if "from" not in parsed_email:
        if "From" in parsed_email["headers"]:
            parsed_email["from"] = parsed_email["Headers"]["From"]
        else:
            parsed_email["from"] = None

    if parsed_email["from"] is not None:
        parsed_email["from"] = parse_email_address(parsed_email["from"][0])

    if "date" in parsed_email:
        parsed_email["date"] = parsed_email["date"].replace("T", " ")
    else:
        parsed_email["date"] = None
    if "reply_to" in parsed_email:
        parsed_email["reply_to"] = list(map(lambda x: parse_email_address(x),
                                            parsed_email["reply_to"]))
    else:
        parsed_email["reply_to"] = []

    if "to" in parsed_email:
        parsed_email["to"] = list(map(lambda x: parse_email_address(x),
                                      parsed_email["to"]))
    else:
        parsed_email["to"] = []

    if "cc" in parsed_email:
        parsed_email["cc"] = list(map(lambda x: parse_email_address(x),
                                      parsed_email["cc"]))
    else:
        parsed_email["cc"] = []

    if "bcc" in parsed_email:
        parsed_email["bcc"] = list(map(lambda x: parse_email_address(x),
                                       parsed_email["bcc"]))
    else:
        parsed_email["bcc"] = []

    if "delivered_to" in parsed_email:
        parsed_email["delivered_to"] = list(
            map(lambda x: parse_email_address(x),
                parsed_email["delivered_to"])
        )

    if "attachments" not in parsed_email:
        parsed_email["attachments"] = []
    else:
        for attachment in parsed_email["attachments"]:
            if "payload" in attachment:
                payload = attachment["payload"]
                if "content_transfer_encoding" in attachment:
                    if attachment["content_transfer_encoding"] == "base64":
                        payload = decode_base64(payload)
                    else:
                        payload = str.encode(payload)
                attachment["sha256"] = hashlib.sha256(payload).hexdigest()
        if strip_attachment_payloads:
            for attachment in parsed_email["attachments"]:
                if "payload" in attachment:
                    del attachment["payload"]

    if "subject" not in parsed_email:
        parsed_email["subject"] = None

    parsed_email["filename_safe_subject"] = get_filename_safe_string(
        parsed_email["subject"])

    if "body" not in parsed_email:
        parsed_email["body"] = None

    return parsed_email
