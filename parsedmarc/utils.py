"""Utility functions that might be useful for other projects"""

import logging
import os
from datetime import datetime
from datetime import timezone
from datetime import timedelta
from collections import OrderedDict
import tempfile
import subprocess
import shutil
import mailparser
import json
import hashlib
import base64
import mailbox
import re
import csv
import io

try:
    from importlib.resources import files
except ImportError:
    # Try backported to PY<3 `importlib_resources`
    from importlib.resources import files


from dateutil.parser import parse as parse_date
import dns.reversename
import dns.resolver
import dns.exception
import geoip2.database
import geoip2.errors
import publicsuffixlist
import requests

from parsedmarc.log import logger
import parsedmarc.resources.dbip
import parsedmarc.resources.maps
from parsedmarc.constants import USER_AGENT

parenthesis_regex = re.compile(r"\s*\(.*\)\s*")

null_file = open(os.devnull, "w")
mailparser_logger = logging.getLogger("mailparser")
mailparser_logger.setLevel(logging.CRITICAL)


class EmailParserError(RuntimeError):
    """Raised when an error parsing the email occurs"""


class DownloadError(RuntimeError):
    """Raised when an error occurs when downloading a file"""


def decode_base64(data):
    """
    Decodes a base64 string, with padding being optional

    Args:
        data: A base64 encoded string

    Returns:
        bytes: The decoded bytes

    """
    data = bytes(data, encoding="ascii")
    missing_padding = len(data) % 4
    if missing_padding != 0:
        data += b"=" * (4 - missing_padding)
    return base64.b64decode(data)


def get_base_domain(domain):
    """
    Gets the base domain name for the given domain

    .. note::
        Results are based on a list of public domain suffixes at
        https://publicsuffix.org/list/public_suffix_list.dat.

    Args:
        domain (str): A domain or subdomain

    Returns:
        str: The base domain of the given domain

    """
    psl = publicsuffixlist.PublicSuffixList()
    return psl.privatesuffix(domain)


def query_dns(domain, record_type, cache=None, nameservers=None, timeout=2.0):
    """
    Queries DNS

    Args:
        domain (str): The domain or subdomain to query about
        record_type (str): The record type to query for
        cache (ExpiringDict): Cache storage
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        list: A list of answers
    """
    domain = str(domain).lower()
    record_type = record_type.upper()
    cache_key = "{0}_{1}".format(domain, record_type)
    if cache:
        records = cache.get(cache_key, None)
        if records:
            return records

    resolver = dns.resolver.Resolver()
    timeout = float(timeout)
    if nameservers is None:
        nameservers = [
            "1.1.1.1",
            "1.0.0.1",
            "2606:4700:4700::1111",
            "2606:4700:4700::1001",
        ]
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if record_type == "TXT":
        resource_records = list(
            map(
                lambda r: r.strings,
                resolver.resolve(domain, record_type, lifetime=timeout),
            )
        )
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records
            if resource_record
        ]
        records = [r.decode() for r in _resource_record]
    else:
        records = list(
            map(
                lambda r: r.to_text().replace('"', "").rstrip("."),
                resolver.resolve(domain, record_type, lifetime=timeout),
            )
        )
    if cache:
        cache[cache_key] = records

    return records


def get_reverse_dns(ip_address, cache=None, nameservers=None, timeout=2.0):
    """
    Resolves an IP address to a hostname using a reverse DNS query

    Args:
        ip_address (str): The IP address to resolve
        cache (ExpiringDict): Cache storage
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS query timeout in seconds

    Returns:
        str: The reverse DNS hostname (if any)
    """
    hostname = None
    try:
        address = dns.reversename.from_address(ip_address)
        hostname = query_dns(
            address, "PTR", cache=cache, nameservers=nameservers, timeout=timeout
        )[0]

    except dns.exception.DNSException as e:
        logger.warning(f"get_reverse_dns({ip_address}) exception: {e}")
        pass

    return hostname


def timestamp_to_datetime(timestamp):
    """
    Converts a UNIX/DMARC timestamp to a Python ``datetime`` object

    Args:
        timestamp (int): The timestamp

    Returns:
        datetime: The converted timestamp as a Python ``datetime`` object
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
    Converts a human-readable timestamp into a Python ``datetime`` object

    Args:
        human_timestamp (str): A timestamp string
        to_utc (bool): Convert the timestamp to UTC

    Returns:
        datetime: The converted timestamp
    """

    human_timestamp = human_timestamp.replace("-0000", "")
    human_timestamp = parenthesis_regex.sub("", human_timestamp)

    dt = parse_date(human_timestamp)
    return dt.astimezone(timezone.utc) if to_utc else dt


def human_timestamp_to_unix_timestamp(human_timestamp):
    """
    Converts a human-readable timestamp into a UNIX timestamp

    Args:
        human_timestamp (str): A timestamp in `YYYY-MM-DD HH:MM:SS`` format

    Returns:
        float: The converted timestamp
    """
    human_timestamp = human_timestamp.replace("T", " ")
    return human_timestamp_to_datetime(human_timestamp).timestamp()


def get_ip_address_country(ip_address, db_path=None):
    """
    Returns the ISO code for the country associated
    with the given IPv4 or IPv6 address

    Args:
        ip_address (str): The IP address to query for
        db_path (str): Path to a MMDB file from MaxMind or DBIP

    Returns:
        str: And ISO country code associated with the given IP address
    """
    db_paths = [
        "GeoLite2-Country.mmdb",
        "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
        "/usr/share/GeoIP/GeoLite2-Country.mmdb",
        "/var/lib/GeoIP/GeoLite2-Country.mmdb",
        "/var/local/lib/GeoIP/GeoLite2-Country.mmdb",
        "/usr/local/var/GeoIP/GeoLite2-Country.mmdb",
        "%SystemDrive%\\ProgramData\\MaxMind\\GeoIPUpdate\\GeoIP\\"
        "GeoLite2-Country.mmdb",
        "C:\\GeoIP\\GeoLite2-Country.mmdb",
        "dbip-country-lite.mmdb",
        "dbip-country.mmdb",
    ]

    if db_path is not None:
        if os.path.isfile(db_path) is False:
            db_path = None
            logger.warning(
                f"No file exists at {db_path}. Falling back to an "
                "included copy of the IPDB IP to Country "
                "Lite database."
            )

    if db_path is None:
        for system_path in db_paths:
            if os.path.exists(system_path):
                db_path = system_path
                break

    if db_path is None:
        db_path = str(
            files(parsedmarc.resources.dbip).joinpath("dbip-country-lite.mmdb")
        )

    db_age = datetime.now() - datetime.fromtimestamp(os.stat(db_path).st_mtime)
    if db_age > timedelta(days=30):
        logger.warning("IP database is more than a month old")

    db_reader = geoip2.database.Reader(db_path)

    country = None

    try:
        country = db_reader.country(ip_address).country.iso_code
    except geoip2.errors.AddressNotFoundError:
        pass

    return country


def get_service_from_reverse_dns_base_domain(
    base_domain,
    always_use_local_file=False,
    local_file_path=None,
    url=None,
    offline=False,
    reverse_dns_map=None,
):
    """
    Returns the service name of a given base domain name from reverse DNS.

    Args:
        base_domain (str): The base domain of the reverse DNS lookup
        always_use_local_file (bool): Always use a local map file
        local_file_path (str): Path to a local map file
        url (str): URL ro a reverse DNS map
        offline (bool): Use the built-in copy of the reverse DNS map
        reverse_dns_map (dict): A reverse DNS map
    Returns:
        dict: A dictionary containing name and type.
        If the service is unknown, the name will be
        the supplied reverse_dns_base_domain and the type will be None
    """

    def load_csv(_csv_file):
        reader = csv.DictReader(_csv_file)
        for row in reader:
            key = row["base_reverse_dns"].lower().strip()
            reverse_dns_map[key] = dict(name=row["name"], type=row["type"])

    base_domain = base_domain.lower().strip()
    if url is None:
        url = (
            "https://raw.githubusercontent.com/domainaware"
            "/parsedmarc/master/parsedmarc/"
            "resources/maps/base_reverse_dns_map.csv"
        )
    if reverse_dns_map is None:
        reverse_dns_map = dict()
    csv_file = io.StringIO()

    if not (offline or always_use_local_file) and len(reverse_dns_map) == 0:
        try:
            logger.debug(f"Trying to fetch reverse DNS map from {url}...")
            headers = {"User-Agent": USER_AGENT}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            csv_file.write(response.text)
            csv_file.seek(0)
            load_csv(csv_file)
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch reverse DNS map: {e}")
        except Exception:
            logger.warning("Not a valid CSV file")
            csv_file.seek(0)
            logging.debug("Response body:")
            logger.debug(csv_file.read())

    if len(reverse_dns_map) == 0:
        logger.info("Loading included reverse DNS map...")
        path = str(
            files(parsedmarc.resources.maps).joinpath("base_reverse_dns_map.csv")
        )
        if local_file_path is not None:
            path = local_file_path
        with open(path) as csv_file:
            load_csv(csv_file)
    try:
        service = reverse_dns_map[base_domain]
    except KeyError:
        service = dict(name=base_domain, type=None)

    return service


def get_ip_address_info(
    ip_address,
    ip_db_path=None,
    reverse_dns_map_path=None,
    always_use_local_files=False,
    reverse_dns_map_url=None,
    cache=None,
    reverse_dns_map=None,
    offline=False,
    nameservers=None,
    timeout=2.0,
):
    """
    Returns reverse DNS and country information for the given IP address

    Args:
        ip_address (str): The IP address to check
        ip_db_path (str): path to a MMDB file from MaxMind or DBIP
        reverse_dns_map_path (str): Path to a reverse DNS map file
        reverse_dns_map_url (str): URL to the reverse DNS map file
        always_use_local_files (bool): Do not download files
        cache (ExpiringDict): Cache storage
        reverse_dns_map (dict): A reverse DNS map
        offline (bool): Do not make online queries for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds

    Returns:
        OrderedDict: ``ip_address``, ``reverse_dns``

    """
    ip_address = ip_address.lower()
    if cache is not None:
        info = cache.get(ip_address, None)
        if info:
            logger.debug(f"IP address {ip_address} was found in cache")
            return info
    info = OrderedDict()
    info["ip_address"] = ip_address
    if offline:
        reverse_dns = None
    else:
        reverse_dns = get_reverse_dns(
            ip_address, nameservers=nameservers, timeout=timeout
        )
    country = get_ip_address_country(ip_address, db_path=ip_db_path)
    info["country"] = country
    info["reverse_dns"] = reverse_dns
    info["base_domain"] = None
    info["name"] = None
    info["type"] = None
    if reverse_dns is not None:
        base_domain = get_base_domain(reverse_dns)
        if base_domain is not None:
            service = get_service_from_reverse_dns_base_domain(
                base_domain,
                offline=offline,
                local_file_path=reverse_dns_map_path,
                url=reverse_dns_map_url,
                always_use_local_file=always_use_local_files,
                reverse_dns_map=reverse_dns_map,
            )
            info["base_domain"] = base_domain
            info["type"] = service["type"]
            info["name"] = service["name"]

        if cache is not None:
            cache[ip_address] = info
            logger.debug(f"IP address {ip_address} added to cache")
    else:
        logger.debug(f"IP address {ip_address} reverse_dns not found")

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

    return OrderedDict(
        [
            ("display_name", display_name),
            ("address", address),
            ("local", local),
            ("domain", domain),
        ]
    )


def get_filename_safe_string(string):
    """
    Converts a string to a string that is safe for a filename

    Args:
        string (str): A string to make safe for a filename

    Returns:
        str: A string safe for a filename
    """
    invalid_filename_chars = ["\\", "/", ":", '"', "*", "?", "|", "\n", "\r"]
    if string is None:
        string = "None"
    for char in invalid_filename_chars:
        string = string.replace(char, "")
    string = string.rstrip(".")

    string = (string[:100]) if len(string) > 100 else string

    return string


def is_mbox(path):
    """
    Checks if the given content is an MBOX mailbox file

    Args:
        path: Content to check

    Returns:
        bool: A flag that indicates if the file is an MBOX mailbox file
    """
    _is_mbox = False
    try:
        mbox = mailbox.mbox(path)
        if len(mbox.keys()) > 0:
            _is_mbox = True
    except Exception as e:
        logger.debug("Error checking for MBOX file: {0}".format(e.__str__()))

    return _is_mbox


def is_outlook_msg(content):
    """
    Checks if the given content is an Outlook msg OLE/MSG file

    Args:
        content: Content to check

    Returns:
        bool: A flag that indicates if the file is an Outlook MSG file
    """
    return isinstance(content, bytes) and content.startswith(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    )


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
        subprocess.check_call(
            ["msgconvert", "sample.msg"], stdout=null_file, stderr=null_file
        )
        eml_path = "sample.eml"
        with open(eml_path, "rb") as eml_file:
            rfc822 = eml_file.read()
    except FileNotFoundError:
        raise EmailParserError(
            "Failed to convert Outlook MSG: msgconvert utility not found"
        )
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

    Returns:
        dict: Parsed email data
    """

    if isinstance(data, bytes):
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
                if received["date_utc"] is None:
                    del received["date_utc"]
                else:
                    received["date_utc"] = received["date_utc"].replace("T", " ")

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
        parsed_email["reply_to"] = list(
            map(lambda x: parse_email_address(x), parsed_email["reply_to"])
        )
    else:
        parsed_email["reply_to"] = []

    if "to" in parsed_email:
        parsed_email["to"] = list(
            map(lambda x: parse_email_address(x), parsed_email["to"])
        )
    else:
        parsed_email["to"] = []

    if "cc" in parsed_email:
        parsed_email["cc"] = list(
            map(lambda x: parse_email_address(x), parsed_email["cc"])
        )
    else:
        parsed_email["cc"] = []

    if "bcc" in parsed_email:
        parsed_email["bcc"] = list(
            map(lambda x: parse_email_address(x), parsed_email["bcc"])
        )
    else:
        parsed_email["bcc"] = []

    if "delivered_to" in parsed_email:
        parsed_email["delivered_to"] = list(
            map(lambda x: parse_email_address(x), parsed_email["delivered_to"])
        )

    if "attachments" not in parsed_email:
        parsed_email["attachments"] = []
    else:
        for attachment in parsed_email["attachments"]:
            if "payload" in attachment:
                payload = attachment["payload"]
                try:
                    if "content_transfer_encoding" in attachment:
                        if attachment["content_transfer_encoding"] == "base64":
                            payload = decode_base64(payload)
                        else:
                            payload = str.encode(payload)
                    attachment["sha256"] = hashlib.sha256(payload).hexdigest()
                except Exception as e:
                    logger.debug("Unable to decode attachment: {0}".format(e.__str__()))
        if strip_attachment_payloads:
            for attachment in parsed_email["attachments"]:
                if "payload" in attachment:
                    del attachment["payload"]

    if "subject" not in parsed_email:
        parsed_email["subject"] = None

    parsed_email["filename_safe_subject"] = get_filename_safe_string(
        parsed_email["subject"]
    )

    if "body" not in parsed_email:
        parsed_email["body"] = None

    return parsed_email
