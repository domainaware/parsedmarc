# -*- coding: utf-8 -*-

"""Utility functions that might be useful for other projects"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import logging
import mailbox
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional, TypedDict, Union, cast

import mailparser
from expiringdict import ExpiringDict

try:
    from importlib.resources import files
except ImportError:
    # Try backported to PY<3 `importlib_resources`
    from importlib.resources import files


import dns.exception
import dns.resolver
import dns.reversename
import maxminddb
import publicsuffixlist
import requests
from dateutil.parser import parse as parse_date

import parsedmarc.resources.ipinfo
import parsedmarc.resources.maps
from parsedmarc.constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    USER_AGENT,
)
from parsedmarc.log import logger

# Errors considered transient and retryable by query_dns. LifetimeTimeout is
# dnspython's deadline expiry; NoNameservers typically wraps a SERVFAIL from
# upstream; OSError covers socket-level failures during TCP fallback.
_RETRYABLE_DNS_ERRORS = (
    dns.resolver.LifetimeTimeout,
    dns.resolver.NoNameservers,
    OSError,
)

parenthesis_regex = re.compile(r"\s*\(.*\)\s*")

null_file = open(os.devnull, "w")
mailparser_logger = logging.getLogger("mailparser")
mailparser_logger.setLevel(logging.CRITICAL)
psl = publicsuffixlist.PublicSuffixList()
psl_overrides: list[str] = []


def load_psl_overrides(
    *,
    always_use_local_file: bool = False,
    local_file_path: Optional[str] = None,
    url: Optional[str] = None,
    offline: bool = False,
) -> list[str]:
    """
    Loads the PSL overrides list from a URL or local file.

    Clears and repopulates the module-level ``psl_overrides`` list in place,
    then returns it. The URL is tried first; on failure (or when
    ``offline``/``always_use_local_file`` is set) the local path is used,
    defaulting to the bundled ``psl_overrides.txt``.

    Args:
        always_use_local_file (bool): Always use a local overrides file
        local_file_path (str): Path to a local overrides file
        url (str): URL to a PSL overrides file
        offline (bool): Use the built-in copy of the overrides

    Returns:
        list[str]: the module-level ``psl_overrides`` list
    """
    if url is None:
        url = (
            "https://raw.githubusercontent.com/domainaware"
            "/parsedmarc/master/parsedmarc/"
            "resources/maps/psl_overrides.txt"
        )

    psl_overrides.clear()

    def _load_text(text: str) -> None:
        for line in text.splitlines():
            s = line.strip()
            if s:
                psl_overrides.append(s)

    if not (offline or always_use_local_file):
        try:
            logger.debug(f"Trying to fetch PSL overrides from {url}...")
            headers = {"User-Agent": USER_AGENT}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            _load_text(response.text)
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch PSL overrides: {e}")

    if len(psl_overrides) == 0:
        path = local_file_path or str(
            files(parsedmarc.resources.maps).joinpath("psl_overrides.txt")
        )
        logger.info(f"Loading PSL overrides from {path}")
        with open(path, encoding="utf-8") as f:
            _load_text(f.read())

    return psl_overrides


# Bootstrap with the bundled file at import time — no network call.
load_psl_overrides(offline=True)


class EmailParserError(RuntimeError):
    """Raised when an error parsing the email occurs"""


class DownloadError(RuntimeError):
    """Raised when an error occurs when downloading a file"""


class ReverseDNSService(TypedDict):
    name: str
    type: Optional[str]


ReverseDNSMap = dict[str, ReverseDNSService]


class IPAddressInfo(TypedDict):
    ip_address: str
    reverse_dns: Optional[str]
    country: Optional[str]
    base_domain: Optional[str]
    name: Optional[str]
    type: Optional[str]


def decode_base64(data: str) -> bytes:
    """
    Decodes a base64 string, with padding being optional

    Args:
        data (str): A base64 encoded string

    Returns:
        bytes: The decoded bytes

    """
    data_bytes = bytes(data, encoding="ascii")
    missing_padding = len(data_bytes) % 4
    if missing_padding != 0:
        data_bytes += b"=" * (4 - missing_padding)
    return base64.b64decode(data_bytes)


def get_base_domain(domain: str) -> Optional[str]:
    """
    Gets the base domain name for the given domain

    .. note::
        Results are based on a list of public domain suffixes at
        https://publicsuffix.org/list/public_suffix_list.dat and overrides included in
        parsedmarc.resources.maps.psl_overrides.txt

    Args:
        domain (str): A domain or subdomain

    Returns:
        str: The base domain of the given domain

    """
    domain = domain.lower()
    publicsuffix = psl.privatesuffix(domain)
    for override in psl_overrides:
        if domain.endswith(override):
            return override.strip(".").strip("-")
    return publicsuffix


def query_dns(
    domain: str,
    record_type: str,
    *,
    cache: Optional[ExpiringDict] = None,
    nameservers: Optional[list[str]] = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    _attempt: int = 0,
) -> list[str]:
    """
    Queries DNS

    Args:
        domain (str): The domain or subdomain to query about
        record_type (str): The record type to query for
        cache (ExpiringDict): Cache storage
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default). Pass
            ``parsedmarc.constants.RECOMMENDED_DNS_NAMESERVERS`` for a
            cross-provider mix that fails over when one provider's path is
            slow or broken.
        timeout (float): Overall DNS lifetime budget in seconds per
            configured nameserver. Per-query UDP attempts are capped at
            ``min(1.0, timeout)`` so dnspython retries within the lifetime on
            transient UDP packet loss (mirroring ``dig``'s default
            ``+tries=3`` behavior); with multiple nameservers configured this
            same cap also makes a slow or broken nameserver fall through to
            the next quickly.
        retries (int): Number of times to retry the whole query after a
            timeout or other transient error (``LifetimeTimeout``,
            ``NoNameservers``, ``OSError``). Failover between configured
            nameservers happens within each attempt.

    Returns:
        list: A list of answers
    """
    domain = str(domain).lower()
    record_type = record_type.upper()
    cache_key = "{0}_{1}".format(domain, record_type)
    if cache:
        cached_records = cache.get(cache_key, None)
        if isinstance(cached_records, list):
            return cast(list[str], cached_records)

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
    # Cap per-query UDP timeout at 1s so dnspython retries within the
    # lifetime window on transient packet loss — otherwise with a single
    # nameserver and timeout == lifetime, one dropped UDP datagram consumes
    # the whole budget and raises LifetimeTimeout without a retry (dig's
    # default +tries=3 masks this case). With multiple nameservers the same
    # cap lets a slow/broken one fall through.
    resolver.timeout = min(1.0, timeout)
    if len(resolver.nameservers) > 1:
        resolver.lifetime = timeout * len(resolver.nameservers)
    else:
        resolver.lifetime = timeout
    try:
        answers = resolver.resolve(domain, record_type, lifetime=resolver.lifetime)
    except _RETRYABLE_DNS_ERRORS as e:
        _attempt += 1
        if _attempt > retries:
            raise e
        return query_dns(
            domain,
            record_type,
            cache=cache,
            nameservers=nameservers,
            timeout=timeout,
            retries=retries,
            _attempt=_attempt,
        )
    records = list(
        map(
            lambda r: r.to_text().replace('"', "").rstrip("."),
            answers,
        )
    )
    if cache:
        cache[cache_key] = records

    return records


def get_reverse_dns(
    ip_address,
    *,
    cache: Optional[ExpiringDict] = None,
    nameservers: Optional[list[str]] = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> Optional[str]:
    """
    Resolves an IP address to a hostname using a reverse DNS query

    Args:
        ip_address (str): The IP address to resolve
        cache (ExpiringDict): Cache storage
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS query timeout in seconds
        retries (int): Number of times to retry on timeout or other transient
            errors

    Returns:
        str: The reverse DNS hostname (if any)
    """
    hostname = None
    try:
        address = dns.reversename.from_address(ip_address)
        hostname = query_dns(
            str(address),
            "PTR",
            cache=cache,
            nameservers=nameservers,
            timeout=timeout,
            retries=retries,
        )[0]

    except dns.exception.DNSException as e:
        logger.debug(f"get_reverse_dns({ip_address}) exception: {e}")

    return hostname


def timestamp_to_datetime(timestamp: int) -> datetime:
    """
    Converts a UNIX/DMARC timestamp to a Python ``datetime`` object

    Args:
        timestamp (int): The timestamp

    Returns:
        datetime: The converted timestamp as a Python ``datetime`` object
    """
    return datetime.fromtimestamp(int(timestamp))


def timestamp_to_human(timestamp: int) -> str:
    """
    Converts a UNIX/DMARC timestamp to a human-readable string

    Args:
        timestamp: The timestamp

    Returns:
        str: The converted timestamp in ``YYYY-MM-DD HH:MM:SS`` format
    """
    return timestamp_to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def human_timestamp_to_datetime(
    human_timestamp: str, *, to_utc: bool = False
) -> datetime:
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


def human_timestamp_to_unix_timestamp(human_timestamp: str) -> int:
    """
    Converts a human-readable timestamp into a UNIX timestamp

    Args:
        human_timestamp (str): A timestamp in `YYYY-MM-DD HH:MM:SS`` format

    Returns:
        float: The converted timestamp
    """
    human_timestamp = human_timestamp.replace("T", " ")
    return int(human_timestamp_to_datetime(human_timestamp).timestamp())


_IP_DB_PATH: Optional[str] = None


def load_ip_db(
    *,
    always_use_local_file: bool = False,
    local_file_path: Optional[str] = None,
    url: Optional[str] = None,
    offline: bool = False,
) -> None:
    """
    Downloads the IP-to-country MMDB database from a URL and caches it
    locally. Falls back to the bundled copy on failure or when offline.

    Args:
        always_use_local_file: Always use a local/bundled database file
        local_file_path: Path to a local MMDB file
        url: URL to the MMDB database file
        offline: Do not make online requests
    """
    global _IP_DB_PATH

    if url is None:
        url = (
            "https://github.com/domainaware/parsedmarc/raw/"
            "refs/heads/master/parsedmarc/resources/ipinfo/"
            "ipinfo_lite.mmdb"
        )

    if local_file_path is not None and os.path.isfile(local_file_path):
        _IP_DB_PATH = local_file_path
        logger.info(f"Using local IP database at {local_file_path}")
        return

    cache_dir = os.path.join(tempfile.gettempdir(), "parsedmarc")
    cached_path = os.path.join(cache_dir, "ipinfo_lite.mmdb")

    if not (offline or always_use_local_file):
        try:
            logger.debug(f"Trying to fetch IP database from {url}...")
            headers = {"User-Agent": USER_AGENT}
            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()
            os.makedirs(cache_dir, exist_ok=True)
            tmp_path = cached_path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(response.content)
            shutil.move(tmp_path, cached_path)
            _IP_DB_PATH = cached_path
            logger.info("IP database updated successfully")
            return
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch IP database: {e}")
        except Exception as e:
            logger.warning(f"Failed to save IP database: {e}")

    # Fall back to a previously cached copy if available
    if os.path.isfile(cached_path):
        _IP_DB_PATH = cached_path
        logger.info("Using cached IP database")
        return

    # Final fallback: bundled copy
    _IP_DB_PATH = str(files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb"))
    logger.info("Using bundled IP database")


def get_ip_address_country(
    ip_address: str, *, db_path: Optional[str] = None
) -> Optional[str]:
    """
    Returns the ISO code for the country associated
    with the given IPv4 or IPv6 address

    Args:
        ip_address (str): The IP address to query for
        db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP

    Returns:
        str: And ISO country code associated with the given IP address
    """
    db_paths = [
        "ipinfo_lite.mmdb",
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
        if not os.path.isfile(db_path):
            logger.warning(
                f"No file exists at {db_path}. Falling back to an "
                "included copy of the IPinfo IP to Country "
                "Lite database."
            )
            db_path = None

    if db_path is None:
        for system_path in db_paths:
            if os.path.exists(system_path):
                db_path = system_path
                break

    if db_path is None:
        if _IP_DB_PATH is not None:
            db_path = _IP_DB_PATH
        else:
            db_path = str(
                files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb")
            )

    db_age = datetime.now() - datetime.fromtimestamp(os.stat(db_path).st_mtime)
    if db_age > timedelta(days=30):
        logger.warning("IP database is more than a month old")

    db_reader = maxminddb.open_database(db_path)
    record = db_reader.get(ip_address)

    # Support both the IPinfo schema (flat top-level ``country_code``) and the
    # MaxMind/DBIP schema (nested ``country.iso_code``) so users dropping in
    # their own MMDB from any of these providers keeps working.
    country: Optional[str] = None
    if isinstance(record, dict):
        code = record.get("country_code")
        if code is None:
            nested = record.get("country")
            if isinstance(nested, dict):
                code = nested.get("iso_code")
        if isinstance(code, str):
            country = code

    return country


def load_reverse_dns_map(
    reverse_dns_map: ReverseDNSMap,
    *,
    always_use_local_file: bool = False,
    local_file_path: Optional[str] = None,
    url: Optional[str] = None,
    offline: bool = False,
    psl_overrides_path: Optional[str] = None,
    psl_overrides_url: Optional[str] = None,
) -> None:
    """
    Loads the reverse DNS map from a URL or local file.

    Clears and repopulates the given map dict in place. If the map is
    fetched from a URL, that is tried first; on failure (or if offline/local
    mode is selected) the bundled CSV is used as a fallback.

    ``psl_overrides.txt`` is reloaded at the same time using the same
    ``offline`` / ``always_use_local_file`` flags (with separate path/URL
    kwargs), so map entries that depend on a recent overrides entry fold
    correctly.

    Args:
        reverse_dns_map (dict): The map dict to populate (modified in place)
        always_use_local_file (bool): Always use a local map file
        local_file_path (str): Path to a local map file
        url (str): URL to a reverse DNS map
        offline (bool): Use the built-in copy of the reverse DNS map
        psl_overrides_path (str): Path to a local PSL overrides file
        psl_overrides_url (str): URL to a PSL overrides file
    """
    # Reload PSL overrides first so any map entry that depends on a folded
    # base domain resolves correctly against the current overrides list.
    load_psl_overrides(
        always_use_local_file=always_use_local_file,
        local_file_path=psl_overrides_path,
        url=psl_overrides_url,
        offline=offline,
    )

    if url is None:
        url = (
            "https://raw.githubusercontent.com/domainaware"
            "/parsedmarc/master/parsedmarc/"
            "resources/maps/base_reverse_dns_map.csv"
        )

    reverse_dns_map.clear()

    def load_csv(_csv_file):
        reader = csv.DictReader(_csv_file)
        for row in reader:
            key = row["base_reverse_dns"].lower().strip()
            reverse_dns_map[key] = {
                "name": row["name"].strip(),
                "type": row["type"].strip(),
            }

    csv_file = io.StringIO()

    if not (offline or always_use_local_file):
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


def get_service_from_reverse_dns_base_domain(
    base_domain,
    *,
    always_use_local_file: bool = False,
    local_file_path: Optional[str] = None,
    url: Optional[str] = None,
    offline: bool = False,
    reverse_dns_map: Optional[ReverseDNSMap] = None,
) -> ReverseDNSService:
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

    base_domain = base_domain.lower().strip()
    reverse_dns_map_value: ReverseDNSMap
    if reverse_dns_map is None:
        reverse_dns_map_value = {}
    else:
        reverse_dns_map_value = reverse_dns_map

    if len(reverse_dns_map_value) == 0:
        load_reverse_dns_map(
            reverse_dns_map_value,
            always_use_local_file=always_use_local_file,
            local_file_path=local_file_path,
            url=url,
            offline=offline,
        )

    service: ReverseDNSService
    try:
        service = reverse_dns_map_value[base_domain]
    except KeyError:
        service = {"name": base_domain, "type": None}

    return service


def get_ip_address_info(
    ip_address,
    *,
    ip_db_path: Optional[str] = None,
    reverse_dns_map_path: Optional[str] = None,
    always_use_local_files: bool = False,
    reverse_dns_map_url: Optional[str] = None,
    cache: Optional[ExpiringDict] = None,
    reverse_dns_map: Optional[ReverseDNSMap] = None,
    offline: bool = False,
    nameservers: Optional[list[str]] = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> IPAddressInfo:
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
        retries (int): Number of times to retry on timeout or other transient
            errors

    Returns:
        dict: ``ip_address``, ``reverse_dns``, ``country``

    """
    ip_address = ip_address.lower()
    if cache is not None:
        cached_info = cache.get(ip_address, None)
        if (
            cached_info
            and isinstance(cached_info, dict)
            and "ip_address" in cached_info
        ):
            logger.debug(f"IP address {ip_address} was found in cache")
            return cast(IPAddressInfo, cached_info)
    info: IPAddressInfo = {
        "ip_address": ip_address,
        "reverse_dns": None,
        "country": None,
        "base_domain": None,
        "name": None,
        "type": None,
    }
    if offline:
        reverse_dns = None
    else:
        reverse_dns = get_reverse_dns(
            ip_address,
            nameservers=nameservers,
            timeout=timeout,
            retries=retries,
        )
    country = get_ip_address_country(ip_address, db_path=ip_db_path)
    info["country"] = country
    info["reverse_dns"] = reverse_dns
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


def parse_email_address(original_address: str) -> dict[str, Optional[str]]:
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

    return {
        "display_name": display_name,
        "address": address,
        "local": local,
        "domain": domain,
    }


def get_filename_safe_string(string: str) -> str:
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


def is_mbox(path: str) -> bool:
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


def is_outlook_msg(content) -> bool:
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


def convert_outlook_msg(msg_bytes: bytes) -> bytes:
    """
    Uses the ``msgconvert`` Perl utility to convert an Outlook MS file to
    standard RFC 822 format

    Args:
        msg_bytes (bytes): the content of the .msg file

    Returns:
        A RFC 822 bytes payload
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


def parse_email(
    data: Union[bytes, str], *, strip_attachment_payloads: bool = False
) -> dict:
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
