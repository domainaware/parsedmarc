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
from typing import TypedDict, cast
from urllib.parse import urlsplit

import mailparser
from expiringdict import ExpiringDict

from importlib.resources import files


import dns.exception
import dns.inet
import dns.message
import dns.nameserver
import dns.query
import dns.resolver
import dns.reversename
import httpx
import maxminddb
import publicsuffixlist
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

# The process-wide httpx client used for DNS over HTTPS queries, and the PID
# it was created under. See _get_doh_session().
_DOH_SESSION: httpx.Client | None = None
_DOH_SESSION_PID: int | None = None

parenthesis_regex = re.compile(r"\s*\(.*\)\s*")

null_file = subprocess.DEVNULL
mailparser_logger = logging.getLogger("mailparser")
mailparser_logger.setLevel(logging.CRITICAL)
psl = publicsuffixlist.PublicSuffixList()
psl_overrides: list[str] = []


def load_psl_overrides(
    *,
    always_use_local_file: bool = False,
    local_file_path: str | None = None,
    url: str | None = None,
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
        offline (bool): Do not make online requests

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
            response = httpx.get(
                url, headers=headers, timeout=60, follow_redirects=True
            )
            response.raise_for_status()
            _load_text(response.text)
        except httpx.HTTPError as e:
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
    type: str | None


ReverseDNSMap = dict[str, ReverseDNSService]


class IPAddressInfo(TypedDict):
    ip_address: str
    reverse_dns: str | None
    country: str | None
    base_domain: str | None
    name: str | None
    type: str | None
    asn: int | None
    as_name: str | None
    as_domain: str | None


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


def get_base_domain(domain: str) -> str | None:
    """
    Gets the base domain name for the given domain

    .. note::
        Results are based on a list of public domain suffixes at
        https://publicsuffix.org/list/public_suffix_list.dat and overrides included in
        parsedmarc.resources.maps.psl_overrides.txt

    Args:
        domain (str): A domain or subdomain

    Returns:
        str: The base domain of the given domain, or ``None`` if one
        cannot be determined

    """
    domain = domain.lower()
    publicsuffix = psl.privatesuffix(domain)
    for override in psl_overrides:
        if domain.endswith(override):
            return override.strip(".").strip("-")
    return publicsuffix


def _get_doh_session() -> httpx.Client:
    """
    Returns the shared ``httpx.Client`` used for DNS over HTTPS queries.

    The client is created on first use and reused afterwards, so DoH queries
    share TLS connections instead of renegotiating one per lookup. It is
    deliberately never closed: like the module's other shared state, it lives
    for the life of the process.

    The client is rebuilt when the current PID differs from the one it was
    created under, because a ``fork()``-based worker pool (``n_procs``) would
    otherwise inherit — and concurrently use — the parent's sockets.

    ``httpx.Client`` defaults are what make this work behind a corporate
    proxy: ``trust_env=True`` honors ``HTTP_PROXY``/``HTTPS_PROXY``/
    ``NO_PROXY`` and ``SSL_CERT_FILE``/``SSL_CERT_DIR``, and ``verify=True``
    keeps certificate verification on. Neither is overridden here.

    Returns:
        httpx.Client: The shared DoH client for this process
    """
    global _DOH_SESSION, _DOH_SESSION_PID
    pid = os.getpid()
    if _DOH_SESSION is None or _DOH_SESSION_PID != pid:
        _DOH_SESSION = httpx.Client(http1=True, http2=True)
        _DOH_SESSION_PID = pid
    return _DOH_SESSION


class _SessionDoHNameserver(dns.nameserver.DoHNameserver):
    """
    A DNS over HTTPS nameserver that queries through a shared ``httpx``
    client.

    dnspython's stock ``DoHNameserver`` calls ``dns.query.https()`` without a
    ``session``, which makes that function build an ``httpx.Client`` with its
    own custom transport — and httpx only reads proxy environment variables
    when no transport is supplied (``allow_env_proxies = trust_env and
    transport is None``). Stock DoH therefore ignores ``HTTPS_PROXY``
    entirely — and a proxy is the only way out of the networks this exists
    for (https://github.com/domainaware/parsedmarc/issues/880).

    Passing our own session instead gets environment proxies, environment CA
    configuration (``SSL_CERT_FILE``), and connection reuse across queries.
    ``bootstrap_address`` is deliberately not passed: with a session, the DoH
    server's hostname is resolved by httpx — locally through the OS resolver,
    or by the proxy itself via ``CONNECT`` when one is configured — so no
    UDP/53 access is required.
    """

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool = False,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return dns.query.https(
            request,
            self.url,
            timeout=timeout,
            source=source,
            source_port=source_port,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            verify=self.verify,
            post=(not self.want_get),
            http_version=self.http_version,
            session=_get_doh_session(),
        )


def _parse_dot_nameserver(entry: str) -> dns.nameserver.DoTNameserver:
    """
    Parses a ``tls://ip[:port][#hostname]`` nameserver entry.

    The optional ``#hostname`` suffix names the TLS certificate identity to
    use for SNI and verification, matching systemd-resolved's syntax.

    Args:
        entry (str): A ``tls://`` nameserver entry

    Returns:
        dns.nameserver.DoTNameserver: The parsed nameserver

    Raises:
        ValueError: The entry has no host, an unusable port, a host that
            is not a literal IP address, or extra URL components
    """
    parts = urlsplit(entry)
    try:
        port = parts.port
    except ValueError as e:
        # urlsplit only validates the port when it is accessed
        raise ValueError(f"Invalid DNS over TLS nameserver {entry}: {e}") from e
    if parts.username or parts.path or parts.query:
        # Catch tls://9.9.9.9/dns.quad9.net — a plausible slash-for-#
        # typo that would otherwise "work" with no certificate identity
        # and fail only at query time with an opaque TLS error
        raise ValueError(
            f"Invalid DNS over TLS nameserver {entry}: only "
            "tls://ip[:port][#hostname] is supported — the TLS certificate "
            "identity is given after #, not /"
        )
    address = parts.hostname
    if not address:
        raise ValueError(f"Invalid DNS over TLS nameserver {entry}: missing IP address")
    if not dns.inet.is_address(address):
        raise ValueError(
            f"Invalid DNS over TLS nameserver {entry}: {address} is not an IP "
            "address. Use tls://ip[:port][#hostname], where the optional "
            "#hostname is the TLS certificate identity of the server"
        )
    hostname = parts.fragment or None
    if port is None:
        return dns.nameserver.DoTNameserver(address, hostname=hostname)
    return dns.nameserver.DoTNameserver(address, port, hostname)


def _nameservers_to_resolver_input(
    nameservers: list[str],
) -> list[str | dns.nameserver.Nameserver]:
    """
    Converts configured nameserver strings into values that
    ``dns.resolver.Resolver.nameservers`` accepts.

    ``https://`` entries become DNS over HTTPS nameservers that share this
    process's ``httpx`` client (so proxy and CA environment variables apply),
    and ``tls://ip[:port][#hostname]`` entries become DNS over TLS
    nameservers. Everything else — plain IPv4/IPv6 addresses — is passed
    through untouched, leaving dnspython to enrich and validate it exactly as
    before.

    Args:
        nameservers (list[str]): The configured nameservers

    Returns:
        list: A list of strings and/or ``dns.nameserver.Nameserver`` objects,
        in the configured order

    Raises:
        ValueError: A ``tls://`` entry is malformed
    """
    resolver_input: list[str | dns.nameserver.Nameserver] = []
    for entry in nameservers:
        try:
            # urlsplit lowercases the scheme, so HTTPS:// and TLS:// work too
            scheme = urlsplit(entry).scheme
        except ValueError:
            # e.g. an unbalanced IPv6 bracket; let dnspython reject it with
            # its own message about what a nameserver may be
            scheme = ""
        if scheme == "https":
            resolver_input.append(_SessionDoHNameserver(entry))
        elif scheme == "tls":
            resolver_input.append(_parse_dot_nameserver(entry))
        else:
            resolver_input.append(entry)
    return resolver_input


def query_dns(
    domain: str,
    record_type: str,
    *,
    cache: ExpiringDict | None = None,
    nameservers: list[str] | None = None,
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
            slow or broken. Each entry is an IP address (DNS over UDP/TCP
            port 53), an ``https://`` URL (DNS over HTTPS, honoring the
            ``HTTP_PROXY``/``HTTPS_PROXY``/``NO_PROXY`` and ``SSL_CERT_FILE``
            environment variables), or ``tls://ip[:port][#hostname]`` (DNS
            over TLS, port 853 by default, with the optional ``#hostname``
            naming the server's TLS certificate identity).
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
    cache_key = f"{domain}_{record_type}"
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
    resolver.nameservers = _nameservers_to_resolver_input(nameservers)
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
    cache: ExpiringDict | None = None,
    nameservers: list[str] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> str | None:
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
    human_timestamp: str, *, to_utc: bool = False, assume_utc: bool = False
) -> datetime:
    """
    Converts a human-readable timestamp into a Python ``datetime`` object

    Args:
        human_timestamp (str): A timestamp string
        to_utc (bool): Convert the timestamp to UTC
        assume_utc (bool): Treat a timestamp that carries no UTC offset as
            UTC wall-clock time instead of local time. Pass this when the
            string is known to be UTC (e.g. an ``arrival_date_utc`` value);
            otherwise naive results are interpreted as local time by
            ``datetime.astimezone()`` / ``datetime.timestamp()``.

    Returns:
        datetime: The converted timestamp
    """

    human_timestamp = human_timestamp.replace("-0000", "")
    human_timestamp = parenthesis_regex.sub("", human_timestamp)

    dt = parse_date(human_timestamp)
    if assume_utc and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc) if to_utc else dt


def human_timestamp_to_unix_timestamp(
    human_timestamp: str, *, assume_utc: bool = False
) -> int:
    """
    Converts a human-readable timestamp into a UNIX timestamp

    Args:
        human_timestamp (str): A timestamp in ``YYYY-MM-DD HH:MM:SS`` format
        assume_utc (bool): Treat a timestamp that carries no UTC offset as
            UTC wall-clock time instead of local time

    Returns:
        int: The converted timestamp
    """
    human_timestamp = human_timestamp.replace("T", " ")
    return int(
        human_timestamp_to_datetime(human_timestamp, assume_utc=assume_utc).timestamp()
    )


_IP_DB_PATH: str | None = None

# The last database path logged by _get_ip_database_path(), so the
# selection is logged when it changes rather than on every lookup.
_LAST_LOGGED_IP_DB_PATH: str | None = None


def load_ip_db(
    *,
    always_use_local_file: bool = False,
    local_file_path: str | None = None,
    url: str | None = None,
    offline: bool = False,
) -> None:
    """
    Downloads the IP-to-country MMDB database from a URL and caches it
    locally. An existing ``local_file_path`` is used as-is, with no
    download. On download failure (or when offline), a previously cached
    download is used if available, falling back to the bundled copy.

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
            response = httpx.get(
                url, headers=headers, timeout=60, follow_redirects=True
            )
            response.raise_for_status()
            os.makedirs(cache_dir, exist_ok=True)
            tmp_path = cached_path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(response.content)
            shutil.move(tmp_path, cached_path)
            _IP_DB_PATH = cached_path
            logger.info("IP database updated successfully")
            return
        except httpx.HTTPError as e:
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


class _IPDatabaseRecord(TypedDict):
    country: str | None
    asn: int | None
    as_name: str | None
    as_domain: str | None


class InvalidIPinfoAPIKey(Exception):
    """Raised when the IPinfo API rejects the configured token."""


# IPinfo Lite REST API. When ``_IPINFO_API_TOKEN`` is set,
# ``get_ip_address_db_record()`` queries the API first and falls back to the
# bundled/cached MMDB on any non-2xx response or network error. A 401/403
# propagates as ``InvalidIPinfoAPIKey`` so the CLI exits fatally.
#
# The IPinfo Lite API is documented as having no daily or monthly request
# limit ("unlimited access"), so there is no rate-limit or quota handling
# here — adding it would be inventing behavior the service doesn't document.
# Authentication uses the documented ``?token=`` query parameter.
_IPINFO_API_URL = "https://api.ipinfo.io/lite"
_IPINFO_API_TOKEN: str | None = None
_IPINFO_API_TIMEOUT: float = 5.0


def configure_ipinfo_api(
    token: str | None,
    *,
    probe: bool = True,
) -> None:
    """Configure the IPinfo Lite REST API as the primary source for IP lookups.

    When a token is configured, ``get_ip_address_db_record()`` hits the API
    first for every lookup and falls back to the MMDB on network errors or
    non-2xx responses. An invalid token raises ``InvalidIPinfoAPIKey`` — the
    CLI catches that and exits fatally.

    Args:
        token: IPinfo API token. ``None`` or empty disables the API.
        probe: If ``True``, verify the token by looking up ``1.1.1.1``. A
            401/403 raises ``InvalidIPinfoAPIKey``; other errors are logged
            and the token is still accepted so per-request fallback can take
            over.
    """
    global _IPINFO_API_TOKEN
    _IPINFO_API_TOKEN = token or None

    if not _IPINFO_API_TOKEN or not probe:
        return

    # _ipinfo_api_lookup() raises InvalidIPinfoAPIKey on 401/403 (which
    # must propagate) and returns None on any other failure — network
    # errors, non-2xx responses, malformed bodies.
    if _ipinfo_api_lookup("1.1.1.1") is None:
        logger.warning("IPinfo API probe failed (will fall back per-request)")
    else:
        logger.info("IPinfo API configured")


def _ipinfo_api_lookup(ip_address: str) -> _IPDatabaseRecord | None:
    """Look up an IP via the IPinfo Lite REST API.

    Returns the normalized record on success, or ``None`` when no token is
    configured, on network error, on a malformed response body, or on any
    non-2xx response other than 401/403. 401/403 raises
    ``InvalidIPinfoAPIKey``.
    """
    if not _IPINFO_API_TOKEN:
        return None

    url = f"{_IPINFO_API_URL}/{ip_address}"
    params = {"token": _IPINFO_API_TOKEN}
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        response = httpx.get(
            url,
            headers=headers,
            params=params,
            timeout=_IPINFO_API_TIMEOUT,
            follow_redirects=True,
        )
    except httpx.HTTPError as e:
        logger.debug(f"IPinfo API request for {ip_address} failed: {e}")
        return None

    if response.status_code in (401, 403):
        raise InvalidIPinfoAPIKey(
            f"IPinfo API rejected the configured token (HTTP {response.status_code})"
        )
    if not response.is_success:
        logger.debug(
            f"IPinfo API returned HTTP {response.status_code} for {ip_address}"
        )
        return None

    try:
        payload = response.json()
    except ValueError:
        logger.debug(f"IPinfo API returned non-JSON for {ip_address}")
        return None
    if not isinstance(payload, dict):
        return None

    return _normalize_ip_record(payload)


def _normalize_ip_record(record: dict) -> _IPDatabaseRecord:
    """Normalize an IPinfo / MaxMind record to the internal shape.

    Shared between the API path and the MMDB path so both schemas produce the
    same output: country as ISO code, ASN as plain int, as_name string,
    as_domain lowercased.
    """
    country: str | None = None
    asn: int | None = None
    as_name: str | None = None
    as_domain: str | None = None

    code = record.get("country_code")
    if code is None:
        nested = record.get("country")
        if isinstance(nested, dict):
            code = nested.get("iso_code")
    if isinstance(code, str):
        country = code

    raw_asn = record.get("asn")
    if isinstance(raw_asn, int):
        asn = raw_asn
    elif isinstance(raw_asn, str) and raw_asn:
        digits = raw_asn.removeprefix("AS").removeprefix("as")
        if digits.isdigit():
            asn = int(digits)
    if asn is None:
        mm_asn = record.get("autonomous_system_number")
        if isinstance(mm_asn, int):
            asn = mm_asn

    name = record.get("as_name") or record.get("autonomous_system_organization")
    if isinstance(name, str) and name:
        as_name = name
    domain = record.get("as_domain")
    if isinstance(domain, str) and domain:
        as_domain = domain.lower()

    return {
        "country": country,
        "asn": asn,
        "as_name": as_name,
        "as_domain": as_domain,
    }


def _get_ip_database_path(db_path: str | None) -> str:
    # Last-resort fallbacks for unusual installs where the bundled database
    # is missing. Country-only databases (GeoLite2 / DBIP) lack the ASN
    # fields source attribution depends on, so an incidental system GeoIP
    # file must never shadow the parsedmarc-managed database
    # (https://github.com/domainaware/parsedmarc/issues/810). To use
    # MaxMind or DBIP data deliberately, set the ip_db_path option.
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

    if db_path is not None and not os.path.isfile(db_path):
        logger.warning(
            f"No file exists at {db_path}. Falling back to an "
            "included copy of the IPinfo IP to Country "
            "Lite database."
        )
        db_path = None

    # The database parsedmarc manages takes precedence: the one selected by
    # load_ip_db() (downloaded, cached, or bundled), or the bundled copy
    # directly for library callers that never call load_ip_db().
    if db_path is None and _IP_DB_PATH is not None:
        db_path = _IP_DB_PATH

    if db_path is None:
        bundled_path = str(
            files(parsedmarc.resources.ipinfo).joinpath("ipinfo_lite.mmdb")
        )
        if os.path.isfile(bundled_path):
            db_path = bundled_path
        else:
            for system_path in db_paths:
                if os.path.exists(system_path):
                    db_path = system_path
                    break
            else:
                # Nothing found anywhere; use the bundled path so the
                # os.stat() below raises a FileNotFoundError naming the
                # expected install location.
                db_path = bundled_path

    global _LAST_LOGGED_IP_DB_PATH
    if db_path != _LAST_LOGGED_IP_DB_PATH:
        # Log per selected path, not per lookup — this function runs on
        # every uncached IP lookup and would flood --debug output.
        logger.debug(f"Using IP database at {db_path}")
        _LAST_LOGGED_IP_DB_PATH = db_path

    db_age = datetime.now() - datetime.fromtimestamp(os.stat(db_path).st_mtime)
    if db_age > timedelta(days=30):
        logger.warning("IP database is more than a month old")

    return db_path


def get_ip_address_db_record(
    ip_address: str, *, db_path: str | None = None
) -> _IPDatabaseRecord:
    """Look up an IP and return country + ASN fields.

    If the IPinfo Lite API is configured via ``configure_ipinfo_api()``, the
    API is queried first; any non-fatal failure (a network error, or a
    non-2xx response other than 401/403) falls through to the MMDB. An
    invalid API token raises ``InvalidIPinfoAPIKey`` and is not caught here.

    IPinfo Lite carries ``country_code``, ``asn``, ``as_name``, and
    ``as_domain`` on every record. MaxMind/DBIP country-only databases carry
    only country, so ``asn`` / ``as_name`` / ``as_domain`` come back None
    for those users.
    """
    api_record = _ipinfo_api_lookup(ip_address)
    if api_record is not None:
        return api_record

    resolved_path = _get_ip_database_path(db_path)
    db_reader = maxminddb.open_database(resolved_path)
    record = db_reader.get(ip_address)
    if not isinstance(record, dict):
        return {
            "country": None,
            "asn": None,
            "as_name": None,
            "as_domain": None,
        }
    return _normalize_ip_record(record)


def get_ip_address_country(
    ip_address: str, *, db_path: str | None = None
) -> str | None:
    """
    Returns the ISO code for the country associated
    with the given IPv4 or IPv6 address.

    Args:
        ip_address (str): The IP address to query for
        db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP

    Returns:
        str: An ISO country code associated with the given IP address,
        or ``None`` if the country is unknown
    """
    return get_ip_address_db_record(ip_address, db_path=db_path)["country"]


def load_reverse_dns_map(
    reverse_dns_map: ReverseDNSMap,
    *,
    always_use_local_file: bool = False,
    local_file_path: str | None = None,
    url: str | None = None,
    offline: bool = False,
    psl_overrides_path: str | None = None,
    psl_overrides_url: str | None = None,
) -> None:
    """
    Loads the reverse DNS map from a URL or local file.

    Clears and repopulates the given map dict in place. The URL is tried
    first; on failure (or when ``offline``/``always_use_local_file`` is set)
    the local path is used, defaulting to the bundled CSV.

    ``psl_overrides.txt`` is reloaded at the same time using the same
    ``offline`` / ``always_use_local_file`` flags (with separate path/URL
    kwargs), so map entries that depend on a recent overrides entry fold
    correctly.

    Args:
        reverse_dns_map (dict): The map dict to populate (modified in place)
        always_use_local_file (bool): Always use a local map file
        local_file_path (str): Path to a local map file
        url (str): URL to a reverse DNS map
        offline (bool): Do not make online requests
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
            response = httpx.get(
                url, headers=headers, timeout=60, follow_redirects=True
            )
            response.raise_for_status()
            csv_file.write(response.text)
            csv_file.seek(0)
            load_csv(csv_file)
        except httpx.HTTPError as e:
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
    local_file_path: str | None = None,
    url: str | None = None,
    offline: bool = False,
    reverse_dns_map: ReverseDNSMap | None = None,
    psl_overrides_path: str | None = None,
    psl_overrides_url: str | None = None,
) -> ReverseDNSService:
    """
    Returns the service name of a given base domain name from reverse DNS.

    Args:
        base_domain (str): The base domain of the reverse DNS lookup
        always_use_local_file (bool): Always use a local map file
        local_file_path (str): Path to a local map file
        url (str): URL to a reverse DNS map
        offline (bool): Do not make online requests
        reverse_dns_map (dict): A reverse DNS map
        psl_overrides_path (str): Path to a local PSL overrides file
        psl_overrides_url (str): URL to a PSL overrides file

    Returns:
        dict: A dictionary containing name and type.
        If the service is unknown, the name will be
        the supplied ``base_domain`` and the type will be None
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
            psl_overrides_path=psl_overrides_path,
            psl_overrides_url=psl_overrides_url,
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
    ip_db_path: str | None = None,
    reverse_dns_map_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_url: str | None = None,
    cache: ExpiringDict | None = None,
    reverse_dns_map: ReverseDNSMap | None = None,
    offline: bool = False,
    nameservers: list[str] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    psl_overrides_path: str | None = None,
    psl_overrides_url: str | None = None,
) -> IPAddressInfo:
    """
    Returns reverse DNS, country, ASN, and service information for the
    given IP address

    Args:
        ip_address (str): The IP address to check
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        reverse_dns_map_path (str): Path to a reverse DNS map file
        always_use_local_files (bool): Do not download files
        reverse_dns_map_url (str): URL to the reverse DNS map file
        cache (ExpiringDict): Cache storage
        reverse_dns_map (dict): A reverse DNS map
        offline (bool): Do not make online queries for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds
        retries (int): Number of times to retry on timeout or other transient
            errors
        psl_overrides_path (str): Path to a local PSL overrides file
        psl_overrides_url (str): URL to a PSL overrides file

    Returns:
        dict: ``ip_address``, ``reverse_dns``, ``country``, ``base_domain``,
        ``name``, ``type``, ``asn``, ``as_name``, ``as_domain``

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
        "asn": None,
        "as_name": None,
        "as_domain": None,
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
    db_record = get_ip_address_db_record(ip_address, db_path=ip_db_path)
    info["country"] = db_record["country"]
    info["asn"] = db_record["asn"]
    info["as_name"] = db_record["as_name"]
    info["as_domain"] = db_record["as_domain"]
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
                psl_overrides_path=psl_overrides_path,
                psl_overrides_url=psl_overrides_url,
            )
            info["base_domain"] = base_domain
            info["type"] = service["type"]
            info["name"] = service["name"]
    else:
        logger.debug(f"IP address {ip_address} reverse_dns not found")
        # Fall back to ASN data for source attribution. ``reverse_dns`` and
        # ``base_domain`` are left null so consumers can still tell an
        # ASN-derived row apart from one resolved via a real PTR.
        map_value: ReverseDNSMap = (
            reverse_dns_map if reverse_dns_map is not None else {}
        )
        if len(map_value) == 0:
            load_reverse_dns_map(
                map_value,
                always_use_local_file=always_use_local_files,
                local_file_path=reverse_dns_map_path,
                url=reverse_dns_map_url,
                offline=offline,
                psl_overrides_path=psl_overrides_path,
                psl_overrides_url=psl_overrides_url,
            )
        if info["as_domain"] and info["as_domain"] in map_value:
            service = map_value[info["as_domain"]]
            info["name"] = service["name"]
            info["type"] = service["type"]
        elif info["as_name"]:
            # ASN-domain not in the map: surface the raw AS name with no
            # classification. Better than leaving the row unattributed.
            info["name"] = info["as_name"]

    # Don't cache weak-fallback attributions — rows where we had no PTR AND
    # the ASN domain wasn't in the map, so ``name`` is just the raw ``as_name``
    # from the MMDB. ``get_reverse_dns()`` swallows every ``DNSException`` as
    # ``None``, so a transient PTR lookup failure (timeout, SERVFAIL, OSError)
    # is indistinguishable from a real no-PTR case at this point. Caching the
    # weak result would poison the 4-hour cache with a misattribution even
    # after the PTR becomes resolvable again. Re-running on the next lookup
    # is cheap and either produces a proper PTR-backed match or the same
    # (still-best-effort) ASN attribution.
    weak_fallback = (
        info["reverse_dns"] is None
        and info["type"] is None
        and info["name"] is not None
        and info["name"] == info["as_name"]
    )
    if cache is not None and not weak_fallback:
        cache[ip_address] = info
        logger.debug(f"IP address {ip_address} added to cache")

    return info


def parse_email_address(original_address: str) -> dict[str, str | None]:
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


def get_filename_safe_string(string: str | None) -> str:
    """
    Converts a string to a string that is safe to use as a filename

    The returned string is a single path component, never a path: it
    contains no path separator (``/`` or ``\\``), no drive separator
    (``:``), and no NUL byte, so it cannot be absolute, drive-relative, or
    escape the directory it is joined to. It never ends in ``.`` or a
    space (Windows drops both when creating a file, which would make two
    distinct subjects collide on one name), and it is never ``.`` or ``..``
    (both consist only of stripped characters and collapse to ``""``). It
    is at most 100 characters long. It can be empty -- when the input is
    empty, consists only of stripped characters, or is truncated to a run
    of dots and spaces -- so callers that need a non-empty name must supply
    their own fallback (e.g. ``get_filename_safe_string(subject) or
    "sample"``). Windows reserved device names such as ``CON`` are not
    rewritten.

    Args:
        string (str | None): A string to make safe for a filename.
            ``None`` is treated as the literal string ``"None"``.

    Returns:
        str: A string safe for a filename
    """
    invalid_filename_chars = ["\\", "/", ":", '"', "*", "?", "|", "\n", "\r", "\x00"]
    if string is None:
        string = "None"
    for char in invalid_filename_chars:
        string = string.replace(char, "")

    # Truncate before stripping trailing dots and spaces, so that a name cut
    # off just after one cannot end in it.
    string = (string[:100]) if len(string) > 100 else string
    string = string.rstrip(". ")

    return string


def is_mbox(path: str) -> bool:
    """
    Checks if the file at the given path is an mbox mailbox file

    Args:
        path (str): Path to the file to check

    Returns:
        bool: A flag that indicates if the file is an mbox mailbox file
    """
    _is_mbox = False
    try:
        mbox = mailbox.mbox(path)
        if len(mbox.keys()) > 0:
            _is_mbox = True
    except Exception as e:
        logger.debug(f"Error checking for MBOX file: {e.__str__()}")

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
    Uses the ``msgconvert`` Perl utility to convert an Outlook MSG file to
    standard RFC 822 format

    Args:
        msg_bytes (bytes): the content of the .msg file

    Returns:
        An RFC 822 bytes payload

    Raises:
        ValueError: The supplied bytes are not an Outlook MSG file
        EmailParserError: The ``msgconvert`` utility is not installed
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


def parse_email(data: bytes | str, *, strip_attachment_payloads: bool = False) -> dict:
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
        # mailparser omits "from" from mail_json when the From header is
        # present but unparseable (e.g. an empty "From:"); headers_json may
        # still carry a "From" entry, which can be an empty list — treat
        # that the same as a missing header.
        parsed_email["from"] = parsed_email["headers"].get("From") or None

    if parsed_email["from"] is not None:
        parsed_email["from"] = parse_email_address(parsed_email["from"][0])

    if "date" in parsed_email:
        parsed_email["date"] = parsed_email["date"].replace("T", " ")
    else:
        parsed_email["date"] = None
    # mailparser's mail_json names these headers with hyphens
    # ("reply-to", "delivered-to"), not underscores. Reading the
    # underscored key always missed, so every Reply-To address was
    # silently dropped. Convert under the underscored name consumers
    # expect and drop the raw hyphenated key so the body carries a
    # single representation, matching how "to"/"cc"/"bcc" are handled.
    if "reply-to" in parsed_email:
        parsed_email["reply_to"] = list(
            map(lambda x: parse_email_address(x), parsed_email.pop("reply-to"))
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

    if "delivered-to" in parsed_email:
        parsed_email["delivered_to"] = list(
            map(lambda x: parse_email_address(x), parsed_email.pop("delivered-to"))
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
                    logger.debug(f"Unable to decode attachment: {e.__str__()}")
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
