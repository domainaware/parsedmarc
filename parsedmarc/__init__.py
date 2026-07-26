# -*- coding: utf-8 -*-

"""A Python package for parsing DMARC reports"""

from __future__ import annotations

import binascii
import email
import email.utils
import functools
import json
import logging
import mailbox
import os
import re
import shutil
import tempfile
import traceback
import xml.parsers.expat as expat
import zipfile
import zlib
from base64 import b64decode
from collections import deque
from collections.abc import Callable, Sequence
from csv import DictWriter
from datetime import date, datetime, timedelta, timezone, tzinfo
from io import BytesIO, StringIO
from typing import (
    Any,
    BinaryIO,
    cast,
)

import lxml.etree as etree
import mailparser
import xmltodict
from expiringdict import ExpiringDict
from mailsuite.smtp import send_email
from tqdm import tqdm

from parsedmarc.config import (
    IP_ADDRESS_CACHE,
    REVERSE_DNS_MAP,
    SEEN_AGGREGATE_REPORT_IDS,
    ParserConfig,
)
from parsedmarc.constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    __version__,
)
from parsedmarc.log import logger
from parsedmarc.mail import (
    GmailConnection,
    IMAPConnection,
    MailboxConnection,
    MaildirConnection,
    MSGraphConnection,
)
from parsedmarc.types import (
    AggregateReport,
    FailureReport,
    ForensicReport as ForensicReport,
    ParsedReport,
    ParsingResults,
    ReportType,
    SMTPTLSReport,
)
from parsedmarc.utils import (
    convert_outlook_msg,
    get_base_domain,
    get_ip_address_info,
    human_timestamp_to_datetime,
    is_outlook_msg,
    parse_email,
    timestamp_to_human,
)

logger.debug(f"parsedmarc v{__version__}")

feedback_report_regex = re.compile(r"^([\w\-]+): (.+)$", re.MULTILINE)
xml_header_regex = re.compile(r"^<\?xml .*?>", re.MULTILINE)
xml_schema_regex = re.compile(r"</??xs:schema.*>", re.MULTILINE)
text_report_regex = re.compile(r"\s*([a-zA-Z\s]+):\s(.+)", re.MULTILINE)
# Captures the value of any xmlns (default or prefixed) declaration so the
# RFC 9990 namespace can be detected before xmltodict drops it.
xml_namespace_regex = re.compile(
    r"""xmlns(?::[a-zA-Z_][\w.-]*)?\s*=\s*["']([^"']+)["']"""
)

# The XML namespace assigned to DMARC aggregate reports by RFC 9990.
RFC_9990_NAMESPACE = "urn:ietf:params:xml:ns:dmarc-2.0"

# PolicyOverrideType enumeration from RFC 9990. Compared to RFC 7489,
# `policy_test_mode` was added (emitted when t=y suppresses enforcement)
# and `forwarded` / `sampled_out` were removed.
RFC_9990_POLICY_OVERRIDE_TYPES = frozenset(
    {
        "local_policy",
        "mailing_list",
        "other",
        "policy_test_mode",
        "trusted_forwarder",
    }
)
RFC_7489_REMOVED_POLICY_OVERRIDE_TYPES = frozenset({"forwarded", "sampled_out"})

MAGIC_ZIP = b"\x50\x4b\x03\x04"
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_XML = b"\x3c\x3f\x78\x6d\x6c\x20"
MAGIC_XML_TAG = b"\x3c"  # '<' - XML starting with an element tag (no declaration)
MAGIC_JSON = b"\7b"

# Per-message count of consecutive failed saves, keyed on
# ``(reports_folder, str(message_uid))``. Populated only when
# ``get_dmarc_reports_from_mailbox()`` is given a ``save_callback`` that
# reports a batch as unsaved; a message whose count exceeds
# ``max_unsaved_retries`` is moved to ``{archive_folder}/Unsaved`` instead
# of being retried forever, and its entry is dropped. A successful save
# clears the entries for that batch's messages.
#
# Process-local and deliberately not persisted: a restart re-attempts every
# message still in the reports folder, which is the safe direction (retry
# rather than shelve). The key carries no connection identity, so a library
# caller processing two connections that share a folder name (two IMAP
# servers, both "INBOX") in one process could collide counters if UIDs
# happen to match; the CLI uses one connection per process. It is not a
# ``ParserConfig`` field for the same reason ``batch_size`` and the
# ``delete`` flags are not -- it governs mailbox orchestration, not
# parsing.
_FAILED_SAVE_ATTEMPTS: dict[tuple[str, str], int] = {}

EMAIL_SAMPLE_CONTENT_TYPES = (
    "text/rfc822",
    "text-rfc-822",
    "text/rfc822-headers",
    "text/rfc-822-headers",
    "message/rfc822",
    "message/rfc-822",
    "message/rfc822-headers",
    "message/rfc-822-headers",
)


class ParserError(RuntimeError):
    """Raised whenever the parser fails for some reason"""


class InvalidDMARCReport(ParserError):
    """Raised when an invalid DMARC report is encountered"""


class InvalidSMTPTLSReport(ParserError):
    """Raised when an invalid SMTP TLS report is encountered"""


class InvalidAggregateReport(InvalidDMARCReport):
    """Raised when an invalid DMARC aggregate report is encountered"""


class InvalidFailureReport(InvalidDMARCReport):
    """Raised when an invalid DMARC failure report is encountered"""


# Backward-compatible alias
InvalidForensicReport = InvalidFailureReport


def _resolve_config(
    config: ParserConfig | None,
    *,
    offline: bool = False,
    ip_db_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    strip_attachment_payloads: bool = False,
    normalize_timespan_threshold_hours: float = 24.0,
) -> ParserConfig:
    """Resolve the effective :class:`~parsedmarc.config.ParserConfig` for a
    public parsing call, from either an explicit ``config`` or the caller's
    individual option keyword arguments.

    If ``config`` is not ``None``, it is returned unchanged: per the
    documented ``config=`` contract, the individual option keyword arguments
    are ignored in favor of the config's own values, so no merging happens
    here.

    Otherwise, a new ``ParserConfig`` is built from the given keyword
    arguments. Its three cache fields are deliberately *not* left to their
    ``default_factory`` -- doing so would hand back a config with brand new,
    empty caches on every call, silently defeating cross-call IP-info
    caching and aggregate-report dedup. Instead, the module-default caches
    (:data:`IP_ADDRESS_CACHE`, :data:`SEEN_AGGREGATE_REPORT_IDS`,
    :data:`REVERSE_DNS_MAP`) are injected explicitly, so kwargs-style calls
    keep observing and mutating the same shared caches they always have.

    ``dataclasses.replace`` is deliberately not used here: it would need an
    existing ``ParserConfig`` to start from, and there isn't one on the
    kwargs path -- this function's job is to build the first one.

    ``psl_overrides_path`` / ``psl_overrides_url`` have no corresponding
    keyword arguments on the public functions (see AGENTS.md's guidance on
    justifying new config options), so they stay ``None`` on this path; they
    are only ever set via an explicitly constructed ``config=``.
    """
    if config is not None:
        return config
    return ParserConfig(
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        strip_attachment_payloads=strip_attachment_payloads,
        normalize_timespan_threshold_hours=float(normalize_timespan_threshold_hours),
        ip_address_cache=IP_ADDRESS_CACHE,
        seen_aggregate_report_ids=SEEN_AGGREGATE_REPORT_IDS,
        reverse_dns_map=REVERSE_DNS_MAP,
    )


def _exc_origin(error: BaseException) -> str:
    """Returns a ``" (raised at <file>:<line>)"`` suffix pointing at where an
    unexpected exception actually originated, but only when the parsedmarc
    logger is at ``DEBUG`` level. Returns ``""`` otherwise, so normal output is
    unchanged.

    The deepest traceback frame is the line that raised, which is the useful
    breadcrumb when a catch-all ``except Exception`` turns an unforeseen error
    into a generic ``Invalid*Report`` -- without it, the message says *what*
    failed but not *where*.
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return ""
    frames = traceback.extract_tb(error.__traceback__)
    if not frames:
        return ""
    last = frames[-1]
    return f" (raised at {last.filename}:{last.lineno})"


def _text(value: Any) -> str | None:
    """Unwrap a possibly-langAttrString value parsed by xmltodict.

    RFC 9990 changed several aggregate-report elements (extra_contact_info,
    error, comment, human_result) to type ``langAttrString`` — an
    xs:simpleContent string with an optional ``lang`` attribute. When the
    attribute is present, xmltodict parses the element as
    ``{"#text": "...", "@lang": "en"}`` instead of a plain string. Returns
    the text payload for both shapes, ``None`` for unset values, and leaves
    other scalar shapes untouched so callers can preserve whatever the
    reporter sent.
    """
    if value is None:
        return None
    if isinstance(value, dict):
        text = value.get("#text")
        return None if text is None else str(text)
    return value


def _normalize_result_word(value: Any) -> Any:
    """Lowercase a reporter-supplied enum word; RFC 7489 Appendix C and
    RFC 9990 define result/disposition types as lowercase tokens. Non-string
    values (e.g. xmltodict dicts from attribute-bearing elements) pass
    through unchanged.
    """
    return value.lower() if isinstance(value, str) else value


def _bucket_interval_by_day(
    begin: datetime,
    end: datetime,
    total_count: int,
) -> list[dict[str, Any]]:
    """
    Split the interval [begin, end) into daily buckets and distribute
    `total_count` proportionally across those buckets.

    The function:
      1. Identifies each calendar day touched by [begin, end)
      2. Computes how many seconds of the interval fall into each day
      3. Assigns counts in proportion to those overlaps
      4. Ensures the final counts sum exactly to total_count

    Args:
        begin: timezone-aware datetime, inclusive start of interval
        end: timezone-aware datetime, exclusive end of interval
        total_count: number of messages to distribute

    Returns:
        A list of dicts like:
            {
                "begin": datetime,
                "end": datetime,
                "count": int
            }
    """
    # --- Input validation ----------------------------------------------------
    if begin > end:
        raise ValueError("begin must be earlier than end")
    if begin.tzinfo is None or end.tzinfo is None:
        raise ValueError("begin and end must be timezone-aware")
    if begin.tzinfo is not end.tzinfo:
        raise ValueError("begin and end must have the same tzinfo")
    if total_count < 0:
        raise ValueError("total_count must be non-negative")

    # --- Short-circuit trivial cases -----------------------------------------
    interval_seconds = (end - begin).total_seconds()
    if interval_seconds <= 0 or total_count == 0:
        return []

    tz: tzinfo = begin.tzinfo

    # --- Step 1: Determine all calendar days touched by [begin, end) ----------
    #
    # For example:
    #   begin = Jan 1 12:00
    #   end   = Jan 3 06:00
    #
    # We need buckets for:
    #   Jan 1 12:00 → Jan 2 00:00
    #   Jan 2 00:00 → Jan 3 00:00
    #   Jan 3 00:00 → Jan 3 06:00
    #

    # Start at midnight on the day of `begin`.
    day_cursor = datetime(begin.year, begin.month, begin.day, tzinfo=tz)

    # If `begin` is earlier on that day (e.g. 10:00), we want that midnight.
    # If `begin` is past that midnight (e.g. 00:30), this is correct.
    # If `begin` is BEFORE that midnight (rare unless tz shifts), adjust:
    if day_cursor > begin:
        day_cursor -= timedelta(days=1)

    day_buckets: list[dict[str, Any]] = []

    while day_cursor < end:
        day_start = day_cursor
        day_end = day_cursor + timedelta(days=1)

        # Overlap between [begin, end) and this day
        overlap_start = max(begin, day_start)
        overlap_end = min(end, day_end)

        overlap_seconds = (overlap_end - overlap_start).total_seconds()

        if overlap_seconds > 0:
            day_buckets.append(
                {
                    "begin": overlap_start,
                    "end": overlap_end,
                    "seconds": overlap_seconds,
                }
            )

        day_cursor = day_end

    # --- Step 2: Pro-rate counts across buckets -------------------------------
    #
    # Compute the exact fractional count for each bucket:
    #     bucket_fraction = bucket_seconds / interval_seconds
    #     bucket_exact    = total_count * bucket_fraction
    #
    # Then apply a "largest remainder" rounding strategy to ensure the sum
    # equals exactly total_count.

    exact_values: list[float] = [
        (b["seconds"] / interval_seconds) * total_count for b in day_buckets
    ]

    floor_values: list[int] = [int(x) for x in exact_values]
    fractional_parts: list[float] = [x - int(x) for x in exact_values]

    # How many counts do we still need to distribute after flooring?
    remainder = total_count - sum(floor_values)

    # Sort buckets by descending fractional remainder
    indices_by_fraction = sorted(
        range(len(day_buckets)),
        key=lambda i: fractional_parts[i],
        reverse=True,
    )

    # Start with floor values
    final_counts = floor_values[:]

    # Add +1 to the buckets with the largest fractional parts
    for idx in indices_by_fraction[:remainder]:
        final_counts[idx] += 1

    # --- Step 3: Build the final per-day result list -------------------------
    results: list[dict[str, Any]] = []
    for bucket, count in zip(day_buckets, final_counts):
        if count > 0:
            results.append(
                {
                    "begin": bucket["begin"],
                    "end": bucket["end"],
                    "count": count,
                }
            )

    return results


def _append_parsed_record(
    parsed_record: dict[str, Any],
    records: list[dict[str, Any]],
    begin_dt: datetime,
    end_dt: datetime,
    normalize: bool,
) -> None:
    """
    Append a parsed DMARC record either unchanged or normalized.

    Args:
        parsed_record: The record returned by _parse_report_record().
        records: Accumulating list of output records.
        begin_dt: Report-level begin datetime (UTC).
        end_dt: Report-level end datetime (UTC).
        normalize: Whether this report exceeded the allowed timespan
                   and should be normalized per-day.
    """

    if not normalize:
        parsed_record["normalized_timespan"] = False
        parsed_record["interval_begin"] = begin_dt.strftime("%Y-%m-%d %H:%M:%S")
        parsed_record["interval_end"] = end_dt.strftime("%Y-%m-%d %H:%M:%S")

        records.append(parsed_record)
        return

    # Normalization path: break record into daily buckets
    total_count = int(parsed_record.get("count", 0))
    buckets = _bucket_interval_by_day(begin_dt, end_dt, total_count)
    if not buckets:
        return

    for part_index, bucket in enumerate(buckets):
        new_rec = parsed_record.copy()
        new_rec["count"] = bucket["count"]
        new_rec["normalized_timespan"] = True

        new_rec["interval_begin"] = bucket["begin"].strftime("%Y-%m-%d %H:%M:%S")
        new_rec["interval_end"] = bucket["end"].strftime("%Y-%m-%d %H:%M:%S")

        records.append(new_rec)


def _parse_report_record(
    record: dict[str, Any],
    *,
    config: ParserConfig,
    is_rfc_9990: bool = False,
) -> dict[str, Any]:
    """
    Converts a record from a DMARC aggregate report into a more consistent
    format

    Args:
        record (dict): The record to convert
        config (ParserConfig): Parsing and enrichment options, plus caches
        is_rfc_9990 (bool): Whether the enclosing report was detected as
            RFC 9990-shaped, for RFC 9990-aware validation warnings

    Returns:
        dict: The converted record
    """
    record = record.copy()
    new_record: dict[str, Any] = {}
    if record["row"]["source_ip"] is None:
        raise ValueError("Source IP address is empty")
    new_record_source = get_ip_address_info(
        record["row"]["source_ip"],
        cache=config.ip_address_cache,
        ip_db_path=config.ip_db_path,
        always_use_local_files=config.always_use_local_files,
        reverse_dns_map_path=config.reverse_dns_map_path,
        reverse_dns_map_url=config.reverse_dns_map_url,
        reverse_dns_map=config.reverse_dns_map,
        offline=config.offline,
        nameservers=config.nameservers,
        timeout=config.dns_timeout,
        retries=config.dns_retries,
        psl_overrides_path=config.psl_overrides_path,
        psl_overrides_url=config.psl_overrides_url,
    )
    new_record["source"] = new_record_source
    new_record["count"] = int(record["row"]["count"])
    policy_evaluated = record["row"]["policy_evaluated"].copy()
    new_policy_evaluated: dict[str, Any] = {
        "disposition": "none",
        "dkim": "fail",
        "spf": "fail",
        "policy_override_reasons": [],
    }
    if "disposition" in policy_evaluated:
        new_policy_evaluated["disposition"] = _normalize_result_word(
            policy_evaluated["disposition"]
        )
    for key in ("dkim", "spf"):
        if key in policy_evaluated:
            new_policy_evaluated[key] = _normalize_result_word(policy_evaluated[key])
    reasons = []
    spf_aligned = (
        policy_evaluated["spf"] is not None
        and policy_evaluated["spf"].lower() == "pass"
    )
    dkim_aligned = (
        policy_evaluated["dkim"] is not None
        and policy_evaluated["dkim"].lower() == "pass"
    )
    dmarc_aligned = spf_aligned or dkim_aligned
    new_record["alignment"] = dict()
    new_record["alignment"]["spf"] = spf_aligned
    new_record["alignment"]["dkim"] = dkim_aligned
    new_record["alignment"]["dmarc"] = dmarc_aligned
    if "reason" in policy_evaluated:
        if type(policy_evaluated["reason"]) is list:
            reasons = policy_evaluated["reason"]
        else:
            reasons = [policy_evaluated["reason"]]
    for reason in reasons:
        # `comment` is langAttrString in RFC 9990 — unwrap {"#text": ..., "@lang": ...}
        reason["comment"] = _text(reason.get("comment"))
        reason_type = reason.get("type")
        if is_rfc_9990 and reason_type in RFC_7489_REMOVED_POLICY_OVERRIDE_TYPES:
            logger.warning(
                "Policy override reason type %r was removed in RFC 9990; "
                "expected one of %s",
                reason_type,
                sorted(RFC_9990_POLICY_OVERRIDE_TYPES),
            )
        elif (
            is_rfc_9990
            and reason_type is not None
            and reason_type not in RFC_9990_POLICY_OVERRIDE_TYPES
        ):
            logger.warning(
                "Unknown policy override reason type %r per RFC 9990; "
                "expected one of %s",
                reason_type,
                sorted(RFC_9990_POLICY_OVERRIDE_TYPES),
            )
    new_policy_evaluated["policy_override_reasons"] = reasons
    new_record["policy_evaluated"] = new_policy_evaluated
    if "identities" in record:
        new_record["identifiers"] = record["identities"].copy()
    else:
        new_record["identifiers"] = record["identifiers"].copy()
    new_record["auth_results"] = {"dkim": [], "spf": []}
    if type(new_record["identifiers"]["header_from"]) is str:
        lowered_from = new_record["identifiers"]["header_from"].lower()
    else:
        lowered_from = ""
    new_record["identifiers"]["header_from"] = lowered_from
    if isinstance(record["auth_results"], dict):
        auth_results = record["auth_results"].copy()
        if "spf" not in auth_results:
            auth_results["spf"] = []
        if "dkim" not in auth_results:
            auth_results["dkim"] = []
    else:
        auth_results = new_record["auth_results"].copy()

    if not isinstance(auth_results["dkim"], list):
        auth_results["dkim"] = [auth_results["dkim"]]
    for result in auth_results["dkim"]:
        if "domain" in result and result["domain"] is not None:
            new_result: dict[str, Any] = {"domain": result["domain"]}
            if "selector" in result and result["selector"] is not None:
                new_result["selector"] = result["selector"]
            else:
                if is_rfc_9990:
                    logger.warning(
                        "DKIM auth result for %r is missing the 'selector' "
                        "element, which is REQUIRED by RFC 9990",
                        result["domain"],
                    )
                new_result["selector"] = "none"
            if "result" in result and result["result"] is not None:
                new_result["result"] = _normalize_result_word(result["result"])
            else:
                new_result["result"] = "none"
            new_result["human_result"] = _text(result.get("human_result"))
            new_record["auth_results"]["dkim"].append(new_result)

    if not isinstance(auth_results["spf"], list):
        auth_results["spf"] = [auth_results["spf"]]
    for result in auth_results["spf"]:
        if "domain" in result and result["domain"] is not None:
            new_result: dict[str, Any] = {"domain": result["domain"]}
            if "scope" in result and result["scope"] is not None:
                new_result["scope"] = result["scope"]
            else:
                new_result["scope"] = "mfrom"
            if "result" in result and result["result"] is not None:
                new_result["result"] = _normalize_result_word(result["result"])
            else:
                new_result["result"] = "none"
            new_result["human_result"] = _text(result.get("human_result"))
            new_record["auth_results"]["spf"].append(new_result)

    # Backfill envelope_from from the last SPF result's domain when the
    # reporter omitted the identifier or sent it empty.
    if new_record["identifiers"].get("envelope_from") is None:
        envelope_from = None
        if len(auth_results["spf"]) > 0:
            spf_result = auth_results["spf"][-1]
            if "domain" in spf_result:
                envelope_from = spf_result["domain"]
        if envelope_from is not None:
            envelope_from = str(envelope_from).lower()
        new_record["identifiers"]["envelope_from"] = envelope_from

    envelope_to = None
    if "envelope_to" in new_record["identifiers"]:
        envelope_to = new_record["identifiers"]["envelope_to"]
        del new_record["identifiers"]["envelope_to"]

    new_record["identifiers"]["envelope_to"] = envelope_to

    return new_record


def _parse_smtp_tls_failure_details(failure_details: dict[str, Any]):
    try:
        new_failure_details: dict[str, Any] = {
            "result_type": failure_details["result-type"],
            "failed_session_count": failure_details["failed-session-count"],
        }

        if "sending-mta-ip" in failure_details:
            new_failure_details["sending_mta_ip"] = failure_details["sending-mta-ip"]
        if "receiving-ip" in failure_details:
            new_failure_details["receiving_ip"] = failure_details["receiving-ip"]
        if "receiving-mx-hostname" in failure_details:
            new_failure_details["receiving_mx_hostname"] = failure_details[
                "receiving-mx-hostname"
            ]
        if "receiving-mx-helo" in failure_details:
            new_failure_details["receiving_mx_helo"] = failure_details[
                "receiving-mx-helo"
            ]
        if "additional-info-uri" in failure_details:
            new_failure_details["additional_info_uri"] = failure_details[
                "additional-info-uri"
            ]
        if "failure-reason-code" in failure_details:
            new_failure_details["failure_reason_code"] = failure_details[
                "failure-reason-code"
            ]

        return new_failure_details

    except KeyError as e:
        raise InvalidSMTPTLSReport(
            f"Missing required failure details field: {e}"
        ) from e
    except Exception as e:
        raise InvalidSMTPTLSReport(str(e) + _exc_origin(e)) from e


def _parse_smtp_tls_report_policy(policy: dict[str, Any]):
    policy_types = ["tlsa", "sts", "no-policy-found"]
    try:
        policy_domain = policy["policy"]["policy-domain"]
        policy_type = policy["policy"]["policy-type"]
        failure_details = []
        if policy_type not in policy_types:
            raise InvalidSMTPTLSReport(f"Invalid policy type {policy_type}")
        new_policy: dict[str, Any] = {
            "policy_domain": policy_domain,
            "policy_type": policy_type,
        }
        if "policy-string" in policy["policy"]:
            if isinstance(policy["policy"]["policy-string"], list):
                if len(policy["policy"]["policy-string"]) > 0:
                    new_policy["policy_strings"] = policy["policy"]["policy-string"]

        if "mx-host-pattern" in policy["policy"]:
            if isinstance(policy["policy"]["mx-host-pattern"], list):
                if len(policy["policy"]["mx-host-pattern"]) > 0:
                    new_policy["mx_host_patterns"] = policy["policy"]["mx-host-pattern"]
        new_policy["successful_session_count"] = policy["summary"][
            "total-successful-session-count"
        ]
        new_policy["failed_session_count"] = policy["summary"][
            "total-failure-session-count"
        ]
        if "failure-details" in policy:
            for details in policy["failure-details"]:
                failure_details.append(_parse_smtp_tls_failure_details(details))
            new_policy["failure_details"] = failure_details

        return new_policy

    except KeyError as e:
        raise InvalidSMTPTLSReport(f"Missing required policy field: {e}") from e
    except Exception as e:
        raise InvalidSMTPTLSReport(str(e) + _exc_origin(e)) from e


def parse_smtp_tls_report_json(report: str | bytes) -> SMTPTLSReport:
    """Parses and validates an SMTP TLS report"""
    required_fields = [
        "organization-name",
        "date-range",
        "contact-info",
        "report-id",
        "policies",
    ]

    try:
        if isinstance(report, bytes):
            report = report.decode("utf-8", errors="replace")

        policies = []
        report_dict = json.loads(report)
        for required_field in required_fields:
            if required_field not in report_dict:
                raise Exception(f"Missing required field: {required_field}]")
        if not isinstance(report_dict["policies"], list):
            policies_type = type(report_dict["policies"])
            raise InvalidSMTPTLSReport(f"policies must be a list, not {policies_type}")
        for policy in report_dict["policies"]:
            policies.append(_parse_smtp_tls_report_policy(policy))

        new_report: SMTPTLSReport = {
            "organization_name": report_dict["organization-name"],
            "begin_date": report_dict["date-range"]["start-datetime"],
            "end_date": report_dict["date-range"]["end-datetime"],
            "contact_info": report_dict["contact-info"],
            "report_id": report_dict["report-id"],
            "policies": policies,
        }

        return new_report

    except KeyError as e:
        raise InvalidSMTPTLSReport(f"Missing required field: {e}") from e
    except Exception as e:
        raise InvalidSMTPTLSReport(str(e) + _exc_origin(e)) from e


def parsed_smtp_tls_reports_to_csv_rows(
    reports: SMTPTLSReport | list[SMTPTLSReport],
) -> list[dict[str, Any]]:
    """Converts one oor more parsed SMTP TLS reports into a list of single
    layer dict objects suitable for use in a CSV"""
    if isinstance(reports, dict):
        reports = [reports]

    rows = []
    for report in reports:
        common_fields: dict[str, Any] = {
            "organization_name": report["organization_name"],
            "begin_date": report["begin_date"],
            "end_date": report["end_date"],
            "report_id": report["report_id"],
        }
        record: dict[str, Any] = common_fields.copy()
        for policy in report["policies"]:
            if "policy_strings" in policy:
                record["policy_strings"] = "|".join(policy["policy_strings"])
            if "mx_host_patterns" in policy:
                record["mx_host_patterns"] = "|".join(policy["mx_host_patterns"])
            successful_record = record.copy()
            successful_record["policy_domain"] = policy["policy_domain"]
            successful_record["policy_type"] = policy["policy_type"]
            successful_record["successful_session_count"] = policy[
                "successful_session_count"
            ]
            successful_record["failed_session_count"] = policy["failed_session_count"]
            rows.append(successful_record)
            if "failure_details" in policy:
                for failure_details in policy["failure_details"]:
                    failure_record = record.copy()
                    for key in failure_details.keys():
                        failure_record[key] = failure_details[key]
                    rows.append(failure_record)

    return rows


def parsed_smtp_tls_reports_to_csv(
    reports: SMTPTLSReport | list[SMTPTLSReport],
) -> str:
    """
    Converts one or more parsed SMTP TLS reports to flat CSV format, including
    headers

    Args:
        reports: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        str: Parsed aggregate report data in flat CSV format, including headers
    """

    fields = [
        "organization_name",
        "begin_date",
        "end_date",
        "report_id",
        "result_type",
        "successful_session_count",
        "failed_session_count",
        "policy_domain",
        "policy_type",
        "policy_strings",
        "mx_host_patterns",
        "sending_mta_ip",
        "receiving_ip",
        "receiving_mx_hostname",
        "receiving_mx_helo",
        "additional_info_uri",
        "failure_reason_code",
    ]

    csv_file_object = StringIO(newline="\n")
    writer = DictWriter(csv_file_object, fields)
    writer.writeheader()

    rows = parsed_smtp_tls_reports_to_csv_rows(reports)

    for row in rows:
        writer.writerow(row)
        csv_file_object.flush()

    return csv_file_object.getvalue()


def parse_aggregate_report_xml(
    xml: str | bytes,
    *,
    ip_db_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    offline: bool = False,
    nameservers: list[str] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    keep_alive: Callable | None = None,
    normalize_timespan_threshold_hours: float = 24.0,
    config: ParserConfig | None = None,
) -> AggregateReport:
    """Parses a DMARC XML report string and returns a consistent dict

    Args:
        xml (str | bytes): DMARC aggregate report XML (bytes are decoded
            with errors ignored)
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map file
        reverse_dns_map_url (str): URL to a reverse DNS map file
        offline (bool): Do not query online for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        timeout (float): Sets the DNS timeout in seconds
        retries (int): Number of times to retry DNS queries on timeout or
            other transient errors
        keep_alive (callable): Keep alive function. Not part of ``config``;
            always applies.
        normalize_timespan_threshold_hours (float): Normalize timespans beyond this
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, the
            individual option keyword arguments listed above are ignored in
            favor of the config's values.

    Returns:
        dict: The parsed aggregate DMARC report
    """
    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=timeout,
        dns_retries=retries,
        normalize_timespan_threshold_hours=normalize_timespan_threshold_hours,
    )
    errors = []
    # Parse XML and recover from errors
    if isinstance(xml, bytes):
        xml = xml.decode(errors="ignore")

    # Detect the XML namespace before any rewriting strips it. The dmarc-2.0
    # namespace is one of the indicators for an RFC 9990 report but it is
    # NOT a reliable sole discriminator: the <version> element value is
    # ambiguous (RFC 9990's appendix sample uses <version>1.0</version>
    # inside the dmarc-2.0 namespace), and real-world reporters frequently
    # emit RFC 9990-shaped reports without declaring the namespace at all.
    # The final `is_rfc_9990` decision is made post-parse so that
    # RFC 9990-only fields (np, testing, discovery_method, generator,
    # human_result) can also vote it in.
    xml_namespace: str | None = None
    namespace_match = xml_namespace_regex.search(xml)
    if namespace_match:
        xml_namespace = namespace_match.group(1)

    try:
        xmltodict.parse(xml)["feedback"]
    except Exception as e:
        errors.append(f"Invalid XML: {e.__str__()}")
        try:
            tree = etree.parse(
                BytesIO(xml.encode("utf-8")),
                etree.XMLParser(recover=True, resolve_entities=False),
            )
            s = etree.tostring(tree)
            xml = "" if s is None else s.decode("utf-8")
        except Exception:
            xml = "<a/>"

    try:
        # Replace XML header (sometimes they are invalid)
        xml = xml_header_regex.sub('<?xml version="1.0"?>', xml)

        # Remove invalid schema tags
        xml = xml_schema_regex.sub("", xml)

        report = xmltodict.parse(xml)["feedback"]
        report_metadata = report["report_metadata"]
        # <email> is xs:string in both RFC 7489 and RFC 9990, but defensive
        # parsing in the wild: some reporters emit it with an xml:lang or
        # similar attribute, which xmltodict turns into a dict.
        if isinstance(report_metadata.get("email"), dict):
            unwrapped = _text(report_metadata["email"])
            if unwrapped is None:
                logger.debug(
                    "Discarding malformed <email> in report_metadata: %r",
                    report_metadata["email"],
                )
            report_metadata["email"] = unwrapped
        schema = "draft"
        if "version" in report:
            schema = report["version"]
        new_report: dict[str, Any] = {
            "xml_schema": schema,
            "xml_namespace": xml_namespace,
        }
        new_report_metadata: dict[str, Any] = {}
        if report_metadata["org_name"] is None:
            if report_metadata["email"] is not None:
                report_metadata["org_name"] = report_metadata["email"].split("@")[-1]
        org_name = report_metadata["org_name"]
        if org_name is not None and " " not in org_name:
            new_org_name = get_base_domain(org_name)
            if new_org_name is not None:
                org_name = new_org_name
        if not org_name:
            logger.debug(f"Could not parse org_name from XML.\r\n{report.__str__()}")
            raise KeyError(
                "Organization name is missing. This field is a requirement "
                "for saving the report"
            )
        new_report_metadata["org_name"] = org_name
        new_report_metadata["org_email"] = report_metadata["email"]
        # extra_contact_info is langAttrString in RFC 9990 (xs:string in
        # RFC 7489) — unwrap {"#text": ..., "@lang": ...} if present.
        extra = _text(report_metadata.get("extra_contact_info"))
        new_report_metadata["org_extra_contact_info"] = extra
        new_report_metadata["report_id"] = report_metadata["report_id"]
        report_id = new_report_metadata["report_id"]
        report_id = report_id.replace("<", "").replace(">", "").split("@")[0]
        new_report_metadata["report_id"] = report_id
        date_range = report["report_metadata"]["date_range"]

        begin_ts = int(date_range["begin"].split(".")[0])
        end_ts = int(date_range["end"].split(".")[0])
        span_seconds = end_ts - begin_ts

        normalize_timespan = (
            span_seconds > cfg.normalize_timespan_threshold_hours * 3600
        )

        date_range["begin"] = timestamp_to_human(begin_ts)
        date_range["end"] = timestamp_to_human(end_ts)

        new_report_metadata["begin_date"] = date_range["begin"]
        new_report_metadata["end_date"] = date_range["end"]
        new_report_metadata["timespan_requires_normalization"] = normalize_timespan
        new_report_metadata["original_timespan_seconds"] = span_seconds
        begin_dt = human_timestamp_to_datetime(
            new_report_metadata["begin_date"], to_utc=True
        )
        end_dt = human_timestamp_to_datetime(
            new_report_metadata["end_date"], to_utc=True
        )

        # <error> is langAttrString in RFC 9990 (xs:string in RFC 7489) and
        # was cardinality-narrowed from "unbounded" to "1" in RFC 9990, but
        # the parser still accepts a list for backward compatibility with
        # RFC 7489 reports that carry multiple errors.
        if "error" in report["report_metadata"]:
            raw_errors = report["report_metadata"]["error"]
            if not isinstance(raw_errors, list):
                raw_errors = [raw_errors]
            errors = [text for text in (_text(e) for e in raw_errors) if text]
        new_report_metadata["errors"] = errors
        # <generator> is a plain xs:string in RFC 9990 but apply _text() so
        # a malformed reporter that decorates it with attributes still
        # yields a string instead of breaking downstream consumers.
        generator = _text(report_metadata.get("generator"))
        new_report_metadata["generator"] = generator
        new_report["report_metadata"] = new_report_metadata
        records = []
        policy_published = report["policy_published"]
        if type(policy_published) is list:
            policy_published = policy_published[0]

        # Final RFC 9990 detection: the dmarc-2.0 XML namespace OR any
        # RFC 9990-only field. Real-world reporters that follow the schema
        # without declaring the namespace still get RFC 9990-aware
        # warnings (missing DKIM selector, removed override-reason types,
        # etc.) and a truthful audit trail in `xml_namespace`.
        rfc_9990_only_policy_fields = {"np", "testing", "discovery_method"}
        is_rfc_9990 = (
            xml_namespace == RFC_9990_NAMESPACE
            or "generator" in report_metadata
            or any(f in policy_published for f in rfc_9990_only_policy_fields)
        )
        new_policy_published: dict[str, Any] = {}
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
                sp = policy_published["sp"]
        new_policy_published["sp"] = sp
        pct = None
        if "pct" in policy_published:
            if policy_published["pct"] is not None:
                pct = policy_published["pct"]
        new_policy_published["pct"] = pct
        fo = None
        if "fo" in policy_published:
            if policy_published["fo"] is not None:
                fo = policy_published["fo"]
        new_policy_published["fo"] = fo
        np_ = None
        if "np" in policy_published:
            if policy_published["np"] is not None:
                np_ = policy_published["np"]
                if np_ not in ("none", "quarantine", "reject"):
                    logger.warning(f"Invalid np value: {np_}")
        new_policy_published["np"] = np_
        testing = None
        if "testing" in policy_published:
            if policy_published["testing"] is not None:
                testing = policy_published["testing"]
                if testing not in ("n", "y"):
                    logger.warning(f"Invalid testing value: {testing}")
        new_policy_published["testing"] = testing
        discovery_method = None
        if "discovery_method" in policy_published:
            if policy_published["discovery_method"] is not None:
                discovery_method = policy_published["discovery_method"]
                if discovery_method not in ("psl", "treewalk"):
                    logger.warning(
                        f"Invalid discovery_method value: {discovery_method}"
                    )
        new_policy_published["discovery_method"] = discovery_method
        new_report["policy_published"] = new_policy_published

        if type(report["record"]) is list:
            for i in range(len(report["record"])):
                if keep_alive is not None and i > 0 and i % 20 == 0:
                    logger.debug("Sending keepalive cmd")
                    keep_alive()
                    logger.debug("Processed {}/{}".format(i, len(report["record"])))
                try:
                    report_record = _parse_report_record(
                        report["record"][i],
                        config=cfg,
                        is_rfc_9990=is_rfc_9990,
                    )
                    _append_parsed_record(
                        parsed_record=report_record,
                        records=records,
                        begin_dt=begin_dt,
                        end_dt=end_dt,
                        normalize=normalize_timespan,
                    )
                except Exception as e:
                    logger.warning(f"Could not parse record: {e}")

        else:
            report_record = _parse_report_record(
                report["record"],
                config=cfg,
                is_rfc_9990=is_rfc_9990,
            )
            _append_parsed_record(
                parsed_record=report_record,
                records=records,
                begin_dt=begin_dt,
                end_dt=end_dt,
                normalize=normalize_timespan,
            )

        new_report["records"] = records

        return cast(AggregateReport, new_report)

    except expat.ExpatError as error:
        raise InvalidAggregateReport(f"Invalid XML: {error.__str__()}") from error

    except KeyError as error:
        raise InvalidAggregateReport(f"Missing field: {error.__str__()}") from error
    except AttributeError as error:
        raise InvalidAggregateReport("Report missing required section") from error

    except Exception as error:
        raise InvalidAggregateReport(
            f"Unexpected error: {error.__str__()}{_exc_origin(error)}"
        ) from error


def extract_report(content: bytes | str | BinaryIO) -> str:
    """
    Extracts text from a zip or gzip file, as a base64-encoded string,
    file-like object, or bytes.

    Args:
        content: report file as a base64-encoded string, file-like object or
        bytes.

    Returns:
        str: The extracted text

    """
    file_object: BinaryIO | None = None
    header: bytes
    try:
        if isinstance(content, str):
            try:
                file_object = BytesIO(
                    b64decode(
                        content.replace("\n", "").replace("\r", ""), validate=True
                    )
                )
            except binascii.Error:
                return content
            header = file_object.read(6)
            file_object.seek(0)
        elif isinstance(content, (bytes)):
            file_object = BytesIO(bytes(content))
            header = file_object.read(6)
            file_object.seek(0)
        else:
            stream = cast(BinaryIO, content)
            seekable = getattr(stream, "seekable", None)
            can_seek = False
            if callable(seekable):
                try:
                    can_seek = bool(seekable())
                except Exception:
                    can_seek = False

            if can_seek:
                header_raw = stream.read(6)
                if isinstance(header_raw, str):
                    raise ParserError("File objects must be opened in binary (rb) mode")
                header = bytes(header_raw)
                stream.seek(0)
                file_object = stream
            else:
                header_raw = stream.read(6)
                if isinstance(header_raw, str):
                    raise ParserError("File objects must be opened in binary (rb) mode")
                header = bytes(header_raw)
                remainder = stream.read()
                file_object = BytesIO(header + bytes(remainder))

        if header[: len(MAGIC_ZIP)] == MAGIC_ZIP:
            _zip = zipfile.ZipFile(file_object)
            report = _zip.open(_zip.namelist()[0]).read().decode(errors="ignore")
        elif header[: len(MAGIC_GZIP)] == MAGIC_GZIP:
            report = zlib.decompress(file_object.read(), zlib.MAX_WBITS | 16).decode(
                errors="ignore"
            )
        elif (
            header[: len(MAGIC_XML)] == MAGIC_XML
            or header[: len(MAGIC_XML_TAG)] == MAGIC_XML_TAG
            or header[: len(MAGIC_JSON)] == MAGIC_JSON
        ):
            report = file_object.read().decode(errors="ignore")
        else:
            raise ParserError("Not a valid zip, gzip, json, or xml file")

    except Exception as error:
        raise ParserError(
            f"Invalid archive file: {error.__str__()}{_exc_origin(error)}"
        ) from error
    finally:
        if file_object:
            try:
                file_object.close()
            except Exception:
                pass

    return report


def extract_report_from_file_path(
    file_path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
) -> str:
    """Extracts report from a file at the given file_path"""
    try:
        with open(os.fspath(file_path), "rb") as report_file:
            return extract_report(report_file.read())
    except FileNotFoundError:
        raise ParserError("File was not found")


def parse_aggregate_report_file(
    _input: str | bytes | BinaryIO,
    *,
    offline: bool = False,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    ip_db_path: str | None = None,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    keep_alive: Callable | None = None,
    normalize_timespan_threshold_hours: float = 24.0,
    config: ParserConfig | None = None,
) -> AggregateReport:
    """Parses a file at the given path, a file-like object. or bytes as an
    aggregate DMARC report

    Args:
        _input (str | bytes | IO): A path to a file, a file like object, or bytes
        offline (bool): Do not query online for geolocation or DNS
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map file
        reverse_dns_map_url (str): URL to a reverse DNS map file
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        dns_retries (int): Number of times to retry DNS queries on timeout
            or other transient errors
        keep_alive (callable): Keep alive function. Not part of ``config``;
            always applies.
        normalize_timespan_threshold_hours (float): Normalize timespans beyond this
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, the
            individual option keyword arguments listed above are ignored in
            favor of the config's values.

    Returns:
        dict: The parsed DMARC aggregate report
    """
    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        normalize_timespan_threshold_hours=normalize_timespan_threshold_hours,
    )

    try:
        xml = extract_report(_input)
    except Exception as e:
        raise InvalidAggregateReport(str(e) + _exc_origin(e)) from e

    return parse_aggregate_report_xml(
        xml,
        config=cfg,
        keep_alive=keep_alive,
    )


def parsed_aggregate_reports_to_csv_rows(
    reports: AggregateReport | list[AggregateReport],
) -> list[dict[str, Any]]:
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

    if isinstance(reports, dict):
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
        normalized_timespan = report["report_metadata"][
            "timespan_requires_normalization"
        ]
        errors = "|".join(report["report_metadata"]["errors"])
        domain = report["policy_published"]["domain"]
        adkim = report["policy_published"]["adkim"]
        aspf = report["policy_published"]["aspf"]
        p = report["policy_published"]["p"]
        sp = report["policy_published"]["sp"]
        pct = report["policy_published"]["pct"]
        fo = report["policy_published"]["fo"]
        np_ = report["policy_published"].get("np", None)
        testing = report["policy_published"].get("testing", None)
        discovery_method = report["policy_published"].get("discovery_method", None)

        report_dict: dict[str, Any] = dict(
            xml_schema=xml_schema,
            org_name=org_name,
            org_email=org_email,
            org_extra_contact_info=org_extra_contact,
            report_id=report_id,
            begin_date=begin_date,
            end_date=end_date,
            normalized_timespan=normalized_timespan,
            errors=errors,
            domain=domain,
            adkim=adkim,
            aspf=aspf,
            p=p,
            sp=sp,
            np=np_,
            pct=pct,
            fo=fo,
            testing=testing,
            discovery_method=discovery_method,
        )

        for record in report["records"]:
            row: dict[str, Any] = report_dict.copy()
            row["begin_date"] = record["interval_begin"]
            row["end_date"] = record["interval_end"]
            row["source_ip_address"] = record["source"]["ip_address"]
            row["source_country"] = record["source"]["country"]
            row["source_reverse_dns"] = record["source"]["reverse_dns"]
            row["source_base_domain"] = record["source"]["base_domain"]
            row["source_name"] = record["source"]["name"]
            row["source_type"] = record["source"]["type"]
            row["source_asn"] = record["source"]["asn"]
            row["source_as_name"] = record["source"]["as_name"]
            row["source_as_domain"] = record["source"]["as_domain"]
            row["count"] = record["count"]
            row["spf_aligned"] = record["alignment"]["spf"]
            row["dkim_aligned"] = record["alignment"]["dkim"]
            row["dmarc_aligned"] = record["alignment"]["dmarc"]
            row["disposition"] = record["policy_evaluated"]["disposition"]
            policy_override_reasons = list(
                map(
                    lambda r_: r_["type"] or "none",
                    record["policy_evaluated"]["policy_override_reasons"],
                )
            )
            policy_override_comments = list(
                map(
                    lambda r_: r_["comment"] or "none",
                    record["policy_evaluated"]["policy_override_reasons"],
                )
            )
            row["policy_override_reasons"] = ",".join(policy_override_reasons)
            row["policy_override_comments"] = "|".join(policy_override_comments)
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
                r[k] = ""

    return rows


def parsed_aggregate_reports_to_csv(
    reports: AggregateReport | list[AggregateReport],
) -> str:
    """
    Converts one or more parsed aggregate reports to flat CSV format, including
    headers

    Args:
        reports: A parsed aggregate report or list of parsed aggregate reports

    Returns:
        str: Parsed aggregate report data in flat CSV format, including headers
    """

    fields = [
        "xml_schema",
        "org_name",
        "org_email",
        "org_extra_contact_info",
        "report_id",
        "begin_date",
        "end_date",
        "normalized_timespan",
        "errors",
        "domain",
        "adkim",
        "aspf",
        "p",
        "sp",
        "np",
        "pct",
        "fo",
        "testing",
        "discovery_method",
        "source_ip_address",
        "source_country",
        "source_reverse_dns",
        "source_base_domain",
        "source_name",
        "source_type",
        "source_asn",
        "source_as_name",
        "source_as_domain",
        "count",
        "spf_aligned",
        "dkim_aligned",
        "dmarc_aligned",
        "disposition",
        "policy_override_reasons",
        "policy_override_comments",
        "envelope_from",
        "header_from",
        "envelope_to",
        "dkim_domains",
        "dkim_selectors",
        "dkim_results",
        "spf_domains",
        "spf_scopes",
        "spf_results",
    ]

    csv_file_object = StringIO(newline="\n")
    writer = DictWriter(csv_file_object, fields)
    writer.writeheader()

    rows = parsed_aggregate_reports_to_csv_rows(reports)

    for row in rows:
        writer.writerow(row)
        csv_file_object.flush()

    return csv_file_object.getvalue()


def parse_failure_report(
    feedback_report: str,
    sample: str,
    msg_date: datetime,
    *,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    offline: bool = False,
    ip_db_path: str | None = None,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    strip_attachment_payloads: bool = False,
    config: ParserConfig | None = None,
) -> FailureReport:
    """
    Converts a DMARC failure report and sample to a dict

    Args:
        feedback_report (str): A message's feedback report as a string
        sample (str): The RFC 822 headers or RFC 822 message sample
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map file
        reverse_dns_map_url (str): URL to a reverse DNS map file
        offline (bool): Do not query online for geolocation or DNS
        msg_date (str): The message's date header
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        dns_retries (int): Number of times to retry DNS queries on timeout
            or other transient errors
        strip_attachment_payloads (bool): Remove attachment payloads from
            failure report results
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, the
            individual option keyword arguments listed above are ignored in
            favor of the config's values.

    Returns:
        dict: A parsed report and sample
    """
    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        strip_attachment_payloads=strip_attachment_payloads,
    )
    delivery_results = ["delivered", "spam", "policy", "reject", "other"]

    try:
        parsed_report: dict[str, Any] = {}
        report_values = feedback_report_regex.findall(feedback_report)
        for report_value in report_values:
            key = report_value[0].lower().replace("-", "_")
            parsed_report[key] = report_value[1]

        if "arrival_date" not in parsed_report:
            if msg_date is None:
                raise InvalidFailureReport("Failure sample is not a valid email")
            parsed_report["arrival_date"] = msg_date.isoformat()

        if "version" not in parsed_report:
            parsed_report["version"] = None

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
            parsed_report["arrival_date"], to_utc=True
        )
        arrival_utc = arrival_utc.strftime("%Y-%m-%d %H:%M:%S")
        parsed_report["arrival_date_utc"] = arrival_utc

        ip_address = re.split(r"\s", parsed_report["source_ip"]).pop(0)
        parsed_report_source = get_ip_address_info(
            ip_address,
            cache=cfg.ip_address_cache,
            ip_db_path=cfg.ip_db_path,
            always_use_local_files=cfg.always_use_local_files,
            reverse_dns_map_path=cfg.reverse_dns_map_path,
            reverse_dns_map_url=cfg.reverse_dns_map_url,
            reverse_dns_map=cfg.reverse_dns_map,
            offline=cfg.offline,
            nameservers=cfg.nameservers,
            timeout=cfg.dns_timeout,
            retries=cfg.dns_retries,
            psl_overrides_path=cfg.psl_overrides_path,
            psl_overrides_url=cfg.psl_overrides_url,
        )
        parsed_report["source"] = parsed_report_source
        del parsed_report["source_ip"]

        # Identity-Alignment is REQUIRED per RFC 9991 §4. Default silently for
        # backward compatibility with pre-9991 reporters, but log so the
        # offending reporter is visible. Values are CFWS-separated per the
        # ABNF, so each mechanism is stripped after splitting.
        if "identity_alignment" not in parsed_report:
            logger.warning(
                "Failure report missing required 'Identity-Alignment' "
                "field (RFC 9991 §4); defaulting to no aligned mechanisms"
            )
            parsed_report["authentication_mechanisms"] = []
        else:
            raw_alignment = parsed_report["identity_alignment"].strip()
            if raw_alignment.lower() == "none":
                parsed_report["authentication_mechanisms"] = []
            else:
                parsed_report["authentication_mechanisms"] = [
                    m.strip() for m in raw_alignment.split(",") if m.strip()
                ]
            del parsed_report["identity_alignment"]

        # Auth-Failure is REQUIRED per RFC 9991 §4. Comma-separated per ABNF
        # so strip each token.
        if "auth_failure" not in parsed_report:
            logger.warning(
                "Failure report missing required 'Auth-Failure' field "
                "(RFC 9991 §4); defaulting to 'dmarc'"
            )
            parsed_report["auth_failure"] = "dmarc"
        parsed_report["auth_failure"] = [
            f.strip() for f in parsed_report["auth_failure"].split(",") if f.strip()
        ]

        # Feedback-Type is REQUIRED per RFC 5965 §3.1, but some gateways
        # (e.g. Exim/cPanel-based ones that send a plain-text summary without
        # a machine-readable message/feedback-report part) omit it. The
        # Elasticsearch/OpenSearch outputs require the key, so default it
        # instead of dropping the report there (see issue #332).
        if "feedback_type" not in parsed_report:
            logger.warning(
                "Failure report missing required 'Feedback-Type' field "
                "(RFC 5965 §3.1); defaulting to 'auth-failure'"
            )
            parsed_report["feedback_type"] = "auth-failure"

        # Authentication-Results is likewise REQUIRED per RFC 6591 §3.1 and
        # required by the Elasticsearch/OpenSearch outputs.
        if "authentication_results" not in parsed_report:
            logger.warning(
                "Failure report missing required 'Authentication-Results' "
                "field (RFC 6591 §3.1); defaulting to None"
            )
            parsed_report["authentication_results"] = None

        optional_fields = [
            "original_envelope_id",
            "dkim_domain",
            "original_mail_from",
            "original_rcpt_to",
        ]
        for optional_field in optional_fields:
            if optional_field not in parsed_report:
                parsed_report[optional_field] = None

        parsed_sample = parse_email(
            sample, strip_attachment_payloads=cfg.strip_attachment_payloads
        )

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

        return cast(FailureReport, parsed_report)

    except KeyError as error:
        raise InvalidFailureReport(f"Missing value: {error.__str__()}") from error

    except Exception as error:
        raise InvalidFailureReport(
            f"Unexpected error: {error.__str__()}{_exc_origin(error)}"
        ) from error


def parsed_failure_reports_to_csv_rows(
    reports: FailureReport | list[FailureReport],
) -> list[dict[str, Any]]:
    """
    Converts one or more parsed failure reports to a list of dicts in flat CSV
    format

    Args:
        reports: A parsed failure report or list of parsed failure reports

    Returns:
        list: Parsed failure report data as a list of dicts in flat CSV format
    """
    if isinstance(reports, dict):
        reports = [reports]

    rows = []

    for report in reports:
        row: dict[str, Any] = dict(report)
        row["source_ip_address"] = report["source"]["ip_address"]
        row["source_reverse_dns"] = report["source"]["reverse_dns"]
        row["source_base_domain"] = report["source"]["base_domain"]
        row["source_name"] = report["source"]["name"]
        row["source_type"] = report["source"]["type"]
        row["source_asn"] = report["source"]["asn"]
        row["source_as_name"] = report["source"]["as_name"]
        row["source_as_domain"] = report["source"]["as_domain"]
        row["source_country"] = report["source"]["country"]
        del row["source"]
        row["subject"] = report["parsed_sample"].get("subject")
        row["auth_failure"] = ",".join(report["auth_failure"])
        authentication_mechanisms = report["authentication_mechanisms"]
        row["authentication_mechanisms"] = ",".join(authentication_mechanisms)
        del row["sample"]
        del row["parsed_sample"]
        rows.append(row)

    return rows


def parsed_failure_reports_to_csv(
    reports: FailureReport | list[FailureReport],
) -> str:
    """
    Converts one or more parsed failure reports to flat CSV format, including
    headers

    Args:
        reports: A parsed failure report or list of parsed failure reports

    Returns:
        str: Parsed failure report data in flat CSV format, including headers
    """
    fields = [
        "feedback_type",
        "user_agent",
        "version",
        "original_envelope_id",
        "original_mail_from",
        "original_rcpt_to",
        "arrival_date",
        "arrival_date_utc",
        "subject",
        "message_id",
        "authentication_results",
        "dkim_domain",
        "source_ip_address",
        "source_country",
        "source_reverse_dns",
        "source_base_domain",
        "source_name",
        "source_type",
        "source_asn",
        "source_as_name",
        "source_as_domain",
        "delivery_result",
        "auth_failure",
        "reported_domain",
        "authentication_mechanisms",
        "sample_headers_only",
    ]

    csv_file = StringIO()
    csv_writer = DictWriter(csv_file, fieldnames=fields)
    csv_writer.writeheader()

    rows = parsed_failure_reports_to_csv_rows(reports)

    for row in rows:
        new_row: dict[str, Any] = {}
        for key in fields:
            new_row[key] = row.get(key)
        csv_writer.writerow(new_row)

    return csv_file.getvalue()


def parse_report_email(
    input_: bytes | str,
    *,
    offline: bool = False,
    ip_db_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    strip_attachment_payloads: bool = False,
    keep_alive: Callable | None = None,
    normalize_timespan_threshold_hours: float = 24.0,
    config: ParserConfig | None = None,
) -> ParsedReport:
    """
    Parses a DMARC report from an email

    Args:
        input_: An emailed DMARC report in RFC 822 format, as bytes or a string
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map
        reverse_dns_map_url (str): URL to a reverse DNS map
        offline (bool): Do not query online for geolocation on DNS
        nameservers (list): A list of one or more nameservers to use
        dns_timeout (float): Sets the DNS timeout in seconds
        dns_retries (int): Number of times to retry DNS queries on timeout
            or other transient errors
        strip_attachment_payloads (bool): Remove attachment payloads from
            failure report results
        keep_alive (callable): keep alive function. Not part of ``config``;
            always applies.
        normalize_timespan_threshold_hours (float): Normalize timespans beyond this
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, the
            individual option keyword arguments listed above are ignored in
            favor of the config's values.

    Returns:
        dict:
        * ``report_type``: ``aggregate`` or ``failure``
        * ``report``: The parsed report
    """
    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        strip_attachment_payloads=strip_attachment_payloads,
        normalize_timespan_threshold_hours=normalize_timespan_threshold_hours,
    )
    result: ParsedReport | None = None
    msg_date: datetime = datetime.now(timezone.utc)

    try:
        input_data: str | bytes | bytearray | memoryview = input_
        if isinstance(input_data, (bytes, bytearray, memoryview)):
            input_bytes = bytes(input_data)
            if is_outlook_msg(input_bytes):
                converted = convert_outlook_msg(input_bytes)
                if isinstance(converted, str):
                    input_str = converted
                else:
                    input_str = bytes(converted).decode(
                        encoding="utf8", errors="replace"
                    )
            else:
                input_str = input_bytes.decode(encoding="utf8", errors="replace")
        else:
            input_str = input_data

        msg = mailparser.parse_from_string(input_str)
        msg_headers = json.loads(msg.headers_json)
        if "Date" in msg_headers:
            msg_date = human_timestamp_to_datetime(msg_headers["Date"])
        date = email.utils.format_datetime(msg_date)
        msg = email.message_from_string(input_str)

    except Exception as e:
        raise ParserError(e.__str__() + _exc_origin(e)) from e
    subject = None
    feedback_report = None
    smtp_tls_report = None
    sample = None
    is_feedback_report: bool = False
    if "From" in msg_headers:
        logger.info("Parsing mail from {} on {}".format(msg_headers["From"], date))
    if "Subject" in msg_headers:
        subject = msg_headers["Subject"]
    for part in msg.walk():
        content_type = part.get_content_type().lower()
        payload_obj = part.get_payload()
        if not isinstance(payload_obj, list):
            payload_obj = [payload_obj]
        payload = str(payload_obj[0])
        if content_type.startswith("multipart/"):
            continue
        if content_type == "text/html":
            continue
        elif content_type == "message/feedback-report":
            is_feedback_report = True
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
        elif is_feedback_report and content_type in EMAIL_SAMPLE_CONTENT_TYPES:
            sample = payload
        elif content_type == "application/tlsrpt+json":
            if not payload.strip().startswith("{"):
                payload = b64decode(payload).decode("utf-8", errors="replace")
            smtp_tls_report = parse_smtp_tls_report_json(payload)
            return {"report_type": "smtp_tls", "report": smtp_tls_report}
        elif content_type == "application/tlsrpt+gzip":
            payload = extract_report(payload)
            smtp_tls_report = parse_smtp_tls_report_json(payload)
            return {"report_type": "smtp_tls", "report": smtp_tls_report}
        elif content_type == "text/plain":
            if "A message claiming to be from you has failed" in payload:
                try:
                    parts = payload.split("detected.", 1)
                    field_matches = text_report_regex.findall(parts[0])
                    fields = dict()
                    for match in field_matches:
                        field_name = match[0].lower().replace(" ", "-")
                        fields[field_name] = match[1].strip()

                    feedback_report = "Arrival-Date: {}\nSource-IP: {}".format(
                        fields["received-date"], fields["sender-ip-address"]
                    )
                except Exception as e:
                    error = f'Unable to parse message with subject "{subject}": {e}{_exc_origin(e)}'
                    raise InvalidDMARCReport(error) from e

                sample = parts[1].lstrip()
                logger.debug(sample)
        else:
            try:
                payload_bytes = b64decode(payload)
                if payload_bytes.startswith(MAGIC_ZIP) or payload_bytes.startswith(
                    MAGIC_GZIP
                ):
                    payload_text = extract_report(payload_bytes)
                else:
                    payload_text = payload_bytes.decode("utf-8", errors="replace")

                if payload_text.strip().startswith("{"):
                    smtp_tls_report = parse_smtp_tls_report_json(payload_text)
                    result = {"report_type": "smtp_tls", "report": smtp_tls_report}
                    return result
                elif payload_text.strip().startswith("<"):
                    aggregate_report = parse_aggregate_report_xml(
                        payload_text,
                        config=cfg,
                        keep_alive=keep_alive,
                    )
                    result = {"report_type": "aggregate", "report": aggregate_report}

                    return result

            except (TypeError, ValueError, binascii.Error):
                pass

            except InvalidDMARCReport as e:
                error = (
                    f'Message with subject "{subject}" is not a valid DMARC report: {e}'
                )
                raise ParserError(error) from e

            except Exception as e:
                error = f'Unable to parse message with subject "{subject}": {e}{_exc_origin(e)}'
                raise ParserError(error) from e

    if feedback_report and sample:
        try:
            failure_report = parse_failure_report(
                feedback_report,
                sample,
                msg_date,
                config=cfg,
            )
        except InvalidFailureReport as e:
            error = (
                f'Message with subject "{subject}" '
                "is not a valid "
                f"failure DMARC report: {e}"
            )
            raise InvalidFailureReport(error) from e

        result = {"report_type": "failure", "report": failure_report}
        return result

    if result is None:
        error = f'Message with subject "{subject}" is not a valid report'
        raise InvalidDMARCReport(error)

    return result


# An RFC 5322 header field name (printable ASCII excluding the colon) followed
# by a colon at the start of a line, or an mbox "From " separator.
_email_header_regex = re.compile(r"^(From |[\x21-\x39\x3b-\x7e]+:)")


def _looks_like_email(text: str) -> bool:
    """Returns True if the first line looks like an email header.

    Callers pass already-``lstrip()``-ed text, so the first line is the first
    meaningful line.
    """
    first_line = text.split("\n", 1)[0]
    return _email_header_regex.match(first_line) is not None


def _describe_parse_failure(
    content: str | bytes,
    aggregate_error: InvalidAggregateReport,
    smtp_tls_error: InvalidSMTPTLSReport,
    email_error: InvalidDMARCReport,
) -> str:
    """Builds a human-readable reason for a parse_report_file failure.

    parse_report_file tries the aggregate XML, SMTP TLS JSON, and report-email
    parsers in turn; when all three reject the input, only the parser for the
    format the content actually resembles produced a meaningful error. The
    other two are noise -- a malformed aggregate report is also "not JSON" and
    "not an email". Sniff the leading non-whitespace byte to surface the single
    relevant reason.
    """
    if isinstance(content, (bytes, bytearray, memoryview)):
        sniff = bytes(content)[:512].decode("utf-8", errors="replace")
    else:
        sniff = content[:512]
    sniff = sniff.lstrip()

    if sniff.startswith("<"):
        return f"Invalid aggregate report: {aggregate_error}"
    if sniff.startswith("{"):
        return f"Invalid SMTP TLS report: {smtp_tls_error}"
    if _looks_like_email(sniff):
        return f"Invalid report email: {email_error}"
    return (
        "Not a recognized report format (not a DMARC aggregate XML report, "
        "an SMTP TLS JSON report, or a DMARC report email)"
    )


def parse_report_file(
    input_: bytes | str | os.PathLike[str] | os.PathLike[bytes] | BinaryIO,
    *,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    strip_attachment_payloads: bool = False,
    ip_db_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    offline: bool = False,
    keep_alive: Callable | None = None,
    normalize_timespan_threshold_hours: float = 24.0,
    config: ParserConfig | None = None,
) -> ParsedReport:
    """Parses a DMARC aggregate or failure file at the given path, a
    file-like object. or bytes

    Args:
        input_ (str | os.PathLike | bytes | BinaryIO): A path to a file,
            a file-like object, or bytes
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        dns_retries (int): Number of times to retry DNS queries on timeout
            or other transient errors
        strip_attachment_payloads (bool): Remove attachment payloads from
            failure report results
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map
        reverse_dns_map_url (str): URL to a reverse DNS map
        offline (bool): Do not make online queries for geolocation or DNS
        keep_alive (callable): Keep alive function. Not part of ``config``;
            always applies.
        normalize_timespan_threshold_hours (float): Normalize timespans beyond this
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, the
            individual option keyword arguments listed above are ignored in
            favor of the config's values.

    Returns:
        dict: The parsed DMARC report
    """
    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        strip_attachment_payloads=strip_attachment_payloads,
        normalize_timespan_threshold_hours=normalize_timespan_threshold_hours,
    )
    file_object: BinaryIO
    if isinstance(input_, (str, os.PathLike)):
        file_path = os.fspath(input_)
        logger.debug(f"Parsing {file_path}")
        file_object = open(file_path, "rb")
    elif isinstance(input_, (bytes, bytearray, memoryview)):
        file_object = BytesIO(bytes(input_))
    else:
        file_object = input_

    content = file_object.read()
    file_object.close()
    if content.startswith(MAGIC_ZIP) or content.startswith(MAGIC_GZIP):
        content = extract_report(content)

    results: ParsedReport | None = None

    # parse_report_file tries the three report formats in turn. When all three
    # reject the input, keep each format's specific error so the final message
    # can explain *why* the file is invalid instead of a bare "Not a valid
    # report" (see _describe_parse_failure).
    try:
        report = parse_aggregate_report_file(
            content,
            config=cfg,
            keep_alive=keep_alive,
        )
        results = {"report_type": "aggregate", "report": report}
    except InvalidAggregateReport as aggregate_error:
        try:
            report = parse_smtp_tls_report_json(content)
            results = {"report_type": "smtp_tls", "report": report}
        except InvalidSMTPTLSReport as smtp_tls_error:
            try:
                results = parse_report_email(
                    content,
                    config=cfg,
                    keep_alive=keep_alive,
                )
            except InvalidDMARCReport as email_error:
                raise ParserError(
                    _describe_parse_failure(
                        content, aggregate_error, smtp_tls_error, email_error
                    )
                ) from email_error

    if results is None:
        raise ParserError("Not a valid report")
    return results


def _classify_parsed_email(
    parsed_email: ParsedReport,
    aggregate_reports: list[AggregateReport],
    failure_reports: list[FailureReport],
    smtp_tls_reports: list[SMTPTLSReport],
    *,
    seen_aggregate_report_ids: ExpiringDict,
    pending_aggregate_keys: set[str] | None = None,
) -> ReportType:
    """Classify a parsed report email, appending it to the matching list.

    Owns the seen-aggregate-report-ID dedup check against
    ``seen_aggregate_report_ids``: an aggregate report already seen (keyed
    on ``{org_name}_{report_id}``) is logged and dropped instead of
    appended. Shared, unmodified, by the sequential and parallel branches
    of ``get_dmarc_reports_from_mbox`` and ``get_dmarc_reports_from_mailbox``
    so both dedup identically -- callers pass the config's
    ``seen_aggregate_report_ids`` cache so dedup state stays scoped to
    whichever ``ParserConfig`` (explicit or module-default) is in effect.

    ``pending_aggregate_keys`` lets a caller *defer* the dedup-cache write:
    when a set is supplied, a newly seen key is staged in that set instead
    of being written to ``seen_aggregate_report_ids``, and the dedup check
    consults both. The caller then folds the staged keys into the cache
    once the batch is known to have been saved (see
    ``get_dmarc_reports_from_mailbox``), or drops them so a retry reparses
    the same reports rather than silently skipping them as duplicates.
    ``None`` (the default) keeps the immediate-write behavior.

    Returns the report type so mailbox callers know which UID list to
    append the source message's UID to.
    """
    report_type = parsed_email["report_type"]
    # Compare against parsed_email["report_type"] directly (not the
    # report_type local above) in each branch so pyright's TypedDict
    # discriminated-union narrowing applies to parsed_email["report"].
    if parsed_email["report_type"] == "aggregate":
        report_org = parsed_email["report"]["report_metadata"]["org_name"]
        report_id = parsed_email["report"]["report_metadata"]["report_id"]
        report_key = f"{report_org}_{report_id}"
        already_seen = report_key in seen_aggregate_report_ids or (
            pending_aggregate_keys is not None and report_key in pending_aggregate_keys
        )
        if not already_seen:
            if pending_aggregate_keys is None:
                seen_aggregate_report_ids[report_key] = True
            else:
                pending_aggregate_keys.add(report_key)
            aggregate_reports.append(parsed_email["report"])
        else:
            logger.debug(
                f"Skipping duplicate aggregate report from {report_org} "
                f"with ID: {report_id}"
            )
    elif parsed_email["report_type"] == "failure":
        failure_reports.append(parsed_email["report"])
    elif parsed_email["report_type"] == "smtp_tls":
        smtp_tls_reports.append(parsed_email["report"])
    return report_type


def _fetch_mailbox_message(
    connection: MailboxConnection, msg_uid: Any, test: bool
) -> tuple[int | str, str]:
    """Fetch one message from ``connection`` by UID, casting the UID to the
    type each backend's ``fetch_message`` expects.

    Shared, unmodified, by the sequential and parallel branches of
    ``get_dmarc_reports_from_mailbox`` so both fetch identically.

    Returns ``(message_id, msg_content)``; ``message_id`` is the
    backend-appropriate id to use for later move/delete calls.
    """
    message_id: int | str
    if isinstance(connection, IMAPConnection):
        message_id = int(msg_uid)
        msg_content = connection.fetch_message(message_id)
    elif isinstance(connection, MSGraphConnection):
        message_id = str(msg_uid)
        msg_content = connection.fetch_message(message_id, mark_read=not test)
    elif isinstance(connection, MaildirConnection):
        message_id = str(msg_uid) if not isinstance(msg_uid, str) else msg_uid
        msg_content = connection.fetch_message(message_id, mark_read=not test)
    else:
        message_id = str(msg_uid) if not isinstance(msg_uid, str) else msg_uid
        msg_content = connection.fetch_message(message_id)
    return message_id, msg_content


def _dispose_invalid_message(
    connection: MailboxConnection,
    message_id: int | str,
    delete: bool,
    invalid_reports_folder: str,
) -> None:
    """Delete or move an unparseable message, per ``delete``.

    Callers pass their effective ``delete_invalid`` value as ``delete``.

    Shared, unmodified, by the sequential and parallel branches of
    ``get_dmarc_reports_from_mailbox`` so both dispose of invalid messages
    identically.
    """
    if delete:
        logger.debug(f"Deleting message UID {message_id}")
        if isinstance(connection, IMAPConnection):
            connection.delete_message(int(message_id))
        else:
            connection.delete_message(str(message_id))
    else:
        logger.debug(f"Moving message UID {message_id} to {invalid_reports_folder}")
        if isinstance(connection, IMAPConnection):
            connection.move_message(int(message_id), invalid_reports_folder)
        else:
            connection.move_message(str(message_id), invalid_reports_folder)


def get_dmarc_reports_from_mbox(
    input_: str,
    *,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    strip_attachment_payloads: bool = False,
    ip_db_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    offline: bool = False,
    normalize_timespan_threshold_hours: float = 24.0,
    n_procs: int = 1,
    config: ParserConfig | None = None,
) -> ParsingResults:
    """Parses a mailbox in mbox format containing e-mails with attached
    DMARC reports

    Args:
        input_ (str): A path to a mbox file
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Sets the DNS timeout in seconds
        dns_retries (int): Number of times to retry DNS queries on timeout
            or other transient errors
        strip_attachment_payloads (bool): Remove attachment payloads from
            failure report results
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map file
        reverse_dns_map_url (str): URL to a reverse DNS map file
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        offline (bool): Do not make online queries for geolocation or DNS
        normalize_timespan_threshold_hours (float): Normalize timespans beyond this
        n_procs (int): Number of processes to use for parsing messages in
            parallel. Message reading, deduplication, and result assembly
            stay in the calling process; only parsing is parallelized. Not
            part of ``config``; always applies.
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, the
            individual option keyword arguments listed above are ignored in
            favor of the config's values.

    Returns:
        dict: Lists of ``aggregate_reports``, ``failure_reports``, and ``smtp_tls_reports``

    """
    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        strip_attachment_payloads=strip_attachment_payloads,
        normalize_timespan_threshold_hours=normalize_timespan_threshold_hours,
    )
    aggregate_reports: list[AggregateReport] = []
    failure_reports: list[FailureReport] = []
    smtp_tls_reports: list[SMTPTLSReport] = []
    try:
        mbox = mailbox.mbox(input_)
        message_keys = mbox.keys()
        total_messages = len(message_keys)
        logger.debug(f"Found {total_messages} messages in {input_}")

        if n_procs > 1 and total_messages > 1:
            from parsedmarc.parallel import _parse_report_email_job, parallel_map

            func = functools.partial(_parse_report_email_job, config=cfg)

            def _jobs():
                for i in range(total_messages):
                    message_key = message_keys[i]
                    logger.info(f"Processing message {i + 1} of {total_messages}")
                    yield mbox.get_string(message_key)

            for result in tqdm(
                parallel_map(func, _jobs(), n_procs),
                total=total_messages,
                disable=None,
            ):
                if isinstance(result, InvalidDMARCReport):
                    logger.warning(str(result))
                elif isinstance(result, ParserError):
                    raise result
                else:
                    _classify_parsed_email(
                        result,
                        aggregate_reports,
                        failure_reports,
                        smtp_tls_reports,
                        seen_aggregate_report_ids=cfg.seen_aggregate_report_ids,
                    )
        else:
            for i in tqdm(range(total_messages), disable=None):
                message_key = message_keys[i]
                logger.info(f"Processing message {i + 1} of {total_messages}")
                msg_content = mbox.get_string(message_key)
                try:
                    parsed_email = parse_report_email(msg_content, config=cfg)
                    _classify_parsed_email(
                        parsed_email,
                        aggregate_reports,
                        failure_reports,
                        smtp_tls_reports,
                        seen_aggregate_report_ids=cfg.seen_aggregate_report_ids,
                    )
                except InvalidDMARCReport as error:
                    logger.warning(error.__str__())
    except mailbox.NoSuchMailboxError:
        raise InvalidDMARCReport(f"Mailbox {input_} does not exist")
    return {
        "aggregate_reports": aggregate_reports,
        "failure_reports": failure_reports,
        "smtp_tls_reports": smtp_tls_reports,
    }


def _migrate_forensic_archive_folder(
    connection: MailboxConnection, archive_folder: str
) -> None:
    """Consolidate a pre-rename ``<archive>/Forensic`` subfolder into
    ``<archive>/Failure``.

    Before failure reports were renamed from "forensic" reports, they were
    archived under ``<archive_folder>/Forensic``; they now go to
    ``<archive_folder>/Failure``. This best-effort, run-on-startup migration
    moves any pre-existing legacy archive into the new location so reports
    filed before and after the rename live in the same folder.

    It is a no-op when there is no legacy ``Forensic`` folder (the common
    case), and never raises: a mailbox that cannot be reorganized is logged
    and skipped, consistent with the rest of parsedmarc's mailbox handling
    (warn, don't crash). Uses the folder-management API added in mailsuite
    2.1.0 (``folder_exists`` / ``rename_folder`` / ``merge_folders``).
    """
    old_folder = f"{archive_folder}/Forensic"
    new_folder = f"{archive_folder}/Failure"
    try:
        if not connection.folder_exists(old_folder):
            return
        if connection.folder_exists(new_folder):
            # Both exist (e.g. a partial earlier migration, or a manually
            # created Failure folder): move the legacy folder's messages into
            # the new one and drop the now-empty legacy folder.
            connection.merge_folders(old_folder, new_folder)
            logger.info(f"Merged legacy archive folder {old_folder} into {new_folder}")
        else:
            connection.rename_folder(old_folder, new_folder)
            logger.info(f"Renamed legacy archive folder {old_folder} to {new_folder}")
    except Exception as error:
        logger.warning(
            f"Could not migrate legacy archive folder {old_folder} to {new_folder}: {error}"
        )


def _ensure_folder(connection: MailboxConnection, folder: str) -> None:
    """Best-effort create ``folder`` if the backend says it is missing.

    ``get_dmarc_reports_from_mailbox()`` creates its destination folders up
    front, but only when ``create_folders`` is set -- watch mode calls it
    with ``create_folders=False``, and the ``Unsaved`` holding folder is
    only created up front when a ``save_callback`` was supplied. This is the
    defensive check immediately before a message is moved there.

    Like ``_migrate_forensic_archive_folder``, it never raises: a backend
    that cannot report on or create the folder is logged and skipped, and
    the move that follows either succeeds anyway (the folder already
    existed) or fails and is logged by its own error handler -- warn, don't
    crash.
    """
    try:
        if not connection.folder_exists(folder):
            connection.create_folder(folder)
    except Exception as error:
        logger.warning(f"Could not create folder {folder}: {error}")


def get_dmarc_reports_from_mailbox(
    connection: MailboxConnection,
    *,
    reports_folder: str = "INBOX",
    archive_folder: str = "Archive",
    delete: bool = False,
    delete_aggregate: bool | None = None,
    delete_failure: bool | None = None,
    delete_smtp_tls: bool | None = None,
    delete_invalid: bool | None = None,
    test: bool = False,
    ip_db_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    offline: bool = False,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    strip_attachment_payloads: bool = False,
    results: ParsingResults | None = None,
    batch_size: int = 10,
    since: datetime | date | str | None = None,
    create_folders: bool = True,
    normalize_timespan_threshold_hours: float = 24.0,
    n_procs: int = 1,
    save_callback: Callable[[ParsingResults], bool | None] | None = None,
    max_unsaved_retries: int = 2,
    config: ParserConfig | None = None,
) -> ParsingResults:
    """
    Fetches and parses DMARC reports from a mailbox

    Args:
        connection: A Mailbox connection object
        reports_folder (str): The folder where reports can be found
        archive_folder (str): The folder to move processed mail to
        delete (bool): Delete messages after processing them
        delete_aggregate (bool | None): Delete aggregate report messages
            after processing them, instead of moving them to the
            ``Aggregate`` archive subfolder; ``None`` (the default) inherits
            the value of ``delete``
        delete_failure (bool | None): Delete failure report messages after
            processing them, instead of moving them to the ``Failure``
            archive subfolder; ``None`` (the default) inherits the value of
            ``delete``
        delete_smtp_tls (bool | None): Delete SMTP TLS report messages after
            processing them, instead of moving them to the ``SMTP-TLS``
            archive subfolder; ``None`` (the default) inherits the value of
            ``delete``
        delete_invalid (bool | None): Delete unparseable messages, instead
            of moving them to the ``Invalid`` archive subfolder where they
            can be inspected for debugging; ``None`` (the default) inherits
            the value of ``delete``
        test (bool): Do not move or delete messages after processing them
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map file
        reverse_dns_map_url (str): URL to a reverse DNS map file
        offline (bool): Do not query online for geolocation or DNS
        nameservers (list): A list of DNS nameservers to query
        dns_timeout (float): Set the DNS query timeout
        dns_retries (int): Number of times to retry DNS queries on timeout
            or other transient errors
        strip_attachment_payloads (bool): Remove attachment payloads from
            failure report results
        results (dict): Results from the previous run
        batch_size (int): Number of messages to read and process before saving
            (use 0 for no limit)
        since: Search for messages since certain time
            (units - {"m":"minutes", "h":"hours", "d":"days", "w":"weeks"})
        create_folders (bool): Whether to create the destination folders
            (not used in watch)
        normalize_timespan_threshold_hours (float): Normalize timespans beyond this
        n_procs (int): Number of processes to use for parsing messages in
            parallel. Fetching, archiving, and deduplication remain
            sequential in the calling process; only parsing is
            parallelized. With ``n_procs > 1``, invalid-message disposition
            happens after the parsing phase completes, rather than
            interleaved message-by-message as it is when ``n_procs`` is 1.
            Not part of ``config``; always applies.
        save_callback: An optional callable invoked once per fetched batch
            with a ``ParsingResults`` dict holding only that batch's newly
            parsed reports, after parsing but before any of the batch's
            messages are deleted or moved out of ``reports_folder``. It
            tells this function whether the batch was actually persisted:

            * Returning ``False`` means "not saved": the batch's messages
              are left in ``reports_folder`` for retry on the next run (or
              moved to ``{archive_folder}/Unsaved`` once they have failed
              ``max_unsaved_retries`` retries -- see below), and the
              aggregate-report dedup cache is not updated for that batch, so
              a retry reparses the same reports instead of skipping them as
              duplicates.
            * Raising counts as "not saved" too: the same bookkeeping runs
              (the batch's messages are held back or moved to ``Unsaved`` at
              the cap, and the failed attempt counts toward
              ``max_unsaved_retries``), and the exception is then re-raised
              to the caller.
            * Any other return value, including ``None``, commits the batch:
              the dedup cache is updated and the messages are deleted or
              archived exactly as they are with no callback.

            ``None`` (the default) commits every batch, preserving the prior
            behavior. The callback is still invoked when ``test`` is
            ``True``, so a test run exercises the full pipeline, but neither
            the mailbox nor the retry counters are touched regardless of
            what it returns.
        max_unsaved_retries (int): How many times a message may be *retried*
            after ``save_callback`` first reported its batch unsaved, before
            it is moved to the ``Unsaved`` archive subfolder instead of
            being retried again (default 2, i.e. the initial attempt plus
            two retries -- at most three deliveries to any output
            destination that does not deduplicate). ``0`` moves a message on
            the first failed save. Messages moved to ``Unsaved`` are never
            deleted, whatever the ``delete`` options say; recover them by
            fixing the output destination and moving them back into
            ``reports_folder``. Counts are kept in memory, per message and
            per process, are reset by a successful save, and are only kept
            when a ``save_callback`` is supplied -- so the cap applies
            across repeated calls within one process (``watch_inbox()``'s
            checks), not across separate one-shot processes, each of which
            starts a message's count over. Mailbox orchestration, so like
            ``batch_size`` it is not part of ``config``.
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, it replaces
            the individual parsing and enrichment option keyword arguments
            listed above (DNS, GeoIP, offline mode, attachment payload
            stripping, timespan normalization), whose values are then
            ignored. The remaining keyword arguments control mailbox
            handling and orchestration rather than parsing (the folder
            names, the ``delete`` options, ``test``, ``since``,
            ``batch_size``, ``save_callback``, ``max_unsaved_retries``);
            they are not part of ``config`` and always apply.

    Returns:
        dict: Lists of ``aggregate_reports``, ``failure_reports``, and ``smtp_tls_reports``
    """
    # Each per-report-type flag inherits the overall ``delete`` value when it
    # is left unset (``None``). Resolve once, up front: every decision below
    # reads only these four resolved flags. The raw ``delete`` parameter is
    # still forwarded verbatim to the recursive self-call at the end of this
    # function, where it is inert because all four resolved flags accompany
    # it.
    delete_aggregate = delete if delete_aggregate is None else delete_aggregate
    delete_failure = delete if delete_failure is None else delete_failure
    delete_smtp_tls = delete if delete_smtp_tls is None else delete_smtp_tls
    delete_invalid = delete if delete_invalid is None else delete_invalid

    if test and (
        delete_aggregate or delete_failure or delete_smtp_tls or delete_invalid
    ):
        raise ValueError("delete options and test are mutually exclusive")

    if connection is None:
        raise ValueError("Must supply a connection")

    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        strip_attachment_payloads=strip_attachment_payloads,
        normalize_timespan_threshold_hours=normalize_timespan_threshold_hours,
    )

    # current_time useful to fetch_messages later in the program
    current_time: datetime | date | str | None = None

    aggregate_reports: list[AggregateReport] = []
    failure_reports: list[FailureReport] = []
    smtp_tls_reports: list[SMTPTLSReport] = []
    # This call's own reports, kept separate from the accumulated lists
    # above (which carry earlier batches' reports in via ``results``) so the
    # save callback is handed only what this batch parsed.
    batch_aggregate_reports: list[AggregateReport] = []
    batch_failure_reports: list[FailureReport] = []
    batch_smtp_tls_reports: list[SMTPTLSReport] = []
    # Aggregate dedup keys are staged here and only written to the shared
    # cache once the batch is known to be saved, so an unsaved batch (or a
    # mid-batch crash) leaves the cache clean and the reports are reparsed
    # on the retry instead of being dropped as duplicates.
    pending_aggregate_keys: set[str] = set()
    aggregate_report_msg_uids = []
    failure_report_msg_uids = []
    smtp_tls_msg_uids = []
    aggregate_reports_folder = f"{archive_folder}/Aggregate"
    failure_reports_folder = f"{archive_folder}/Failure"
    smtp_tls_reports_folder = f"{archive_folder}/SMTP-TLS"
    invalid_reports_folder = f"{archive_folder}/Invalid"
    unsaved_reports_folder = f"{archive_folder}/Unsaved"

    if results:
        aggregate_reports = results["aggregate_reports"].copy()
        failure_reports = results["failure_reports"].copy()
        smtp_tls_reports = results["smtp_tls_reports"].copy()

    if not test and create_folders:
        _migrate_forensic_archive_folder(connection, archive_folder)
        connection.create_folder(archive_folder)
        connection.create_folder(aggregate_reports_folder)
        connection.create_folder(failure_reports_folder)
        connection.create_folder(smtp_tls_reports_folder)
        connection.create_folder(invalid_reports_folder)
        if save_callback is not None:
            # Only reachable when a callback can report a batch unsaved;
            # without one no message is ever held back, so the folder would
            # sit empty in every mailbox.
            connection.create_folder(unsaved_reports_folder)

    if since and isinstance(since, str):
        _since = 1440  # default one day
        if re.match(r"\d+[mhdw]$", since):
            s = re.split(r"(\d+)", since)
            if s[2] == "m":
                _since = int(s[1])
            elif s[2] == "h":
                _since = int(s[1]) * 60
            elif s[2] == "d":
                _since = int(s[1]) * 60 * 24
            elif s[2] == "w":
                _since = int(s[1]) * 60 * 24 * 7
        else:
            logger.warning(
                f"Incorrect format for 'since' option. Provided value: {since}, "
                "expected values: (5m|3h|2d|1w). Ignoring option, fetching "
                "messages for last 24hrs. SMTP does not support a time or "
                "timezone in since. See "
                "https://www.rfc-editor.org/rfc/rfc3501#page-52"
            )

        if isinstance(connection, IMAPConnection):
            logger.debug(
                "Only days and weeks values in 'since' option are considered "
                "for IMAP connections. Examples: 2d or 1w"
            )
            since = (datetime.now(timezone.utc) - timedelta(minutes=_since)).strftime(
                "%d-%b-%Y"
            )
            current_time = datetime.now(timezone.utc).strftime("%d-%b-%Y")
        elif isinstance(connection, MSGraphConnection):
            since = (datetime.now(timezone.utc) - timedelta(minutes=_since)).isoformat()
            current_time = datetime.now(timezone.utc).isoformat()
        elif isinstance(connection, GmailConnection):
            since = (datetime.now(timezone.utc) - timedelta(minutes=_since)).strftime(
                "%s"
            )
            current_time = datetime.now(timezone.utc).strftime("%s")
        else:
            pass

    messages = connection.fetch_messages(
        reports_folder, batch_size=batch_size, since=since
    )
    total_messages = len(messages)
    logger.debug(f"Found {len(messages)} messages in {reports_folder}")

    if batch_size and not since:
        message_limit = min(total_messages, batch_size)
    else:
        message_limit = total_messages

    logger.debug(f"Processing {message_limit} messages")

    if n_procs > 1 and message_limit > 1:
        from parsedmarc.parallel import _parse_report_email_job, parallel_map

        # The config's caches (ip_address_cache, seen_aggregate_report_ids,
        # reverse_dns_map) never cross the process boundary --
        # ParserConfig.__getstate__ drops them, and each worker accumulates
        # its own via the module defaults it rebinds to on unpickling (see
        # ParserConfig.__setstate__). keep_alive is a bound method of the
        # live connection object and is not a ParserConfig field, so it is
        # never submitted to the pool either; the heartbeat passed to
        # parallel_map below keeps the connection alive instead.
        func = functools.partial(_parse_report_email_job, config=cfg)

        # parallel_map yields results in submission order, so the oldest
        # queued id always belongs to the next yielded result; popping as
        # results arrive keeps this queue no larger than the in-flight
        # submission window.
        fetched_ids: deque[int | str] = deque()
        invalid_msg_ids: list[int | str] = []

        def _jobs():
            for i in range(message_limit):
                msg_uid = messages[i]
                logger.debug(
                    f"Processing message {i + 1} of {message_limit}: UID {msg_uid}"
                )
                message_id, msg_content = _fetch_mailbox_message(
                    connection, msg_uid, test
                )
                fetched_ids.append(message_id)
                yield msg_content

        for result in parallel_map(
            func, _jobs(), n_procs, heartbeat=connection.keepalive
        ):
            message_id = fetched_ids.popleft()
            if isinstance(result, ParserError):
                logger.warning(str(result))
                invalid_msg_ids.append(message_id)
            else:
                report_type = _classify_parsed_email(
                    result,
                    batch_aggregate_reports,
                    batch_failure_reports,
                    batch_smtp_tls_reports,
                    seen_aggregate_report_ids=cfg.seen_aggregate_report_ids,
                    pending_aggregate_keys=pending_aggregate_keys,
                )
                if report_type == "aggregate":
                    aggregate_report_msg_uids.append(message_id)
                elif report_type == "failure":
                    failure_report_msg_uids.append(message_id)
                elif report_type == "smtp_tls":
                    smtp_tls_msg_uids.append(message_id)

        if not test:
            for invalid_message_id in invalid_msg_ids:
                _dispose_invalid_message(
                    connection,
                    invalid_message_id,
                    delete_invalid,
                    invalid_reports_folder,
                )
    else:
        for i in range(message_limit):
            msg_uid = messages[i]
            logger.debug(
                f"Processing message {i + 1} of {message_limit}: UID {msg_uid}"
            )
            message_id, msg_content = _fetch_mailbox_message(connection, msg_uid, test)
            try:
                parsed_email = parse_report_email(
                    msg_content,
                    config=cfg,
                    keep_alive=connection.keepalive,
                )
                report_type = _classify_parsed_email(
                    parsed_email,
                    batch_aggregate_reports,
                    batch_failure_reports,
                    batch_smtp_tls_reports,
                    seen_aggregate_report_ids=cfg.seen_aggregate_report_ids,
                    pending_aggregate_keys=pending_aggregate_keys,
                )
                if report_type == "aggregate":
                    aggregate_report_msg_uids.append(message_id)
                elif report_type == "failure":
                    failure_report_msg_uids.append(message_id)
                elif report_type == "smtp_tls":
                    smtp_tls_msg_uids.append(message_id)
            except ParserError as error:
                logger.warning(error.__str__())
                if not test:
                    _dispose_invalid_message(
                        connection, message_id, delete_invalid, invalid_reports_folder
                    )

    # Ask the caller whether this batch actually made it to its output
    # destinations before touching a single message. A callback that says
    # otherwise (or raises) means the reports exist nowhere else yet, so no
    # message may be archived or deleted -- only retained for retry, or moved
    # intact to the Unsaved folder once retries run out (#242).
    batch_results: ParsingResults = {
        "aggregate_reports": batch_aggregate_reports,
        "failure_reports": batch_failure_reports,
        "smtp_tls_reports": batch_smtp_tls_reports,
    }
    persisted = True
    callback_error: Exception | None = None
    if save_callback is not None:
        try:
            persisted = save_callback(batch_results) is not False
        except Exception as error:
            # A raising callback is a failed save too: the failure
            # bookkeeping below still runs (count the attempt, hold or shelve
            # the messages) before the exception is re-raised, so a callback
            # that always raises -- e.g. the CLI's under
            # ``fail_on_output_error`` -- is still bounded by
            # ``max_unsaved_retries`` even when the caller's watch loop
            # swallows the exception and keeps checking, as mailsuite's IMAP
            # and Maildir backends do.
            persisted = False
            callback_error = error

    batch_msg_uids = (
        aggregate_report_msg_uids + failure_report_msg_uids + smtp_tls_msg_uids
    )

    if persisted:
        # Committing: the reports are safely stored elsewhere, so record
        # their dedup keys and forget any earlier failures for these
        # messages.
        for report_key in pending_aggregate_keys:
            cfg.seen_aggregate_report_ids[report_key] = True
        if not test:
            for msg_uid in batch_msg_uids:
                _FAILED_SAVE_ATTEMPTS.pop((reports_folder, str(msg_uid)), None)
    elif not test:
        # Held back for retry. Messages that have now failed the initial
        # attempt plus ``max_unsaved_retries`` retries stop being retried and
        # move to the Unsaved folder, bounding duplicate delivery to output
        # destinations that do not deduplicate; the rest stay put.
        retained_uids: list[int | str] = []
        over_cap_uids: list[int | str] = []
        highest_attempt = 0
        for msg_uid in batch_msg_uids:
            attempts_key = (reports_folder, str(msg_uid))
            attempts = _FAILED_SAVE_ATTEMPTS.get(attempts_key, 0) + 1
            _FAILED_SAVE_ATTEMPTS[attempts_key] = attempts
            if attempts > max_unsaved_retries:
                over_cap_uids.append(msg_uid)
            else:
                retained_uids.append(msg_uid)
                highest_attempt = max(highest_attempt, attempts)
        if retained_uids:
            logger.error(
                f"Reports were not saved: leaving {len(retained_uids)} "
                f"message(s) in {reports_folder} to retry on the next run "
                f"or check (failed attempt {highest_attempt} of "
                f"{max_unsaved_retries + 1})"
            )
        if over_cap_uids:
            logger.error(
                f"Reports were not saved after {max_unsaved_retries + 1} "
                f"attempt(s): moving {len(over_cap_uids)} message(s) from "
                f"{reports_folder} to {unsaved_reports_folder} instead of "
                "retrying them further. They are never deleted -- fix the "
                f"output destination, then move them back to {reports_folder}"
            )
            _ensure_folder(connection, unsaved_reports_folder)
            for msg_uid in over_cap_uids:
                try:
                    connection.move_message(msg_uid, unsaved_reports_folder)
                except Exception as e:
                    e = f"Error moving message UID {msg_uid}: {e}"
                    logger.error(f"Mailbox error: {e}")
                else:
                    # Drop the counter only once the message is actually out
                    # of the retry loop. Clearing it before a failed move
                    # would hand the still-in-place message a fresh set of
                    # under-cap retries (and deliveries); keeping it means
                    # the next failed save classifies the message over-cap
                    # again and re-attempts the move instead.
                    _FAILED_SAVE_ATTEMPTS.pop((reports_folder, str(msg_uid)), None)

    if callback_error is not None:
        raise callback_error

    aggregate_reports += batch_aggregate_reports
    failure_reports += batch_failure_reports
    smtp_tls_reports += batch_smtp_tls_reports

    if persisted and not test:
        # Each report type is disposed of according to its own effective
        # delete flag: deleted outright, or moved to its archive subfolder.
        for msg_uids, delete_type, destination_folder, label in (
            (
                aggregate_report_msg_uids,
                delete_aggregate,
                aggregate_reports_folder,
                "aggregate report",
            ),
            (
                failure_report_msg_uids,
                delete_failure,
                failure_reports_folder,
                "failure report",
            ),
            (
                smtp_tls_msg_uids,
                delete_smtp_tls,
                smtp_tls_reports_folder,
                "SMTP TLS report",
            ),
        ):
            number_of_msgs = len(msg_uids)
            if number_of_msgs == 0:
                continue
            if not delete_type:
                message = f"Moving {label} messages from"
                logger.debug(f"{message} {reports_folder} to {destination_folder}")
            for i in range(number_of_msgs):
                msg_uid = msg_uids[i]
                if delete_type:
                    logger.debug(
                        f"Deleting message {i + 1} of {number_of_msgs}: UID {msg_uid}"
                    )
                    try:
                        connection.delete_message(msg_uid)
                    except Exception as e:
                        message = "Error deleting message UID"
                        e = f"{message} {msg_uid}: {e}"
                        logger.error(f"Mailbox error: {e}")
                else:
                    message = "Moving message"
                    logger.debug(
                        f"{message} {i + 1} of {number_of_msgs}: UID {msg_uid}"
                    )
                    try:
                        connection.move_message(msg_uid, destination_folder)
                    except Exception as e:
                        e = f"Error moving message UID {msg_uid}: {e}"
                        logger.error(f"Mailbox error: {e}")
    results = {
        "aggregate_reports": aggregate_reports,
        "failure_reports": failure_reports,
        "smtp_tls_reports": smtp_tls_reports,
    }

    # An unsaved batch left its messages in ``reports_folder``, so the
    # re-check below would find them again and immediately reprocess the
    # very messages that just failed -- burning through the retry cap in one
    # call. Skip it and let the next run retry them.
    if persisted and not test and not batch_size:
        if current_time:
            total_messages = len(
                connection.fetch_messages(reports_folder, since=current_time)
            )
        else:
            total_messages = len(connection.fetch_messages(reports_folder))
    else:
        total_messages = 0

    if total_messages > 0:
        # Process emails that came in during the last run
        results = get_dmarc_reports_from_mailbox(
            connection=connection,
            reports_folder=reports_folder,
            archive_folder=archive_folder,
            delete=delete,
            delete_aggregate=delete_aggregate,
            delete_failure=delete_failure,
            delete_smtp_tls=delete_smtp_tls,
            delete_invalid=delete_invalid,
            test=test,
            results=results,
            since=current_time,
            n_procs=n_procs,
            save_callback=save_callback,
            max_unsaved_retries=max_unsaved_retries,
            config=cfg,
        )

    return results


def watch_inbox(
    mailbox_connection: MailboxConnection,
    callback: Callable,
    *,
    reports_folder: str = "INBOX",
    archive_folder: str = "Archive",
    delete: bool = False,
    delete_aggregate: bool | None = None,
    delete_failure: bool | None = None,
    delete_smtp_tls: bool | None = None,
    delete_invalid: bool | None = None,
    test: bool = False,
    check_timeout: int = 30,
    ip_db_path: str | None = None,
    always_use_local_files: bool = False,
    reverse_dns_map_path: str | None = None,
    reverse_dns_map_url: str | None = None,
    offline: bool = False,
    nameservers: list[str] | None = None,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES,
    strip_attachment_payloads: bool = False,
    batch_size: int = 10,
    since: datetime | date | str | None = None,
    normalize_timespan_threshold_hours: float = 24.0,
    config_reloading: Callable | None = None,
    n_procs: int = 1,
    max_unsaved_retries: int = 2,
    config: ParserConfig | None = None,
):
    """
    Watches the mailbox for new messages and
      sends the results to a callback function

    Args:
        mailbox_connection: The mailbox connection object
        callback: The callback function to receive the parsing results.
            Passed straight through to ``get_dmarc_reports_from_mailbox()``
            as its ``save_callback``, so it now runs once per fetched batch,
            with only that batch's reports, *before* those messages are
            deleted or moved out of ``reports_folder`` -- rather than once
            afterward with the whole check's accumulated results. Returning
            ``False`` reports the batch as unsaved, leaving its messages in
            place to be retried on the next check instead of archived or
            deleted (see ``save_callback`` and ``max_unsaved_retries`` on
            ``get_dmarc_reports_from_mailbox()``). Raising counts as an
            unsaved batch too -- same retention and retry cap -- before the
            exception reaches the mailbox backend's watch loop; what happens
            then is backend-specific: the Microsoft Graph and Gmail backends
            let it propagate and end the watch, while mailsuite's IMAP and
            Maildir watch loops log it and keep checking.
        reports_folder (str): The IMAP folder where reports can be found
        archive_folder (str): The folder to move processed mail to
        delete (bool): Delete messages after processing them
        delete_aggregate (bool | None): Delete aggregate report messages
            after processing them, instead of moving them to the
            ``Aggregate`` archive subfolder; ``None`` (the default) inherits
            the value of ``delete``
        delete_failure (bool | None): Delete failure report messages after
            processing them, instead of moving them to the ``Failure``
            archive subfolder; ``None`` (the default) inherits the value of
            ``delete``
        delete_smtp_tls (bool | None): Delete SMTP TLS report messages after
            processing them, instead of moving them to the ``SMTP-TLS``
            archive subfolder; ``None`` (the default) inherits the value of
            ``delete``
        delete_invalid (bool | None): Delete unparseable messages, instead
            of moving them to the ``Invalid`` archive subfolder where they
            can be inspected for debugging; ``None`` (the default) inherits
            the value of ``delete``
        test (bool): Do not move or delete messages after processing them
        check_timeout (int): Number of seconds to wait for a IMAP IDLE response
            or the number of seconds until the next mail check
        ip_db_path (str): Path to a MMDB file from IPinfo, MaxMind, or DBIP
        always_use_local_files (bool): Do not download files
        reverse_dns_map_path (str): Path to a reverse DNS map file
        reverse_dns_map_url (str): URL to a reverse DNS map file
        offline (bool): Do not query online for geolocation or DNS
        nameservers (list): A list of one or more nameservers to use
            (Cloudflare's public DNS resolvers by default)
        dns_timeout (float): Set the DNS query timeout
        dns_retries (int): Number of times to retry DNS queries on timeout
            or other transient errors
        strip_attachment_payloads (bool): Replace attachment payloads in
            failure report samples with None
        batch_size (int): Number of messages to read and process before saving
        since: Search for messages since certain time
        normalize_timespan_threshold_hours (float): Normalize timespans beyond this
        config_reloading: Optional callable that returns True when a config
            reload (or shutdown) has been requested (e.g. via SIGHUP/SIGTERM).
            Polled by the mailbox backend between checks, including the IMAP
            IDLE loop, so the watcher exits cleanly at a safe boundary.
        n_procs (int): Number of processes to use for parsing messages in
            parallel. Passed through to ``get_dmarc_reports_from_mailbox``
            on each check. Not part of ``config``; always applies.
        max_unsaved_retries (int): How many times a message may be retried
            after ``callback`` first reported its batch unsaved, before it is
            moved to the ``Unsaved`` archive subfolder (default 2). Passed
            through to ``get_dmarc_reports_from_mailbox``, where it is
            documented in full. Not part of ``config``; always applies.
        config (ParserConfig): a single object carrying all parsing and
            enrichment options plus the caches; when provided, it replaces
            the individual parsing and enrichment option keyword arguments
            listed above (DNS, GeoIP, offline mode, attachment payload
            stripping, timespan normalization), whose values are then
            ignored. The remaining keyword arguments control mailbox
            handling and orchestration rather than parsing (the folder
            names, the ``delete`` options, ``test``, ``since``,
            ``batch_size``, ``max_unsaved_retries``); they are not part of
            ``config`` and always apply.
    """
    cfg = _resolve_config(
        config,
        offline=offline,
        ip_db_path=ip_db_path,
        always_use_local_files=always_use_local_files,
        reverse_dns_map_path=reverse_dns_map_path,
        reverse_dns_map_url=reverse_dns_map_url,
        nameservers=nameservers,
        dns_timeout=dns_timeout,
        dns_retries=dns_retries,
        strip_attachment_payloads=strip_attachment_payloads,
        normalize_timespan_threshold_hours=normalize_timespan_threshold_hours,
    )

    def check_callback(connection):
        get_dmarc_reports_from_mailbox(
            connection=connection,
            reports_folder=reports_folder,
            archive_folder=archive_folder,
            delete=delete,
            delete_aggregate=delete_aggregate,
            delete_failure=delete_failure,
            delete_smtp_tls=delete_smtp_tls,
            delete_invalid=delete_invalid,
            test=test,
            batch_size=batch_size,
            since=since,
            create_folders=False,
            n_procs=n_procs,
            save_callback=callback,
            max_unsaved_retries=max_unsaved_retries,
            config=cfg,
        )

    watch_kwargs: dict = {
        "check_callback": check_callback,
        "check_timeout": check_timeout,
    }
    if config_reloading is not None:
        watch_kwargs["config_reloading"] = config_reloading

    mailbox_connection.watch(**watch_kwargs)


def append_json(
    filename: str,
    reports: Sequence[AggregateReport]
    | Sequence[FailureReport]
    | Sequence[SMTPTLSReport],
) -> None:
    """Append ``reports`` to a JSON array on disk, creating the file
    if needed.

    Reads the existing array (if the file exists and parses cleanly),
    merges the new reports onto the end, and rewrites the file as a
    single valid JSON array. An earlier version of this used an
    ``open(..., "a+")`` + ``seek()`` + overwrite pattern, but Python's
    documentation is explicit that on POSIX, ``a`` / ``a+`` writes
    *always* go to EOF regardless of seek position — so the second
    call onto an existing file produced ``[...],\\n[...]``-style
    corrupted output. Read-merge-write is the only way to get a valid
    JSON array out of repeated appends.
    """
    if len(reports) == 0:
        # Don't create an empty-array file for an empty input; if a
        # file already exists, leave it alone.
        return

    existing: list = []
    if os.path.isfile(filename) and os.path.getsize(filename) > 0:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                loaded = json.loads(f.read())
            if isinstance(loaded, list):
                existing = loaded
        except (json.JSONDecodeError, OSError):
            # Corrupted or unreadable: overwrite cleanly rather than
            # silently fail to record.
            existing = []

    merged = existing + list(reports)
    with open(filename, "w", newline="\n", encoding="utf-8") as output:
        json.dump(merged, output, ensure_ascii=False, indent=2)


def append_csv(filename: str, csv: str) -> None:
    with open(filename, "a+", newline="\n", encoding="utf-8") as output:
        if output.seek(0, os.SEEK_END) != 0:
            # strip the headers from the CSV
            _headers, csv = csv.split("\n", 1)
            if len(csv) == 0:
                # not appending anything, don't do any dance to
                # append it correctly
                return
        output.write(csv)


def save_output(
    results: ParsingResults,
    *,
    output_directory: str = "output",
    aggregate_json_filename: str = "aggregate.json",
    failure_json_filename: str = "failure.json",
    smtp_tls_json_filename: str = "smtp_tls.json",
    aggregate_csv_filename: str = "aggregate.csv",
    failure_csv_filename: str = "failure.csv",
    smtp_tls_csv_filename: str = "smtp_tls.csv",
):
    """
    Save report data in the given directory

    Args:
        results: Parsing results
        output_directory (str): The path to the directory to save in
        aggregate_json_filename (str): Filename for the aggregate JSON file
        failure_json_filename (str): Filename for the failure JSON file
        smtp_tls_json_filename (str): Filename for the SMTP TLS JSON file
        aggregate_csv_filename (str): Filename for the aggregate CSV file
        failure_csv_filename (str): Filename for the failure CSV file
        smtp_tls_csv_filename (str): Filename for the SMTP TLS CSV file
    """

    aggregate_reports = results["aggregate_reports"]
    failure_reports = results["failure_reports"]
    smtp_tls_reports = results["smtp_tls_reports"]
    output_directory = os.path.expanduser(output_directory)

    if os.path.exists(output_directory):
        if not os.path.isdir(output_directory):
            raise ValueError(f"{output_directory} is not a directory")
    else:
        os.makedirs(output_directory)

    append_json(
        os.path.join(output_directory, aggregate_json_filename), aggregate_reports
    )

    append_csv(
        os.path.join(output_directory, aggregate_csv_filename),
        parsed_aggregate_reports_to_csv(aggregate_reports),
    )

    append_json(os.path.join(output_directory, failure_json_filename), failure_reports)

    append_csv(
        os.path.join(output_directory, failure_csv_filename),
        parsed_failure_reports_to_csv(failure_reports),
    )

    append_json(
        os.path.join(output_directory, smtp_tls_json_filename), smtp_tls_reports
    )

    append_csv(
        os.path.join(output_directory, smtp_tls_csv_filename),
        parsed_smtp_tls_reports_to_csv(smtp_tls_reports),
    )

    samples_directory = os.path.join(output_directory, "samples")
    if not os.path.exists(samples_directory):
        os.makedirs(samples_directory)

    sample_filenames = []
    for failure_report in failure_reports:
        sample = failure_report["sample"]
        message_count = 0
        parsed_sample = failure_report["parsed_sample"]
        subject = (
            parsed_sample.get("filename_safe_subject")
            or parsed_sample.get("subject")
            or "sample"
        )
        filename = subject

        while filename in sample_filenames:
            message_count += 1
            filename = f"{subject} ({message_count})"

        sample_filenames.append(filename)

        filename = f"{filename}.eml"
        path = os.path.join(samples_directory, filename)
        with open(path, "w", newline="\n", encoding="utf-8") as sample_file:
            sample_file.write(sample)


def get_report_zip(results: ParsingResults) -> bytes:
    """
    Creates a zip file of parsed report output

    Args:
        results: The parsed results

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
        save_output(results, output_directory=tmp_dir)
        with zipfile.ZipFile(storage, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for root, dirs, files in os.walk(tmp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):
                        arcname = os.path.join(os.path.relpath(root, tmp_dir), file)
                        zip_file.write(file_path, arcname)
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    if os.path.isdir(dir_path):
                        zip_file.write(dir_path, directory)
                        add_subdir(root, directory)
    finally:
        shutil.rmtree(tmp_dir)

    return storage.getvalue()


def _build_report_email_content(
    results: ParsingResults,
    *,
    subject: str | None = None,
    attachment_filename: str | None = None,
    message: str | None = None,
) -> tuple[str, str, list[tuple[str, bytes]]]:
    """Builds the subject, plain-text body, and zip attachment shared by
    every report-summary email transport.

    Returns:
        A ``(subject, plain_message, attachments)`` tuple.
    """
    date_string = datetime.now().strftime("%Y-%m-%d")
    if attachment_filename:
        if not attachment_filename.lower().endswith(".zip"):
            attachment_filename += ".zip"
        filename = attachment_filename
    else:
        filename = f"DMARC-{date_string}.zip"

    if subject is None:
        subject = f"DMARC results for {date_string}"
    if message is None:
        message = f"DMARC results for {date_string}"
    zip_bytes = get_report_zip(results)
    attachments = [(filename, zip_bytes)]

    return subject, message, attachments


def email_results(
    results: ParsingResults,
    host: str,
    mail_from: str,
    mail_to: list[str] | None,
    *,
    mail_cc: list[str] | None = None,
    mail_bcc: list[str] | None = None,
    port: int = 0,
    require_encryption: bool = False,
    verify: bool = True,
    username: str | None = None,
    password: str | None = None,
    subject: str | None = None,
    attachment_filename: str | None = None,
    message: str | None = None,
):
    """
    Emails parsing results as a zip file

    Args:
        results (dict): Parsing results
        host (str): Mail server hostname or IP address
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
        message (str): Override the default plain text body
    """
    logger.debug("Emailing report")
    assert isinstance(mail_to, list)

    subject, message, attachments = _build_report_email_content(
        results,
        subject=subject,
        attachment_filename=attachment_filename,
        message=message,
    )

    send_email(
        host,
        mail_from,
        mail_to,
        message_cc=mail_cc,
        message_bcc=mail_bcc,
        port=port,
        require_encryption=require_encryption,
        verify=verify,
        username=username,
        password=password,
        subject=subject,
        attachments=attachments,
        plain_message=message,
    )


def email_results_via_msgraph(
    results: ParsingResults,
    connection: MSGraphConnection,
    mail_to: list[str],
    *,
    mail_cc: list[str] | None = None,
    mail_bcc: list[str] | None = None,
    subject: str | None = None,
    attachment_filename: str | None = None,
    message: str | None = None,
) -> None:
    """
    Emails parsing results as a zip file via an already-authenticated
    Microsoft Graph mailbox connection (``/users/{mailbox}/sendMail``),
    saving a copy to Sent Items.

    Args:
        results (dict): Parsing results
        connection (MSGraphConnection): An already-authenticated Microsoft
            Graph mailbox connection
        mail_to (list): A list of addresses to mail to
        mail_cc (list): A list of addresses to CC
        mail_bcc (list): A list addresses to BCC
        subject (str): Overrides the default message subject
        attachment_filename (str): Override the default attachment filename
        message (str): Override the default plain text body
    """
    logger.debug("Emailing report via Microsoft Graph")

    subject, message, attachments = _build_report_email_content(
        results,
        subject=subject,
        attachment_filename=attachment_filename,
        message=message,
    )

    # Graph derives the From header from the authenticated mailbox and
    # ignores message_from; it's still passed for API parity with
    # send_message()'s signature.
    connection.send_message(
        message_from=connection.mailbox_name or "",
        message_to=mail_to,
        message_cc=mail_cc,
        message_bcc=mail_bcc,
        subject=subject,
        attachments=attachments,
        plain_message=message,
    )


# Backward-compatible aliases
parse_forensic_report = parse_failure_report
parsed_forensic_reports_to_csv_rows = parsed_failure_reports_to_csv_rows
parsed_forensic_reports_to_csv = parsed_failure_reports_to_csv
