from __future__ import annotations

from typing import Any, Literal, TypedDict

# NOTE: This module targets Python 3.10.
# - PEP 604 unions (A | B) and PEP 585 generics (list[str]) are used; both are
#   available in 3.10.
# - No typing.NotRequired / Required (3.11+); for optional TypedDict keys, use
#   total=False TypedDicts.


ReportType = Literal["aggregate", "failure", "smtp_tls"]


class AggregateReportMetadata(TypedDict):
    org_name: str
    org_email: str
    org_extra_contact_info: str | None
    report_id: str
    begin_date: str
    end_date: str
    timespan_requires_normalization: bool
    original_timespan_seconds: int
    errors: list[str]
    generator: str | None


class AggregatePolicyPublished(TypedDict):
    domain: str
    adkim: str
    aspf: str
    p: str
    sp: str
    pct: str | None
    fo: str | None
    np: str | None
    testing: str | None
    discovery_method: str | None


class IPSourceInfo(TypedDict):
    ip_address: str
    country: str | None
    reverse_dns: str | None
    base_domain: str | None
    name: str | None
    type: str | None
    asn: int | None
    as_name: str | None
    as_domain: str | None


class AggregateAlignment(TypedDict):
    spf: bool
    dkim: bool
    dmarc: bool


class AggregateIdentifiers(TypedDict):
    header_from: str
    envelope_from: str | None
    envelope_to: str | None


class AggregatePolicyOverrideReason(TypedDict):
    type: str | None
    comment: str | None


class AggregateAuthResultDKIM(TypedDict):
    domain: str
    result: str
    selector: str
    human_result: str | None


class AggregateAuthResultSPF(TypedDict):
    domain: str
    result: str
    scope: str
    human_result: str | None


class AggregateAuthResults(TypedDict):
    dkim: list[AggregateAuthResultDKIM]
    spf: list[AggregateAuthResultSPF]


class AggregatePolicyEvaluated(TypedDict):
    disposition: str
    dkim: str
    spf: str
    policy_override_reasons: list[AggregatePolicyOverrideReason]


class AggregateRecord(TypedDict):
    interval_begin: str
    interval_end: str
    source: IPSourceInfo
    count: int
    alignment: AggregateAlignment
    policy_evaluated: AggregatePolicyEvaluated
    disposition: str
    identifiers: AggregateIdentifiers
    auth_results: AggregateAuthResults


class AggregateReport(TypedDict):
    xml_schema: str
    xml_namespace: str | None
    report_metadata: AggregateReportMetadata
    policy_published: AggregatePolicyPublished
    records: list[AggregateRecord]


class EmailAddress(TypedDict):
    display_name: str | None
    address: str
    local: str | None
    domain: str | None


class EmailAttachment(TypedDict, total=False):
    filename: str | None
    mail_content_type: str | None
    sha256: str | None


ParsedEmail = TypedDict(
    "ParsedEmail",
    {
        # This is a lightly-specified version of mailsuite/mailparser JSON.
        # It focuses on the fields parsedmarc uses in failure report handling.
        "headers": dict[str, Any],
        "subject": str | None,
        "filename_safe_subject": str | None,
        "date": str | None,
        "from": EmailAddress,
        "to": list[EmailAddress],
        "cc": list[EmailAddress],
        "bcc": list[EmailAddress],
        "attachments": list[EmailAttachment],
        "body": str | None,
        "has_defects": bool,
        "defects": Any,
        "defects_categories": Any,
    },
    total=False,
)


class FailureReport(TypedDict):
    feedback_type: str | None
    user_agent: str | None
    version: str | None
    original_envelope_id: str | None
    original_mail_from: str | None
    original_rcpt_to: str | None
    arrival_date: str
    arrival_date_utc: str
    authentication_results: str | None
    delivery_result: str | None
    auth_failure: list[str]
    authentication_mechanisms: list[str]
    dkim_domain: str | None
    reported_domain: str
    sample_headers_only: bool
    source: IPSourceInfo
    sample: str
    parsed_sample: ParsedEmail


# Backward-compatible alias
ForensicReport = FailureReport


class SMTPTLSFailureDetails(TypedDict):
    result_type: str
    failed_session_count: int


class SMTPTLSFailureDetailsOptional(SMTPTLSFailureDetails, total=False):
    sending_mta_ip: str
    receiving_ip: str
    receiving_mx_hostname: str
    receiving_mx_helo: str
    additional_info_uri: str
    failure_reason_code: str
    ip_address: str


class SMTPTLSPolicySummary(TypedDict):
    policy_domain: str
    policy_type: str
    successful_session_count: int
    failed_session_count: int


class SMTPTLSPolicy(SMTPTLSPolicySummary, total=False):
    policy_strings: list[str]
    mx_host_patterns: list[str]
    failure_details: list[SMTPTLSFailureDetailsOptional]


class SMTPTLSReport(TypedDict):
    organization_name: str
    begin_date: str
    end_date: str
    contact_info: str | list[str]
    report_id: str
    policies: list[SMTPTLSPolicy]


class AggregateParsedReport(TypedDict):
    report_type: Literal["aggregate"]
    report: AggregateReport


class FailureParsedReport(TypedDict):
    report_type: Literal["failure"]
    report: FailureReport


# Backward-compatible alias
ForensicParsedReport = FailureParsedReport


class SMTPTLSParsedReport(TypedDict):
    report_type: Literal["smtp_tls"]
    report: SMTPTLSReport


ParsedReport = AggregateParsedReport | FailureParsedReport | SMTPTLSParsedReport


class ParsingResults(TypedDict):
    aggregate_reports: list[AggregateReport]
    failure_reports: list[FailureReport]
    smtp_tls_reports: list[SMTPTLSReport]
