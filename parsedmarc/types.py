from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict, Union

# NOTE: This module is intentionally Python 3.9 compatible.
# - No PEP 604 unions (A | B)
# - No typing.NotRequired / Required (3.11+) to avoid an extra dependency.
#   For optional keys, use total=False TypedDicts.


ReportType = Literal["aggregate", "failure", "smtp_tls"]


class AggregateReportMetadata(TypedDict):
    org_name: str
    org_email: str
    org_extra_contact_info: Optional[str]
    report_id: str
    begin_date: str
    end_date: str
    timespan_requires_normalization: bool
    original_timespan_seconds: int
    errors: List[str]
    generator: Optional[str]


class AggregatePolicyPublished(TypedDict):
    domain: str
    adkim: str
    aspf: str
    p: str
    sp: str
    pct: str
    fo: str
    np: Optional[str]
    testing: Optional[str]
    discovery_method: Optional[str]


class IPSourceInfo(TypedDict):
    ip_address: str
    country: Optional[str]
    reverse_dns: Optional[str]
    base_domain: Optional[str]
    name: Optional[str]
    type: Optional[str]


class AggregateAlignment(TypedDict):
    spf: bool
    dkim: bool
    dmarc: bool


class AggregateIdentifiers(TypedDict):
    header_from: str
    envelope_from: Optional[str]
    envelope_to: Optional[str]


class AggregatePolicyOverrideReason(TypedDict):
    type: Optional[str]
    comment: Optional[str]


class AggregateAuthResultDKIM(TypedDict):
    domain: str
    result: str
    selector: str
    human_result: Optional[str]


class AggregateAuthResultSPF(TypedDict):
    domain: str
    result: str
    scope: str
    human_result: Optional[str]


class AggregateAuthResults(TypedDict):
    dkim: List[AggregateAuthResultDKIM]
    spf: List[AggregateAuthResultSPF]


class AggregatePolicyEvaluated(TypedDict):
    disposition: str
    dkim: str
    spf: str
    policy_override_reasons: List[AggregatePolicyOverrideReason]


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
    report_metadata: AggregateReportMetadata
    policy_published: AggregatePolicyPublished
    records: List[AggregateRecord]


class EmailAddress(TypedDict):
    display_name: Optional[str]
    address: str
    local: Optional[str]
    domain: Optional[str]


class EmailAttachment(TypedDict, total=False):
    filename: Optional[str]
    mail_content_type: Optional[str]
    sha256: Optional[str]


ParsedEmail = TypedDict(
    "ParsedEmail",
    {
        # This is a lightly-specified version of mailsuite/mailparser JSON.
        # It focuses on the fields parsedmarc uses in failure report handling.
        "headers": Dict[str, Any],
        "subject": Optional[str],
        "filename_safe_subject": Optional[str],
        "date": Optional[str],
        "from": EmailAddress,
        "to": List[EmailAddress],
        "cc": List[EmailAddress],
        "bcc": List[EmailAddress],
        "attachments": List[EmailAttachment],
        "body": Optional[str],
        "has_defects": bool,
        "defects": Any,
        "defects_categories": Any,
    },
    total=False,
)


class FailureReport(TypedDict):
    feedback_type: Optional[str]
    user_agent: Optional[str]
    version: Optional[str]
    original_envelope_id: Optional[str]
    original_mail_from: Optional[str]
    original_rcpt_to: Optional[str]
    arrival_date: str
    arrival_date_utc: str
    authentication_results: Optional[str]
    delivery_result: Optional[str]
    auth_failure: List[str]
    authentication_mechanisms: List[str]
    dkim_domain: Optional[str]
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
    policy_strings: List[str]
    mx_host_patterns: List[str]
    failure_details: List[SMTPTLSFailureDetailsOptional]


class SMTPTLSReport(TypedDict):
    organization_name: str
    begin_date: str
    end_date: str
    contact_info: Union[str, List[str]]
    report_id: str
    policies: List[SMTPTLSPolicy]


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


ParsedReport = Union[AggregateParsedReport, FailureParsedReport, SMTPTLSParsedReport]


class ParsingResults(TypedDict):
    aggregate_reports: List[AggregateReport]
    failure_reports: List[FailureReport]
    smtp_tls_reports: List[SMTPTLSReport]
