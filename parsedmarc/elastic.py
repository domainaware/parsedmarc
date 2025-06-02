# -*- coding: utf-8 -*-

from collections import OrderedDict

from elasticsearch_dsl.search import Q
from elasticsearch_dsl import (
    connections,
    Object,
    Document,
    Index,
    Nested,
    InnerDoc,
    Integer,
    Text,
    Boolean,
    Ip,
    Date,
    Search,
)
from elasticsearch.helpers import reindex

from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime
from parsedmarc import InvalidForensicReport


class ElasticsearchError(Exception):
    """Raised when an Elasticsearch error occurs"""


class _PolicyOverride(InnerDoc):
    type = Text()
    comment = Text()


class _PublishedPolicy(InnerDoc):
    domain = Text()
    adkim = Text()
    aspf = Text()
    p = Text()
    sp = Text()
    pct = Integer()
    fo = Text()


class _DKIMResult(InnerDoc):
    domain = Text()
    selector = Text()
    result = Text()


class _SPFResult(InnerDoc):
    domain = Text()
    scope = Text()
    results = Text()


class _AggregateReportDoc(Document):
    class Index:
        name = "dmarc_aggregate"

    xml_schema = Text()
    org_name = Text()
    org_email = Text()
    org_extra_contact_info = Text()
    report_id = Text()
    date_range = Date()
    date_begin = Date()
    date_end = Date()
    errors = Text()
    published_policy = Object(_PublishedPolicy)
    source_ip_address = Ip()
    source_country = Text()
    source_reverse_dns = Text()
    source_base_domain = Text()
    source_type = Text()
    source_name = Text()
    message_count = Integer
    disposition = Text()
    dkim_aligned = Boolean()
    spf_aligned = Boolean()
    passed_dmarc = Boolean()
    policy_overrides = Nested(_PolicyOverride)
    header_from = Text()
    envelope_from = Text()
    envelope_to = Text()
    dkim_results = Nested(_DKIMResult)
    spf_results = Nested(_SPFResult)

    def add_policy_override(self, type_, comment):
        self.policy_overrides.append(_PolicyOverride(type=type_, comment=comment))

    def add_dkim_result(self, domain, selector, result):
        self.dkim_results.append(
            _DKIMResult(domain=domain, selector=selector, result=result)
        )

    def add_spf_result(self, domain, scope, result):
        self.spf_results.append(_SPFResult(domain=domain, scope=scope, result=result))

    def save(self, **kwargs):
        self.passed_dmarc = False
        self.passed_dmarc = self.spf_aligned or self.dkim_aligned

        return super().save(**kwargs)


class _EmailAddressDoc(InnerDoc):
    display_name = Text()
    address = Text()


class _EmailAttachmentDoc(Document):
    filename = Text()
    content_type = Text()
    sha256 = Text()


class _ForensicSampleDoc(InnerDoc):
    raw = Text()
    headers = Object()
    headers_only = Boolean()
    to = Nested(_EmailAddressDoc)
    subject = Text()
    filename_safe_subject = Text()
    _from = Object(_EmailAddressDoc)
    date = Date()
    reply_to = Nested(_EmailAddressDoc)
    cc = Nested(_EmailAddressDoc)
    bcc = Nested(_EmailAddressDoc)
    body = Text()
    attachments = Nested(_EmailAttachmentDoc)

    def add_to(self, display_name, address):
        self.to.append(_EmailAddressDoc(display_name=display_name, address=address))

    def add_reply_to(self, display_name, address):
        self.reply_to.append(
            _EmailAddressDoc(display_name=display_name, address=address)
        )

    def add_cc(self, display_name, address):
        self.cc.append(_EmailAddressDoc(display_name=display_name, address=address))

    def add_bcc(self, display_name, address):
        self.bcc.append(_EmailAddressDoc(display_name=display_name, address=address))

    def add_attachment(self, filename, content_type, sha256):
        self.attachments.append(
            _EmailAttachmentDoc(
                filename=filename, content_type=content_type, sha256=sha256
            )
        )


class _ForensicReportDoc(Document):
    class Index:
        name = "dmarc_forensic"

    feedback_type = Text()
    user_agent = Text()
    version = Text()
    original_mail_from = Text()
    arrival_date = Date()
    domain = Text()
    original_envelope_id = Text()
    authentication_results = Text()
    delivery_results = Text()
    source_ip_address = Ip()
    source_country = Text()
    source_reverse_dns = Text()
    source_authentication_mechanisms = Text()
    source_auth_failures = Text()
    dkim_domain = Text()
    original_rcpt_to = Text()
    sample = Object(_ForensicSampleDoc)


class _SMTPTLSFailureDetailsDoc(InnerDoc):
    result_type = Text()
    sending_mta_ip = Ip()
    receiving_mx_helo = Text()
    receiving_ip = Ip()
    failed_session_count = Integer()
    additional_information_uri = Text()
    failure_reason_code = Text()


class _SMTPTLSPolicyDoc(InnerDoc):
    policy_domain = Text()
    policy_type = Text()
    policy_strings = Text()
    mx_host_patterns = Text()
    successful_session_count = Integer()
    failed_session_count = Integer()
    failure_details = Nested(_SMTPTLSFailureDetailsDoc)

    def add_failure_details(
        self,
        result_type,
        ip_address,
        receiving_ip,
        receiving_mx_helo,
        failed_session_count,
        sending_mta_ip=None,
        receiving_mx_hostname=None,
        additional_information_uri=None,
        failure_reason_code=None,
    ):
        _details = _SMTPTLSFailureDetailsDoc(
            result_type=result_type,
            ip_address=ip_address,
            sending_mta_ip=sending_mta_ip,
            receiving_mx_hostname=receiving_mx_hostname,
            receiving_mx_helo=receiving_mx_helo,
            receiving_ip=receiving_ip,
            failed_session_count=failed_session_count,
            additional_information=additional_information_uri,
            failure_reason_code=failure_reason_code,
        )
        self.failure_details.append(_details)


class _SMTPTLSReportDoc(Document):
    class Index:
        name = "smtp_tls"

    organization_name = Text()
    date_range = Date()
    date_begin = Date()
    date_end = Date()
    contact_info = Text()
    report_id = Text()
    policies = Nested(_SMTPTLSPolicyDoc)

    def add_policy(
        self,
        policy_type,
        policy_domain,
        successful_session_count,
        failed_session_count,
        policy_string=None,
        mx_host_patterns=None,
        failure_details=None,
    ):
        self.policies.append(
            policy_type=policy_type,
            policy_domain=policy_domain,
            successful_session_count=successful_session_count,
            failed_session_count=failed_session_count,
            policy_string=policy_string,
            mx_host_patterns=mx_host_patterns,
            failure_details=failure_details,
        )


class AlreadySaved(ValueError):
    """Raised when a report to be saved matches an existing report"""


def set_hosts(
    hosts,
    use_ssl=False,
    ssl_cert_path=None,
    username=None,
    password=None,
    apiKey=None,
    timeout=60.0,
):
    """
    Sets the Elasticsearch hosts to use

    Args:
        hosts (str): A single hostname or URL, or list of hostnames or URLs
        use_ssl (bool): Use a HTTPS connection to the server
        ssl_cert_path (str): Path to the certificate chain
        username (str): The username to use for authentication
        password (str): The password to use for authentication
        apiKey (str): The Base64 encoded API key to use for authentication
        timeout (float): Timeout in seconds
    """
    if not isinstance(hosts, list):
        hosts = [hosts]
    conn_params = {"hosts": hosts, "timeout": timeout}
    if use_ssl:
        conn_params["use_ssl"] = True
        if ssl_cert_path:
            conn_params["verify_certs"] = True
            conn_params["ca_certs"] = ssl_cert_path
        else:
            conn_params["verify_certs"] = False
    if username:
        conn_params["http_auth"] = username + ":" + password
    if apiKey:
        conn_params["api_key"] = apiKey
    connections.create_connection(**conn_params)


def create_indexes(names, settings=None):
    """
    Create Elasticsearch indexes

    Args:
        names (list): A list of index names
        settings (dict): Index settings

    """
    for name in names:
        index = Index(name)
        try:
            if not index.exists():
                logger.debug("Creating Elasticsearch index: {0}".format(name))
                if settings is None:
                    index.settings(number_of_shards=1, number_of_replicas=0)
                else:
                    index.settings(**settings)
                index.create()
        except Exception as e:
            raise ElasticsearchError("Elasticsearch error: {0}".format(e.__str__()))


def migrate_indexes(aggregate_indexes=None, forensic_indexes=None):
    """
    Updates index mappings

    Args:
        aggregate_indexes (list): A list of aggregate index names
        forensic_indexes (list): A list of forensic index names
    """
    version = 2
    if aggregate_indexes is None:
        aggregate_indexes = []
    if forensic_indexes is None:
        forensic_indexes = []
    for aggregate_index_name in aggregate_indexes:
        if not Index(aggregate_index_name).exists():
            continue
        aggregate_index = Index(aggregate_index_name)
        doc = "doc"
        fo_field = "published_policy.fo"
        fo = "fo"
        fo_mapping = aggregate_index.get_field_mapping(fields=[fo_field])
        fo_mapping = fo_mapping[list(fo_mapping.keys())[0]]["mappings"]
        if doc not in fo_mapping:
            continue

        fo_mapping = fo_mapping[doc][fo_field]["mapping"][fo]
        fo_type = fo_mapping["type"]
        if fo_type == "long":
            new_index_name = "{0}-v{1}".format(aggregate_index_name, version)
            body = {
                "properties": {
                    "published_policy.fo": {
                        "type": "text",
                        "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                    }
                }
            }
            Index(new_index_name).create()
            Index(new_index_name).put_mapping(doc_type=doc, body=body)
            reindex(connections.get_connection(), aggregate_index_name, new_index_name)
            Index(aggregate_index_name).delete()

    for forensic_index in forensic_indexes:
        pass


def save_aggregate_report_to_elasticsearch(
    aggregate_report,
    index_suffix=None,
    index_prefix=None,
    monthly_indexes=False,
    number_of_shards=1,
    number_of_replicas=0,
):
    """
    Saves a parsed DMARC aggregate report to Elasticsearch

    Args:
        aggregate_report (OrderedDict): A parsed forensic report
        index_suffix (str): The suffix of the name of the index to save to
        index_prefix (str): The prefix of the name of the index to save to
        monthly_indexes (bool): Use monthly indexes instead of daily indexes
        number_of_shards (int): The number of shards to use in the index
        number_of_replicas (int): The number of replicas to use in the index

    Raises:
            AlreadySaved
    """
    logger.info("Saving aggregate report to Elasticsearch")
    aggregate_report = aggregate_report.copy()
    metadata = aggregate_report["report_metadata"]
    org_name = metadata["org_name"]
    report_id = metadata["report_id"]
    domain = aggregate_report["policy_published"]["domain"]
    begin_date = human_timestamp_to_datetime(metadata["begin_date"], to_utc=True)
    end_date = human_timestamp_to_datetime(metadata["end_date"], to_utc=True)
    begin_date_human = begin_date.strftime("%Y-%m-%d %H:%M:%SZ")
    end_date_human = end_date.strftime("%Y-%m-%d %H:%M:%SZ")
    if monthly_indexes:
        index_date = begin_date.strftime("%Y-%m")
    else:
        index_date = begin_date.strftime("%Y-%m-%d")
    aggregate_report["begin_date"] = begin_date
    aggregate_report["end_date"] = end_date
    date_range = [aggregate_report["begin_date"], aggregate_report["end_date"]]

    org_name_query = Q(dict(match_phrase=dict(org_name=org_name)))
    report_id_query = Q(dict(match_phrase=dict(report_id=report_id)))
    domain_query = Q(dict(match_phrase={"published_policy.domain": domain}))
    begin_date_query = Q(dict(match=dict(date_begin=begin_date)))
    end_date_query = Q(dict(match=dict(date_end=end_date)))

    if index_suffix is not None:
        search_index = "dmarc_aggregate_{0}*".format(index_suffix)
    else:
        search_index = "dmarc_aggregate*"
    if index_prefix is not None:
        search_index = "{0}{1}".format(index_prefix, search_index)
    search = Search(index=search_index)
    query = org_name_query & report_id_query & domain_query
    query = query & begin_date_query & end_date_query
    search.query = query

    try:
        existing = search.execute()
    except Exception as error_:
        raise ElasticsearchError(
            "Elasticsearch's search for existing report \
            error: {}".format(error_.__str__())
        )

    if len(existing) > 0:
        raise AlreadySaved(
            "An aggregate report ID {0} from {1} about {2} "
            "with a date range of {3} UTC to {4} UTC already "
            "exists in "
            "Elasticsearch".format(
                report_id, org_name, domain, begin_date_human, end_date_human
            )
        )
    published_policy = _PublishedPolicy(
        domain=aggregate_report["policy_published"]["domain"],
        adkim=aggregate_report["policy_published"]["adkim"],
        aspf=aggregate_report["policy_published"]["aspf"],
        p=aggregate_report["policy_published"]["p"],
        sp=aggregate_report["policy_published"]["sp"],
        pct=aggregate_report["policy_published"]["pct"],
        fo=aggregate_report["policy_published"]["fo"],
    )

    for record in aggregate_report["records"]:
        agg_doc = _AggregateReportDoc(
            xml_schema=aggregate_report["xml_schema"],
            org_name=metadata["org_name"],
            org_email=metadata["org_email"],
            org_extra_contact_info=metadata["org_extra_contact_info"],
            report_id=metadata["report_id"],
            date_range=date_range,
            date_begin=aggregate_report["begin_date"],
            date_end=aggregate_report["end_date"],
            errors=metadata["errors"],
            published_policy=published_policy,
            source_ip_address=record["source"]["ip_address"],
            source_country=record["source"]["country"],
            source_reverse_dns=record["source"]["reverse_dns"],
            source_base_domain=record["source"]["base_domain"],
            source_type=record["source"]["type"],
            source_name=record["source"]["name"],
            message_count=record["count"],
            disposition=record["policy_evaluated"]["disposition"],
            dkim_aligned=record["policy_evaluated"]["dkim"] is not None
            and record["policy_evaluated"]["dkim"].lower() == "pass",
            spf_aligned=record["policy_evaluated"]["spf"] is not None
            and record["policy_evaluated"]["spf"].lower() == "pass",
            header_from=record["identifiers"]["header_from"],
            envelope_from=record["identifiers"]["envelope_from"],
            envelope_to=record["identifiers"]["envelope_to"],
        )

        for override in record["policy_evaluated"]["policy_override_reasons"]:
            agg_doc.add_policy_override(
                type_=override["type"], comment=override["comment"]
            )

        for dkim_result in record["auth_results"]["dkim"]:
            agg_doc.add_dkim_result(
                domain=dkim_result["domain"],
                selector=dkim_result["selector"],
                result=dkim_result["result"],
            )

        for spf_result in record["auth_results"]["spf"]:
            agg_doc.add_spf_result(
                domain=spf_result["domain"],
                scope=spf_result["scope"],
                result=spf_result["result"],
            )

        index = "dmarc_aggregate"
        if index_suffix:
            index = "{0}_{1}".format(index, index_suffix)
        if index_prefix:
            index = "{0}{1}".format(index_prefix, index)

        index = "{0}-{1}".format(index, index_date)
        index_settings = dict(
            number_of_shards=number_of_shards, number_of_replicas=number_of_replicas
        )
        create_indexes([index], index_settings)
        agg_doc.meta.index = index

        try:
            agg_doc.save()
        except Exception as e:
            raise ElasticsearchError("Elasticsearch error: {0}".format(e.__str__()))


def save_forensic_report_to_elasticsearch(
    forensic_report,
    index_suffix=None,
    index_prefix=None,
    monthly_indexes=False,
    number_of_shards=1,
    number_of_replicas=0,
):
    """
    Saves a parsed DMARC forensic report to Elasticsearch

    Args:
        forensic_report (OrderedDict): A parsed forensic report
        index_suffix (str): The suffix of the name of the index to save to
        index_prefix (str): The prefix of the name of the index to save to
        monthly_indexes (bool): Use monthly indexes instead of daily
                                indexes
        number_of_shards (int): The number of shards to use in the index
        number_of_replicas (int): The number of replicas to use in the
                                  index

    Raises:
        AlreadySaved

    """
    logger.info("Saving forensic report to Elasticsearch")
    forensic_report = forensic_report.copy()
    sample_date = None
    if forensic_report["parsed_sample"]["date"] is not None:
        sample_date = forensic_report["parsed_sample"]["date"]
        sample_date = human_timestamp_to_datetime(sample_date)
    original_headers = forensic_report["parsed_sample"]["headers"]
    headers = OrderedDict()
    for original_header in original_headers:
        headers[original_header.lower()] = original_headers[original_header]

    arrival_date = human_timestamp_to_datetime(forensic_report["arrival_date_utc"])
    arrival_date_epoch_milliseconds = int(arrival_date.timestamp() * 1000)

    if index_suffix is not None:
        search_index = "dmarc_forensic_{0}*".format(index_suffix)
    else:
        search_index = "dmarc_forensic*"
    if index_prefix is not None:
        search_index = "{0}{1}".format(index_prefix, search_index)
    search = Search(index=search_index)
    q = Q(dict(match=dict(arrival_date=arrival_date_epoch_milliseconds)))

    from_ = None
    to_ = None
    subject = None
    if "from" in headers:
        # We convert the FROM header from a string list to a flat string.
        headers["from"] = headers["from"][0]
        if headers["from"][0] == "":
            headers["from"] = headers["from"][1]
        else:
            headers["from"] = " <".join(headers["from"]) + ">"

        from_ = dict()
        from_["sample.headers.from"] = headers["from"]
        from_query = Q(dict(match_phrase=from_))
        q = q & from_query
    if "to" in headers:
        # We convert the TO header from a string list to a flat string.
        headers["to"] = headers["to"][0]
        if headers["to"][0] == "":
            headers["to"] = headers["to"][1]
        else:
            headers["to"] = " <".join(headers["to"]) + ">"

        to_ = dict()
        to_["sample.headers.to"] = headers["to"]
        to_query = Q(dict(match_phrase=to_))
        q = q & to_query
    if "subject" in headers:
        subject = headers["subject"]
        subject_query = {"match_phrase": {"sample.headers.subject": subject}}
        q = q & Q(subject_query)

    search.query = q
    existing = search.execute()

    if len(existing) > 0:
        raise AlreadySaved(
            "A forensic sample to {0} from {1} "
            "with a subject of {2} and arrival date of {3} "
            "already exists in "
            "Elasticsearch".format(
                to_, from_, subject, forensic_report["arrival_date_utc"]
            )
        )

    parsed_sample = forensic_report["parsed_sample"]
    sample = _ForensicSampleDoc(
        raw=forensic_report["sample"],
        headers=headers,
        headers_only=forensic_report["sample_headers_only"],
        date=sample_date,
        subject=forensic_report["parsed_sample"]["subject"],
        filename_safe_subject=parsed_sample["filename_safe_subject"],
        body=forensic_report["parsed_sample"]["body"],
    )

    for address in forensic_report["parsed_sample"]["to"]:
        sample.add_to(display_name=address["display_name"], address=address["address"])
    for address in forensic_report["parsed_sample"]["reply_to"]:
        sample.add_reply_to(
            display_name=address["display_name"], address=address["address"]
        )
    for address in forensic_report["parsed_sample"]["cc"]:
        sample.add_cc(display_name=address["display_name"], address=address["address"])
    for address in forensic_report["parsed_sample"]["bcc"]:
        sample.add_bcc(display_name=address["display_name"], address=address["address"])
    for attachment in forensic_report["parsed_sample"]["attachments"]:
        sample.add_attachment(
            filename=attachment["filename"],
            content_type=attachment["mail_content_type"],
            sha256=attachment["sha256"],
        )
    try:
        forensic_doc = _ForensicReportDoc(
            feedback_type=forensic_report["feedback_type"],
            user_agent=forensic_report["user_agent"],
            version=forensic_report["version"],
            original_mail_from=forensic_report["original_mail_from"],
            arrival_date=arrival_date_epoch_milliseconds,
            domain=forensic_report["reported_domain"],
            original_envelope_id=forensic_report["original_envelope_id"],
            authentication_results=forensic_report["authentication_results"],
            delivery_results=forensic_report["delivery_result"],
            source_ip_address=forensic_report["source"]["ip_address"],
            source_country=forensic_report["source"]["country"],
            source_reverse_dns=forensic_report["source"]["reverse_dns"],
            source_base_domain=forensic_report["source"]["base_domain"],
            authentication_mechanisms=forensic_report["authentication_mechanisms"],
            auth_failure=forensic_report["auth_failure"],
            dkim_domain=forensic_report["dkim_domain"],
            original_rcpt_to=forensic_report["original_rcpt_to"],
            sample=sample,
        )

        index = "dmarc_forensic"
        if index_suffix:
            index = "{0}_{1}".format(index, index_suffix)
        if index_prefix:
            index = "{0}{1}".format(index_prefix, index)
        if monthly_indexes:
            index_date = arrival_date.strftime("%Y-%m")
        else:
            index_date = arrival_date.strftime("%Y-%m-%d")
        index = "{0}-{1}".format(index, index_date)
        index_settings = dict(
            number_of_shards=number_of_shards, number_of_replicas=number_of_replicas
        )
        create_indexes([index], index_settings)
        forensic_doc.meta.index = index
        try:
            forensic_doc.save()
        except Exception as e:
            raise ElasticsearchError("Elasticsearch error: {0}".format(e.__str__()))
    except KeyError as e:
        raise InvalidForensicReport(
            "Forensic report missing required field: {0}".format(e.__str__())
        )


def save_smtp_tls_report_to_elasticsearch(
    report,
    index_suffix=None,
    index_prefix=None,
    monthly_indexes=False,
    number_of_shards=1,
    number_of_replicas=0,
):
    """
    Saves a parsed SMTP TLS report to Elasticsearch

    Args:
        report (OrderedDict): A parsed SMTP TLS report
        index_suffix (str): The suffix of the name of the index to save to
        index_prefix (str): The prefix of the name of the index to save to
        monthly_indexes (bool): Use monthly indexes instead of daily indexes
        number_of_shards (int): The number of shards to use in the index
        number_of_replicas (int): The number of replicas to use in the index

    Raises:
            AlreadySaved
    """
    logger.info("Saving smtp tls report to Elasticsearch")
    org_name = report["organization_name"]
    report_id = report["report_id"]
    begin_date = human_timestamp_to_datetime(report["begin_date"], to_utc=True)
    end_date = human_timestamp_to_datetime(report["end_date"], to_utc=True)
    begin_date_human = begin_date.strftime("%Y-%m-%d %H:%M:%SZ")
    end_date_human = end_date.strftime("%Y-%m-%d %H:%M:%SZ")
    if monthly_indexes:
        index_date = begin_date.strftime("%Y-%m")
    else:
        index_date = begin_date.strftime("%Y-%m-%d")
    report["begin_date"] = begin_date
    report["end_date"] = end_date

    org_name_query = Q(dict(match_phrase=dict(org_name=org_name)))
    report_id_query = Q(dict(match_phrase=dict(report_id=report_id)))
    begin_date_query = Q(dict(match=dict(date_begin=begin_date)))
    end_date_query = Q(dict(match=dict(date_end=end_date)))

    if index_suffix is not None:
        search_index = "smtp_tls_{0}*".format(index_suffix)
    else:
        search_index = "smtp_tls*"
    if index_prefix is not None:
        search_index = "{0}{1}".format(index_prefix, search_index)
    search = Search(index=search_index)
    query = org_name_query & report_id_query
    query = query & begin_date_query & end_date_query
    search.query = query

    try:
        existing = search.execute()
    except Exception as error_:
        raise ElasticsearchError(
            "Elasticsearch's search for existing report \
            error: {}".format(error_.__str__())
        )

    if len(existing) > 0:
        raise AlreadySaved(
            f"An SMTP TLS report ID {report_id} from "
            f" {org_name} with a date range of "
            f"{begin_date_human} UTC to "
            f"{end_date_human} UTC already "
            "exists in Elasticsearch"
        )

    index = "smtp_tls"
    if index_suffix:
        index = "{0}_{1}".format(index, index_suffix)
    if index_prefix:
        index = "{0}{1}".format(index_prefix, index)
    index = "{0}-{1}".format(index, index_date)
    index_settings = dict(
        number_of_shards=number_of_shards, number_of_replicas=number_of_replicas
    )

    smtp_tls_doc = _SMTPTLSReportDoc(
        org_name=report["organization_name"],
        date_range=[report["begin_date"], report["end_date"]],
        date_begin=report["begin_date"],
        date_end=report["end_date"],
        contact_info=report["contact_info"],
        report_id=report["report_id"],
    )

    for policy in report["policies"]:
        policy_strings = None
        mx_host_patterns = None
        if "policy_strings" in policy:
            policy_strings = policy["policy_strings"]
        if "mx_host_patterns" in policy:
            mx_host_patterns = policy["mx_host_patterns"]
        policy_doc = _SMTPTLSPolicyDoc(
            policy_domain=policy["policy_domain"],
            policy_type=policy["policy_type"],
            succesful_session_count=policy["successful_session_count"],
            failed_session_count=policy["failed_session_count"],
            policy_string=policy_strings,
            mx_host_patterns=mx_host_patterns,
        )
        if "failure_details" in policy:
            for failure_detail in policy["failure_details"]:
                receiving_mx_hostname = None
                additional_information_uri = None
                failure_reason_code = None
                ip_address = None
                receiving_ip = None
                receiving_mx_helo = None
                sending_mta_ip = None

                if "receiving_mx_hostname" in failure_detail:
                    receiving_mx_hostname = failure_detail["receiving_mx_hostname"]
                if "additional_information_uri" in failure_detail:
                    additional_information_uri = failure_detail[
                        "additional_information_uri"
                    ]
                if "failure_reason_code" in failure_detail:
                    failure_reason_code = failure_detail["failure_reason_code"]
                if "ip_address" in failure_detail:
                    ip_address = failure_detail["ip_address"]
                if "receiving_ip" in failure_detail:
                    receiving_ip = failure_detail["receiving_ip"]
                if "receiving_mx_helo" in failure_detail:
                    receiving_mx_helo = failure_detail["receiving_mx_helo"]
                if "sending_mta_ip" in failure_detail:
                    sending_mta_ip = failure_detail["sending_mta_ip"]
                policy_doc.add_failure_details(
                    result_type=failure_detail["result_type"],
                    ip_address=ip_address,
                    receiving_ip=receiving_ip,
                    receiving_mx_helo=receiving_mx_helo,
                    failed_session_count=failure_detail["failed_session_count"],
                    sending_mta_ip=sending_mta_ip,
                    receiving_mx_hostname=receiving_mx_hostname,
                    additional_information_uri=additional_information_uri,
                    failure_reason_code=failure_reason_code,
                )
        smtp_tls_doc.policies.append(policy_doc)

    create_indexes([index], index_settings)
    smtp_tls_doc.meta.index = index

    try:
        smtp_tls_doc.save()
    except Exception as e:
        raise ElasticsearchError("Elasticsearch error: {0}".format(e.__str__()))
