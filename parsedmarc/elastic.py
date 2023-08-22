# -*- coding: utf-8 -*-

from collections import OrderedDict

from elasticsearch_dsl.search import Q
from elasticsearch_dsl import connections, Object, Document, Index, Nested, \
    InnerDoc, Integer, Text, Boolean, Ip, Date, Search
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
    source_Base_domain = Text()
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
        self.policy_overrides.append(_PolicyOverride(type=type_,
                                                     comment=comment))

    def add_dkim_result(self, domain, selector, result):
        self.dkim_results.append(_DKIMResult(domain=domain,
                                             selector=selector,
                                             result=result))

    def add_spf_result(self, domain, scope, result):
        self.spf_results.append(_SPFResult(domain=domain,
                                           scope=scope,
                                           result=result))

    def save(self, ** kwargs):
        self.passed_dmarc = False
        self.passed_dmarc = self.spf_aligned or self.dkim_aligned

        return super().save(** kwargs)


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
        self.to.append(_EmailAddressDoc(display_name=display_name,
                                        address=address))

    def add_reply_to(self, display_name, address):
        self.reply_to.append(_EmailAddressDoc(display_name=display_name,
                                              address=address))

    def add_cc(self, display_name, address):
        self.cc.append(_EmailAddressDoc(display_name=display_name,
                                        address=address))

    def add_bcc(self, display_name, address):
        self.bcc.append(_EmailAddressDoc(display_name=display_name,
                                         address=address))

    def add_attachment(self, filename, content_type, sha256):
        self.attachments.append(_EmailAttachmentDoc(filename=filename,
                                content_type=content_type, sha256=sha256))


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


class AlreadySaved(ValueError):
    """Raised when a report to be saved matches an existing report"""


def set_hosts(hosts, use_ssl=False, ssl_cert_path=None,
              username=None, password=None, timeout=60.0):
    """
    Sets the Elasticsearch hosts to use

    Args:
        hosts (str): A single hostname or URL, or list of hostnames or URLs
        use_ssl (bool): Use a HTTPS connection to the server
        ssl_cert_path (str): Path to the certificate chain
        username (str): The username to use for authentication
        password (str): The password to use for authentication
        timeout (float): Timeout in seconds
    """
    if not isinstance(hosts, list):
        hosts = [hosts]
    conn_params = {
        "hosts": hosts,
        "timeout": timeout
    }
    if use_ssl:
        conn_params['use_ssl'] = True
        if ssl_cert_path:
            conn_params['verify_certs'] = True
            conn_params['ca_certs'] = ssl_cert_path
        else:
            conn_params['verify_certs'] = False
    if username:
        conn_params['http_auth'] = (username+":"+password)
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
                    index.settings(number_of_shards=1,
                                   number_of_replicas=0)
                else:
                    index.settings(**settings)
                index.create()
        except Exception as e:
            raise ElasticsearchError(
                "Elasticsearch error: {0}".format(e.__str__()))


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
            body = {"properties": {"published_policy.fo": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 256
                    }
                }
            }
            }
            }
            Index(new_index_name).create()
            Index(new_index_name).put_mapping(doc_type=doc, body=body)
            reindex(connections.get_connection(), aggregate_index_name,
                    new_index_name)
            Index(aggregate_index_name).delete()

    for forensic_index in forensic_indexes:
        pass


def save_aggregate_report_to_elasticsearch(aggregate_report,
                                           index_suffix=None,
                                           monthly_indexes=False,
                                           number_of_shards=1,
                                           number_of_replicas=0):
    """
    Saves a parsed DMARC aggregate report to ElasticSearch

    Args:
        aggregate_report (OrderedDict): A parsed forensic report
        index_suffix (str): The suffix of the name of the index to save to
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
    begin_date = human_timestamp_to_datetime(metadata["begin_date"],
                                             to_utc=True)
    end_date = human_timestamp_to_datetime(metadata["end_date"],
                                           to_utc=True)
    begin_date_human = begin_date.strftime("%Y-%m-%d %H:%M:%SZ")
    end_date_human = end_date.strftime("%Y-%m-%d %H:%M:%SZ")
    if monthly_indexes:
        index_date = begin_date.strftime("%Y-%m")
    else:
        index_date = begin_date.strftime("%Y-%m-%d")
    aggregate_report["begin_date"] = begin_date
    aggregate_report["end_date"] = end_date
    date_range = [aggregate_report["begin_date"],
                  aggregate_report["end_date"]]

    org_name_query = Q(dict(match_phrase=dict(org_name=org_name)))
    report_id_query = Q(dict(match_phrase=dict(report_id=report_id)))
    domain_query = Q(dict(match_phrase={"published_policy.domain": domain}))
    begin_date_query = Q(dict(match=dict(date_begin=begin_date)))
    end_date_query = Q(dict(match=dict(date_end=end_date)))

    if index_suffix is not None:
        search = Search(index="dmarc_aggregate_{0}*".format(index_suffix))
    else:
        search = Search(index="dmarc_aggregate*")
    query = org_name_query & report_id_query & domain_query
    query = query & begin_date_query & end_date_query
    search.query = query

    try:
        existing = search.execute()
    except Exception as error_:
        raise ElasticsearchError("Elasticsearch's search for existing report \
            error: {}".format(error_.__str__()))

    if len(existing) > 0:
        raise AlreadySaved("An aggregate report ID {0} from {1} about {2} "
                           "with a date range of {3} UTC to {4} UTC already "
                           "exists in "
                           "Elasticsearch".format(report_id,
                                                  org_name,
                                                  domain,
                                                  begin_date_human,
                                                  end_date_human))
    published_policy = _PublishedPolicy(
        domain=aggregate_report["policy_published"]["domain"],
        adkim=aggregate_report["policy_published"]["adkim"],
        aspf=aggregate_report["policy_published"]["aspf"],
        p=aggregate_report["policy_published"]["p"],
        sp=aggregate_report["policy_published"]["sp"],
        pct=aggregate_report["policy_published"]["pct"],
        fo=aggregate_report["policy_published"]["fo"]
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
            message_count=record["count"],
            disposition=record["policy_evaluated"]["disposition"],
            dkim_aligned=record["policy_evaluated"]["dkim"] is not None and
            record["policy_evaluated"]["dkim"].lower() == "pass",
            spf_aligned=record["policy_evaluated"]["spf"] is not None and
            record["policy_evaluated"]["spf"].lower() == "pass",
            header_from=record["identifiers"]["header_from"],
            envelope_from=record["identifiers"]["envelope_from"],
            envelope_to=record["identifiers"]["envelope_to"]
        )

        for override in record["policy_evaluated"]["policy_override_reasons"]:
            agg_doc.add_policy_override(type_=override["type"],
                                        comment=override["comment"])

        for dkim_result in record["auth_results"]["dkim"]:
            agg_doc.add_dkim_result(domain=dkim_result["domain"],
                                    selector=dkim_result["selector"],
                                    result=dkim_result["result"])

        for spf_result in record["auth_results"]["spf"]:
            agg_doc.add_spf_result(domain=spf_result["domain"],
                                   scope=spf_result["scope"],
                                   result=spf_result["result"])

        index = "dmarc_aggregate"
        if index_suffix:
            index = "{0}_{1}".format(index, index_suffix)
        index = "{0}-{1}".format(index, index_date)
        index_settings = dict(number_of_shards=number_of_shards,
                              number_of_replicas=number_of_replicas)
        create_indexes([index], index_settings)
        agg_doc.meta.index = index

        try:
            agg_doc.save()
        except Exception as e:
            raise ElasticsearchError(
                "Elasticsearch error: {0}".format(e.__str__()))


def save_forensic_report_to_elasticsearch(forensic_report,
                                          index_suffix=None,
                                          monthly_indexes=False,
                                          number_of_shards=1,
                                          number_of_replicas=0):
    """
        Saves a parsed DMARC forensic report to ElasticSearch

        Args:
            forensic_report (OrderedDict): A parsed forensic report
            index_suffix (str): The suffix of the name of the index to save to
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

    arrival_date_human = forensic_report["arrival_date_utc"]
    arrival_date = human_timestamp_to_datetime(arrival_date_human)

    if index_suffix is not None:
        search = Search(index="dmarc_forensic_{0}*".format(index_suffix))
    else:
        search = Search(index="dmarc_forensic*")
    arrival_query = {"match": {"arrival_date": arrival_date}}
    q = Q(arrival_query)

    from_ = None
    to_ = None
    subject = None
    if "from" in headers:
        from_ = headers["from"]
        from_query = {"match_phrase": {"sample.headers.from": from_}}
        q = q & Q(from_query)
    if "to" in headers:
        to_ = headers["to"]
        to_query = {"match_phrase": {"sample.headers.to": to_}}
        q = q & Q(to_query)
    if "subject" in headers:
        subject = headers["subject"]
        subject_query = {"match_phrase": {"sample.headers.subject": subject}}
        q = q & Q(subject_query)

    search.query = q
    existing = search.execute()

    if len(existing) > 0:
        raise AlreadySaved("A forensic sample to {0} from {1} "
                           "with a subject of {2} and arrival date of {3} "
                           "already exists in "
                           "Elasticsearch".format(to_,
                                                  from_,
                                                  subject,
                                                  arrival_date_human
                                                  ))

    parsed_sample = forensic_report["parsed_sample"]
    sample = _ForensicSampleDoc(
        raw=forensic_report["sample"],
        headers=headers,
        headers_only=forensic_report["sample_headers_only"],
        date=sample_date,
        subject=forensic_report["parsed_sample"]["subject"],
        filename_safe_subject=parsed_sample["filename_safe_subject"],
        body=forensic_report["parsed_sample"]["body"]
    )

    for address in forensic_report["parsed_sample"]["to"]:
        sample.add_to(display_name=address["display_name"],
                      address=address["address"])
    for address in forensic_report["parsed_sample"]["reply_to"]:
        sample.add_reply_to(display_name=address["display_name"],
                            address=address["address"])
    for address in forensic_report["parsed_sample"]["cc"]:
        sample.add_cc(display_name=address["display_name"],
                      address=address["address"])
    for address in forensic_report["parsed_sample"]["bcc"]:
        sample.add_bcc(display_name=address["display_name"],
                       address=address["address"])
    for attachment in forensic_report["parsed_sample"]["attachments"]:
        sample.add_attachment(filename=attachment["filename"],
                              content_type=attachment["mail_content_type"],
                              sha256=attachment["sha256"])
    try:
        forensic_doc = _ForensicReportDoc(
            feedback_type=forensic_report["feedback_type"],
            user_agent=forensic_report["user_agent"],
            version=forensic_report["version"],
            original_mail_from=forensic_report["original_mail_from"],
            arrival_date=arrival_date,
            domain=forensic_report["reported_domain"],
            original_envelope_id=forensic_report["original_envelope_id"],
            authentication_results=forensic_report["authentication_results"],
            delivery_results=forensic_report["delivery_result"],
            source_ip_address=forensic_report["source"]["ip_address"],
            source_country=forensic_report["source"]["country"],
            source_reverse_dns=forensic_report["source"]["reverse_dns"],
            source_base_domain=forensic_report["source"]["base_domain"],
            authentication_mechanisms=forensic_report[
                "authentication_mechanisms"],
            auth_failure=forensic_report["auth_failure"],
            dkim_domain=forensic_report["dkim_domain"],
            original_rcpt_to=forensic_report["original_rcpt_to"],
            sample=sample
        )

        index = "dmarc_forensic"
        if index_suffix:
            index = "{0}_{1}".format(index, index_suffix)
        if monthly_indexes:
            index_date = arrival_date.strftime("%Y-%m")
        else:
            index_date = arrival_date.strftime("%Y-%m-%d")
        index = "{0}-{1}".format(index, index_date)
        index_settings = dict(number_of_shards=number_of_shards,
                              number_of_replicas=number_of_replicas)
        create_indexes([index], index_settings)
        forensic_doc.meta.index = index
        try:
            forensic_doc.save()
        except Exception as e:
            raise ElasticsearchError(
                "Elasticsearch error: {0}".format(e.__str__()))
    except KeyError as e:
        raise InvalidForensicReport(
            "Forensic report missing required field: {0}".format(e.__str__()))
