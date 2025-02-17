#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A CLI for parsing DMARC reports"""

from argparse import Namespace, ArgumentParser
import os
from configparser import ConfigParser
from glob import glob
import logging
import math
from collections import OrderedDict
import json
from ssl import CERT_NONE, create_default_context
from multiprocessing import Pipe, Process
import sys
import http.client
from tqdm import tqdm

from parsedmarc import (
    get_dmarc_reports_from_mailbox,
    watch_inbox,
    parse_report_file,
    get_dmarc_reports_from_mbox,
    elastic,
    opensearch,
    kafkaclient,
    splunk,
    save_output,
    email_results,
    ParserError,
    __version__,
    InvalidDMARCReport,
    s3,
    syslog,
    loganalytics,
    gelf,
    webhook,
)
from parsedmarc.mail import (
    IMAPConnection,
    MSGraphConnection,
    GmailConnection,
    MaildirConnection,
)
from parsedmarc.mail.graph import AuthMethod

from parsedmarc.log import logger
from parsedmarc.utils import is_mbox, get_reverse_dns
from parsedmarc import SEEN_AGGREGATE_REPORT_IDS

http.client._MAXHEADERS = 200  # pylint:disable=protected-access

formatter = logging.Formatter(
    fmt="%(levelname)8s:%(filename)s:%(lineno)d:%(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


def _str_to_list(s):
    """Converts a comma separated string to a list"""
    _list = s.split(",")
    return list(map(lambda i: i.lstrip(), _list))


def cli_parse(
    file_path,
    sa,
    nameservers,
    dns_timeout,
    ip_db_path,
    offline,
    always_use_local_files,
    reverse_dns_map_path,
    reverse_dns_map_url,
    conn,
):
    """Separated this function for multiprocessing"""
    try:
        file_results = parse_report_file(
            file_path,
            ip_db_path=ip_db_path,
            offline=offline,
            always_use_local_files=always_use_local_files,
            reverse_dns_map_path=reverse_dns_map_path,
            reverse_dns_map_url=reverse_dns_map_url,
            nameservers=nameservers,
            dns_timeout=dns_timeout,
            strip_attachment_payloads=sa,
        )
        conn.send([file_results, file_path])
    except ParserError as error:
        conn.send([error, file_path])
    finally:
        conn.close()


def _main():
    """Called when the module is executed"""

    def process_reports(reports_):
        output_str = "{0}\n".format(json.dumps(reports_, ensure_ascii=False, indent=2))

        if not opts.silent:
            print(output_str)
        if opts.output:
            save_output(
                results,
                output_directory=opts.output,
                aggregate_json_filename=opts.aggregate_json_filename,
                forensic_json_filename=opts.forensic_json_filename,
                smtp_tls_json_filename=opts.smtp_tls_json_filename,
                aggregate_csv_filename=opts.aggregate_csv_filename,
                forensic_csv_filename=opts.forensic_csv_filename,
                smtp_tls_csv_filename=opts.smtp_tls_csv_filename,
            )
        if opts.save_aggregate:
            for report in reports_["aggregate_reports"]:
                try:
                    if opts.elasticsearch_hosts:
                        shards = opts.elasticsearch_number_of_shards
                        replicas = opts.elasticsearch_number_of_replicas
                        elastic.save_aggregate_report_to_elasticsearch(
                            report,
                            index_suffix=opts.elasticsearch_index_suffix,
                            index_prefix=opts.elasticsearch_index_prefix,
                            monthly_indexes=opts.elasticsearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas,
                        )
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except elastic.ElasticsearchError as error_:
                    logger.error("Elasticsearch Error: {0}".format(error_.__str__()))
                except Exception as error_:
                    logger.error(
                        "Elasticsearch exception error: {}".format(error_.__str__())
                    )

                try:
                    if opts.opensearch_hosts:
                        shards = opts.opensearch_number_of_shards
                        replicas = opts.opensearch_number_of_replicas
                        opensearch.save_aggregate_report_to_opensearch(
                            report,
                            index_suffix=opts.opensearch_index_suffix,
                            index_prefix=opts.opensearch_index_prefix,
                            monthly_indexes=opts.opensearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas,
                        )
                except opensearch.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except opensearch.OpenSearchError as error_:
                    logger.error("OpenSearch Error: {0}".format(error_.__str__()))
                except Exception as error_:
                    logger.error(
                        "OpenSearch exception error: {}".format(error_.__str__())
                    )

                try:
                    if opts.kafka_hosts:
                        kafka_client.save_aggregate_reports_to_kafka(
                            report, kafka_aggregate_topic
                        )
                except Exception as error_:
                    logger.error("Kafka Error: {0}".format(error_.__str__()))

                try:
                    if opts.s3_bucket:
                        s3_client.save_aggregate_report_to_s3(report)
                except Exception as error_:
                    logger.error("S3 Error: {0}".format(error_.__str__()))

                try:
                    if opts.syslog_server:
                        syslog_client.save_aggregate_report_to_syslog(report)
                except Exception as error_:
                    logger.error("Syslog Error: {0}".format(error_.__str__()))

                try:
                    if opts.gelf_host:
                        gelf_client.save_aggregate_report_to_gelf(report)
                except Exception as error_:
                    logger.error("GELF Error: {0}".format(error_.__str__()))

                try:
                    if opts.webhook_aggregate_url:
                        webhook_client.save_aggregate_report_to_webhook(
                            json.dumps(report, ensure_ascii=False, indent=2)
                        )
                except Exception as error_:
                    logger.error("Webhook Error: {0}".format(error_.__str__()))

            if opts.hec:
                try:
                    aggregate_reports_ = reports_["aggregate_reports"]
                    if len(aggregate_reports_) > 0:
                        hec_client.save_aggregate_reports_to_splunk(aggregate_reports_)
                except splunk.SplunkError as e:
                    logger.error("Splunk HEC error: {0}".format(e.__str__()))

        if opts.save_forensic:
            for report in reports_["forensic_reports"]:
                try:
                    shards = opts.elasticsearch_number_of_shards
                    replicas = opts.elasticsearch_number_of_replicas
                    if opts.elasticsearch_hosts:
                        elastic.save_forensic_report_to_elasticsearch(
                            report,
                            index_suffix=opts.elasticsearch_index_suffix,
                            index_prefix=opts.elasticsearch_index_prefix,
                            monthly_indexes=opts.elasticsearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas,
                        )
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except elastic.ElasticsearchError as error_:
                    logger.error("Elasticsearch Error: {0}".format(error_.__str__()))
                except InvalidDMARCReport as error_:
                    logger.error(error_.__str__())

                try:
                    shards = opts.opensearch_number_of_shards
                    replicas = opts.opensearch_number_of_replicas
                    if opts.opensearch_hosts:
                        opensearch.save_forensic_report_to_opensearch(
                            report,
                            index_suffix=opts.opensearch_index_suffix,
                            index_prefix=opts.opensearch_index_prefix,
                            monthly_indexes=opts.opensearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas,
                        )
                except opensearch.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except opensearch.OpenSearchError as error_:
                    logger.error("OpenSearch Error: {0}".format(error_.__str__()))
                except InvalidDMARCReport as error_:
                    logger.error(error_.__str__())

                try:
                    if opts.kafka_hosts:
                        kafka_client.save_forensic_reports_to_kafka(
                            report, kafka_forensic_topic
                        )
                except Exception as error_:
                    logger.error("Kafka Error: {0}".format(error_.__str__()))

                try:
                    if opts.s3_bucket:
                        s3_client.save_forensic_report_to_s3(report)
                except Exception as error_:
                    logger.error("S3 Error: {0}".format(error_.__str__()))

                try:
                    if opts.syslog_server:
                        syslog_client.save_forensic_report_to_syslog(report)
                except Exception as error_:
                    logger.error("Syslog Error: {0}".format(error_.__str__()))

                try:
                    if opts.gelf_host:
                        gelf_client.save_forensic_report_to_gelf(report)
                except Exception as error_:
                    logger.error("GELF Error: {0}".format(error_.__str__()))

                try:
                    if opts.webhook_forensic_url:
                        webhook_client.save_forensic_report_to_webhook(
                            json.dumps(report, ensure_ascii=False, indent=2)
                        )
                except Exception as error_:
                    logger.error("Webhook Error: {0}".format(error_.__str__()))

            if opts.hec:
                try:
                    forensic_reports_ = reports_["forensic_reports"]
                    if len(forensic_reports_) > 0:
                        hec_client.save_forensic_reports_to_splunk(forensic_reports_)
                except splunk.SplunkError as e:
                    logger.error("Splunk HEC error: {0}".format(e.__str__()))

        if opts.save_smtp_tls:
            for report in reports_["smtp_tls_reports"]:
                try:
                    shards = opts.elasticsearch_number_of_shards
                    replicas = opts.elasticsearch_number_of_replicas
                    if opts.elasticsearch_hosts:
                        elastic.save_smtp_tls_report_to_elasticsearch(
                            report,
                            index_suffix=opts.elasticsearch_index_suffix,
                            index_prefix=opts.elasticsearch_index_prefix,
                            monthly_indexes=opts.elasticsearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas,
                        )
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except elastic.ElasticsearchError as error_:
                    logger.error("Elasticsearch Error: {0}".format(error_.__str__()))
                except InvalidDMARCReport as error_:
                    logger.error(error_.__str__())

                try:
                    shards = opts.opensearch_number_of_shards
                    replicas = opts.opensearch_number_of_replicas
                    if opts.opensearch_hosts:
                        opensearch.save_smtp_tls_report_to_opensearch(
                            report,
                            index_suffix=opts.opensearch_index_suffix,
                            index_prefix=opts.opensearch_index_prefix,
                            monthly_indexes=opts.opensearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas,
                        )
                except opensearch.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except opensearch.OpenSearchError as error_:
                    logger.error("OpenSearch Error: {0}".format(error_.__str__()))
                except InvalidDMARCReport as error_:
                    logger.error(error_.__str__())

                try:
                    if opts.kafka_hosts:
                        kafka_client.save_smtp_tls_reports_to_kafka(
                            smtp_tls_reports, kafka_smtp_tls_topic
                        )
                except Exception as error_:
                    logger.error("Kafka Error: {0}".format(error_.__str__()))

                try:
                    if opts.s3_bucket:
                        s3_client.save_smtp_tls_report_to_s3(report)
                except Exception as error_:
                    logger.error("S3 Error: {0}".format(error_.__str__()))

                try:
                    if opts.syslog_server:
                        syslog_client.save_smtp_tls_report_to_syslog(report)
                except Exception as error_:
                    logger.error("Syslog Error: {0}".format(error_.__str__()))

                try:
                    if opts.gelf_host:
                        gelf_client.save_smtp_tls_report_to_gelf(report)
                except Exception as error_:
                    logger.error("GELF Error: {0}".format(error_.__str__()))

                try:
                    if opts.webhook_smtp_tls_url:
                        webhook_client.save_smtp_tls_report_to_webhook(
                            json.dumps(report, ensure_ascii=False, indent=2)
                        )
                except Exception as error_:
                    logger.error("Webhook Error: {0}".format(error_.__str__()))

            if opts.hec:
                try:
                    smtp_tls_reports_ = reports_["smtp_tls_reports"]
                    if len(smtp_tls_reports_) > 0:
                        hec_client.save_smtp_tls_reports_to_splunk(smtp_tls_reports_)
                except splunk.SplunkError as e:
                    logger.error("Splunk HEC error: {0}".format(e.__str__()))

        if opts.la_dce:
            try:
                la_client = loganalytics.LogAnalyticsClient(
                    client_id=opts.la_client_id,
                    client_secret=opts.la_client_secret,
                    tenant_id=opts.la_tenant_id,
                    dce=opts.la_dce,
                    dcr_immutable_id=opts.la_dcr_immutable_id,
                    dcr_aggregate_stream=opts.la_dcr_aggregate_stream,
                    dcr_forensic_stream=opts.la_dcr_forensic_stream,
                    dcr_smtp_tls_stream=opts.la_dcr_smtp_tls_stream,
                )
                la_client.publish_results(
                    reports_,
                    opts.save_aggregate,
                    opts.save_forensic,
                    opts.save_smtp_tls,
                )
            except loganalytics.LogAnalyticsException as e:
                logger.error("Log Analytics error: {0}".format(e.__str__()))
            except Exception as e:
                logger.error(
                    "Unknown error occurred"
                    + " during the publishing"
                    + " to Log Analytics: "
                    + e.__str__()
                )

    arg_parser = ArgumentParser(description="Parses DMARC reports")
    arg_parser.add_argument(
        "-c",
        "--config-file",
        help="a path to a configuration file (--silent implied)",
    )
    arg_parser.add_argument(
        "file_path",
        nargs="*",
        help="one or more paths to aggregate or forensic "
        "report files, emails, or mbox files'",
    )
    strip_attachment_help = "remove attachment payloads from forensic report output"
    arg_parser.add_argument(
        "--strip-attachment-payloads", help=strip_attachment_help, action="store_true"
    )
    arg_parser.add_argument(
        "-o", "--output", help="write output files to the given directory"
    )
    arg_parser.add_argument(
        "--aggregate-json-filename",
        help="filename for the aggregate JSON output file",
        default="aggregate.json",
    )
    arg_parser.add_argument(
        "--forensic-json-filename",
        help="filename for the forensic JSON output file",
        default="forensic.json",
    )
    arg_parser.add_argument(
        "--smtp-tls-json-filename",
        help="filename for the SMTP TLS JSON output file",
        default="smtp_tls.json",
    )
    arg_parser.add_argument(
        "--aggregate-csv-filename",
        help="filename for the aggregate CSV output file",
        default="aggregate.csv",
    )
    arg_parser.add_argument(
        "--forensic-csv-filename",
        help="filename for the forensic CSV output file",
        default="forensic.csv",
    )
    arg_parser.add_argument(
        "--smtp-tls-csv-filename",
        help="filename for the SMTP TLS CSV output file",
        default="smtp_tls.csv",
    )
    arg_parser.add_argument(
        "-n", "--nameservers", nargs="+", help="nameservers to query"
    )
    arg_parser.add_argument(
        "-t",
        "--dns_timeout",
        help="number of seconds to wait for an answer from DNS (default: 2.0)",
        type=float,
        default=2.0,
    )
    arg_parser.add_argument(
        "--offline",
        action="store_true",
        help="do not make online queries for geolocation  or  DNS",
    )
    arg_parser.add_argument(
        "-s", "--silent", action="store_true", help="only print errors"
    )
    arg_parser.add_argument(
        "-w",
        "--warnings",
        action="store_true",
        help="print warnings in addition to errors",
    )
    arg_parser.add_argument(
        "--verbose", action="store_true", help="more verbose output"
    )
    arg_parser.add_argument(
        "--debug", action="store_true", help="print debugging information"
    )
    arg_parser.add_argument("--log-file", default=None, help="output logging to a file")
    arg_parser.add_argument("-v", "--version", action="version", version=__version__)

    aggregate_reports = []
    forensic_reports = []
    smtp_tls_reports = []

    args = arg_parser.parse_args()

    default_gmail_api_scope = "https://www.googleapis.com/auth/gmail.modify"

    opts = Namespace(
        file_path=args.file_path,
        config_file=args.config_file,
        offline=args.offline,
        strip_attachment_payloads=args.strip_attachment_payloads,
        output=args.output,
        aggregate_csv_filename=args.aggregate_csv_filename,
        aggregate_json_filename=args.aggregate_json_filename,
        forensic_csv_filename=args.forensic_csv_filename,
        forensic_json_filename=args.forensic_json_filename,
        smtp_tls_json_filename=args.smtp_tls_json_filename,
        smtp_tls_csv_filename=args.smtp_tls_csv_filename,
        nameservers=args.nameservers,
        dns_test_address="1.1.1.1",
        silent=args.silent,
        warnings=args.warnings,
        dns_timeout=args.dns_timeout,
        debug=args.debug,
        verbose=args.verbose,
        save_aggregate=False,
        save_forensic=False,
        save_smtp_tls=False,
        mailbox_reports_folder="INBOX",
        mailbox_archive_folder="Archive",
        mailbox_watch=False,
        mailbox_delete=False,
        mailbox_test=False,
        mailbox_batch_size=10,
        mailbox_check_timeout=30,
        mailbox_since=None,
        imap_host=None,
        imap_skip_certificate_verification=False,
        imap_ssl=True,
        imap_port=993,
        imap_timeout=30,
        imap_max_retries=4,
        imap_user=None,
        imap_password=None,
        graph_auth_method=None,
        graph_user=None,
        graph_password=None,
        graph_client_id=None,
        graph_client_secret=None,
        graph_tenant_id=None,
        graph_mailbox=None,
        graph_allow_unencrypted_storage=False,
        graph_url="https://graph.microsoft.com",
        hec=None,
        hec_token=None,
        hec_index=None,
        hec_skip_certificate_verification=False,
        elasticsearch_hosts=None,
        elasticsearch_timeout=60,
        elasticsearch_number_of_shards=1,
        elasticsearch_number_of_replicas=0,
        elasticsearch_index_suffix=None,
        elasticsearch_index_prefix=None,
        elasticsearch_ssl=True,
        elasticsearch_ssl_cert_path=None,
        elasticsearch_monthly_indexes=False,
        elasticsearch_username=None,
        elasticsearch_password=None,
        elasticsearch_apiKey=None,
        opensearch_hosts=None,
        opensearch_timeout=60,
        opensearch_number_of_shards=1,
        opensearch_number_of_replicas=0,
        opensearch_index_suffix=None,
        opensearch_index_prefix=None,
        opensearch_ssl=True,
        opensearch_ssl_cert_path=None,
        opensearch_monthly_indexes=False,
        opensearch_username=None,
        opensearch_password=None,
        opensearch_apiKey=None,
        kafka_hosts=None,
        kafka_username=None,
        kafka_password=None,
        kafka_aggregate_topic=None,
        kafka_forensic_topic=None,
        kafka_smtp_tls_topic=None,
        kafka_ssl=False,
        kafka_skip_certificate_verification=False,
        smtp_host=None,
        smtp_port=25,
        smtp_ssl=False,
        smtp_skip_certificate_verification=False,
        smtp_user=None,
        smtp_password=None,
        smtp_from=None,
        smtp_to=[],
        smtp_subject="parsedmarc report",
        smtp_message="Please see the attached DMARC results.",
        s3_bucket=None,
        s3_path=None,
        s3_region_name=None,
        s3_endpoint_url=None,
        s3_access_key_id=None,
        s3_secret_access_key=None,
        syslog_server=None,
        syslog_port=None,
        gmail_api_credentials_file=None,
        gmail_api_token_file=None,
        gmail_api_include_spam_trash=False,
        gmail_api_paginate_messages=True,
        gmail_api_scopes=[],
        gmail_api_oauth2_port=8080,
        maildir_path=None,
        maildir_create=False,
        log_file=args.log_file,
        n_procs=1,
        ip_db_path=None,
        always_use_local_files=False,
        reverse_dns_map_path=None,
        reverse_dns_map_url=None,
        la_client_id=None,
        la_client_secret=None,
        la_tenant_id=None,
        la_dce=None,
        la_dcr_immutable_id=None,
        la_dcr_aggregate_stream=None,
        la_dcr_forensic_stream=None,
        la_dcr_smtp_tls_stream=None,
        gelf_host=None,
        gelf_port=None,
        gelf_mode=None,
        webhook_aggregate_url=None,
        webhook_forensic_url=None,
        webhook_smtp_tls_url=None,
        webhook_timeout=60,
    )
    args = arg_parser.parse_args()

    if args.config_file:
        abs_path = os.path.abspath(args.config_file)
        if not os.path.exists(abs_path):
            logger.error("A file does not exist at {0}".format(abs_path))
            exit(-1)
        opts.silent = True
        config = ConfigParser()
        config.read(args.config_file)
        if "general" in config.sections():
            general_config = config["general"]
            if "offline" in general_config:
                opts.offline = general_config.getboolean("offline")
            if "strip_attachment_payloads" in general_config:
                opts.strip_attachment_payloads = general_config.getboolean(
                    "strip_attachment_payloads"
                )
            if "output" in general_config:
                opts.output = general_config["output"]
            if "aggregate_json_filename" in general_config:
                opts.aggregate_json_filename = general_config["aggregate_json_filename"]
            if "forensic_json_filename" in general_config:
                opts.forensic_json_filename = general_config["forensic_json_filename"]
            if "smtp_tls_json_filename" in general_config:
                opts.smtp_tls_json_filename = general_config["smtp_tls_json_filename"]
            if "aggregate_csv_filename" in general_config:
                opts.aggregate_csv_filename = general_config["aggregate_csv_filename"]
            if "forensic_csv_filename" in general_config:
                opts.forensic_csv_filename = general_config["forensic_csv_filename"]
            if "smtp_tls_csv_filename" in general_config:
                opts.smtp_tls_csv_filename = general_config["smtp_tls_csv_filename"]
            if "dns_timeout" in general_config:
                opts.dns_timeout = general_config.getfloat("dns_timeout")
            if "dns_test_address" in general_config:
                opts.dns_test_address = general_config["dns_test_address"]
            if "nameservers" in general_config:
                opts.nameservers = _str_to_list(general_config["nameservers"])
                # nameservers pre-flight check
                dummy_hostname = None
                try:
                    dummy_hostname = get_reverse_dns(
                        opts.dns_test_address,
                        nameservers=opts.nameservers,
                        timeout=opts.dns_timeout,
                    )
                except Exception as ns_error:
                    logger.critical("DNS pre-flight check failed: {}".format(ns_error))
                    exit(-1)
                if not dummy_hostname:
                    logger.critical(
                        "DNS pre-flight check failed: no PTR record for "
                        "{} from {}".format(opts.dns_test_address, opts.nameservers)
                    )
                    exit(-1)
            if "save_aggregate" in general_config:
                opts.save_aggregate = general_config["save_aggregate"]
            if "save_forensic" in general_config:
                opts.save_forensic = general_config["save_forensic"]
            if "save_smtp_tls" in general_config:
                opts.save_smtp_tls = general_config["save_smtp_tls"]
            if "debug" in general_config:
                opts.debug = general_config.getboolean("debug")
            if "verbose" in general_config:
                opts.verbose = general_config.getboolean("verbose")
            if "silent" in general_config:
                opts.silent = general_config.getboolean("silent")
            if "warnings" in general_config:
                opts.warnings = general_config.getboolean("warnings")
            if "log_file" in general_config:
                opts.log_file = general_config["log_file"]
            if "n_procs" in general_config:
                opts.n_procs = general_config.getint("n_procs")
            if "ip_db_path" in general_config:
                opts.ip_db_path = general_config["ip_db_path"]
            else:
                opts.ip_db_path = None
            if "always_use_local_files" in general_config:
                opts.always_use_local_files = general_config.getboolean(
                    "always_use_local_files"
                )
            if "reverse_dns_map_path" in general_config:
                opts.reverse_dns_map_path = general_config["reverse_dns_path"]
            if "reverse_dns_map_url" in general_config:
                opts.reverse_dns_map_url = general_config["reverse_dns_url"]

        if "mailbox" in config.sections():
            mailbox_config = config["mailbox"]
            if "msgraph" in config.sections():
                opts.mailbox_reports_folder = "Inbox"
            if "reports_folder" in mailbox_config:
                opts.mailbox_reports_folder = mailbox_config["reports_folder"]
            if "archive_folder" in mailbox_config:
                opts.mailbox_archive_folder = mailbox_config["archive_folder"]
            if "watch" in mailbox_config:
                opts.mailbox_watch = mailbox_config.getboolean("watch")
            if "delete" in mailbox_config:
                opts.mailbox_delete = mailbox_config.getboolean("delete")
            if "test" in mailbox_config:
                opts.mailbox_test = mailbox_config.getboolean("test")
            if "batch_size" in mailbox_config:
                opts.mailbox_batch_size = mailbox_config.getint("batch_size")
            if "check_timeout" in mailbox_config:
                opts.mailbox_check_timeout = mailbox_config.getint("check_timeout")
            if "since" in mailbox_config:
                opts.mailbox_since = mailbox_config["since"]

        if "imap" in config.sections():
            imap_config = config["imap"]
            if "watch" in imap_config:
                logger.warning(
                    "Starting in 8.0.0, the watch option has been "
                    "moved from the imap configuration section to "
                    "the mailbox configuration section."
                )
            if "host" in imap_config:
                opts.imap_host = imap_config["host"]
            else:
                logger.error("host setting missing from the imap config section")
                exit(-1)
            if "port" in imap_config:
                opts.imap_port = imap_config.getint("port")
            if "timeout" in imap_config:
                opts.imap_timeout = imap_config.getfloat("timeout")
            if "max_retries" in imap_config:
                opts.imap_max_retries = imap_config.getint("max_retries")
            if "ssl" in imap_config:
                opts.imap_ssl = imap_config.getboolean("ssl")
            if "skip_certificate_verification" in imap_config:
                imap_verify = imap_config.getboolean("skip_certificate_verification")
                opts.imap_skip_certificate_verification = imap_verify
            if "user" in imap_config:
                opts.imap_user = imap_config["user"]
            else:
                logger.critical("user setting missing from the imap config section")
                exit(-1)
            if "password" in imap_config:
                opts.imap_password = imap_config["password"]
            else:
                logger.critical("password setting missing from the imap config section")
                exit(-1)
            if "reports_folder" in imap_config:
                opts.mailbox_reports_folder = imap_config["reports_folder"]
                logger.warning(
                    "Use of the reports_folder option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "archive_folder" in imap_config:
                opts.mailbox_archive_folder = imap_config["archive_folder"]
                logger.warning(
                    "Use of the archive_folder option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "watch" in imap_config:
                opts.mailbox_watch = imap_config.getboolean("watch")
                logger.warning(
                    "Use of the watch option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "delete" in imap_config:
                logger.warning(
                    "Use of the delete option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "test" in imap_config:
                opts.mailbox_test = imap_config.getboolean("test")
                logger.warning(
                    "Use of the test option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )
            if "batch_size" in imap_config:
                opts.mailbox_batch_size = imap_config.getint("batch_size")
                logger.warning(
                    "Use of the batch_size option in the imap "
                    "configuration section has been deprecated. "
                    "Use this option in the mailbox configuration "
                    "section instead."
                )

        if "msgraph" in config.sections():
            graph_config = config["msgraph"]
            opts.graph_token_file = graph_config.get("token_file", ".token")

            if "auth_method" not in graph_config:
                logger.info(
                    "auth_method setting missing from the "
                    "msgraph config section "
                    "defaulting to UsernamePassword"
                )
                opts.graph_auth_method = AuthMethod.UsernamePassword.name
            else:
                opts.graph_auth_method = graph_config["auth_method"]

            if opts.graph_auth_method == AuthMethod.UsernamePassword.name:
                if "user" in graph_config:
                    opts.graph_user = graph_config["user"]
                else:
                    logger.critical(
                        "user setting missing from the msgraph config section"
                    )
                    exit(-1)
                if "password" in graph_config:
                    opts.graph_password = graph_config["password"]
                else:
                    logger.critical(
                        "password setting missing from the msgraph config section"
                    )
                if "client_secret" in graph_config:
                    opts.graph_client_secret = graph_config["client_secret"]
                else:
                    logger.critical(
                        "client_secret setting missing from the msgraph config section"
                    )
                    exit(-1)

            if opts.graph_auth_method == AuthMethod.DeviceCode.name:
                if "user" in graph_config:
                    opts.graph_user = graph_config["user"]

            if opts.graph_auth_method != AuthMethod.UsernamePassword.name:
                if "tenant_id" in graph_config:
                    opts.graph_tenant_id = graph_config["tenant_id"]
                else:
                    logger.critical(
                        "tenant_id setting missing from the msgraph config section"
                    )
                    exit(-1)

            if opts.graph_auth_method == AuthMethod.ClientSecret.name:
                if "client_secret" in graph_config:
                    opts.graph_client_secret = graph_config["client_secret"]
                else:
                    logger.critical(
                        "client_secret setting missing from the msgraph config section"
                    )
                    exit(-1)

            if "client_id" in graph_config:
                opts.graph_client_id = graph_config["client_id"]
            else:
                logger.critical(
                    "client_id setting missing from the msgraph config section"
                )
                exit(-1)

            if "mailbox" in graph_config:
                opts.graph_mailbox = graph_config["mailbox"]
            elif opts.graph_auth_method != AuthMethod.UsernamePassword.name:
                logger.critical(
                    "mailbox setting missing from the msgraph config section"
                )
                exit(-1)

            if "graph_url" in graph_config:
                opts.graph_url = graph_config["graph_url"]

            if "allow_unencrypted_storage" in graph_config:
                opts.graph_allow_unencrypted_storage = graph_config.getboolean(
                    "allow_unencrypted_storage"
                )

        if "elasticsearch" in config:
            elasticsearch_config = config["elasticsearch"]
            if "hosts" in elasticsearch_config:
                opts.elasticsearch_hosts = _str_to_list(elasticsearch_config["hosts"])
            else:
                logger.critical(
                    "hosts setting missing from the elasticsearch config section"
                )
                exit(-1)
            if "timeout" in elasticsearch_config:
                timeout = elasticsearch_config.getfloat("timeout")
                opts.elasticsearch_timeout = timeout
            if "number_of_shards" in elasticsearch_config:
                number_of_shards = elasticsearch_config.getint("number_of_shards")
                opts.elasticsearch_number_of_shards = number_of_shards
                if "number_of_replicas" in elasticsearch_config:
                    number_of_replicas = elasticsearch_config.getint(
                        "number_of_replicas"
                    )
                    opts.elasticsearch_number_of_replicas = number_of_replicas
            if "index_suffix" in elasticsearch_config:
                opts.elasticsearch_index_suffix = elasticsearch_config["index_suffix"]
            if "index_prefix" in elasticsearch_config:
                opts.elasticsearch_index_prefix = elasticsearch_config["index_prefix"]
            if "monthly_indexes" in elasticsearch_config:
                monthly = elasticsearch_config.getboolean("monthly_indexes")
                opts.elasticsearch_monthly_indexes = monthly
            if "ssl" in elasticsearch_config:
                opts.elasticsearch_ssl = elasticsearch_config.getboolean("ssl")
            if "cert_path" in elasticsearch_config:
                opts.elasticsearch_ssl_cert_path = elasticsearch_config["cert_path"]
            if "user" in elasticsearch_config:
                opts.elasticsearch_username = elasticsearch_config["user"]
            if "password" in elasticsearch_config:
                opts.elasticsearch_password = elasticsearch_config["password"]
            if "apiKey" in elasticsearch_config:
                opts.elasticsearch_apiKey = elasticsearch_config["apiKey"]

        if "opensearch" in config:
            opensearch_config = config["opensearch"]
            if "hosts" in opensearch_config:
                opts.opensearch_hosts = _str_to_list(opensearch_config["hosts"])
            else:
                logger.critical(
                    "hosts setting missing from the opensearch config section"
                )
                exit(-1)
            if "timeout" in opensearch_config:
                timeout = opensearch_config.getfloat("timeout")
                opts.opensearch_timeout = timeout
            if "number_of_shards" in opensearch_config:
                number_of_shards = opensearch_config.getint("number_of_shards")
                opts.opensearch_number_of_shards = number_of_shards
                if "number_of_replicas" in opensearch_config:
                    number_of_replicas = opensearch_config.getint("number_of_replicas")
                    opts.opensearch_number_of_replicas = number_of_replicas
            if "index_suffix" in opensearch_config:
                opts.opensearch_index_suffix = opensearch_config["index_suffix"]
            if "index_prefix" in opensearch_config:
                opts.opensearch_index_prefix = opensearch_config["index_prefix"]
            if "monthly_indexes" in opensearch_config:
                monthly = opensearch_config.getboolean("monthly_indexes")
                opts.opensearch_monthly_indexes = monthly
            if "ssl" in opensearch_config:
                opts.opensearch_ssl = opensearch_config.getboolean("ssl")
            if "cert_path" in opensearch_config:
                opts.opensearch_ssl_cert_path = opensearch_config["cert_path"]
            if "user" in opensearch_config:
                opts.opensearch_username = opensearch_config["user"]
            if "password" in opensearch_config:
                opts.opensearch_password = opensearch_config["password"]
            if "apiKey" in opensearch_config:
                opts.opensearch_apiKey = opensearch_config["apiKey"]

        if "splunk_hec" in config.sections():
            hec_config = config["splunk_hec"]
            if "url" in hec_config:
                opts.hec = hec_config["url"]
            else:
                logger.critical(
                    "url setting missing from the splunk_hec config section"
                )
                exit(-1)
            if "token" in hec_config:
                opts.hec_token = hec_config["token"]
            else:
                logger.critical(
                    "token setting missing from the splunk_hec config section"
                )
                exit(-1)
            if "index" in hec_config:
                opts.hec_index = hec_config["index"]
            else:
                logger.critical(
                    "index setting missing from the splunk_hec config section"
                )
                exit(-1)
            if "skip_certificate_verification" in hec_config:
                opts.hec_skip_certificate_verification = hec_config[
                    "skip_certificate_verification"
                ]

        if "kafka" in config.sections():
            kafka_config = config["kafka"]
            if "hosts" in kafka_config:
                opts.kafka_hosts = _str_to_list(kafka_config["hosts"])
            else:
                logger.critical("hosts setting missing from the kafka config section")
                exit(-1)
            if "user" in kafka_config:
                opts.kafka_username = kafka_config["user"]
            if "password" in kafka_config:
                opts.kafka_password = kafka_config["password"]
            if "ssl" in kafka_config:
                opts.kafka_ssl = kafka_config.getboolean("ssl")
            if "skip_certificate_verification" in kafka_config:
                kafka_verify = kafka_config.getboolean("skip_certificate_verification")
                opts.kafka_skip_certificate_verification = kafka_verify
            if "aggregate_topic" in kafka_config:
                opts.kafka_aggregate_topic = kafka_config["aggregate_topic"]
            else:
                logger.critical(
                    "aggregate_topic setting missing from the kafka config section"
                )
                exit(-1)
            if "forensic_topic" in kafka_config:
                opts.kafka_forensic_topic = kafka_config["forensic_topic"]
            else:
                logger.critical(
                    "forensic_topic setting missing from the kafka config section"
                )
            if "smtp_tls_topic" in kafka_config:
                opts.kafka_smtp_tls_topic = kafka_config["smtp_tls_topic"]
            else:
                logger.critical(
                    "forensic_topic setting missing from the splunk_hec config section"
                )

        if "smtp" in config.sections():
            smtp_config = config["smtp"]
            if "host" in smtp_config:
                opts.smtp_host = smtp_config["host"]
            else:
                logger.critical("host setting missing from the smtp config section")
                exit(-1)
            if "port" in smtp_config:
                opts.smtp_port = smtp_config.getint("port")
            if "ssl" in smtp_config:
                opts.smtp_ssl = smtp_config.getboolean("ssl")
            if "skip_certificate_verification" in smtp_config:
                smtp_verify = smtp_config.getboolean("skip_certificate_verification")
                opts.smtp_skip_certificate_verification = smtp_verify
            if "user" in smtp_config:
                opts.smtp_user = smtp_config["user"]
            else:
                logger.critical("user setting missing from the smtp config section")
                exit(-1)
            if "password" in smtp_config:
                opts.smtp_password = smtp_config["password"]
            else:
                logger.critical("password setting missing from the smtp config section")
                exit(-1)
            if "from" in smtp_config:
                opts.smtp_from = smtp_config["from"]
            else:
                logger.critical("from setting missing from the smtp config section")
            if "to" in smtp_config:
                opts.smtp_to = _str_to_list(smtp_config["to"])
            else:
                logger.critical("to setting missing from the smtp config section")
            if "subject" in smtp_config:
                opts.smtp_subject = smtp_config["subject"]
            if "attachment" in smtp_config:
                opts.smtp_attachment = smtp_config["attachment"]
            if "message" in smtp_config:
                opts.smtp_message = smtp_config["message"]

        if "s3" in config.sections():
            s3_config = config["s3"]
            if "bucket" in s3_config:
                opts.s3_bucket = s3_config["bucket"]
            else:
                logger.critical("bucket setting missing from the s3 config section")
                exit(-1)
            if "path" in s3_config:
                opts.s3_path = s3_config["path"]
                if opts.s3_path.startswith("/"):
                    opts.s3_path = opts.s3_path[1:]
                if opts.s3_path.endswith("/"):
                    opts.s3_path = opts.s3_path[:-1]
            else:
                opts.s3_path = ""

            if "region_name" in s3_config:
                opts.s3_region_name = s3_config["region_name"]
            if "endpoint_url" in s3_config:
                opts.s3_endpoint_url = s3_config["endpoint_url"]
            if "access_key_id" in s3_config:
                opts.s3_access_key_id = s3_config["access_key_id"]
            if "secret_access_key" in s3_config:
                opts.s3_secret_access_key = s3_config["secret_access_key"]

        if "syslog" in config.sections():
            syslog_config = config["syslog"]
            if "server" in syslog_config:
                opts.syslog_server = syslog_config["server"]
            else:
                logger.critical("server setting missing from the syslog config section")
                exit(-1)
            if "port" in syslog_config:
                opts.syslog_port = syslog_config["port"]
            else:
                opts.syslog_port = 514

        if "gmail_api" in config.sections():
            gmail_api_config = config["gmail_api"]
            opts.gmail_api_credentials_file = gmail_api_config.get("credentials_file")
            opts.gmail_api_token_file = gmail_api_config.get("token_file", ".token")
            opts.gmail_api_include_spam_trash = gmail_api_config.getboolean(
                "include_spam_trash", False
            )
            opts.gmail_api_paginate_messages = gmail_api_config.getboolean(
                "paginate_messages", True
            )
            opts.gmail_api_scopes = gmail_api_config.get(
                "scopes", default_gmail_api_scope
            )
            opts.gmail_api_scopes = _str_to_list(opts.gmail_api_scopes)
            if "oauth2_port" in gmail_api_config:
                opts.gmail_api_oauth2_port = gmail_api_config.get("oauth2_port", 8080)

        if "maildir" in config.sections():
            maildir_api_config = config["maildir"]
            opts.maildir_path = maildir_api_config.get("maildir_path")
            opts.maildir_create = maildir_api_config.get("maildir_create")

        if "log_analytics" in config.sections():
            log_analytics_config = config["log_analytics"]
            opts.la_client_id = log_analytics_config.get("client_id")
            opts.la_client_secret = log_analytics_config.get("client_secret")
            opts.la_tenant_id = log_analytics_config.get("tenant_id")
            opts.la_dce = log_analytics_config.get("dce")
            opts.la_dcr_immutable_id = log_analytics_config.get("dcr_immutable_id")
            opts.la_dcr_aggregate_stream = log_analytics_config.get(
                "dcr_aggregate_stream"
            )
            opts.la_dcr_forensic_stream = log_analytics_config.get(
                "dcr_forensic_stream"
            )
            opts.la_dcr_smtp_tls_stream = log_analytics_config.get(
                "dcr_smtp_tls_stream"
            )

        if "gelf" in config.sections():
            gelf_config = config["gelf"]
            if "host" in gelf_config:
                opts.gelf_host = gelf_config["host"]
            else:
                logger.critical("host setting missing from the gelf config section")
                exit(-1)
            if "port" in gelf_config:
                opts.gelf_port = gelf_config["port"]
            else:
                logger.critical("port setting missing from the gelf config section")
                exit(-1)
            if "mode" in gelf_config:
                opts.gelf_mode = gelf_config["mode"]
            else:
                logger.critical("mode setting missing from the gelf config section")
                exit(-1)

        if "webhook" in config.sections():
            webhook_config = config["webhook"]
            if "aggregate_url" in webhook_config:
                opts.webhook_aggregate_url = webhook_config["aggregate_url"]
            if "forensic_url" in webhook_config:
                opts.webhook_forensic_url = webhook_config["forensic_url"]
            if "smtp_tls_url" in webhook_config:
                opts.webhook_smtp_tls_url = webhook_config["smtp_tls_url"]
            if "timeout" in webhook_config:
                opts.webhook_timeout = webhook_config["timeout"]

    logger.setLevel(logging.ERROR)

    if opts.warnings:
        logger.setLevel(logging.WARNING)
    if opts.verbose:
        logger.setLevel(logging.INFO)
    if opts.debug:
        logger.setLevel(logging.DEBUG)
    if opts.log_file:
        try:
            fh = logging.FileHandler(opts.log_file, "a")
            formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
            )
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as error:
            logger.warning("Unable to write to log file: {}".format(error))

    if (
        opts.imap_host is None
        and opts.graph_client_id is None
        and opts.gmail_api_credentials_file is None
        and opts.maildir_path is None
        and len(opts.file_path) == 0
    ):
        logger.error("You must supply input files or a mailbox connection")
        exit(1)

    logger.info("Starting parsedmarc")

    if opts.save_aggregate or opts.save_forensic or opts.save_smtp_tls:
        try:
            if opts.elasticsearch_hosts:
                es_aggregate_index = "dmarc_aggregate"
                es_forensic_index = "dmarc_forensic"
                es_smtp_tls_index = "smtp_tls"
                if opts.elasticsearch_index_suffix:
                    suffix = opts.elasticsearch_index_suffix
                    es_aggregate_index = "{0}_{1}".format(es_aggregate_index, suffix)
                    es_forensic_index = "{0}_{1}".format(es_forensic_index, suffix)
                    es_smtp_tls_index = "{0}_{1}".format(es_smtp_tls_index, suffix)
                if opts.elasticsearch_index_prefix:
                    prefix = opts.elasticsearch_index_prefix
                    es_aggregate_index = "{0}{1}".format(prefix, es_aggregate_index)
                    es_forensic_index = "{0}{1}".format(prefix, es_forensic_index)
                    es_smtp_tls_index = "{0}{1}".format(prefix, es_smtp_tls_index)
                elastic.set_hosts(
                    opts.elasticsearch_hosts,
                    opts.elasticsearch_ssl,
                    opts.elasticsearch_ssl_cert_path,
                    opts.elasticsearch_username,
                    opts.elasticsearch_password,
                    opts.elasticsearch_apiKey,
                    timeout=opts.elasticsearch_timeout,
                )
                elastic.migrate_indexes(
                    aggregate_indexes=[es_aggregate_index],
                    forensic_indexes=[es_forensic_index],
                )
        except elastic.ElasticsearchError:
            logger.exception("Elasticsearch Error")
            exit(1)

        try:
            if opts.opensearch_hosts:
                os_aggregate_index = "dmarc_aggregate"
                os_forensic_index = "dmarc_forensic"
                os_smtp_tls_index = "smtp_tls"
                if opts.opensearch_index_suffix:
                    suffix = opts.opensearch_index_suffix
                    os_aggregate_index = "{0}_{1}".format(os_aggregate_index, suffix)
                    os_forensic_index = "{0}_{1}".format(os_forensic_index, suffix)
                    os_smtp_tls_index = "{0}_{1}".format(os_smtp_tls_index, suffix)
                if opts.opensearch_index_prefix:
                    prefix = opts.opensearch_index_prefix
                    os_aggregate_index = "{0}{1}".format(prefix, os_aggregate_index)
                    os_forensic_index = "{0}{1}".format(prefix, os_forensic_index)
                    os_smtp_tls_index = "{0}{1}".format(prefix, os_smtp_tls_index)
                opensearch.set_hosts(
                    opts.opensearch_hosts,
                    opts.opensearch_ssl,
                    opts.opensearch_ssl_cert_path,
                    opts.opensearch_username,
                    opts.opensearch_password,
                    opts.opensearch_apiKey,
                    timeout=opts.opensearch_timeout,
                )
                opensearch.migrate_indexes(
                    aggregate_indexes=[os_aggregate_index],
                    forensic_indexes=[os_forensic_index],
                )
        except opensearch.OpenSearchError:
            logger.exception("OpenSearch Error")
            exit(1)

    if opts.s3_bucket:
        try:
            s3_client = s3.S3Client(
                bucket_name=opts.s3_bucket,
                bucket_path=opts.s3_path,
                region_name=opts.s3_region_name,
                endpoint_url=opts.s3_endpoint_url,
                access_key_id=opts.s3_access_key_id,
                secret_access_key=opts.s3_secret_access_key,
            )
        except Exception as error_:
            logger.error("S3 Error: {0}".format(error_.__str__()))

    if opts.syslog_server:
        try:
            syslog_client = syslog.SyslogClient(
                server_name=opts.syslog_server,
                server_port=int(opts.syslog_port),
            )
        except Exception as error_:
            logger.error("Syslog Error: {0}".format(error_.__str__()))

    if opts.hec:
        if opts.hec_token is None or opts.hec_index is None:
            logger.error("HEC token and HEC index are required when using HEC URL")
            exit(1)

        verify = True
        if opts.hec_skip_certificate_verification:
            verify = False
        hec_client = splunk.HECClient(
            opts.hec, opts.hec_token, opts.hec_index, verify=verify
        )

    if opts.kafka_hosts:
        try:
            ssl_context = None
            if opts.kafka_skip_certificate_verification:
                logger.debug("Skipping Kafka certificate verification")
                ssl_context = create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = CERT_NONE
            kafka_client = kafkaclient.KafkaClient(
                opts.kafka_hosts,
                username=opts.kafka_username,
                password=opts.kafka_password,
                ssl_context=ssl_context,
            )
        except Exception as error_:
            logger.error("Kafka Error: {0}".format(error_.__str__()))

    if opts.gelf_host:
        try:
            gelf_client = gelf.GelfClient(
                host=opts.gelf_host,
                port=int(opts.gelf_port),
                mode=opts.gelf_mode,
            )
        except Exception as error_:
            logger.error("GELF Error: {0}".format(error_.__str__()))

    if (
        opts.webhook_aggregate_url
        or opts.webhook_forensic_url
        or opts.webhook_smtp_tls_url
    ):
        try:
            webhook_client = webhook.WebhookClient(
                aggregate_url=opts.webhook_aggregate_url,
                forensic_url=opts.webhook_forensic_url,
                smtp_tls_url=opts.webhook_smtp_tls_url,
                timeout=opts.webhook_timeout,
            )
        except Exception as error_:
            logger.error("Webhook Error: {0}".format(error_.__str__()))

    kafka_aggregate_topic = opts.kafka_aggregate_topic
    kafka_forensic_topic = opts.kafka_forensic_topic
    kafka_smtp_tls_topic = opts.kafka_smtp_tls_topic

    file_paths = []
    mbox_paths = []

    for file_path in args.file_path:
        file_paths += glob(file_path)
    for file_path in file_paths:
        if is_mbox(file_path):
            mbox_paths.append(file_path)

    file_paths = list(set(file_paths))
    mbox_paths = list(set(mbox_paths))

    for mbox_path in mbox_paths:
        file_paths.remove(mbox_path)

    counter = 0

    results = []

    if sys.stdout.isatty():
        pbar = tqdm(total=len(file_paths))

    for batch_index in range(math.ceil(len(file_paths) / opts.n_procs)):
        processes = []
        connections = []

        for proc_index in range(
            opts.n_procs * batch_index, opts.n_procs * (batch_index + 1)
        ):
            if proc_index >= len(file_paths):
                break

            parent_conn, child_conn = Pipe()
            connections.append(parent_conn)

            process = Process(
                target=cli_parse,
                args=(
                    file_paths[proc_index],
                    opts.strip_attachment_payloads,
                    opts.nameservers,
                    opts.dns_timeout,
                    opts.ip_db_path,
                    opts.offline,
                    opts.always_use_local_files,
                    opts.reverse_dns_map_path,
                    opts.reverse_dns_map_url,
                    child_conn,
                ),
            )
            processes.append(process)

        for proc in processes:
            proc.start()

        for conn in connections:
            results.append(conn.recv())

        for proc in processes:
            proc.join()
            if sys.stdout.isatty():
                counter += 1
                pbar.update(counter - pbar.n)

    for result in results:
        if type(result[0]) is ParserError:
            logger.error("Failed to parse {0} - {1}".format(result[1], result[0]))
        else:
            if result[0]["report_type"] == "aggregate":
                report_org = result[0]["report"]["report_metadata"]["org_name"]
                report_id = result[0]["report"]["report_metadata"]["report_id"]
                report_key = f"{report_org}_{report_id}"
                if report_key not in SEEN_AGGREGATE_REPORT_IDS:
                    SEEN_AGGREGATE_REPORT_IDS[report_key] = True
                    aggregate_reports.append(result[0]["report"])
                else:
                    logger.debug(
                        "Skipping duplicate aggregate report "
                        f"from {report_org} with ID: {report_id}"
                    )
            elif result[0]["report_type"] == "forensic":
                forensic_reports.append(result[0]["report"])
            elif result[0]["report_type"] == "smtp_tls":
                smtp_tls_reports.append(result[0]["report"])

    for mbox_path in mbox_paths:
        strip = opts.strip_attachment_payloads
        reports = get_dmarc_reports_from_mbox(
            mbox_path,
            nameservers=opts.nameservers,
            dns_timeout=opts.dns_timeout,
            strip_attachment_payloads=strip,
            ip_db_path=opts.ip_db_path,
            always_use_local_files=opts.always_use_local_files,
            reverse_dns_map_path=opts.reverse_dns_map_path,
            reverse_dns_map_url=opts.reverse_dns_map_url,
            offline=opts.offline,
        )
        aggregate_reports += reports["aggregate_reports"]
        forensic_reports += reports["forensic_reports"]
        smtp_tls_reports += reports["smtp_tls_reports"]

    mailbox_connection = None
    if opts.imap_host:
        try:
            if opts.imap_user is None or opts.imap_password is None:
                logger.error(
                    "IMAP user and password must be specified ifhost is specified"
                )

            ssl = True
            verify = True
            if opts.imap_skip_certificate_verification:
                logger.debug("Skipping IMAP certificate verification")
                verify = False
            if opts.imap_ssl is False:
                ssl = False

            mailbox_connection = IMAPConnection(
                host=opts.imap_host,
                port=opts.imap_port,
                ssl=ssl,
                verify=verify,
                timeout=opts.imap_timeout,
                max_retries=opts.imap_max_retries,
                user=opts.imap_user,
                password=opts.imap_password,
            )

        except Exception:
            logger.exception("IMAP Error")
            exit(1)

    if opts.graph_client_id:
        try:
            mailbox = opts.graph_mailbox or opts.graph_user
            mailbox_connection = MSGraphConnection(
                auth_method=opts.graph_auth_method,
                mailbox=mailbox,
                tenant_id=opts.graph_tenant_id,
                client_id=opts.graph_client_id,
                client_secret=opts.graph_client_secret,
                username=opts.graph_user,
                password=opts.graph_password,
                token_file=opts.graph_token_file,
                allow_unencrypted_storage=opts.graph_allow_unencrypted_storage,
                graph_url=opts.graph_url,
            )

        except Exception:
            logger.exception("MS Graph Error")
            exit(1)

    if opts.gmail_api_credentials_file:
        if opts.mailbox_delete:
            if "https://mail.google.com/" not in opts.gmail_api_scopes:
                logger.error(
                    "Message deletion requires scope"
                    " 'https://mail.google.com/'. "
                    "Add the scope and remove token file "
                    "to acquire proper access."
                )
                opts.mailbox_delete = False

        try:
            mailbox_connection = GmailConnection(
                credentials_file=opts.gmail_api_credentials_file,
                token_file=opts.gmail_api_token_file,
                scopes=opts.gmail_api_scopes,
                include_spam_trash=opts.gmail_api_include_spam_trash,
                paginate_messages=opts.gmail_api_paginate_messages,
                reports_folder=opts.mailbox_reports_folder,
                oauth2_port=opts.gmail_api_oauth2_port,
            )

        except Exception:
            logger.exception("Gmail API Error")
            exit(1)

    if opts.maildir_path:
        try:
            mailbox_connection = MaildirConnection(
                maildir_path=opts.maildir_path,
                maildir_create=opts.maildir_create,
            )
        except Exception:
            logger.exception("Maildir Error")
            exit(1)

    if mailbox_connection:
        try:
            reports = get_dmarc_reports_from_mailbox(
                connection=mailbox_connection,
                delete=opts.mailbox_delete,
                batch_size=opts.mailbox_batch_size,
                reports_folder=opts.mailbox_reports_folder,
                archive_folder=opts.mailbox_archive_folder,
                ip_db_path=opts.ip_db_path,
                always_use_local_files=opts.always_use_local_files,
                reverse_dns_map_path=opts.reverse_dns_map_path,
                reverse_dns_map_url=opts.reverse_dns_map_url,
                offline=opts.offline,
                nameservers=opts.nameservers,
                test=opts.mailbox_test,
                strip_attachment_payloads=opts.strip_attachment_payloads,
                since=opts.mailbox_since,
            )

            aggregate_reports += reports["aggregate_reports"]
            forensic_reports += reports["forensic_reports"]
            smtp_tls_reports += reports["smtp_tls_reports"]

        except Exception:
            logger.exception("Mailbox Error")
            exit(1)

    results = OrderedDict(
        [
            ("aggregate_reports", aggregate_reports),
            ("forensic_reports", forensic_reports),
            ("smtp_tls_reports", smtp_tls_reports),
        ]
    )

    process_reports(results)

    if opts.smtp_host:
        try:
            verify = True
            if opts.smtp_skip_certificate_verification:
                verify = False
            email_results(
                results,
                opts.smtp_host,
                opts.smtp_from,
                opts.smtp_to,
                port=opts.smtp_port,
                verify=verify,
                username=opts.smtp_user,
                password=opts.smtp_password,
                subject=opts.smtp_subject,
            )
        except Exception:
            logger.exception("Failed to email results")
            exit(1)

    if mailbox_connection and opts.mailbox_watch:
        logger.info("Watching for email - Quit with ctrl-c")

        try:
            watch_inbox(
                mailbox_connection=mailbox_connection,
                callback=process_reports,
                reports_folder=opts.mailbox_reports_folder,
                archive_folder=opts.mailbox_archive_folder,
                delete=opts.mailbox_delete,
                test=opts.mailbox_test,
                check_timeout=opts.mailbox_check_timeout,
                nameservers=opts.nameservers,
                dns_timeout=opts.dns_timeout,
                strip_attachment_payloads=opts.strip_attachment_payloads,
                batch_size=opts.mailbox_batch_size,
                ip_db_path=opts.ip_db_path,
                always_use_local_files=opts.always_use_local_files,
                reverse_dns_map_path=opts.reverse_dns_map_path,
                reverse_dns_map_url=opts.reverse_dns_map_url,
                offline=opts.offline,
            )
        except FileExistsError as error:
            logger.error("{0}".format(error.__str__()))
            exit(1)


if __name__ == "__main__":
    _main()
