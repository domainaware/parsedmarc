#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A CLI for parsing DMARC reports"""

from argparse import Namespace, ArgumentParser
import os
from configparser import ConfigParser
from glob import glob
import logging
from collections import OrderedDict
import json
from ssl import CERT_NONE, create_default_context
from multiprocessing import Pool, Value
from itertools import repeat
import sys
import time
from tqdm import tqdm

from parsedmarc import get_dmarc_reports_from_mailbox, watch_inbox, \
    parse_report_file, get_dmarc_reports_from_mbox, elastic, kafkaclient, \
    splunk, save_output, email_results, ParserError, __version__, \
    InvalidDMARCReport, s3, syslog

from parsedmarc.mail import IMAPConnection, MSGraphConnection, GmailConnection

from parsedmarc.utils import is_mbox

logger = logging.getLogger("parsedmarc")


def _str_to_list(s):
    """Converts a comma separated string to a list"""
    _list = s.split(",")
    return list(map(lambda i: i.lstrip(), _list))


def cli_parse(file_path, sa, nameservers, dns_timeout,
              ip_db_path, offline, parallel=False):
    """Separated this function for multiprocessing"""
    try:
        file_results = parse_report_file(file_path,
                                         ip_db_path=ip_db_path,
                                         offline=offline,
                                         nameservers=nameservers,
                                         dns_timeout=dns_timeout,
                                         strip_attachment_payloads=sa,
                                         parallel=parallel)
    except ParserError as error:
        return error, file_path
    finally:
        global counter
        with counter.get_lock():
            counter.value += 1
    return file_results, file_path


def init(ctr):
    global counter
    counter = ctr


def _main():
    """Called when the module is executed"""
    def process_reports(reports_):
        output_str = "{0}\n".format(json.dumps(reports_,
                                               ensure_ascii=False,
                                               indent=2))

        if not opts.silent:
            print(output_str)
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
                    ssl_context=ssl_context
                )
            except Exception as error_:
                logger.error("Kafka Error: {0}".format(error_.__str__()))
        if opts.s3_bucket:
            try:
                s3_client = s3.S3Client(
                    bucket_name=opts.s3_bucket,
                    bucket_path=opts.s3_path,
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
        if opts.save_aggregate:
            for report in reports_["aggregate_reports"]:
                try:
                    if opts.elasticsearch_hosts:
                        shards = opts.elasticsearch_number_of_shards
                        replicas = opts.elasticsearch_number_of_replicas
                        elastic.save_aggregate_report_to_elasticsearch(
                            report,
                            index_suffix=opts.elasticsearch_index_suffix,
                            monthly_indexes=opts.elasticsearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas
                        )
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except elastic.ElasticsearchError as error_:
                    logger.error("Elasticsearch Error: {0}".format(
                        error_.__str__()))
                try:
                    if opts.kafka_hosts:
                        kafka_client.save_aggregate_reports_to_kafka(
                            report, kafka_aggregate_topic)
                except Exception as error_:
                    logger.error("Kafka Error: {0}".format(
                         error_.__str__()))
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
            if opts.hec:
                try:
                    aggregate_reports_ = reports_["aggregate_reports"]
                    if len(aggregate_reports_) > 0:
                        hec_client.save_aggregate_reports_to_splunk(
                            aggregate_reports_)
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
                            monthly_indexes=opts.elasticsearch_monthly_indexes,
                            number_of_shards=shards,
                            number_of_replicas=replicas)
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except elastic.ElasticsearchError as error_:
                    logger.error("Elasticsearch Error: {0}".format(
                        error_.__str__()))
                except InvalidDMARCReport as error_:
                    logger.error(error_.__str__())
                try:
                    if opts.kafka_hosts:
                        kafka_client.save_forensic_reports_to_kafka(
                            report, kafka_forensic_topic)
                except Exception as error_:
                    logger.error("Kafka Error: {0}".format(
                        error_.__str__()))
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
            if opts.hec:
                try:
                    forensic_reports_ = reports_["forensic_reports"]
                    if len(forensic_reports_) > 0:
                        hec_client.save_forensic_reports_to_splunk(
                            forensic_reports_)
                except splunk.SplunkError as e:
                    logger.error("Splunk HEC error: {0}".format(e.__str__()))

    arg_parser = ArgumentParser(description="Parses DMARC reports")
    arg_parser.add_argument("-c", "--config-file",
                            help="a path to a configuration file "
                                 "(--silent implied)")
    arg_parser.add_argument("file_path", nargs="*",
                            help="one or more paths to aggregate or forensic "
                                 "report files, emails, or mbox files'")
    strip_attachment_help = "remove attachment payloads from forensic " \
                            "report output"
    arg_parser.add_argument("--strip-attachment-payloads",
                            help=strip_attachment_help, action="store_true")
    arg_parser.add_argument("-o", "--output",
                            help="write output files to the given directory")
    arg_parser.add_argument("--aggregate-json-filename",
                            help="filename for the aggregate JSON output file",
                            default="aggregate.json")
    arg_parser.add_argument("--forensic-json-filename",
                            help="filename for the forensic JSON output file",
                            default="forensic.json")
    arg_parser.add_argument("--aggregate-csv-filename",
                            help="filename for the aggregate CSV output file",
                            default="aggregate.csv")
    arg_parser.add_argument("--forensic-csv-filename",
                            help="filename for the forensic CSV output file",
                            default="forensic.csv")
    arg_parser.add_argument("-n", "--nameservers", nargs="+",
                            help="nameservers to query")
    arg_parser.add_argument("-t", "--dns_timeout",
                            help="number of seconds to wait for an answer "
                                 "from DNS (default: 2.0)",
                            type=float,
                            default=2.0)
    arg_parser.add_argument("--offline", action="store_true",
                            help="do not make online queries for geolocation "
                                 " or  DNS")
    arg_parser.add_argument("-s", "--silent", action="store_true",
                            help="only print errors and warnings")
    arg_parser.add_argument("--verbose", action="store_true",
                            help="more verbose output")
    arg_parser.add_argument("--debug", action="store_true",
                            help="print debugging information")
    arg_parser.add_argument("--log-file", default=None,
                            help="output logging to a file")
    arg_parser.add_argument("-v", "--version", action="version",
                            version=__version__)

    aggregate_reports = []
    forensic_reports = []

    args = arg_parser.parse_args()

    default_gmail_api_scope = 'https://www.googleapis.com/auth/gmail.modify'

    opts = Namespace(file_path=args.file_path,
                     config_file=args.config_file,
                     offline=args.offline,
                     strip_attachment_payloads=args.strip_attachment_payloads,
                     output=args.output,
                     aggregate_csv_filename=args.aggregate_csv_filename,
                     aggregate_json_filename=args.aggregate_json_filename,
                     forensic_csv_filename=args.forensic_csv_filename,
                     forensic_json_filename=args.forensic_json_filename,
                     nameservers=args.nameservers,
                     silent=args.silent,
                     dns_timeout=args.dns_timeout,
                     debug=args.debug,
                     verbose=args.verbose,
                     save_aggregate=False,
                     save_forensic=False,
                     mailbox_reports_folder="INBOX",
                     mailbox_archive_folder="Archive",
                     mailbox_watch=False,
                     mailbox_delete=False,
                     mailbox_test=False,
                     mailbox_batch_size=None,
                     imap_host=None,
                     imap_skip_certificate_verification=False,
                     imap_ssl=True,
                     imap_port=993,
                     imap_timeout=30,
                     imap_max_retries=4,
                     imap_user=None,
                     imap_password=None,
                     graph_user=None,
                     graph_password=None,
                     graph_client_id=None,
                     graph_client_secret=None,
                     graph_mailbox=None,
                     hec=None,
                     hec_token=None,
                     hec_index=None,
                     hec_skip_certificate_verification=False,
                     elasticsearch_hosts=None,
                     elasticsearch_timeout=60,
                     elasticsearch_number_of_shards=1,
                     elasticsearch_number_of_replicas=0,
                     elasticsearch_index_suffix=None,
                     elasticsearch_ssl=True,
                     elasticsearch_ssl_cert_path=None,
                     elasticsearch_monthly_indexes=False,
                     elasticsearch_username=None,
                     elasticsearch_password=None,
                     kafka_hosts=None,
                     kafka_username=None,
                     kafka_password=None,
                     kafka_aggregate_topic=None,
                     kafka_forensic_topic=None,
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
                     syslog_server=None,
                     syslog_port=None,
                     gmail_api_credentials_file=None,
                     gmail_api_token_file=None,
                     gmail_api_include_spam_trash=False,
                     gmail_api_scopes=[],
                     log_file=args.log_file,
                     n_procs=1,
                     chunk_size=1,
                     ip_db_path=None
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
                    "strip_attachment_payloads")
            if "output" in general_config:
                opts.output = general_config["output"]
            if "aggregate_json_filename" in general_config:
                opts.aggregate_json_filename = general_config[
                    "aggregate_json_filename"]
            if "forensic_json_filename" in general_config:
                opts.forensic_json_filename = general_config[
                    "forensic_json_filename"]
            if "aggregate_csv_filename" in general_config:
                opts.aggregate_csv_filename = general_config[
                    "aggregate_csv_filename"]
            if "forensic_csv_filename" in general_config:
                opts.forensic_csv_filename = general_config[
                    "forensic_csv_filename"]
            if "nameservers" in general_config:
                opts.nameservers = _str_to_list(general_config["nameservers"])
            if "dns_timeout" in general_config:
                opts.dns_timeout = general_config.getfloat("dns_timeout")
            if "save_aggregate" in general_config:
                opts.save_aggregate = general_config["save_aggregate"]
            if "save_forensic" in general_config:
                opts.save_forensic = general_config["save_forensic"]
            if "debug" in general_config:
                opts.debug = general_config.getboolean("debug")
            if "verbose" in general_config:
                opts.verbose = general_config.getboolean("verbose")
            if "silent" in general_config:
                opts.silent = general_config.getboolean("silent")
            if "log_file" in general_config:
                opts.log_file = general_config["log_file"]
            if "n_procs" in general_config:
                opts.n_procs = general_config.getint("n_procs")
            if "chunk_size" in general_config:
                opts.chunk_size = general_config.getint("chunk_size")
            if "ip_db_path" in general_config:
                opts.ip_db_path = general_config["ip_db_path"]
            else:
                opts.ip_db_path = None

        if "mailbox" in config.sections():
            mailbox_config = config["mailbox"]
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
            else:
                opts.mailbox_batch_size = None

        if "imap" in config.sections():
            imap_config = config["imap"]
            if "watch" in imap_config:
                logger.warning("Starting in 8.0.0, the watch option has been "
                               "moved from the imap configuration section to "
                               "the mailbox configuration section.")
            if "host" in imap_config:
                opts.imap_host = imap_config["host"]
            else:
                logger.error("host setting missing from the "
                             "imap config section")
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
                imap_verify = imap_config.getboolean(
                    "skip_certificate_verification")
                opts.imap_skip_certificate_verification = imap_verify
            if "user" in imap_config:
                opts.imap_user = imap_config["user"]
            else:
                logger.critical("user setting missing from the "
                                "imap config section")
                exit(-1)
            if "password" in imap_config:
                opts.imap_password = imap_config["password"]
            else:
                logger.critical("password setting missing from the "
                                "imap config section")
                exit(-1)

        if "msgraph" in config.sections():
            graph_config = config["msgraph"]
            if "user" in graph_config:
                opts.graph_user = graph_config["user"]
            else:
                logger.critical("user setting missing from the "
                                "msgraph config section")
                exit(-1)
            if "password" in graph_config:
                opts.graph_password = graph_config["password"]
            else:
                logger.critical("password setting missing from the "
                                "msgraph config section")
                exit(-1)

            if "client_id" in graph_config:
                opts.graph_client_id = graph_config["client_id"]
            else:
                logger.critical("client_id setting missing from the "
                                "msgraph config section")
                exit(-1)

            if "client_secret" in graph_config:
                opts.graph_client_secret = graph_config["client_secret"]
            else:
                logger.critical("client_secret setting missing from the "
                                "msgraph config section")
                exit(-1)
            if "mailbox" in graph_config:
                opts.graph_mailbox = graph_config["mailbox"]

        if "elasticsearch" in config:
            elasticsearch_config = config["elasticsearch"]
            if "hosts" in elasticsearch_config:
                opts.elasticsearch_hosts = _str_to_list(elasticsearch_config[
                    "hosts"])
            else:
                logger.critical("hosts setting missing from the "
                                "elasticsearch config section")
                exit(-1)
            if "timeout" in elasticsearch_config:
                timeout = elasticsearch_config.getfloat("timeout")
                opts.elasticsearch_timeout = timeout
            if "number_of_shards" in elasticsearch_config:
                number_of_shards = elasticsearch_config.getint(
                    "number_of_shards")
                opts.elasticsearch_number_of_shards = number_of_shards
                if "number_of_replicas" in elasticsearch_config:
                    number_of_replicas = elasticsearch_config.getint(
                        "number_of_replicas")
                    opts.elasticsearch_number_of_replicas = number_of_replicas
            if "index_suffix" in elasticsearch_config:
                opts.elasticsearch_index_suffix = elasticsearch_config[
                    "index_suffix"]
            if "monthly_indexes" in elasticsearch_config:
                monthly = elasticsearch_config.getboolean("monthly_indexes")
                opts.elasticsearch_monthly_indexes = monthly
            if "ssl" in elasticsearch_config:
                opts.elasticsearch_ssl = elasticsearch_config.getboolean(
                    "ssl")
            if "cert_path" in elasticsearch_config:
                opts.elasticsearch_ssl_cert_path = elasticsearch_config[
                    "cert_path"]
            if "user" in elasticsearch_config:
                opts.elasticsearch_username = elasticsearch_config[
                    "user"]
            if "password" in elasticsearch_config:
                opts.elasticsearch_password = elasticsearch_config[
                    "password"]
        if "splunk_hec" in config.sections():
            hec_config = config["splunk_hec"]
            if "url" in hec_config:
                opts.hec = hec_config["url"]
            else:
                logger.critical("url setting missing from the "
                                "splunk_hec config section")
                exit(-1)
            if "token" in hec_config:
                opts.hec_token = hec_config["token"]
            else:
                logger.critical("token setting missing from the "
                                "splunk_hec config section")
                exit(-1)
            if "index" in hec_config:
                opts.hec_index = hec_config["index"]
            else:
                logger.critical("index setting missing from the "
                                "splunk_hec config section")
                exit(-1)
            if "skip_certificate_verification" in hec_config:
                opts.hec_skip_certificate_verification = hec_config[
                    "skip_certificate_verification"]
        if "kafka" in config.sections():
            kafka_config = config["kafka"]
            if "hosts" in kafka_config:
                opts.kafka_hosts = _str_to_list(kafka_config["hosts"])
            else:
                logger.critical("hosts setting missing from the "
                                "kafka config section")
                exit(-1)
            if "user" in kafka_config:
                opts.kafka_username = kafka_config["user"]
            else:
                logger.critical("user setting missing from the "
                                "kafka config section")
                exit(-1)
            if "password" in kafka_config:
                opts.kafka_password = kafka_config["password"]
            else:
                logger.critical("password setting missing from the "
                                "kafka config section")
                exit(-1)
            if "ssl" in kafka_config:
                opts.kafka_ssl = kafka_config.getboolean("ssl")
            if "skip_certificate_verification" in kafka_config:
                kafka_verify = kafka_config.getboolean(
                    "skip_certificate_verification")
                opts.kafka_skip_certificate_verification = kafka_verify
            if "aggregate_topic" in kafka_config:
                opts.kafka_aggregate = kafka_config["aggregate_topic"]
            else:
                logger.critical("aggregate_topic setting missing from the "
                                "kafka config section")
                exit(-1)
            if "forensic_topic" in kafka_config:
                opts.kafka_username = kafka_config["forensic_topic"]
            else:
                logger.critical("forensic_topic setting missing from the "
                                "splunk_hec config section")
        if "smtp" in config.sections():
            smtp_config = config["smtp"]
            if "host" in smtp_config:
                opts.smtp_host = smtp_config["host"]
            else:
                logger.critical("host setting missing from the "
                                "smtp config section")
                exit(-1)
            if "port" in smtp_config:
                opts.smtp_port = smtp_config.getint("port")
            if "ssl" in smtp_config:
                opts.smtp_ssl = smtp_config.getboolean("ssl")
            if "skip_certificate_verification" in smtp_config:
                smtp_verify = smtp_config.getboolean(
                    "skip_certificate_verification")
                opts.smtp_skip_certificate_verification = smtp_verify
            if "user" in smtp_config:
                opts.smtp_user = smtp_config["user"]
            else:
                logger.critical("user setting missing from the "
                                "smtp config section")
                exit(-1)
            if "password" in smtp_config:
                opts.smtp_password = smtp_config["password"]
            else:
                logger.critical("password setting missing from the "
                                "smtp config section")
                exit(-1)
            if "from" in smtp_config:
                opts.smtp_from = smtp_config["from"]
            else:
                logger.critical("from setting missing from the "
                                "smtp config section")
            if "to" in smtp_config:
                opts.smtp_to = _str_to_list(smtp_config["to"])
            else:
                logger.critical("to setting missing from the "
                                "smtp config section")
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
                logger.critical("bucket setting missing from the "
                                "s3 config section")
                exit(-1)
            if "path" in s3_config:
                opts.s3_path = s3_config["path"]
                if opts.s3_path.startswith("/"):
                    opts.s3_path = opts.s3_path[1:]
                if opts.s3_path.endswith("/"):
                    opts.s3_path = opts.s3_path[:-1]
            else:
                opts.s3_path = ""
        if "syslog" in config.sections():
            syslog_config = config["syslog"]
            if "server" in syslog_config:
                opts.syslog_server = syslog_config["server"]
            else:
                logger.critical("server setting missing from the "
                                "syslog config section")
                exit(-1)
            if "port" in syslog_config:
                opts.syslog_port = syslog_config["port"]
            else:
                opts.syslog_port = 514

        if "gmail_api" in config.sections():
            gmail_api_config = config["gmail_api"]
            opts.gmail_api_credentials_file = \
                gmail_api_config.get("credentials_file")
            opts.gmail_api_token_file = \
                gmail_api_config.get("token_file", ".token")
            opts.gmail_api_include_spam_trash = \
                gmail_api_config.getboolean("include_spam_trash", False)
            opts.gmail_api_scopes = \
                gmail_api_config.get("scopes",
                                     default_gmail_api_scope)
            opts.gmail_api_scopes = \
                _str_to_list(opts.gmail_api_scopes)

    logger.setLevel(logging.WARNING)

    if opts.verbose:
        logger.setLevel(logging.INFO)
    if opts.debug:
        logger.setLevel(logging.DEBUG)
    if opts.log_file:
        fh = logging.FileHandler(opts.log_file)
        formatter = logging.Formatter(
            '%(asctime)s - '
            '%(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    if opts.imap_host is None \
            and opts.graph_user is None \
            and opts.gmail_api_credentials_file is None \
            and len(opts.file_path) == 0:
        logger.error("You must supply input files or a mailbox connection")
        exit(1)

    logger.info("Starting parsedmarc")

    if opts.save_aggregate or opts.save_forensic:
        try:
            if opts.elasticsearch_hosts:
                es_aggregate_index = "dmarc_aggregate"
                es_forensic_index = "dmarc_forensic"
                if opts.elasticsearch_index_suffix:
                    suffix = opts.elasticsearch_index_suffix
                    es_aggregate_index = "{0}_{1}".format(
                        es_aggregate_index, suffix)
                    es_forensic_index = "{0}_{1}".format(
                        es_forensic_index, suffix)
                elastic.set_hosts(opts.elasticsearch_hosts,
                                  opts.elasticsearch_ssl,
                                  opts.elasticsearch_ssl_cert_path,
                                  opts.elasticsearch_username,
                                  opts.elasticsearch_password,
                                  timeout=opts.elasticsearch_timeout)
                elastic.migrate_indexes(aggregate_indexes=[es_aggregate_index],
                                        forensic_indexes=[es_forensic_index])
        except elastic.ElasticsearchError as error:
            logger.error("Elasticsearch Error: {0}".format(error.__str__()))
            exit(1)

    if opts.hec:
        if opts.hec_token is None or opts.hec_index is None:
            logger.error("HEC token and HEC index are required when "
                         "using HEC URL")
            exit(1)

        verify = True
        if opts.hec_skip_certificate_verification:
            verify = False
        hec_client = splunk.HECClient(opts.hec, opts.hec_token,
                                      opts.hec_index,
                                      verify=verify)

    kafka_aggregate_topic = opts.kafka_aggregate_topic
    kafka_forensic_topic = opts.kafka_forensic_topic

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

    counter = Value('i', 0)
    pool = Pool(opts.n_procs, initializer=init, initargs=(counter,))
    results = pool.starmap_async(cli_parse,
                                 zip(file_paths,
                                     repeat(opts.strip_attachment_payloads),
                                     repeat(opts.nameservers),
                                     repeat(opts.dns_timeout),
                                     repeat(opts.ip_db_path),
                                     repeat(opts.offline),
                                     repeat(opts.n_procs >= 1)),
                                 opts.chunk_size)
    if sys.stdout.isatty():
        pbar = tqdm(total=len(file_paths))
        while not results.ready():
            pbar.update(counter.value - pbar.n)
            time.sleep(0.1)
        pbar.close()
    else:
        while not results.ready():
            time.sleep(0.1)
    results = results.get()
    pool.close()
    pool.join()

    for result in results:
        if type(result[0]) is InvalidDMARCReport:
            logger.error("Failed to parse {0} - {1}".format(result[1],
                                                            result[0]))
        else:
            if result[0]["report_type"] == "aggregate":
                aggregate_reports.append(result[0]["report"])
            elif result[0]["report_type"] == "forensic":
                forensic_reports.append(result[0]["report"])

    for mbox_path in mbox_paths:
        strip = opts.strip_attachment_payloads
        reports = get_dmarc_reports_from_mbox(mbox_path,
                                              nameservers=opts.nameservers,
                                              dns_timeout=opts.dns_timeout,
                                              strip_attachment_payloads=strip,
                                              ip_db_path=opts.ip_db_path,
                                              offline=opts.offline,
                                              parallel=False)
        aggregate_reports += reports["aggregate_reports"]
        forensic_reports += reports["forensic_reports"]

    mailbox_connection = None
    if opts.imap_host:
        try:
            if opts.imap_user is None or opts.imap_password is None:
                logger.error("IMAP user and password must be specified if"
                             "host is specified")

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

        except Exception as error:
            logger.error("IMAP Error: {0}".format(error.__str__()))
            exit(1)

    if opts.graph_user:
        try:
            mailbox = opts.graph_mailbox or opts.graph_user
            mailbox_connection = MSGraphConnection(
                client_id=opts.graph_client_id,
                client_secret=opts.graph_client_secret,
                username=opts.graph_user,
                password=opts.graph_password,
                mailbox=mailbox
            )

        except Exception as error:
            logger.error("MS Graph Error: {0}".format(error.__str__()))
            exit(1)

    if opts.gmail_api_credentials_file:
        if opts.mailbox_delete:
            if 'https://mail.google.com/' not in opts.gmail_api_scopes:
                logger.error("Message deletion requires scope"
                             " 'https://mail.google.com/'. "
                             "Add the scope and remove token file "
                             "to acquire proper access.")
                opts.mailbox_delete = False

        try:
            mailbox_connection = GmailConnection(
                credentials_file=opts.gmail_api_credentials_file,
                token_file=opts.gmail_api_token_file,
                scopes=opts.gmail_api_scopes,
                include_spam_trash=opts.gmail_api_include_spam_trash,
                reports_folder=opts.mailbox_reports_folder
            )

        except Exception as error:
            logger.error("Gmail API Error: {0}".format(error.__str__()))
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
                offline=opts.offline,
                nameservers=opts.nameservers,
                test=opts.mailbox_test,
                strip_attachment_payloads=opts.strip_attachment_payloads,
            )

            aggregate_reports += reports["aggregate_reports"]
            forensic_reports += reports["forensic_reports"]

        except Exception as error:
            logger.error("Mailbox Error: {0}".format(error.__str__()))
            exit(1)

    results = OrderedDict([("aggregate_reports", aggregate_reports),
                           ("forensic_reports", forensic_reports)])

    if opts.output:
        save_output(results, output_directory=opts.output,
                    aggregate_json_filename=opts.aggregate_json_filename,
                    forensic_json_filename=opts.forensic_json_filename,
                    aggregate_csv_filename=opts.aggregate_csv_filename,
                    forensic_csv_filename=opts.forensic_csv_filename)

    process_reports(results)

    if opts.smtp_host:
        try:
            verify = True
            if opts.smtp_skip_certificate_verification:
                verify = False
            email_results(results, opts.smtp_host, opts.smtp_from,
                          opts.smtp_to, port=opts.smtp_port, verify=verify,
                          username=opts.smtp_user,
                          password=opts.smtp_password,
                          subject=opts.smtp_subject)
        except Exception as error:
            logger.error("{0}".format(error.__str__()))
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
                nameservers=opts.nameservers,
                dns_timeout=opts.dns_timeout,
                strip_attachment_payloads=opts.strip_attachment_payloads,
                batch_size=opts.mailbox_batch_size,
                ip_db_path=opts.ip_db_path,
                offline=opts.offline)
        except FileExistsError as error:
            logger.error("{0}".format(error.__str__()))
            exit(1)


if __name__ == "__main__":
    _main()
