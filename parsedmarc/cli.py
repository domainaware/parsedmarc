#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A CLI for parsing DMARC reports"""


from argparse import ArgumentParser
from glob import glob
import logging
from collections import OrderedDict
import json

from elasticsearch.exceptions import ElasticsearchException

from parsedmarc import IMAPError, get_dmarc_reports_from_inbox, \
    parse_report_file, elastic, kafkaclient, splunk, save_output, \
    watch_inbox, email_results, SMTPError, ParserError, __version__

logger = logging.getLogger("parsedmarc")


def _main():
    """Called when the module is executed"""

    def process_reports(reports_):
        output_str = "{0}\n".format(json.dumps(reports_,
                                               ensure_ascii=False,
                                               indent=2))
        if not args.silent:
            print(output_str)
        if args.kafka_hosts:
            try:
                kafka_client = kafkaclient.KafkaClient(args.kafka_hosts)
            except Exception as error_:
                logger.error("Kafka Error: {0}".format(error_.__str__()))
        if args.save_aggregate:
            for report in reports_["aggregate_reports"]:
                try:
                    if args.elasticsearch_host:
                        elastic.save_aggregate_report_to_elasticsearch(
                            report, index=es_aggregate_index)
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except ElasticsearchException as error_:
                    logger.error("Elasticsearch Error: {0}".format(
                        error_.__str__()))
                    exit(1)
                try:
                    if args.kafka_hosts:
                        kafka_client.save_aggregate_reports_to_kafka(
                            report, kafka_aggregate_topic)
                except Exception as error_:
                    logger.error("Kafka Error: {0}".format(
                         error_.__str__()))
            if args.hec:
                try:
                    aggregate_reports_ = reports_["aggregate_reports"]
                    if len(aggregate_reports_) > 0:
                        hec_client.save_aggregate_reports_to_splunk(
                            aggregate_reports_)
                except splunk.SplunkError as e:
                    logger.error("Splunk HEC error: {0}".format(e.__str__()))
        if args.save_forensic:
            for report in reports_["forensic_reports"]:
                try:
                    if args.elasticsearch_host:
                        elastic.save_forensic_report_to_elasticsearch(
                            report, index=es_forensic_index)
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except ElasticsearchException as error_:
                    logger.error("Elasticsearch Error: {0}".format(
                        error_.__str__()))
                try:
                    if args.kafka_hosts:
                        kafka_client.save_forensic_reports_to_kafka(
                            report, kafka_forensic_topic)
                except Exception as error_:
                    logger.error("Kafka Error: {0}".format(
                        error_.__str__()))
            if args.hec:
                try:
                    forensic_reports_ = reports_["forensic_reports"]
                    if len(forensic_reports_) > 0:
                        hec_client.save_forensic_reports_to_splunk(
                            forensic_reports_)
                except splunk.SplunkError as e:
                    logger.error("Splunk HEC error: {0}".format(e.__str__()))

    arg_parser = ArgumentParser(description="Parses DMARC reports")
    arg_parser.add_argument("file_path", nargs="*",
                            help="one or more paths to aggregate or forensic "
                                 "report files or emails")
    strip_attachment_help = "Remove attachment payloads from forensic " \
                            "report output"
    arg_parser.add_argument("--strip-attachment-payloads",
                            help=strip_attachment_help, action="store_true")
    arg_parser.add_argument("-o", "--output",
                            help="Write output files to the given directory")
    arg_parser.add_argument("-n", "--nameservers", nargs="+",
                            help="nameservers to query "
                                 "(Default is Cloudflare's nameservers)")
    arg_parser.add_argument("-t", "--timeout",
                            help="number of seconds to wait for an answer "
                                 "from DNS (Default: 2.0)",
                            type=float,
                            default=6.0)
    arg_parser.add_argument("-H", "--host", help="IMAP hostname or IP address")
    arg_parser.add_argument("-u", "--user", help="IMAP user")
    arg_parser.add_argument("-p", "--password", help="IMAP password")
    arg_parser.add_argument("--imap-port", default=None, help="IMAP port")
    arg_parser.add_argument("--imap-no-ssl", action="store_true",
                            default=False,
                            help="Do not use SSL/TLS when connecting to IMAP")
    arg_parser.add_argument("-r", "--reports-folder", default="INBOX",
                            help="The IMAP folder containing the reports\n"
                                 "(Default: INBOX)")
    arg_parser.add_argument("-a", "--archive-folder",
                            help="Specifies the IMAP folder to move "
                                 "messages to after processing them\n"
                                 "(Default: Archive)",
                            default="Archive")
    arg_parser.add_argument("-d", "--delete",
                            help="Delete the reports after processing them",
                            action="store_true", default=False)

    arg_parser.add_argument("-E", "--elasticsearch-host", nargs="*",
                            help="One or more Elasticsearch "
                                 "hostnames or URLs to use (e.g. "
                                 "localhost:9200)")
    arg_parser.add_argument("--elasticsearch-index-prefix",
                            help="Prefix to add in front of the "
                                 "dmarc_aggregate and dmarc_forensic "
                                 "Elasticsearch index names, joined by _")
    arg_parser.add_argument("--elasticsearch-index-suffix",
                            help="Append this suffix to the "
                                 "dmarc_aggregate and dmarc_forensic "
                                 "Elasticsearch index names, joined by _")
    arg_parser.add_argument("--hec", help="URL to a Splunk HTTP Event "
                                          "Collector (HEC)")
    arg_parser.add_argument("--hec-token", help="The authorization token for "
                                                "a Splunk "
                                                "HTTP Event Collector (HEC)")
    arg_parser.add_argument("--hec-index", help="The index to use when "
                                                "sending events to the "
                                                "Splunk HTTP Event Collector "
                                                "(HEC)")
    arg_parser.add_argument("--hec-skip-certificate-verification",
                            action="store_true",
                            default=False,
                            help="Skip certificate verification for Splunk "
                                 "HEC")
    arg_parser.add_argument("-K", "--kafka-hosts", nargs="*",
                            help="A list of one or more Kafka hostnames"
                            " or URLs")
    arg_parser.add_argument("--kafka-aggregate-topic",
                            help="The Kafka topic to publish aggregate "
                            "reports to (Default: dmarc_aggregate)",
                            default="dmarc_aggregate")
    arg_parser.add_argument("--kafka-forensic_topic",
                            help="The Kafka topic to publish forensic reports"
                            " to (Default: dmarc_forensic)",
                            default="dmarc_forensic")
    arg_parser.add_argument("--save-aggregate", action="store_true",
                            default=False,
                            help="Save aggregate reports to search indexes")
    arg_parser.add_argument("--save-forensic", action="store_true",
                            default=False,
                            help="Save forensic reports to search indexes")
    arg_parser.add_argument("-O", "--outgoing-host",
                            help="Email the results using this host")
    arg_parser.add_argument("-U", "--outgoing-user",
                            help="Email the results using this user")
    arg_parser.add_argument("-P", "--outgoing-password",
                            help="Email the results using this password")
    arg_parser.add_argument("--outgoing-port",
                            help="Email the results using this port")
    arg_parser.add_argument("--outgoing-ssl",
                            help="Use SSL/TLS instead of STARTTLS (more "
                                 "secure, and required by some providers, "
                                 "like Gmail)")
    arg_parser.add_argument("-F", "--outgoing-from",
                            help="Email the results using this from address")
    arg_parser.add_argument("-T", "--outgoing-to", nargs="+",
                            help="Email the results to these addresses")
    arg_parser.add_argument("-S", "--outgoing-subject",
                            help="Email the results using this subject")
    arg_parser.add_argument("-A", "--outgoing-attachment",
                            help="Email the results using this filename")
    arg_parser.add_argument("-M", "--outgoing-message",
                            help="Email the results using this message")
    arg_parser.add_argument("-w", "--watch", action="store_true",
                            help="Use an IMAP IDLE connection to process "
                                 "reports as they arrive in the inbox")
    arg_parser.add_argument("--test",
                            help="Do not move or delete IMAP messages",
                            action="store_true", default=False)
    arg_parser.add_argument("-s", "--silent", action="store_true",
                            help="Only print errors and warnings")
    arg_parser.add_argument("--debug", action="store_true",
                            help="Print debugging information")
    arg_parser.add_argument("-v", "--version", action="version",
                            version=__version__)

    aggregate_reports = []
    forensic_reports = []

    args = arg_parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    logger.setLevel(logging.WARNING)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    if args.host is None and len(args.file_path) == 0:
        arg_parser.print_help()
        exit(1)

    es_aggregate_index = "dmarc_aggregate"
    es_forensic_index = "dmarc_forensic"

    if args.elasticsearch_index_prefix:
        prefix = args.elasticsearch_index_prefix
        es_aggregate_index = "{0}_{1}".format(prefix, es_aggregate_index)
        es_forensic_index = "{0}_{1}".format(prefix, es_forensic_index)

    if args.elasticsearch_index_suffix:
        suffix = args.elasticsearch_index_suffix
        es_aggregate_index = "{0}_{1}".format(es_aggregate_index, suffix)
        es_forensic_index = "{0}_{1}".format(es_forensic_index, suffix)

    if args.save_aggregate or args.save_forensic:
        if (args.elasticsearch_host is None and args.hec is None
                and args.kafka_hosts is None):
            args.elasticsearch_host = ["localhost:9200"]
        try:
            if args.elasticsearch_host:
                elastic.set_hosts(args.elasticsearch_host)
                elastic.create_indexes([es_aggregate_index, es_forensic_index])
        except ElasticsearchException as error:
            logger.error("Elasticsearch Error: {0}".format(error.__str__()))
            exit(1)

    if args.hec:
        if args.hec_token is None or args.hec_index is None:
            logger.error("HEC token and HEC index are required when "
                         "using HEC URL")
            exit(1)

        verify = True
        if args.hec_skip_certificate_verification:
            verify = False
        hec_client = splunk.HECClient(args.hec, args.hec_token,
                                      args.hec_index,
                                      verify=verify)

    kafka_aggregate_topic = args.kafka_aggregate_topic
    kafka_forensic_topic = args.kafka_forensic_topic

    file_paths = []
    for file_path in args.file_path:
        file_paths += glob(file_path)
    file_paths = list(set(file_paths))

    for file_path in file_paths:
        try:
            sa = args.strip_attachment_payloads
            file_results = parse_report_file(file_path,
                                             nameservers=args.nameservers,
                                             timeout=args.timeout,
                                             strip_attachment_payloads=sa)
            if file_results["report_type"] == "aggregate":
                aggregate_reports.append(file_results["report"])
            elif file_results["report_type"] == "forensic":
                forensic_reports.append(file_results["report"])

        except ParserError as error:
            logger.error("Failed to parse {0} - {1}".format(file_path,
                                                            error))

    if args.host:
        try:
            if args.user is None or args.password is None:
                logger.error("user and password must be specified if"
                             "host is specified")

            rf = args.reports_folder
            af = args.archive_folder
            ns = args.nameservers
            sa = args.strip_attachment_payloads
            ssl = True
            if args.imap_no_ssl:
                ssl = False
            reports = get_dmarc_reports_from_inbox(host=args.host,
                                                   port=args.imap_port,
                                                   ssl=ssl,
                                                   user=args.user,
                                                   password=args.password,
                                                   reports_folder=rf,
                                                   archive_folder=af,
                                                   delete=args.delete,
                                                   nameservers=ns,
                                                   test=args.test,
                                                   strip_attachment_payloads=sa
                                                   )

            aggregate_reports += reports["aggregate_reports"]
            forensic_reports += reports["forensic_reports"]

        except IMAPError as error:
            logger.error("IMAP Error: {0}".format(error.__str__()))
            exit(1)

    results = OrderedDict([("aggregate_reports", aggregate_reports),
                           ("forensic_reports", forensic_reports)])

    if args.output:
        save_output(results, output_directory=args.output)

    process_reports(results)

    if args.outgoing_host:
        if args.outgoing_from is None or args.outgoing_to is None:
            logger.error("--outgoing-from and --outgoing-to must "
                         "be provided if --outgoing-host is used")
            exit(1)

        try:
            email_results(results, args.outgoing_host, args.outgoing_from,
                          args.outgoing_to, use_ssl=args.outgoing_ssl,
                          user=args.outgoing_user,
                          password=args.outgoing_password,
                          subject=args.outgoing_subject)
        except SMTPError as error:
            logger.error("SMTP Error: {0}".format(error.__str__()))
            exit(1)

    if args.host and args.watch:
        logger.info("Watching for email - Quit with ctrl-c")
        ssl = True
        if args.imap_no_ssl:
            ssl = False
        try:
            sa = args.strip_attachment_payloads
            watch_inbox(args.host, args.user, args.password, process_reports,
                        port=args.imap_port, ssl=ssl,
                        reports_folder=args.reports_folder,
                        archive_folder=args.archive_folder, delete=args.delete,
                        test=args.test, nameservers=args.nameservers,
                        dns_timeout=args.timeout, strip_attachment_payloads=sa)
        except IMAPError as error:
            logger.error("IMAP Error: {0}".format(error.__str__()))
            exit(1)


if __name__ == "__main__":
    _main()
