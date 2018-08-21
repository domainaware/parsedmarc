#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A CLI for parsing DMARC reports"""


from argparse import ArgumentParser
from glob import glob
import logging
from collections import OrderedDict
import json

from elasticsearch.exceptions import ElasticsearchException

from parsedmarc import logger, IMAPError, get_dmarc_reports_from_inbox, \
    parse_report_file, elastic, save_output, watch_inbox, email_results, \
    SMTPError, ParserError, __version__


def _main():
    """Called when the module is executed"""
    def process_reports(reports_):
        output_str = "{0}\n".format(json.dumps(reports_,
                                               ensure_ascii=False,
                                               indent=2))
        if not args.silent:
            print(output_str)
        if args.save_aggregate:
            for report in reports_["aggregate_reports"]:
                try:
                    elastic.save_aggregate_report_to_elasticsearch(report)
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except ElasticsearchException as error_:
                    logger.error("Elasticsearch Error: {0}".format(
                        error_.__str__()))
                    exit(1)
        if args.save_forensic:
            for report in reports_["forensic_reports"]:
                try:
                    elastic.save_forensic_report_to_elasticsearch(report)
                except elastic.AlreadySaved as warning:
                    logger.warning(warning.__str__())
                except ElasticsearchException as error_:
                    logger.error("Elasticsearch Error: {0}".format(
                        error_.__str__()))

    arg_parser = ArgumentParser(description="Parses DMARC reports")
    arg_parser.add_argument("file_path", nargs="*",
                            help="one or more paths to aggregate or forensic "
                                 "report files or emails")
    arg_parser.add_argument("-o", "--output",
                            help="Write output files to the given directory")
    arg_parser.add_argument("-n", "--nameservers", nargs="+",
                            help="nameservers to query "
                                 "(Default is Cloudflare's)")
    arg_parser.add_argument("-t", "--timeout",
                            help="number of seconds to wait for an answer "
                                 "from DNS (default 6.0)",
                            type=float,
                            default=6.0)
    arg_parser.add_argument("-H", "--host", help="IMAP hostname or IP address")
    arg_parser.add_argument("-u", "--user", help="IMAP user")
    arg_parser.add_argument("-p", "--password", help="IMAP password")
    arg_parser.add_argument("-r", "--reports-folder", default="INBOX",
                            help="The IMAP folder containing the reports\n"
                                 "Default: INBOX")
    arg_parser.add_argument("-a", "--archive-folder",
                            help="Specifies the IMAP folder to move "
                                 "messages to after processing them\n"
                                 "Default: Archive",
                            default="Archive")
    arg_parser.add_argument("-d", "--delete",
                            help="Delete the reports after processing them",
                            action="store_true", default=False)

    arg_parser.add_argument("-E", "--elasticsearch-host", nargs="*",
                            help="A list of one or more Elasticsearch "
                                 "hostnames or URLs to use (Default "
                                 "localhost:9200)",
                            default=["localhost:9200"])
    arg_parser.add_argument("--save-aggregate", action="store_true",
                            default=False,
                            help="Save aggregate reports to Elasticsearch")
    arg_parser.add_argument("--save-forensic", action="store_true",
                            default=False,
                            help="Save forensic reports to Elasticsearch")
    arg_parser.add_argument("-O", "--outgoing-host",
                            help="Email the results using this host")
    arg_parser.add_argument("-U", "--outgoing-user",
                            help="Email the results using this user")
    arg_parser.add_argument("-P", "--outgoing-password",
                            help="Email the results using this password")
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
                            help="Only print errors")
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
        logging.basicConfig(level=logging.INFO)
        logger.setLevel(logging.INFO)
    if args.host is None and len(args.file_path) == 0:
        arg_parser.print_help()
        exit(1)

    if args.save_aggregate or args.save_forensic:
        try:
            elastic.set_hosts(args.elasticsearch_host)
            elastic.create_indexes()
        except ElasticsearchException as error:
            logger.error("Elasticsearch Error: {0}".format(error.__str__()))
            exit(1)

    file_paths = []
    for file_path in args.file_path:
        file_paths += glob(file_path)
    file_paths = list(set(file_paths))

    for file_path in file_paths:
        try:
            file_results = parse_report_file(file_path,
                                             nameservers=args.nameservers,
                                             timeout=args.timeout)
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
            reports = get_dmarc_reports_from_inbox(args.host,
                                                   args.user,
                                                   args.password,
                                                   reports_folder=rf,
                                                   archive_folder=af,
                                                   delete=args.delete,
                                                   test=args.test)

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
                          args.outgoing_to, user=args.outgoing_user,
                          password=args.outgoing_password,
                          subject=args.outgoing_subject)
        except SMTPError as error:
            logger.error("SMTP Error: {0}".format(error.__str__()))
            exit(1)

    if args.host and args.watch:
        logger.info("Watching for email - Quit with ^c")
        try:
            watch_inbox(args.host, args.user, args.password, process_reports,
                        reports_folder=args.reports_folder,
                        archive_folder=args.archive_folder, delete=args.delete,
                        test=args.test, nameservers=args.nameservers,
                        dns_timeout=args.timeout)
        except IMAPError as error:
            logger.error("IMAP Error: {0}".format(error.__str__()))
            exit(1)


if __name__ == "__main__":
    _main()
