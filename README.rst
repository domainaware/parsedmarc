==========
parsedmarc
==========

|Build Status| |Code Coverage| |PyPI Package|

.. image:: https://raw.githubusercontent.com/domainaware/parsedmarc/master/docs/_static/screenshots/dmarc-summary-charts.png
   :alt: A screenshot of DMARC summary charts in Kibana
   :align: center
   :scale: 50
   :target: https://raw.githubusercontent.com/domainaware/parsedmarc/master/docs/_static/screenshots/dmarc-summary-charts.png

``parsedmarc`` is a Python module and CLI utility for parsing DMARC reports.
When used with Elasticsearch and Kibana (or Splunk), it works as a self-hosted
open source alternative to commercial DMARC report processing services such
as Agari Brand Protection, Dmarcian, OnDMARC, ProofPoint Email Fraud Defense,
and Valimail.

Features
========

* Parses draft and 1.0 standard aggregate/rua reports
* Parses forensic/failure/ruf reports
* Can parse reports from an inbox over IMAP
* Transparently handles gzip or zip compressed reports
* Consistent data structures
* Simple JSON and/or CSV output
* Optionally email the results
* Optionally send the results to Elasticsearch and/or Splunk, for use with
  premade dashboards
* Optionally send reports to Apache Kafka

Resources
=========

DMARC guides
------------

* `Demystifying DMARC`_ - A complete guide to SPF, DKIM, and DMARC

SPF and DMARC record validation
-------------------------------

If you are looking for SPF and DMARC record validation and parsing,
check out the sister project,
`checkdmarc <https://domainaware.github.io/checkdmarc/>`_.

Lookalike domains
-----------------

DMARC protects against domain spoofing, not lookalike domains. For open source
lookalike domain monitoring, check out
`DomainAware <https://github.com/seanthegeek/domainaware>`_.


CLI help
========

::

    usage: parsedmarc [-h] [-c CONFIG_FILE] [--strip-attachment-payloads]
                      [-o OUTPUT] [-n NAMESERVERS [NAMESERVERS ...]]
                      [-t DNS_TIMEOUT] [--offline] [-s] [--debug]
                      [--log-file LOG_FILE] [-v]
                      [file_path [file_path ...]]

    Parses DMARC reports

    positional arguments:
      file_path             one or more paths to aggregate or forensic report
                            files or emails

    optional arguments:
      -h, --help            show this help message and exit
      -c CONFIG_FILE, --config-file CONFIG_FILE
                            a path to a configuration file (--silent implied)
      --strip-attachment-payloads
                            remove attachment payloads from forensic report output
      -o OUTPUT, --output OUTPUT
                            write output files to the given directory
      -n NAMESERVERS [NAMESERVERS ...], --nameservers NAMESERVERS [NAMESERVERS ...]
                            nameservers to query (default is Cloudflare's
                            nameservers)
      -t DNS_TIMEOUT, --dns_timeout DNS_TIMEOUT
                            number of seconds to wait for an answer from DNS
                            (default: 2.0)
      --offline             do not make online queries for geolocation or DNS
      -s, --silent          only print errors and warnings
      --debug               print debugging information
      --log-file LOG_FILE   output logging to a file
      -v, --version         show program's version number and exit

.. note::

   In ``parsedmarc`` 6.0.0, most CLI options were moved to a configuration file, described below.

Configuration file
==================

``parsedmarc`` can be configured by supplying the path to an INI file

.. code-block:: bash

    parsedmarc -c /etc/parsedmarc.ini

For example

.. code-block:: ini

   # This is an example comment

   [general]
   save_aggregate = True
   save_forensic = True

   [imap]
   host = imap.example.com
   user = dmarcresports@example.com
   password = $uperSecure
   watch = True

   [elasticsearch]
   hosts = 127.0.0.1:9200
   ssl = False

   [splunk_hec]
   url = https://splunkhec.example.com
   token = HECTokenGoesHere
   index = email

The full set of configuration options are:

- ``general``
    - ``save_aggregate`` - bool: Save aggregate report data to the Elasticsearch and/or Splunk
    - ``save_forensic`` - bool: Save forensic report data to the Elasticsearch and/or Splunk
    - ``strip_attachment_payloads`` - bool: Remove attachment payloads from results
    - ``output`` - str: Directory to place JSON and CSV files in
    - ``offline`` - bool: Do not use online queries for geolocation or DNS
    - ``nameservers`` -  str: A comma separated list of DNS resolvers (Default: `Cloudflare's public resolvers`_)
    - ``dns_timeout`` - float: DNS timeout period
    - ``debug`` - bool: Print debugging messages
    - ``silent`` - bool: Only print errors (Default: True)
    - ``log_file`` - str: Write log messages to a file at this path
    - ``n_procs`` - int: Number of process to run in parallel when parsing in CLI mode (Default: 1)
    - ``chunk_size`` - int: Number of files to give to each process when running in parallel. Setting this to a number larger than one can improve performance when processing thousands of files
- ``imap``
    - ``host`` - str: The IMAP server hostname or IP address
    - ``port`` - int: The IMAP server port (Default: 993)
    - ``ssl`` - bool: Use an encrypted SSL/TLS connection (Default: True)
    - ``skip_certificate_verification`` - bool: Skip certificate verification (not recommended)
    - ``user`` - str: The IMAP user
    - ``password`` - str: The IMAP password
    - ``reports_folder`` - str: The IMAP folder where the incoming reports can be found (Default: INBOX)
    - ``archive_folder`` - str:  The IMAP folder to sort processed emails into (Default: Archive)
    - ``watch`` - bool: Use the IMAP ``IDLE`` command to process messages as they arrive
    - ``delete`` - bool: Delete messages after processing them, instead of archiving them
    - ``test`` - bool: Do not move or delete messages
- ``elasticsearch``
    - ``hosts`` - str: A comma separated list of hostnames and ports or URLs (e.g. ``127.0.0.1:9200`` or ``https://user:secret@localhost``)

      .. note::
         Special characters in the username or password must be `URL encoded`_.
    - ``ssl`` - bool: Use an encrypted SSL/TLS connection (Default: True)
    - ``cert_path`` - str: Path to a trusted certificates
    - ``index_suffix`` - str: A suffix to apply to the index names
    - ``monthly_indexes`` - bool: Use monthly indexes instead of daily indexes
    - ``number_of_shards`` - int: The number of shards to use when creating the index (Default: 1)
    - ``number_of_replicas`` - int: The number of replicas to use when creating the index (Default: 1)
- ``splunk_hec``
    - ``url`` - str: The URL of the Splunk HTTP Events Collector (HEC)
    - ``token`` - str: The HEC token
    - ``index`` - str: The Splunk index to use
    - ``skip_certificate_verification`` - bool: Skip certificate verification (not recommended)
- ``kafka``
    - ``hosts`` - str: A comma separated list of Kafka hosts
    - ``user`` - str: The Kafka user
    - ``passsword`` - str: The Kafka password
    - ``ssl`` - bool: Use an encrypted SSL/TLS connection (Default: True)
    - ``skip_certificate_verification`` - bool: Skip certificate verification (not recommended)
    - ``aggregate_topic`` - str: The Kafka topic for aggregate reports
    - ``forensic_topic`` - str: The Kafka topic for forensic reports
- ``smtp``
    - ``host`` - str: The SMTP hostname
    - ``port`` - int: The SMTP port (Default: 25)
    - ``ssl`` - bool: Require SSL/TLS instead of using STARTTLS
    - ``skip_certificate_verification`` - bool: Skip certificate verification (not recommended)
    - ``user`` - str: the SMTP username
    - ``password`` - str: the SMTP password
    - ``from`` - str: The From header to use in the email
    - ``to`` - list: A list of email addresses to send to
    - ``subject`` - str: The Subject header to use in the email (Default: parsedmarc report)
    - ``attachment`` - str: The ZIP attachment filenames
    - ``message`` - str: The email message (Default: Please see the attached parsedmarc report.)


.. warning::

    It is **strongly recommended** to **not** use the ``nameservers`` setting.
    By default, ``parsedmarc`` uses `Cloudflare's public resolvers`_,
    which are much faster and more reliable than Google, Cisco OpenDNS, or
    even most local resolvers.

    The ``nameservers`` option should only be used if your network blocks DNS
    requests to outside resolvers.

.. warning::

   ``save_aggregate`` and ``save_forensic`` are separate options because
   you may not want to save forensic reports (also known as failure reports)
   to your Elasticsearch instance, particularly if you are in a
   highly-regulated industry that handles sensitive data, such as healthcare
   or finance. If your legitimate outgoing email fails DMARC, it is possible
   that email may appear later in a forensic report.

   Forensic reports contain the original headers of an email that failed a
   DMARC check, and sometimes may also include the full message body,
   depending on the policy of the reporting organization.

   Most reporting organizations do not send forensic reports of any kind for
   privacy reasons. While aggregate DMARC reports are sent at least daily,
   it is normal to receive very few forensic reports.

   An alternative approach is to still collect forensic/failure/ruf reports
   in your DMARC inbox, but run ``parsedmarc`` with ``save_forensic = True``
   manually on a separate IMAP folder (using the  ``reports_folder`` option),
   after you have manually moved known samples you want to save to that
   folder (e.g. malicious samples and non-sensitive legitimate samples).

Sample aggregate report output
==============================

Here are the results from parsing the `example <https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F>`_
report from the dmarc.org wiki. It's actually an older draft of the the 1.0
report schema standardized in
`RFC 7480 Appendix C <https://tools.ietf.org/html/rfc7489#appendix-C>`_.
This draft schema is still in wide use.

``parsedmarc`` produces consistent, normalized output, regardless of the report
schema.

JSON
----

.. code-block:: json

    {
      "xml_schema": "draft",
      "report_metadata": {
        "org_name": "acme.com",
        "org_email": "noreply-dmarc-support@acme.com",
        "org_extra_contact_info": "http://acme.com/dmarc/support",
        "report_id": "9391651994964116463",
        "begin_date": "2012-04-27 20:00:00",
        "end_date": "2012-04-28 19:59:59",
        "errors": []
      },
      "policy_published": {
        "domain": "example.com",
        "adkim": "r",
        "aspf": "r",
        "p": "none",
        "sp": "none",
        "pct": "100",
        "fo": "0"
      },
      "records": [
        {
          "source": {
            "ip_address": "72.150.241.94",
            "country": "US",
            "reverse_dns": "adsl-72-150-241-94.shv.bellsouth.net",
            "base_domain": "bellsouth.net"
          },
          "count": 2,
          "alignment": {
            "spf": true,
            "dkim": false,
            "dmarc": true
          },
          "policy_evaluated": {
            "disposition": "none",
            "dkim": "fail",
            "spf": "pass",
            "policy_override_reasons": []
          },
          "identifiers": {
            "header_from": "example.com",
            "envelope_from": "example.com",
            "envelope_to": null
          },
          "auth_results": {
            "dkim": [
              {
                "domain": "example.com",
                "selector": "none",
                "result": "fail"
              }
            ],
            "spf": [
              {
                "domain": "example.com",
                "scope": "mfrom",
                "result": "pass"
              }
            ]
          }
        }
      ]
    }

CSV
---

::

    xml_schema,org_name,org_email,org_extra_contact_info,report_id,begin_date,end_date,errors,domain,adkim,aspf,p,sp,pct,fo,source_ip_address,source_country,source_reverse_dns,source_base_domain,count,spf_aligned,dkim_aligned,dmarc_aligned,disposition,policy_override_reasons,policy_override_comments,envelope_from,header_from,envelope_to,dkim_domains,dkim_selectors,dkim_results,spf_domains,spf_scopes,spf_results
    draft,acme.com,noreply-dmarc-support@acme.com,http://acme.com/dmarc/support,9391651994964116463,2012-04-27 20:00:00,2012-04-28 19:59:59,,example.com,r,r,none,none,100,0,72.150.241.94,US,adsl-72-150-241-94.shv.bellsouth.net,bellsouth.net,2,True,False,True,none,,,example.com,example.com,,example.com,none,fail,example.com,mfrom,pass


Sample forensic report output
=============================

Thanks to Github user `xennn <https://github.com/xennn>`_ for the anonymized
`forensic report email sample
<https://github.com/domainaware/parsedmarc/raw/master/samples/forensic/DMARC%20Failure%20Report%20for%20domain.de%20(mail-from%3Dsharepoint%40domain.de%2C%20ip%3D10.10.10.10).eml>`_.

JSON
----


.. code-block:: json

   {
        "feedback_type": "auth-failure",
        "user_agent": "Lua/1.0",
        "version": "1.0",
        "original_mail_from": "sharepoint@domain.de",
        "original_rcpt_to": "peter.pan@domain.de",
        "arrival_date": "Mon, 01 Oct 2018 11:20:27 +0200",
        "message_id": "<38.E7.30937.BD6E1BB5@ mailrelay.de>",
        "authentication_results": "dmarc=fail (p=none, dis=none) header.from=domain.de",
        "delivery_result": "policy",
        "auth_failure": [
          "dmarc"
        ],
        "reported_domain": "domain.de",
        "arrival_date_utc": "2018-10-01 09:20:27",
        "source": {
          "ip_address": "10.10.10.10",
          "country": null,
          "reverse_dns": null,
          "base_domain": null
        },
        "authentication_mechanisms": [],
        "original_envelope_id": null,
        "dkim_domain": null,
        "sample_headers_only": false,
        "sample": "Received: from Servernameone.domain.local (Servernameone.domain.local [10.10.10.10])\n\tby  mailrelay.de (mail.DOMAIN.de) with SMTP id 38.E7.30937.BD6E1BB5; Mon,  1 Oct 2018 11:20:27 +0200 (CEST)\nDate: 01 Oct 2018 11:20:27 +0200\nMessage-ID: <38.E7.30937.BD6E1BB5@ mailrelay.de>\nTo: <peter.pan@domain.de>\nfrom: \"=?utf-8?B?SW50ZXJha3RpdmUgV2V0dGJld2VyYmVyLcOcYmVyc2ljaHQ=?=\" <sharepoint@domain.de>\nSubject: Subject\nMIME-Version: 1.0\nX-Mailer: Microsoft SharePoint Foundation 2010\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\n<html><head><base href=3D'\nwettbewerb' /></head><body><!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\"=\n><HTML><HEAD><META NAME=3D\"Generator\" CONTENT=3D\"MS Exchange Server version=\n 08.01.0240.003\"></html>\n",
        "parsed_sample": {
          "from": {
            "display_name": "Interaktive Wettbewerber-Übersicht",
            "address": "sharepoint@domain.de",
            "local": "sharepoint",
            "domain": "domain.de"
          },
          "to_domains": [
            "domain.de"
          ],
          "to": [
            {
              "display_name": null,
              "address": "peter.pan@domain.de",
              "local": "peter.pan",
              "domain": "domain.de"
            }
          ],
          "subject": "Subject",
          "timezone": "+2",
          "mime-version": "1.0",
          "date": "2018-10-01 09:20:27",
          "content-type": "text/html; charset=utf-8",
          "x-mailer": "Microsoft SharePoint Foundation 2010",
          "body": "<html><head><base href='\nwettbewerb' /></head><body><!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\"><HTML><HEAD><META NAME=\"Generator\" CONTENT=\"MS Exchange Server version 08.01.0240.003\"></html>",
          "received": [
            {
              "from": "Servernameone.domain.local Servernameone.domain.local 10.10.10.10",
              "by": "mailrelay.de mail.DOMAIN.de",
              "with": "SMTP id 38.E7.30937.BD6E1BB5",
              "date": "Mon, 1 Oct 2018 11:20:27 +0200 CEST",
              "hop": 1,
              "date_utc": "2018-10-01 09:20:27",
              "delay": 0
            }
          ],
          "content-transfer-encoding": "quoted-printable",
          "message-id": "<38.E7.30937.BD6E1BB5@ mailrelay.de>",
          "has_defects": false,
          "headers": {
            "Received": "from Servernameone.domain.local (Servernameone.domain.local [10.10.10.10])\n\tby  mailrelay.de (mail.DOMAIN.de) with SMTP id 38.E7.30937.BD6E1BB5; Mon,  1 Oct 2018 11:20:27 +0200 (CEST)",
            "Date": "01 Oct 2018 11:20:27 +0200",
            "Message-ID": "<38.E7.30937.BD6E1BB5@ mailrelay.de>",
            "To": "<peter.pan@domain.de>",
            "from": "\"Interaktive Wettbewerber-Übersicht\" <sharepoint@domain.de>",
            "Subject": "Subject",
            "MIME-Version": "1.0",
            "X-Mailer": "Microsoft SharePoint Foundation 2010",
            "Content-Type": "text/html; charset=utf-8",
            "Content-Transfer-Encoding": "quoted-printable"
          },
          "reply_to": [],
          "cc": [],
          "bcc": [],
          "attachments": [],
          "filename_safe_subject": "Subject"
        }
      }



CSV
---

::

    feedback_type,user_agent,version,original_envelope_id,original_mail_from,original_rcpt_to,arrival_date,arrival_date_utc,subject,message_id,authentication_results,dkim_domain,source_ip_address,source_country,source_reverse_dns,source_base_domain,delivery_result,auth_failure,reported_domain,authentication_mechanisms,sample_headers_only
    auth-failure,Lua/1.0,1.0,,sharepoint@domain.de,peter.pan@domain.de,"Mon, 01 Oct 2018 11:20:27 +0200",2018-10-01 09:20:27,Subject,<38.E7.30937.BD6E1BB5@ mailrelay.de>,"dmarc=fail (p=none, dis=none) header.from=domain.de",,10.10.10.10,,,,policy,dmarc,domain.de,,False

Bug reports
===========

Please report bugs on the GitHub issue tracker

https://github.com/domainaware/parsedmarc/issues

.. |Build Status| image:: https://travis-ci.org/domainaware/parsedmarc.svg?branch=master
   :target: https://travis-ci.org/domainaware/parsedmarc

.. |Code Coverage| image:: https://codecov.io/gh/domainaware/parsedmarc/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/domainaware/parsedmarc

..  |PyPI Package| image:: https://img.shields.io/pypi/v/parsedmarc.svg
    :target: https://pypi.org/project/parsedmarc/

.. _Demystifying DMARC: https://seanthegeek.net/459/demystifying-dmarc/

.. _Cloudflare's public resolvers: https://1.1.1.1/

.. _URL encoded: https://en.wikipedia.org/wiki/Percent-encoding#Percent-encoding_reserved_characters

