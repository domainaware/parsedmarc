==========
parsedmarc
==========

|Build Status|

.. image:: https://raw.githubusercontent.com/domainaware/parsedmarc/master/docs/_static/screenshots/dmarc-summary-charts.png
   :alt: A screenshot of DMARC summary charts in Kibana
   :align: center
   :scale: 50
   :target: https://raw.githubusercontent.com/domainaware/parsedmarc/master/docs/_static/screenshots/dmarc-summary-charts.png

``parsedmarc`` is a Python module and CLI utility for parsing DMARC reports.
When used with Elasticsearch and Kibana (or Splunk), it works as a self-hosted
open source alternative to commercial DMARC report processing services such
as Agari, Dmarcian, OnDMARC, ProofPoint Email Fraud Defense.

Features
========

* Parses draft and 1.0 standard aggregate/rua reports
* Parses forensic/failure/ruf reports
* Can parse reports from an inbox over IMAP
* Transparently handles gzip or zip compressed reports
* Consistent data structures
* Simple JSON and/or CSV output
* Optionally email the results
* Optionally send the results to Elasticsearch and/or Splunk, for use with premade dashboards
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

DMARC protects against domain spoofing, not lookalike domains. for open source
lookalike domain monitoring, check out `DomainAware <https://github.com/seanthegeek/domainaware>`_.


CLI help
========

::

    usage: parsedmarc [-h] [--strip-attachment-payloads] [-o OUTPUT]
                      [-n NAMESERVERS [NAMESERVERS ...]] [-t TIMEOUT] [-H HOST]
                      [-u USER] [-p PASSWORD] [--imap-port IMAP_PORT]
                      [--imap-no-ssl] [-r REPORTS_FOLDER] [-a ARCHIVE_FOLDER] [-d]
                      [-E [ELASTICSEARCH_HOST [ELASTICSEARCH_HOST ...]]]
                      [--elasticsearch-index-prefix ELASTICSEARCH_INDEX_PREFIX]
                      [--elasticsearch-index-suffix ELASTICSEARCH_INDEX_SUFFIX]
                      [--hec HEC] [--hec-token HEC_TOKEN] [--hec-index HEC_INDEX]
                      [--hec-skip-certificate-verification]
                      [-K [KAFKA_HOSTS [KAFKA_HOSTS ...]]]
                      [--kafka-aggregate-topic KAFKA_AGGREGATE_TOPIC]
                      [--kafka-forensic_topic KAFKA_FORENSIC_TOPIC]
                      [--save-aggregate] [--save-forensic] [-O OUTGOING_HOST]
                      [-U OUTGOING_USER] [-P OUTGOING_PASSWORD]
                      [--outgoing-port OUTGOING_PORT]
                      [--outgoing-ssl OUTGOING_SSL] [-F OUTGOING_FROM]
                      [-T OUTGOING_TO [OUTGOING_TO ...]] [-S OUTGOING_SUBJECT]
                      [-A OUTGOING_ATTACHMENT] [-M OUTGOING_MESSAGE] [-w] [--test]
                      [-s] [--debug] [-v]
                      [file_path [file_path ...]]

    Parses DMARC reports

    positional arguments:
      file_path             one or more paths to aggregate or forensic report
                            files or emails

    optional arguments:
      -h, --help            show this help message and exit
      --strip-attachment-payloads
                            Remove attachment payloads from forensic report output
      -o OUTPUT, --output OUTPUT
                            Write output files to the given directory
      -n NAMESERVERS [NAMESERVERS ...], --nameservers NAMESERVERS [NAMESERVERS ...]
                            nameservers to query (Default is Cloudflare's
                            nameservers)
      -t TIMEOUT, --timeout TIMEOUT
                            number of seconds to wait for an answer from DNS
                            (Default: 2.0)
      -H HOST, --host HOST  IMAP hostname or IP address
      -u USER, --user USER  IMAP user
      -p PASSWORD, --password PASSWORD
                            IMAP password
      --imap-port IMAP_PORT
                            IMAP port
      --imap-no-ssl         Do not use SSL/TLS when connecting to IMAP
      -r REPORTS_FOLDER, --reports-folder REPORTS_FOLDER
                            The IMAP folder containing the reports (Default:
                            INBOX)
      -a ARCHIVE_FOLDER, --archive-folder ARCHIVE_FOLDER
                            Specifies the IMAP folder to move messages to after
                            processing them (Default: Archive)
      -d, --delete          Delete the reports after processing them
      -E [ELASTICSEARCH_HOST [ELASTICSEARCH_HOST ...]], --elasticsearch-host [ELASTICSEARCH_HOST [ELASTICSEARCH_HOST ...]]
                            One or more Elasticsearch hostnames or URLs to use
                            (e.g. localhost:9200)
      --elasticsearch-index-prefix ELASTICSEARCH_INDEX_PREFIX
                            Prefix to add in front of the dmarc_aggregate and
                            dmarc_forensic Elasticsearch index names, joined by _
      --elasticsearch-index-suffix ELASTICSEARCH_INDEX_SUFFIX
                            Append this suffix to the dmarc_aggregate and
                            dmarc_forensic Elasticsearch index names, joined by _
      --hec HEC             URL to a Splunk HTTP Event Collector (HEC)
      --hec-token HEC_TOKEN
                            The authorization token for a Splunk HTTP Event
                            Collector (HEC)
      --hec-index HEC_INDEX
                            The index to use when sending events to the Splunk
                            HTTP Event Collector (HEC)
      --hec-skip-certificate-verification
                            Skip certificate verification for Splunk HEC
      -K [KAFKA_HOSTS [KAFKA_HOSTS ...]], --kafka-hosts [KAFKA_HOSTS [KAFKA_HOSTS ...]]
                            A list of one or more Kafka hostnames or URLs
      --kafka-aggregate-topic KAFKA_AGGREGATE_TOPIC
                            The Kafka topic to publish aggregate reports to
                            (Default: dmarc_aggregate)
      --kafka-forensic_topic KAFKA_FORENSIC_TOPIC
                            The Kafka topic to publish forensic reports to
                            (Default: dmarc_forensic)
      --save-aggregate      Save aggregate reports to search indexes
      --save-forensic       Save forensic reports to search indexes
      -O OUTGOING_HOST, --outgoing-host OUTGOING_HOST
                            Email the results using this host
      -U OUTGOING_USER, --outgoing-user OUTGOING_USER
                            Email the results using this user
      -P OUTGOING_PASSWORD, --outgoing-password OUTGOING_PASSWORD
                            Email the results using this password
      --outgoing-port OUTGOING_PORT
                            Email the results using this port
      --outgoing-ssl OUTGOING_SSL
                            Use SSL/TLS instead of STARTTLS (more secure, and
                            required by some providers, like Gmail)
      -F OUTGOING_FROM, --outgoing-from OUTGOING_FROM
                            Email the results using this from address
      -T OUTGOING_TO [OUTGOING_TO ...], --outgoing-to OUTGOING_TO [OUTGOING_TO ...]
                            Email the results to these addresses
      -S OUTGOING_SUBJECT, --outgoing-subject OUTGOING_SUBJECT
                            Email the results using this subject
      -A OUTGOING_ATTACHMENT, --outgoing-attachment OUTGOING_ATTACHMENT
                            Email the results using this filename
      -M OUTGOING_MESSAGE, --outgoing-message OUTGOING_MESSAGE
                            Email the results using this message
      -w, --watch           Use an IMAP IDLE connection to process reports as they
                            arrive in the inbox
      --test                Do not move or delete IMAP messages
      -s, --silent          Only print errors and warnings
      --debug               Print debugging information
      -v, --version         show program's version number and exit

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

    xml_schema,org_name,org_email,org_extra_contact_info,report_id,begin_date,end_date,errors,domain,adkim,aspf,p,sp,pct,fo,source_ip_address,source_country,source_reverse_dns,source_base_domain,count,disposition,dkim_alignment,spf_alignment,policy_override_reasons,policy_override_comments,envelope_from,header_from,envelope_to,dkim_domains,dkim_selectors,dkim_results,spf_domains,spf_scopes,spf_results
    draft,acme.com,noreply-dmarc-support@acme.com,http://acme.com/dmarc/support,9391651994964116463,2012-04-27 20:00:00,2012-04-28 19:59:59,,example.com,r,r,none,none,100,0,72.150.241.94,US,adsl-72-150-241-94.shv.bellsouth.net,bellsouth.net,2,none,fail,pass,,,example.com,example.com,,example.com,none,fail,example.com,mfrom,pass


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
     "delivery_result": "smg-policy-action",
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
    auth-failure,Lua/1.0,1.0,,sharepoint@domain.de,peter.pan@domain.de,"Mon, 01 Oct 2018 11:20:27 +0200",2018-10-01 09:20:27,Subject,<38.E7.30937.BD6E1BB5@ mailrelay.de>,"dmarc=fail (p=none, dis=none) header.from=domain.de",,10.10.10.10,,,,smg-policy-action,dmarc,domain.de,,False


Documentation
=============

https://domainaware.github.io/parsedmarc

Bug reports
===========

Please report bugs on the GitHub issue tracker

https://github.com/domainaware/parsedmarc/issues

.. |Build Status| image:: https://travis-ci.org/domainaware/parsedmarc.svg?branch=master
   :target: https://travis-ci.org/domainaware/parsedmarc

.. _Demystifying DMARC: https://seanthegeek.net/459/demystifying-dmarc/
