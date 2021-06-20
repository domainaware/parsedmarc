.. parsedmarc documentation master file, created by
   sphinx-quickstart on Mon Feb  5 18:25:39 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

===========================================================================
parsedmarc documentation - Open source DMARC report analyzer and visualizer
===========================================================================

|Build Status| |Code Coverage| |PyPI Package|

.. image:: _static/screenshots/dmarc-summary-charts.png
   :alt: A screenshot of DMARC summary charts in Kibana
   :scale: 50 %
   :align: center
   :target: _static/screenshots/dmarc-summary-charts.png

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

DMARC protects against domain spoofing, not lookalike domains. for open source
lookalike domain monitoring, check out `DomainAware <https://github.com/seanthegeek/domainaware>`_.


CLI help
========

::

   usage: parsedmarc [-h] [-c CONFIG_FILE] [--strip-attachment-payloads] [-o OUTPUT]
                      [--aggregate-json-filename AGGREGATE_JSON_FILENAME]
                      [--forensic-json-filename FORENSIC_JSON_FILENAME]
                      [--aggregate-csv-filename AGGREGATE_CSV_FILENAME]
                      [--forensic-csv-filename FORENSIC_CSV_FILENAME]
                      [-n NAMESERVERS [NAMESERVERS ...]] [-t DNS_TIMEOUT] [--offline]
                      [-s] [--verbose] [--debug] [--log-file LOG_FILE] [-v]
                      [file_path ...]

    Parses DMARC reports

    positional arguments:
      file_path             one or more paths to aggregate or forensic report
                            files, emails, or mbox files'

    optional arguments:
      -h, --help            show this help message and exit
      -c CONFIG_FILE, --config-file CONFIG_FILE
                            a path to a configuration file (--silent implied)
      --strip-attachment-payloads
                            remove attachment payloads from forensic report output
      -o OUTPUT, --output OUTPUT
                            write output files to the given directory
      --aggregate-json-filename AGGREGATE_JSON_FILENAME
                            filename for the aggregate JSON output file
      --forensic-json-filename FORENSIC_JSON_FILENAME
                            filename for the forensic JSON output file
      --aggregate-csv-filename AGGREGATE_CSV_FILENAME
                            filename for the aggregate CSV output file
      --forensic-csv-filename FORENSIC_CSV_FILENAME
                            filename for the forensic CSV output file
      -n NAMESERVERS [NAMESERVERS ...], --nameservers NAMESERVERS [NAMESERVERS ...]
                            nameservers to query
      -t DNS_TIMEOUT, --dns_timeout DNS_TIMEOUT
                            number of seconds to wait for an answer from DNS
                            (default: 2.0)
      --offline             do not make online queries for geolocation or DNS
      -s, --silent          only print errors and warnings
      --verbose             more verbose output
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

   [s3]
   bucket = my-bucket
   path = parsedmarc

The full set of configuration options are:

- ``general``
    - ``save_aggregate`` - bool: Save aggregate report data to Elasticsearch, Splunk and/or S3
    - ``save_forensic`` - bool: Save forensic report data to Elasticsearch, Splunk and/or S3
    - ``strip_attachment_payloads`` - bool: Remove attachment payloads from results
    - ``output`` - str: Directory to place JSON and CSV files in
    - ``aggregate_json_filename`` - str: filename for the aggregate JSON output file
    - ``forensic_json_filename`` - str: filename for the forensic JSON output file
    - ``offline`` - bool: Do not use online queries for geolocation or DNS
    - ``nameservers`` -  str: A comma separated list of DNS resolvers (Default: `Cloudflare's public resolvers`_)
    - ``dns_timeout`` - float: DNS timeout period
    - ``debug`` - bool: Print debugging messages
    - ``silent`` - bool: Only print errors (Default: True)
    - ``log_file`` - str: Write log messages to a file at this path
    - ``n_procs`` - int: Number of process to run in parallel when parsing in CLI mode (Default: 1)
    - ``chunk_size`` - int: Number of files to give to each process when running in parallel.

    .. note::
        Setting this to a number larger than one can improve performance when processing thousands of files
- ``imap``

    - ``host`` - str: The IMAP server hostname or IP address
    - ``port`` - int: The IMAP server port (Default: 993).

    .. note::
        If your host recommends another port, still try 993

    - ``ssl`` - bool: Use an encrypted SSL/TLS connection (Default: True)
    - ``skip_certificate_verification`` - bool: Skip certificate verification (not recommended)
    - ``user`` - str: The IMAP user
    - ``password`` - str: The IMAP password
    - ``reports_folder`` - str: The IMAP folder where the incoming reports can be found (Default: INBOX)
    - ``archive_folder`` - str:  The IMAP folder to sort processed emails into (Default: Archive)
    - ``watch`` - bool: Use the IMAP ``IDLE`` command to process messages as they arrive
    - ``delete`` - bool: Delete messages after processing them, instead of archiving them
    - ``test`` - bool: Do not move or delete messages
    - ``batch_size`` - int: Number of messages to read and process before saving. Defaults to all messages if not set.
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
- ``s3``
    - ``bucket`` - str: The S3 bucket name
    - ``path`` - int: The path to upload reports to (Default: /)

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

Installation
============

``parsedmarc`` works with Python 3 only.

.. note::

   If your system is behind a web proxy, you neeed to configure your system
   to use that proxy. To do this, edit ``/etc/environment`` and add your
   proxy details there, for example:

   ::

      http_proxy=http://user:password@prox-server:3128
      https_proxy=https://user:password@prox-server:3128
      ftp_proxy=http://user:password@prox-server:3128

   Or if no credentials are needed:

   ::

      http_proxy=http://prox-server:3128
      https_proxy=https://prox-server:3128
      ftp_proxy=http://prox-server:3128

   This will set the the proxy up for use system-wide, including for
   ``parsedmarc``.

.. warning::

   If your mail server is Microsoft Exchange, ensure that it is patched to at
   least:

   - Exchange Server 2010 Update Rollup 22 (`KB4295699 <https://support.microsoft.com/KB/4295699>`_)
   - Exchange Server 2013 Cumulative Update 21 (`KB4099855 <https://support.microsoft.com/KB/4099855>`_)
   - Exchange Server 2016 Cumulative Update 11 (`KB4134118 <https://support.microsoft.com/kb/4134118>`_)


geoipupdate setup
-----------------

On Debian 10 (Buster) or later, run:

.. code-block:: bash

    sudo apt-get install -y geoipupdate

On Ubuntu systems run:

.. code-block:: bash

   sudo add-apt-repository ppa:maxmind/ppa
   sudo apt update
   sudo apt install -y geoipupdate

On CentOS or RHEL systems, run:

.. code-block:: bash

   sudo yum install -y geoipupdate

The latest builds for Linux, macOS, and Windows can be downloaded from the `geoipupdate releases page on GitHub`_.

On December 30th, 2019, MaxMind started requiring free accounts to access the free Geolite2 databases, in order `to
comply with various privacy regulations`_.

Start by `registering for a free GeoLite2 account`_, and signing in.

Then, navigate the to the `License Keys`_ page under your account, and create a new license key for the version of
``geoipupdate`` that was installed.

.. warning::

   The configuration file format is different for older (i.e. <=3.1.1) and newer (i.e. >=3.1.1) versions
   of ``geoipupdate``. Be sure to select the correct version for your system.

.. note::

   To check the version of ``geoipupdate`` that is installed, run:

   .. code-block:: bash

      geoipupdate -V

You can use ``parsedmarc`` as the description for the key.

Once you have generated a key, download the config pre-filled configuration file.
This file should be saved at ``/etc/GeoIP.conf`` on Linux or macOS systems, or at
``%SystemDrive%\ProgramData\MaxMind\GeoIPUpdate\GeoIP.conf`` on Windows systems.

Then run

.. code-block:: bash

   sudo geoipupdate

To download the databases for the first time.

The GeoLite2 Country, City, and ASN databases are updated weekly, every Tuesday.
``geoipupdate`` can be run weekly by adding a cron job or scheduled task.

More information about ``geoipupdate`` can be found at the `MaxMind geoipupdate page`_.

Installing parsedmarc
---------------------

On Debian or Ubuntu systems, run:

.. code-block:: bash

    sudo apt-get install -y python3-pip


On CentOS or RHEL systems, run:

.. code-block:: bash

   sudo yum install -y python34-setuptools python34-devel
   sudo easy_install-3.4 pip


Python 3 installers for Windows and macOS can be found at
https://www.python.org/downloads/

.. code-block:: bash

    sudo -H pip3 install -U parsedmarc

Or, install the latest development release directly from GitHub:

.. code-block:: bash

    sudo -H pip3 install -U git+https://github.com/domainaware/parsedmarc.git

.. note::

    On Windows, ``pip3`` is ``pip``, even with Python 3. So on Windows,
    substitute ``pip`` as an administrator in place of ``sudo pip3``, in the
    above commands.


Installation using pypy3
------------------------

For the best possible processing speed, consider using ``parsedmarc`` inside a ``pypy3``
virtualenv. First, `download the latest portable Linux version of pypy3`_. Extract it to
``/opt/pypy3`` (``sudo mkdir /opt`` if ``/opt`` does not exist), then create a
symlink:


.. code-block:: bash

    wget https://bitbucket.org/squeaky/portable-pypy/downloads/pypy3.5-7.0.0-linux_x86_64-portable.tar.bz2
    tar -jxf pypy3.5-7.0.0-linux_x86_64-portable.tar.bz2
    rm pypy3.5-6.0.0-linux_x86_64-portable.tar.bz2
    sudo chown -R root:root pypy3.5-7.0.0-linux_x86_64-portable
    sudo mv pypy3.5-7.0.0-linux_x86_64-portable /opt/pypy3
    sudo ln -s /opt/pypy3/bin/pypy3 /usr/local/bin/pypy3

Install ``virtualenv`` on your system:

.. code-block:: bash

    sudo apt-get install python3-pip
    sudo -H pip3 install -U virtualenv

Uninstall any instance of ``parsedmarc`` that you may have installed globally

.. code-block:: bash

    sudo -H pip3 uninstall -y parsedmarc

Next, create a ``pypy3`` virtualenv for parsedmarc


.. code-block:: bash

    sudo mkdir /opt/venvs
    cd /opt/venvs
    sudo -H pip3 install -U virtualenv
    sudo virtualenv --download -p /usr/local/bin/pypy3 parsedmarc
    sudo -H /opt/venvs/parsedmarc/bin/pip3 install -U parsedmarc
    sudo ln -s /opt/venvs/parsedmarc/bin/parsedmarc /usr/local/bin/parsedmarc

To upgrade ``parsedmarc`` inside the virtualenv, run:


.. code-block:: bash

    sudo -H /opt/venvs/parsedmarc/bin/pip3 install -U parsedmarc

Or, install the latest development release directly from GitHub:

.. code-block:: bash

    sudo -H /opt/venvs/parsedmarc/bin/pip3 install -U git+https://github.com/domainaware/parsedmarc.git

Optional dependencies
---------------------

If you would like to be able to parse emails saved from Microsoft Outlook
(i.e. OLE .msg files), install ``msgconvert``:

On Debian or Ubuntu systems, run:

.. code-block:: bash

    sudo apt-get install libemail-outlook-message-perl

Testing multiple report analyzers
---------------------------------

If you would like to test parsedmarc and another report processing solution
at the same time, you can have up to two mailto URIs each in the rua and ruf
tags in your DMARC record, separated by commas.

Accessing an inbox using OWA/EWS
--------------------------------

Some organisations do not allow IMAP, and only support Exchange Web Services
(EWS)/Outlook Web Access (OWA). In that case, Davmail will need to be set up
as a local EWS/OWA IMAP gateway. It can even work where
`Modern Auth/multi-factor authentication`_ is required.

To do this, download the latest ``davmail-version.zip`` from
https://sourceforge.net/projects/davmail/files/

Extract the zip using the ``unzip`` command.

Install Java:

.. code-block:: bash

    sudo apt-get install default-jre-headless

Configure Davmail by creating a ``davmail.properties`` file

.. code-block:: properties

   # DavMail settings, see http://davmail.sourceforge.net/ for documentation

   #############################################################
   # Basic settings

   # Server or workstation mode
   davmail.server=true

   # connection mode auto, EWS or WebDav
   davmail.enableEws=auto

   # base Exchange OWA or EWS url
   davmail.url=https://outlook.office365.com/EWS/Exchange.asmx

   # Listener ports
   davmail.imapPort=1143

   #############################################################
   # Network settings

   # Network proxy settings
   davmail.enableProxy=false
   davmail.useSystemProxies=false
   davmail.proxyHost=
   davmail.proxyPort=
   davmail.proxyUser=
   davmail.proxyPassword=

   # proxy exclude list
   davmail.noProxyFor=

   # block remote connection to DavMail
   davmail.allowRemote=false

   # bind server sockets to the loopback address
   davmail.bindAddress=127.0.0.1

   # disable SSL for specified listeners
   davmail.ssl.nosecureimap=true

   # Send keepalive character during large folder and messages download
   davmail.enableKeepalive=true

   # Message count limit on folder retrieval
   davmail.folderSizeLimit=0

   #############################################################
   # IMAP settings

   # Delete messages immediately on IMAP STORE \Deleted flag
   davmail.imapAutoExpunge=true

   # Enable IDLE support, set polling delay in minutes
   davmail.imapIdleDelay=1

   # Always reply to IMAP RFC822.SIZE requests with Exchange approximate
   # message size for performance reasons
   davmail.imapAlwaysApproxMsgSize=true

   # Client connection timeout in seconds - default 300, 0 to disable
   davmail.clientSoTimeout=0

   #############################################################


Running DavMail as a systemd service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use systemd to run ``davmail`` as a service.


Create a system user

.. code-block:: bash

    sudo useradd davmail -r -s /bin/false

Protect the ``davmail`` configuration file from prying eyes

.. code-block:: bash

    sudo chown root:davmail /opt/davmail/davmail.properties
    sudo chmod u=rw,g=r,o= /opt/davmail/davmail.properties

Create the service configuration file

.. code-block:: bash

    sudo nano /etc/systemd/system/davmail.service

.. code-block:: ini

    [Unit]
    Description=DavMail gateway service
    Documentation=https://sourceforge.net/projects/davmail/
    Wants=network-online.target
    After=syslog.target network.target

    [Service]
    ExecStart=/opt/davmail/davmail /opt/davmail/davmail.properties
    User=davmail
    Group=davmail
    Restart=always
    RestartSec=5m

    [Install]
    WantedBy=multi-user.target

Then, enable the service

.. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl enable parsedmarc.service
    sudo service davmail restart

.. note::

  You must also run the above commands whenever you edit
  ``davmail.service``.

.. warning::

  Always restart the service every time you upgrade to a new version of
  ``davmail``:

  .. code-block:: bash

   sudo service davmail restart

To check the status of the service, run:

.. code-block:: bash

    service davmail status

.. note::

   In the event of a crash, systemd will restart the service after 5 minutes,
   but the `service davmail status` command will only show the logs for the
   current process. To vew the logs for previous runs as well as the
   current process (newest to oldest), run:

   .. code-block:: bash

       journalctl -u davmail.service -r


Configuring parsedmarc for DavMail
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Because you are interacting with DavMail server over the loopback
(i.e. ``127.0.0.1``), add the following options to ``parsedmarc.ini``
config file:

.. code-block:: ini

   [imap]
   host=127.0.0.1
   port=1143
   ssl=False
   watch=True

Elasticsearch and Kibana
------------------------

.. note::

   Splunk is also supported starting with ``parsedmarc`` 4.3.0


To set up visual dashboards of DMARC data, install Elasticsearch and Kibana.

.. note::

    Elasticsearch and Kibana 6 or later are required

On Debian/Ubuntu based systems, run:

.. code-block:: bash

    sudo apt-get install -y apt-transport-https
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
    sudo apt-get update
    sudo apt-get install -y default-jre-headless elasticsearch kibana

For CentOS, RHEL, and other RPM systems, follow the Elastic RPM guides for
`Elasticsearch`_ and `Kibana`_.

.. warning::

   The default JVM heap size for Elasticsearch is very small (1g), which will
   cause it to crash under a heavy load. To fix this, increase the minimum and
   maximum JVM heap sizes in ``/etc/elasticsearch/jvm.options`` to more
   reasonable levels, depending on your server's resources.

   Make sure the system has at least 2 GB more RAM then the assigned JVM
   heap size.

   Always set the minimum and maximum JVM heap sizes to the same
   value.

   For example, to set a 4 GB heap size, set

   .. code-block:: bash

      -Xms4g
      -Xmx4g

   See https://www.elastic.co/guide/en/elasticsearch/reference/current/heap-size.html
   for more information.

.. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl enable elasticsearch.service
    sudo systemctl enable kibana.service
    sudo service elasticsearch start
    sudo service kibana start

Without the commercial X-Pack_ or ReadonlyREST_ products, Kibana does not have any authentication
mechanism of its own. You can use nginx as a reverse proxy that provides basic
authentication.

.. code-block:: bash

    sudo apt-get install -y nginx apache2-utils

Or, on CentOS:

.. code-block:: bash

   sudo yum install -y nginx httpd-tools

Create a directory to store the certificates and keys:

.. code-block:: bash

    mkdir ~/ssl
    cd ~/ssl

To create a self-signed certificate, run:

.. code-block:: bash

    openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout kibana.key -out kibana.crt

Or, to create a Certificate Signing Request (CSR) for a CA, run:

.. code-block:: bash

    openssl req -newkey rsa:4096-nodes -keyout kibana.key -out kibana.csr

Fill in the prompts. Watch out for Common Name (e.g. server FQDN or YOUR
domain name), which is the IP address or domain name that you will be hosting
Kibana on. it is the most important field.

If you generated a CSR, remove the CSR after you have your certs

.. code-block:: bash

    rm -f kibana.csr


Move the keys into place and secure them:

.. code-block:: bash

    cd
    sudo mv ssl /etc/nginx
    sudo chown -R root:www-data /etc/nginx/ssl
    sudo chmod -R u=rX,g=rX,o= /etc/nginx/ssl

Disable the default nginx configuration:

.. code-block:: bash

    sudo rm /etc/nginx/sites-enabled/default

Create the web server configuration

.. code-block:: bash

    sudo nano /etc/nginx/sites-available/kibana

.. code-block:: nginx

   server {
       listen 443 ssl http2;
       ssl_certificate /etc/nginx/ssl/kibana.crt;
       ssl_certificate_key /etc/nginx/ssl/kibana.key;
       ssl_session_timeout 1d;
       ssl_session_cache shared:SSL:50m;
       ssl_session_tickets off;


       # modern configuration. tweak to your needs.
       ssl_protocols TLSv1.2;
       ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
       ssl_prefer_server_ciphers on;

       # Uncomment this next line if you are using a signed, trusted cert
       #add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
       add_header X-Frame-Options SAMEORIGIN;
       add_header X-Content-Type-Options nosniff;
       auth_basic "Login required";
       auth_basic_user_file /etc/nginx/htpasswd;

       location / {
           proxy_pass http://127.0.0.1:5601;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }

   server {
       listen 80;
       return 301 https://$host$request_uri;
   }


Enable the nginx configuration for Kibana:

.. code-block:: bash

    sudo ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/kibana

Add a user to basic authentication:

.. code-block:: bash

    sudo htpasswd -c /etc/nginx/htpasswd exampleuser

Where ``exampleuser`` is the name of the user you want to add.

Secure the permissions of the httpasswd file:

.. code-block:: bash

    sudo chown root:www-data /etc/nginx/htpasswd
    sudo chmod u=rw,g=r,o= /etc/nginx/htpasswd

Restart nginx:

.. code-block:: bash

    sudo service nginx restart

Now that Elasticsearch is up and running, use ``parsedmarc`` to send data to
it.


Download (right click the link and click save as) export.ndjson_.

Import ``export.ndjson`` the Saved Objects tab of the Stack management
page of Kibana.

It will give you the option to overwrite existing saved dashboards or
visualizations, which could be used to restore them if you or someone else
breaks them, as there are no permissions/access controls in Kibana without
the commercial X-Pack_.

.. image:: _static/screenshots/saved-objects.png
   :alt: A screenshot of setting the Saved Objects Stack management UI in Kibana
   :align: center
   :target: _static/screenshots/saved-objects.png

.. image:: _static/screenshots/confirm-overwrite.png
   :alt: A screenshot of the overwrite conformation prompt
   :align: center
   :target: _static/screenshots/confirm-overwrite.png

Upgrading Kibana index patterns
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``parsedmarc`` 5.0.0 makes some changes to the way data is indexed in
Elasticsearch. if you are upgrading from a previous release of
``parsedmarc``, you need to complete the following steps to replace the
Kibana index patterns with versions that match the upgraded indexes:

1. Login in to Kibana, and click on Management
2. Under Kibana, click on Saved Objects
3. Check the checkboxes for the ``dmarc_aggregate`` and ``dmarc_forensic``
   index patterns
4. Click Delete
5. Click Delete on the conformation message
6. Download (right click the link and click save as)
   the latest version of export.ndjson_
7. Import ``export.ndjson`` by clicking Import from the Kibana
   Saved Objects page


Records retention
~~~~~~~~~~~~~~~~~

Starting in version 5.0.0, ``parsedmarc`` stores data in a separate
index for each day to make it easy to comply with records
retention regulations such as GDPR. For fore information,
check out the Elastic guide to `managing time-based indexes efficiently
<https://www.elastic.co/blog/managing-time-based-indices-efficiently>`_.

Splunk
------

Starting in version 4.3.0 ``parsedmarc`` supports sending aggregate and/or
forensic DMARC data to a Splunk `HTTP Event collector (HEC)`_.


The project repository contains `XML files`_ for premade Splunk dashboards for
aggregate and forensic DMARC reports.

Copy and paste the contents of each file into a separate Splunk dashboard XML
editor.

.. warning::

   Change all occurrences of ``index="email"`` in the XML to
   match your own index name.

The Splunk dashboards display the same content and layout as the Kibana
dashboards, although the Kibana dashboards have slightly easier and more
flexible filtering options.

Running parsedmarc as a systemd service
---------------------------------------

Use systemd to run ``parsedmarc`` as a service and process reports as they
arrive.


Create a system user

.. code-block:: bash

    sudo useradd parsedmarc -r -s /bin/false

Protect the ``parsedmarc`` configuration file from prying eyes

.. code-block:: bash

    sudo chown root:parsedmarc /etc/parsedmarc.ini
    sudo chmod u=rw,g=r,o= /etc/parsedmarc.ini

Create the service configuration file

.. code-block:: bash

    sudo nano /etc/systemd/system/parsedmarc.service

.. code-block:: ini

    [Unit]
    Description=parsedmarc mailbox watcher
    Documentation=https://domainaware.github.io/parsedmarc/
    Wants=network-online.target
    After=network.target network-online.target elasticsearch.service

    [Service]
    ExecStart=/usr/local/bin/parsedmarc -c /etc/parsedmarc.ini
    User=parsedmarc
    Group=parsedmarc
    Restart=always
    RestartSec=5m

    [Install]
    WantedBy=multi-user.target

Then, enable the service

.. code-block:: bash

    sudo systemctl daemon-reload
    sudo systemctl enable parsedmarc.service
    sudo service parsedmarc restart

.. note::

    You must also run the above commands whenever you edit
    ``parsedmarc.service``.

.. warning::

  Always restart the service every time you upgrade to a new version of
  ``parsedmarc``:

  .. code-block:: bash

   sudo service parsedmarc restart

To check the status of the service, run:

.. code-block:: bash

    service parsedmarc status

.. note::

   In the event of a crash, systemd will restart the service after 10 minutes,
   but the `service parsedmarc status` command will only show the logs for the
   current process. To vew the logs for previous runs as well as the
   current process (newest to oldest), run:

   .. code-block:: bash

       journalctl -u parsedmarc.service -r


Using the Kibana dashboards
===========================

The Kibana DMARC dashboards are a human-friendly way to understand the results
from incoming DMARC reports.

.. note::

    The default dashboard is DMARC Summary. To switch between dashboards,
    click on the Dashboard link in the left side menu of Kibana.


DMARC Summary
-------------

As the name suggests, this dashboard is the best place to start reviewing your
aggregate DMARC data.

Across the top of the dashboard, three pie charts display the percentage of
alignment pass/fail for SPF, DKIM, and DMARC. Clicking on any chart segment
will filter for that value.

.. note::

    Messages should not be considered malicious just because they failed to pass
    DMARC; especially if you have just started collecting data. It may be a
    legitimate service that needs SPF and DKIM configured correctly.

Start by filtering the results to only show failed DKIM alignment. While DMARC
passes if a message passes SPF or DKIM alignment, only DKIM alignment remains
valid when a message is forwarded without changing the from address, which is
often caused by a mailbox forwarding rule. This is because DKIM signatures are
part of the message headers, whereas SPF relies on SMTP session headers.

Underneath the pie charts. you can see graphs of DMARC passage and message
disposition over time.

Under the graphs you will find the most useful data tables on the dashboard. On
the left, there is a list of organizations that are sending you DMARC reports.
In the center, there is a list of sending servers grouped by the base domain
in their reverse DNS. On the right, there is a list of email from domains,
sorted by message volume.

By hovering your mouse over a data table value and using the magnifying glass
icons, you can filter on our filter out different values. Start by looking at
the Message Sources by Reverse DNS table. Find a sender that you recognize,
such as an email marketing service, hover over it, and click on the plus (+)
magnifying glass icon, to add a filter that only shows results for that sender.
Now, look at the Message From Header table to the right. That shows you the
domains that a sender is sending as, which might tell you which brand/business
is using a particular service. With that information, you can contact them and
have them set up DKIM.

.. note::
  
    If you have a lot of B2C customers, you may see a high volume of emails as
    your domains coming from consumer email services, such as Google/Gmail and
    Yahoo! This occurs when customers have mailbox rules in place that forward
    emails from an old account to a new account, which is why DKIM
    authentication is so important, as mentioned earlier. Similar patterns may
    be observed with businesses who send from reverse DNS addressees of
    parent, subsidiary, and outdated brands.


Further down the dashboard, you can filter by source country or source IP
address.

Tables showing SPF and DKIM alignment details are located under the IP address
table.

.. note::

    Previously, the alignment tables were included in a separate dashboard
    called DMARC Alignment Failures. That dashboard has been consolidated into
    the DMARC Summary dashboard. To view failures only, use the pie chart.

Any other filters work the same way. You can also add your own custom temporary
filters by clicking on Add Filter at the upper right of the page.

DMARC Forensic Samples
----------------------

The DMARC Forensic Samples dashboard contains information on DMARC forensic
reports (also known as failure reports or ruf reports). These reports contain
samples of emails that have failed to pass DMARC.

.. note::

    Most recipients do not send forensic/failure/ruf reports at all to avoid
    privacy leaks. Some recipients (notably Chinese webmail services) will only
    supply the headers of sample emails. Very few provide the entire email.


DMARC Alignment Guide
=====================

DMARC ensures that SPF and DKM authentication mechanisms actually authenticate
against the same domain that the end user sees.

A message passes a DMARC check by passing DKIM or SPF, **as long as the related
indicators are also in alignment**.

+-----------------------+-----------------------+-----------------------+
|                       | **DKIM**              | **SPF**               |
+-----------------------+-----------------------+-----------------------+
| **Passing**           | The signature in the  | The mail server's IP  |
|                       | DKIM header is        | address is listed in  |
|                       | validated using a     | the SPF record of the |
|                       | public key that is    | domain in the SMTP    |
|                       | published as a DNS    | envelope's mail from  |
|                       | record of the domain  | header                |
|                       | name specified in the |                       |
|                       | signature             |                       |
+-----------------------+-----------------------+-----------------------+
| **Alignment**         | The signing domain    | The domain in the     |
|                       | aligns with the       | SMTP envelope's mail  |
|                       | domain in the         | from header aligns    |
|                       | message's from header | with the domain in    |
|                       |                       | the message's from    |
|                       |                       | header                |
+-----------------------+-----------------------+-----------------------+


What if a sender won't support DKIM/DMARC?
==========================================

#. Some vendors don't know about DMARC yet; ask about SPF and DKIM/email
   authentication.
#. Check if they can send through your email relays instead of theirs.
#. Do they really need to spoof your domain? Why not use the display
   name instead?
#. Worst case, have that vendor send email as a specific subdomain of
   your domain (e.g. ``noreply@news.example.com``), and then create
   separate SPF and DMARC records on ``news.example.com``, and set
   ``p=none`` in that DMARC record.

.. warning ::

  Do not alter the ``p`` or ``sp`` values of the DMARC record on the
  Top-Level Domain (TLD) – that would leave you vulnerable to spoofing of
  your TLD and/or any subdomain.

What about mailing lists?
=========================

When you deploy DMARC on your domain, you might find that messages relayed by
mailing lists are failing DMARC, most likely because the mailing list is
spoofing your from address, and modifying the subject, footer, or other part
of the message, thereby breaking the DKIM signature.

Mailing list list best practices
--------------------------------

Ideally, a mailing list should forward messages without altering the headers
or body content at all. `Joe Nelson`_ does a fantastic job of explaining exactly
what mailing lists should and shouldn't do to be fully DMARC compliant.
Rather than repeat his fine work, here's a summary:

**Do**

- Retain headers from the original message
- Add `RFC 2369`_ List-Unsubscribe headers to outgoing messages, instead of
  adding unsubscribe links to the body

   ::

    List-Unsubscribe: <https://list.example.com/unsubscribe-link>

- Add `RFC 2919`_ List-Id headers instead of modifying the subject

   ::

    List-Id: Example Mailing List <list.example.com>

Modern mail clients and webmail services generate unsubscribe buttons based on
these headers.

**Do not**

* Remove or modify any existing headers from the original message, including
  From, Date, Subject, etc.
* Add to or remove content from the message body, **including traditional
  disclaimers and unsubscribe footers**

In addition to complying with DMARC, this configuration ensures that Reply
and Reply All actions work like they would with any email message. Reply
replies to the message sender, and Reply All replies to the sender and the
list.

Even without a subject prefix or body footer, mailing list users can still
tell that a message came from the mailing list, because the message was sent
to the mailing list post address, and not their email address.

Configuration steps for common mailing list platforms are listed below.

Mailman 2
~~~~~~~~~

Navigate to General Settings, and configure the settings below

============================ ==========
**Setting**                  **Value**
**subject_prefix**
**from_is_list**             No
**first_strip_reply_to**     No
**reply_goes_to_list**       Poster
**include_rfc2369_headers**  Yes
**include_list_post_header** Yes
**include_sender_header**    No
============================ ==========

Navigate to Non-digest options, and configure the settings below

=================== ==========
**Setting**         **Value**
**msg_header**
**msg_footer**
**scrub_nondigest**  No
=================== ==========


Navigate to Privacy Options> Sending Filters, and configure the settings below

====================================== ==========
**Setting**                            **Value**
**dmarc_moderation_action**            Accept
**dmarc_quarentine_moderation_action** Yes
**dmarc_none_moderation_action**       Yes
====================================== ==========


Mailman 3
~~~~~~~~~

Navigate to Settings> List Identity

Make Subject prefix blank.

Navigate to Settings> Alter Messages

Configure the settings below

====================================== ==========
**Setting**                            **Value**
**Convert html to plaintext**          No
**Include RFC2369 headers**            Yes
**Include the list post header**       Yes
**Explicit reply-to address**
**First strip replyo**                 No
**Reply goes to list**                 No munging
====================================== ==========

Navigate to Settings> DMARC Mitigation

Configure the settings below

================================== ===============================
**Setting**	                       **Value**
**DMARC mitigation action**	       No DMARC mitigations
**DMARC mitigate unconditionally** No
================================== ===============================

Create a blank footer template for your mailing list to remove the message
footer. Unfortunately, the Postorius mailing list admin UI will not allow you
to create an empty template, so you'll have to create one using the system's
command line instead, for example:

.. code-block:: bash

   touch var/templates/lists/list.example.com/en/list:member:regular:footer

Where ``list.example.com`` the list ID, and ``en`` is the language.

Then restart mailman core.

Workarounds
-----------

If a mailing list must go **against** best practices and
modify the message (e.g. to add a required legal footer), the mailing
list administrator must configure the list to replace the From address of the
message (also known as munging) with the address of the mailing list, so they
no longer spoof email addresses with domains protected by DMARC.

Configuration steps for common mailing list platforms are listed below.

Mailman 2
~~~~~~~~~

Navigate to Privacy Options> Sending Filters, and configure the settings below

====================================== ==========
**Setting**                            **Value**
**dmarc_moderation_action**            Munge From
**dmarc_quarentine_moderation_action** Yes
**dmarc_none_moderation_action**       Yes
====================================== ==========

.. note::

  Message wrapping could be used as the DMARC mitigation action instead. In
  that case, the original message is added as an attachment to the mailing
  list message, but that could interfere with inbox searching, or mobile
  clients.

  On the other hand, replacing the From address might cause users to
  accidentally reply to the entire list, when they only intended to reply to
  the original sender.

  Choose the option that best fits your community.

Mailman 3
~~~~~~~~~

In the DMARC Mitigations tab of the Settings page, configure the settings below

================================== ===============================
**Setting**	                       **Value**
**DMARC mitigation action**	       Replace From: with list address
**DMARC mitigate unconditionally** No
================================== ===============================

.. note::

  Message wrapping could be used as the DMARC mitigation action instead. In
  that case, the original message is added as an attachment to the mailing
  list message, but that could interfere with inbox searching, or mobile
  clients.

  On the other hand, replacing the From address might cause users to
  accidentally reply to the entire list, when they only intended to reply to
  the original sender.



LISTSERV
~~~~~~~~

`LISTSERV 16.0-2017a`_ and higher will rewrite the From header for domains
that enforce with a DMARC quarantine or reject policy.

Some additional steps are needed for Linux hosts.

API
===

.. automodule:: parsedmarc
   :members:

parsedmarc.elastic
------------------

.. automodule:: parsedmarc.elastic
   :members:

.. toctree::
   :maxdepth: 2
   :caption: Contents:

parsedmarc.splunk
-----------------

.. automodule:: parsedmarc.splunk
   :members:

.. toctree::
   :maxdepth: 2
   :caption: Contents:

parsedmarc.utils
----------------

.. automodule:: parsedmarc.utils
   :members:

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. |Build Status| image:: https://travis-ci.org/domainaware/parsedmarc.svg?branch=master
   :target: https://travis-ci.org/domainaware/parsedmarc

.. |Code Coverage| image:: https://codecov.io/gh/domainaware/parsedmarc/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/domainaware/parsedmarc

..  |PyPI Package| image:: https://img.shields.io/pypi/v/parsedmarc.svg
    :target: https://pypi.org/project/parsedmarc/

.. _Demystifying DMARC: https://seanthegeek.net/459/demystifying-dmarc/

.. _Cloudflare's public resolvers: https://1.1.1.1/

.. _URL encoded: https://en.wikipedia.org/wiki/Percent-encoding#Percent-encoding_reserved_characters

.. _Modern Auth/multi-factor authentication: http://davmail.sourceforge.net/faq.html

.. _to comply with various privacy regulations: https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/

.. _registering for a free GeoLite2 account: https://www.maxmind.com/en/geolite2/signup

.. _License Keys: https://www.maxmind.com/en/accounts/current/license-key

.. _MaxMind geoipupdate page: https://dev.maxmind.com/geoip/geoipupdate/

.. _geoipupdate releases page on GitHub: https://github.com/maxmind/geoipupdate/releases

.. _download the latest portable Linux version of pypy3: https://github.com/squeaky-pl/portable-pypy#portable-pypy-distribution-for-linux

.. _Elasticsearch: https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html

.. _Kibana: https://www.elastic.co/guide/en/kibana/current/rpm.html

.. _X-Pack: https://www.elastic.co/products/x-pack

.. _ReadonlyREST: https://readonlyrest.com/

.. _export.ndjson: https://raw.githubusercontent.com/domainaware/parsedmarc/master/kibana/export.ndjson

.. _HTTP Event collector (HEC): http://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHEC

.. _XML files: https://github.com/domainaware/parsedmarc/tree/master/splunk

.. _Joe Nelson: https://begriffs.com/posts/2018-09-18-dmarc-mailing-list.html

.. _RFC 2369: https://tools.ietf.org/html/rfc2369

.. _RFC 2919: https://tools.ietf.org/html/rfc2919

.. _LISTSERV 16.0-2017a: https://www.lsoft.com/news/dmarc-issue1-2018.asp
