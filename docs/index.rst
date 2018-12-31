.. parsedmarc documentation master file, created by
   sphinx-quickstart on Mon Feb  5 18:25:39 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

===========================================================================
parsedmarc documentation - Open source DMARC report analyzer and visualizer
===========================================================================

|Build Status|

.. image:: _static/screenshots/dmarc-summary-charts.png
   :alt: A screenshot of DMARC summary charts in Kibana
   :scale: 50 %
   :align: center
   :target: _static/screenshots/dmarc-summary-charts.png

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

   usage: parsedmarc [-h] [--strip-attachment-payloads] [-o OUTPUT]
                     [-n NAMESERVERS [NAMESERVERS ...]] [-t TIMEOUT] [-H HOST]
                     [-u USER] [-p PASSWORD] [--imap-port IMAP_PORT]
                     [--imap-skip-certificate-verification] [--imap-no-ssl]
                     [-r REPORTS_FOLDER] [-a ARCHIVE_FOLDER] [-d]
                     [-E [ELASTICSEARCH_HOST [ELASTICSEARCH_HOST ...]]]
                     [--elasticsearch-index-suffix ELASTICSEARCH_INDEX_SUFFIX]
                     [--hec HEC] [--hec-token HEC_TOKEN] [--hec-index HEC_INDEX]
                     [--hec-skip-certificate-verification]
                     [-K [KAFKA_HOSTS [KAFKA_HOSTS ...]]]
                     [--kafka-username KAFKA_USERNAME]
                     [--kafka-password KAFKA_PASSWORD] [--kafka-use-ssl]
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
                           remove attachment payloads from forensic report output
     -o OUTPUT, --output OUTPUT
                           write output files to the given directory
     -n NAMESERVERS [NAMESERVERS ...], --nameservers NAMESERVERS [NAMESERVERS ...]
                           nameservers to query (default is Cloudflare's
                           nameservers)
     -t TIMEOUT, --timeout TIMEOUT
                           number of seconds to wait for an answer from DNS
                           (default: 6.0)
     -H HOST, --host HOST  an IMAP hostname or IP address
     -u USER, --user USER  an IMAP user
     -p PASSWORD, --password PASSWORD
                           an IMAP password
     --imap-port IMAP_PORT
                           an IMAP port
     --imap-skip-certificate-verification
                           skip certificate verification for IMAP
     --imap-no-ssl         do not use SSL/TLS when connecting to IMAP
     -r REPORTS_FOLDER, --reports-folder REPORTS_FOLDER
                           the IMAP folder containing the reports (default:
                           INBOX)
     -a ARCHIVE_FOLDER, --archive-folder ARCHIVE_FOLDER
                           specifies the IMAP folder to move messages to after
                           processing them (default: Archive)
     -d, --delete          delete the reports after processing them
     -E [ELASTICSEARCH_HOST [ELASTICSEARCH_HOST ...]], --elasticsearch-host [ELASTICSEARCH_HOST [ELASTICSEARCH_HOST ...]]
                           une or more Elasticsearch hostnames or URLs to use
                           (e.g. localhost:9200)
     --elasticsearch-index-suffix ELASTICSEARCH_INDEX_SUFFIX
                           append this suffix to the dmarc_aggregate and
                           dmarc_forensic Elasticsearch index names, joined by _
     --hec HEC             the URL to a Splunk HTTP Event Collector (HEC)
     --hec-token HEC_TOKEN
                           the authorization token for a Splunk HTTP Event
                           Collector (HEC)
     --hec-index HEC_INDEX
                           the index to use when sending events to the Splunk
                           HTTP Event Collector (HEC)
     --hec-skip-certificate-verification
                           skip certificate verification for Splunk HEC
     -K [KAFKA_HOSTS [KAFKA_HOSTS ...]], --kafka-hosts [KAFKA_HOSTS [KAFKA_HOSTS ...]]
                           s list of one or more Kafka hostnames
     --kafka-username KAFKA_USERNAME
                           an optional Kafka username
     --kafka-password KAFKA_PASSWORD
                           an optional Kafka password
     --kafka-use-ssl       use SSL/TLS to connect to Kafka (implied when --kafka-
                           username or --kafka-password are provided)
     --kafka-aggregate-topic KAFKA_AGGREGATE_TOPIC
                           the Kafka topic to publish aggregate reports to
                           (default: dmarc_aggregate)
     --kafka-forensic_topic KAFKA_FORENSIC_TOPIC
                           the Kafka topic to publish forensic reports to
                           (default: dmarc_forensic)
     --save-aggregate      save aggregate reports to search indexes
     --save-forensic       save forensic reports to search indexes
     -O OUTGOING_HOST, --outgoing-host OUTGOING_HOST
                           email the results using this host
     -U OUTGOING_USER, --outgoing-user OUTGOING_USER
                           email the results using this user
     -P OUTGOING_PASSWORD, --outgoing-password OUTGOING_PASSWORD
                           email the results using this password
     --outgoing-port OUTGOING_PORT
                           email the results using this port
     --outgoing-ssl OUTGOING_SSL
                           use SSL/TLS instead of STARTTLS (more secure, and
                           required by some providers, like Gmail)
     -F OUTGOING_FROM, --outgoing-from OUTGOING_FROM
                           email the results using this from address
     -T OUTGOING_TO [OUTGOING_TO ...], --outgoing-to OUTGOING_TO [OUTGOING_TO ...]
                           email the results to these addresses
     -S OUTGOING_SUBJECT, --outgoing-subject OUTGOING_SUBJECT
                           email the results using this subject
     -A OUTGOING_ATTACHMENT, --outgoing-attachment OUTGOING_ATTACHMENT
                           email the results using this filename
     -M OUTGOING_MESSAGE, --outgoing-message OUTGOING_MESSAGE
                           email the results using this message
     -w, --watch           use an IMAP IDLE connection to process reports as they
                           arrive in the inbox
     --test                do not move or delete IMAP messages
     -s, --silent          only print errors and warnings
     --debug               print debugging information
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


On Debian or Ubuntu systems, run:

.. code-block:: bash

    sudo apt-get install python3-pip


On CentOS systems, run:

.. code-block:: bash

   sudo yum install -y python34-setuptools
   sudo easy_install-3.4 pip

Python 3 installers for Windows and macOS can be found at
https://www.python.org/downloads/

To install or upgrade to the latest stable release of ``parsedmarc`` on
macOS or Linux, run

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
virtualenv. First, `download the latest version of pypy3`_. Extract it to
``/opt/pypy3`` (``sudo mkdir /opt`` if ``/opt`` does not exist), then create a
symlink:

.. code-block:: bash

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


DNS performance
---------------

You can often improve performance by providing one or more local nameservers
to the CLI or function calls, as long as those nameservers return the same
records as the public DNS.


.. note::

   If you do not specify any nameservers, Cloudflare's public nameservers are
   used by default, **not the system's default nameservers**.

   This is done to avoid a situation where records in a local nameserver do
   not match records in the public DNS.

Testing multiple report analyzers
---------------------------------

If you would like to test parsedmarc and another report processing solution
at the same time, you can have up to two mailto URIs each in the rua and ruf
tags in your DMARC record, separated by commas.

Accessing an inbox using OWA/EWS
--------------------------------

Some organisations do not allow IMAP, and only support Exchange Web Services
(EWS)/Outlook Web Access (OWA). In that case, Davmail will need to be set up
as a local EWS/OWA IMAP gateway.

To do this, download the latest ``davmail-version.zip`` from
https://sourceforge.net/projects/davmail/files/

Extract the zip using the ``unzip`` command.

Install Java:

.. code-block:: bash

    sudo apt-install default-jre-headless

Configure Davmail by creating a ``davmail.properties`` file

::

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

   # allow remote connection to DavMail
   davmail.allowRemote=false

   # bind server sockets to the loopback address
   davmail.bindAddress=127.0.0.1

   # disable SSL for specified listeners
   davmail.ssl.nosecureimap=false

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

   #############################################################

Run Davmail

.. code-block:: bash

    ./davmail.sh


Because you are interacting with Davmail server over the loopback
(i.e. 127.0.0.1), pass the following options to ``parsedmarc``:

.. code-block:: bash

      --imap-no-ssl -H 127.0.0.1 --imap-port 1143

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
    echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
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

Without the commercial X-Pack_, Kibana does not have any authentication
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

Om the same system as Elasticsearch, pass ``--save-aggregate`` and/or
``--save-forensic`` to ``parsedmarc`` save the results in Elasticsearch.

.. warning::

    ``--save-aggregate`` and ``--save-forensic`` are separate options because
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
   in your DMARC inbox, but run ``parsedmarc --save-forensic`` manually on a
   separate IMAP folder (using the  ``-r`` option), after you have manually
   moved known samples you want to save to that folder (e.g. malicious
   samples and non-sensitive legitimate samples).



Download (right click the link and click save as) kibana_saved_objects.json_.

Import ``kibana_saved_objects.json`` the Saved Objects tab of the management
page of Kibana.

It will give you the option to overwrite existing saved dashboards or
visualizations, which could be used to restore them if you or someone else
breaks them, as there are no permissions/access controls in Kibana without
the commercial X-Pack_.

.. image:: _static/screenshots/saved-objects.png
   :alt: A screenshot of setting the Saved Objects management UI in Kibana
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
   the latest version of kibana_saved_objects.json_
7. Import ``kibana_saved_objects.json`` by clicking Import from the Kibana
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
forensic DMARC data to a Splunk `HTTP Event collector (HEC)`_. Simply use the
following command line options, along with ``--save-aggregate`` and/or
``--save-forensic``:


::

     --hec HEC             URL to a Splunk HTTP Event Collector (HEC)
     --hec-token HEC_TOKEN
                           The authorization token for a Splunk HTTP Event
                           Collector (HEC)
     --hec-index HEC_INDEX
                           The index to use when sending events to the Splunk
                           HTTP Event Collector (HEC)
     --hec-skip-certificate-verification
                           Skip certificate verification for Splunk HEC

.. note::

   To maintain CLI backwards compatibility with previous versions of
   ``parsedmarc``, if ``--save-aggregate`` and/or ``--save-forensic`` are used
   without the ``--hec`` or ``-E`` options, ``-E localhost:9200`` is implied.

   It is possible to save data in Elasticsearch and Splunk at the same time by
   supplying ``-E`` and the HEC options, along with ``--save-aggregate`` and/or
   ``--save-forensic``.

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
    ExecStart=/usr/local/bin/parsedmarc --watch --silent --save-aggregate --save-forensic -H "outlook.office365.com" -u "dmarc@example.com" -p "FooBar!"
    Restart=always
    RestartSec=5m

    [Install]
    WantedBy=multi-user.target

Edit the command line options of ``parsedmarc`` in the service's ``ExecStart``
setting to suit your needs.

.. note::

    Always pass the ``--watch`` option to ``parsedmarc`` when running it as a
    service. Use ``--silent`` to only log errors.

.. warning::

    As mentioned earlier, forensic/failure reports contain copies of emails
    that failed DMARC, including emails that may be legitimate and contain
    sensitive customer or business information. For privacy and/or regulatory
    reasons, you may not want to use the ``--save-forensic`` flag included in
    the example service configuration ``ExecStart`` setting, which would save
    these samples to Elasticsearch.

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
| **Passing**           | The signature in the  | The mail server’s IP  |
|                       | DKIM header is        | address is listed in  |
|                       | validated using a     | the SPF record of the |
|                       | public key that is    | domain in the SMTP    |
|                       | published as a DNS    | envelope’s mail from  |
|                       | record of the domain  | header                |
|                       | name specified in the |                       |
|                       | signature             |                       |
+-----------------------+-----------------------+-----------------------+
| **Alignment**         | The signing domain    | The domain in the     |
|                       | aligns with the       | SMTP envelope’s mail  |
|                       | domain in the         | from header aligns    |
|                       | message’s from header | with the domain in    |
|                       |                       | the message’s from    |
|                       |                       | header                |
+-----------------------+-----------------------+-----------------------+


What if a sender won't support DKIM/DMARC?
==========================================

#. Some vendors don’t know about DMARC yet; ask about SPF and DKIM/email
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

.. toctree::
   :maxdepth: 2
   :caption: Contents:

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

.. _Demystifying DMARC: https://seanthegeek.net/459/demystifying-dmarc/

.. _download the latest version of pypy3: https://pypy.org/download.html#default-with-a-jit-compiler

.. _Elasticsearch: https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html

.. _Kibana: https://www.elastic.co/guide/en/kibana/current/rpm.html

.. _X-Pack: https://www.elastic.co/products/x-pack

.. _kibana_saved_objects.json: https://raw.githubusercontent.com/domainaware/parsedmarc/master/kibana/kibana_saved_objects.json

.. _HTTP Event collector (HEC): http://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHEC

.. _XML files: https://github.com/domainaware/parsedmarc/tree/master/splunk