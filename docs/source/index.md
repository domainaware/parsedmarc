# parsedmarc documentation - Open source DMARC report analyzer and visualizer

[![Build
Status](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml/badge.svg)](https://github.com/domainaware/parsedmarc/actions/workflows/python-tests.yml)
[![Code
Coverage](https://codecov.io/gh/domainaware/parsedmarc/branch/master/graph/badge.svg)](https://codecov.io/gh/domainaware/parsedmarc)
[![PyPI
Package](https://img.shields.io/pypi/v/parsedmarc.svg)](https://pypi.org/project/parsedmarc/)

:::{note}
**Help Wanted**

This is a project is maintained by one developer.
Please consider reviewing the open [issues] to see how you can contribute code, documentation, or user support.
Assistance on the pinned issues would be particularly helpful.

Thanks to all [contributors]!
:::

```{image} _static/screenshots/dmarc-summary-charts.png
:align: center
:alt: A screenshot of DMARC summary charts in Kibana
:scale: 50 %
:target: _static/screenshots/dmarc-summary-charts.png
```

`parsedmarc` is a Python module and CLI utility for parsing DMARC reports.
When used with Elasticsearch and Kibana (or Splunk), it works as a self-hosted
open source alternative to commercial DMARC report processing services such
as Agari Brand Protection, Dmarcian, OnDMARC, ProofPoint Email Fraud Defense,
and Valimail.

## Features

- Parses draft and 1.0 standard aggregate/rua reports
- Parses forensic/failure/ruf reports
- Can parse reports from an inbox over IMAP, Microsoft Graph, or Gmail API
- Transparently handles gzip or zip compressed reports
- Consistent data structures
- Simple JSON and/or CSV output
- Optionally email the results
- Optionally send the results to Elasticsearch and/or Splunk, for use with
  premade dashboards
- Optionally send reports to Apache Kafka

## Resources

### DMARC guides

- [Demystifying DMARC] - A complete guide to SPF, DKIM, and DMARC

### SPF and DMARC record validation

If you are looking for SPF and DMARC record validation and parsing,
check out the sister project,
[checkdmarc](https://domainaware.github.io/checkdmarc/).

### Lookalike domains

DMARC protects against domain spoofing, not lookalike domains. for open source
lookalike domain monitoring, check out [DomainAware](https://github.com/seanthegeek/domainaware).

## CLI help

```text
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
```

:::{note}
Starting in `parsedmarc` 6.0.0, most CLI options were moved to a
configuration file, described below.
:::

## Configuration file

`parsedmarc` can be configured by supplying the path to an INI file

```bash
parsedmarc -c /etc/parsedmarc.ini
```

For example

```ini
# This is an example comment

[general]
save_aggregate = True
save_forensic = True

[imap]
host = imap.example.com
user = dmarcresports@example.com
password = $uperSecure

[mailbox]
watch = True
delete = False

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

[syslog]
server = localhost
port = 514
```

The full set of configuration options are:

- `general`
  - `save_aggregate` - bool: Save aggregate report data to
      Elasticsearch, Splunk and/or S3
  - `save_forensic` - bool: Save forensic report data to
      Elasticsearch, Splunk and/or S3
  - `strip_attachment_payloads` - bool: Remove attachment
      payloads from results
  - `output` - str: Directory to place JSON and CSV files in
  - `aggregate_json_filename` - str: filename for the aggregate
      JSON output file
  - `forensic_json_filename` - str: filename for the forensic
      JSON output file
  - `ip_db_path` - str: An optional custom path to a MMDB file
  - from MaxMind or DBIP
  - `offline` - bool: Do not use online queries for geolocation
      or DNS
  - `nameservers` -  str: A comma separated list of
      DNS resolvers (Default: [Cloudflare's public resolvers])
  - `dns_timeout` - float: DNS timeout period
  - `debug` - bool: Print debugging messages
  - `silent` - bool: Only print errors (Default: True)
  - `log_file` - str: Write log messages to a file at this path
  - `n_procs` - int: Number of process to run in parallel when
      parsing in CLI mode (Default: 1)
  - `chunk_size` - int: Number of files to give to each process
      when running in parallel.

    :::{note}
    Setting this to a number larger than one can improve
    performance when processing thousands of files
    :::
- `mailbox`
  - `reports_folder` - str: The mailbox folder (or label for
      Gmail) where the incoming reports can be found
      (Default: `INBOX`)
  - `archive_folder` - str:  The mailbox folder (or label for
      Gmail) to sort processed emails into (Default: `Archive`)
  - `watch` - bool: Use the IMAP `IDLE` command to process
  - messages as they arrive or poll MS Graph for new messages
  - `delete` - bool: Delete messages after processing them,
  - instead of archiving them
  - `test` - bool: Do not move or delete messages
  - `batch_size` - int: Number of messages to read and process
      before saving. Default `10`. Use `0` for no limit.
  - `check_timeout` - int: Number of seconds to wait for a IMAP
      IDLE response or the number of seconds until the next mai
      check (Default: `30`)
- `imap`
  - `host` - str: The IMAP server hostname or IP address
  - `port` - int: The IMAP server port (Default: `993`)

    :::{note}
    `%` characters must be escaped with another `%` character,
    so use `%%` wherever a `%` character is used.
    :::

    :::{note}
    Starting in version 8.0.0, most options from the `imap`
    section have been moved to the `mailbox` section.
    :::

    :::{note}
    If your host recommends another port, still try 993
    :::

  - `ssl` - bool: Use an encrypted SSL/TLS connection
      (Default: True)
  - `skip_certificate_verification` - bool: Skip certificate
      verification (not recommended)
  - `user` - str: The IMAP user
  - `password` - str: The IMAP password
- `msgraph`
  - `auth_method` - str: Authentication method, valid types are
      `UsernamePassword`, `DeviceCode`, or `ClientSecret`
      (Default: `UsernamePassword`).
  - `user` - str: The M365 user, required when the auth method is
      UsernamePassword
  - `password` - str: The user password, required when the auth
      method is UsernamePassword
  - `client_id` - str: The app registration's client ID
  - `client_secret` - str: The app registration's secret
  - `tenant_id` - str: The Azure AD tenant ID. This is required
      for all auth methods except UsernamePassword.
  - `mailbox` - str: The mailbox name. This defaults to the
      current user if using the UsernamePassword auth method, but
      could be a shared mailbox if the user has access to the mailbox
  - `token_file` - str: Path to save the token file
      (Default: `.token`)

    :::{note}
    You must create an app registration in Azure AD and have an
    admin grant the Microsoft Graph `Mail.ReadWrite`
    (delegated) permission to the app. If you are using
    `UsernamePassword` auth and the mailbox is different from the
    username, you must grant the app `Mail.ReadWrite.Shared`.
    :::

    :::{warning}
    If you are using the `ClientSecret` auth method, you need to
    grant the `Mail.ReadWrite` (application) permission to the
    app. You must also restrict the application's access to a
    specific mailbox since it allows all mailboxes by default.
    Use the `New-ApplicationAccessPolicy` command in the
    Exchange PowerShell module. If you need to scope the policy to
    shared mailboxes, you can add them to a mail enabled security
    group and use that as the group id.

    ```powershell
    New-ApplicationAccessPolicy -AccessRight RestrictAccess
    -AppId "<CLIENT_ID>" -PolicyScopeGroupId "<MAILBOX>"
    -Description "Restrict access to dmarc reports mailbox."
    ```

    :::
- `elasticsearch`
  - `hosts` - str: A comma separated list of hostnames and ports
      or URLs (e.g. `127.0.0.1:9200` or
      `https://user:secret@localhost`)

    :::{note}
    Special characters in the username or password must be
    [URL encoded].
    :::

  - `ssl` - bool: Use an encrypted SSL/TLS connection
    (Default: `True`)
  - `cert_path` - str: Path to a trusted certificates
  - `index_suffix` - str: A suffix to apply to the index names
  - `monthly_indexes` - bool: Use monthly indexes instead of daily indexes
  - `number_of_shards` - int: The number of shards to use when
    creating the index (Default: `1`)
  - `number_of_replicas` - int: The number of replicas to use when
    creating the index (Default: `1`)
- `splunk_hec`
  - `url` - str: The URL of the Splunk HTTP Events Collector (HEC)
  - `token` - str: The HEC token
  - `index` - str: The Splunk index to use
  - `skip_certificate_verification` - bool: Skip certificate
    verification (not recommended)
- `kafka`
  - `hosts` - str: A comma separated list of Kafka hosts
  - `user` - str: The Kafka user
  - `passsword` - str: The Kafka password
  - `ssl` - bool: Use an encrypted SSL/TLS connection (Default: True)
  - `skip_certificate_verification` - bool: Skip certificate
    verification (not recommended)
  - `aggregate_topic` - str: The Kafka topic for aggregate reports
  - `forensic_topic` - str: The Kafka topic for forensic reports
- `smtp`
  - `host` - str: The SMTP hostname
  - `port` - int: The SMTP port (Default: 25)
  - `ssl` - bool: Require SSL/TLS instead of using STARTTLS
  - `skip_certificate_verification` - bool: Skip certificate
    verification (not recommended)
  - `user` - str: the SMTP username
  - `password` - str: the SMTP password
  - `from` - str: The From header to use in the email
  - `to` - list: A list of email addresses to send to
  - `subject` - str: The Subject header to use in the email
    (Default: `parsedmarc report`)
  - `attachment` - str: The ZIP attachment filenames
  - `message` - str: The email message
    (Default: `Please see the attached parsedmarc report.`)

    :::{note}
    `%` characters must be escaped with another `%` character,
    so use `%%` wherever a `%` character is used.
    :::
- `s3`
  - `bucket` - str: The S3 bucket name
  - `path` - str: The path to upload reports to (Default: /)
  - `region_name` - str: The region name (Optional)
  - `endpoint_url` - str: The endpoint URL (Optional)
  - `access_key_id` - str: The access key id (Optional)
  - `secret_access_key` - str: The secret access key (Optional)
- `syslog`
  - `server` - str: The Syslog server name or IP address
  - `port` - int: The UDP port to use (Default: 514)
- `gmail_api`
  - `credentials_file` - str: Path to file containing the
      credentials, None to disable (Default: None)
  - `token_file` - str: Path to save the token file
      (Default: .token)
  - `include_spam_trash` - bool: Include messages in Spam and
      Trash when searching reports (Default: False)
  - `scopes` - str: Comma separated list of scopes to use when
      acquiring credentials
      (Default: `https://www.googleapis.com/auth/gmail.modify`)
  - `oauth2_port` - int: The TCP port for the local server to
      listen on for the OAuth2 response (Default: 8080)

:::{warning}
It is **strongly recommended** to **not** use the `nameservers`
setting. By default, `parsedmarc` uses
[Cloudflare's public resolvers], which are much faster and more
reliable than Google, Cisco OpenDNS, or even most local resolvers.

The `nameservers` option should only be used if your network
blocks DNS requests to outside resolvers.
:::

:::{warning}
`save_aggregate` and `save_forensic` are separate options
because you may not want to save forensic reports
(also known as failure reports) to your Elasticsearch instance,
particularly if you are in a highly-regulated industry that
handles sensitive data, such as healthcare or finance. If your
legitimate outgoing email fails DMARC, it is possible
that email may appear later in a forensic report.

Forensic reports contain the original headers of an email that
failed a DMARC check, and sometimes may also include the
full message body, depending on the policy of the reporting
organization.

Most reporting organizations do not send forensic reports of any
kind for privacy reasons. While aggregate DMARC reports are sent
at least daily, it is normal to receive very few forensic reports.

An alternative approach is to still collect forensic/failure/ruf
reports in your DMARC inbox, but run `parsedmarc` with
``` save_forensic = True``manually on a separate IMAP folder (using
the  ``reports_folder ``` option), after you have manually moved
known samples you want to save to that folder
(e.g. malicious samples and non-sensitive legitimate samples).
:::

## Sample aggregate report output

Here are the results from parsing the[example](https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F)
report from the dmarc.org wiki. It's actually an older draft of
the 1.0 report schema standardized in
[RFC 7480 Appendix C](https://tools.ietf.org/html/rfc7489#appendix-C).
This draft schema is still in wide use.

`parsedmarc` produces consistent, normalized output, regardless
of the report schema.

### JSON

```json
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
```

### CSV

```text
xml_schema,org_name,org_email,org_extra_contact_info,report_id,begin_date,end_date,errors,domain,adkim,aspf,p,sp,pct,fo,source_ip_address,source_country,source_reverse_dns,source_base_domain,count,spf_aligned,dkim_aligned,dmarc_aligned,disposition,policy_override_reasons,policy_override_comments,envelope_from,header_from,envelope_to,dkim_domains,dkim_selectors,dkim_results,spf_domains,spf_scopes,spf_results
draft,acme.com,noreply-dmarc-support@acme.com,http://acme.com/dmarc/support,9391651994964116463,2012-04-27 20:00:00,2012-04-28 19:59:59,,example.com,r,r,none,none,100,0,72.150.241.94,US,adsl-72-150-241-94.shv.bellsouth.net,bellsouth.net,2,True,False,True,none,,,example.com,example.com,,example.com,none,fail,example.com,mfrom,pass
```

## Sample forensic report output

Thanks to Github user [xennn](https://github.com/xennn) for the anonymized
[forensic report email sample](<https://github.com/domainaware/parsedmarc/raw/master/samples/forensic/DMARC%20Failure%20Report%20for%20domain.de%20(mail-from%3Dsharepoint%40domain.de%2C%20ip%3D10.10.10.10).eml>).

### JSON

```json
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
```

### CSV

```text
feedback_type,user_agent,version,original_envelope_id,original_mail_from,original_rcpt_to,arrival_date,arrival_date_utc,subject,message_id,authentication_results,dkim_domain,source_ip_address,source_country,source_reverse_dns,source_base_domain,delivery_result,auth_failure,reported_domain,authentication_mechanisms,sample_headers_only
auth-failure,Lua/1.0,1.0,,sharepoint@domain.de,peter.pan@domain.de,"Mon, 01 Oct 2018 11:20:27 +0200",2018-10-01 09:20:27,Subject,<38.E7.30937.BD6E1BB5@ mailrelay.de>,"dmarc=fail (p=none, dis=none) header.from=domain.de",,10.10.10.10,,,,policy,dmarc,domain.de,,False
```

## Bug reports

Please report bugs on the GitHub issue tracker

<https://github.com/domainaware/parsedmarc/issues>

## Installation

`parsedmarc` works with Python 3 only.

:::{note}
If your system is behind a web proxy, you need to configure your system
to use that proxy. To do this, edit `/etc/environment` and add your
proxy details there, for example:

```bash
http_proxy=http://user:password@prox-server:3128
https_proxy=https://user:password@prox-server:3128
ftp_proxy=http://user:password@prox-server:3128
```

Or if no credentials are needed:

```bash
http_proxy=http://prox-server:3128
https_proxy=https://prox-server:3128
ftp_proxy=http://prox-server:3128
```

This will set the the proxy up for use system-wide, including for
`parsedmarc`.
:::

:::{warning}
If your mail server is Microsoft Exchange, ensure that it is patched to at
least:

- Exchange Server 2010 Update Rollup 22 ([KB4295699](https://support.microsoft.com/KB/4295699))
- Exchange Server 2013 Cumulative Update 21 ([KB4099855](https://support.microsoft.com/KB/4099855))
- Exchange Server 2016 Cumulative Update 11 ([KB4134118](https://support.microsoft.com/kb/4134118))
:::

### geoipupdate setup

:::{note}
Starting in `parsedmarc` 7.1.0, a static copy of the
[IP to Country Lite database] from IPDB is distributed with
`parsedmarc`, under the terms of the
[Creative Commons Attribution 4.0 International License].
as a fallback if the [MaxMind GeoLite2 Country database] is not
installed  However, `parsedmarc` cannot install updated versions of
these databases as they are released, so MaxMind's databases and the
[geoipupdate] tool is still the preferable solution.

The location of the database file can be overridden by using the
`ip_db_path` setting.
:::

On Debian 10 (Buster) or later, run:

```bash
sudo apt-get install -y geoipupdate
```
:::{note}
[Component "contrib"] is required in your apt sources.
:::

On Ubuntu systems run:

```bash
sudo add-apt-repository ppa:maxmind/ppa
sudo apt update
sudo apt install -y geoipupdate
```

On CentOS or RHEL systems, run:

```bash
sudo dnf install -y geoipupdate
```

The latest builds for Linux, macOS, and Windows can be downloaded
from the [geoipupdate releases page on GitHub].

On December 30th, 2019, MaxMind started requiring free accounts to
access the free Geolite2 databases, in order [to
comply with various privacy 
regulations][to comply with various privacy regulations].

Start by [registering for a free GeoLite2 account], and signing in.

Then, navigate the to the [License Keys] page under your account,
and create a new license key for the version of
`geoipupdate` that was installed.

:::{warning}
The configuration file format is different for older (i.e. \<=3.1.1) and newer (i.e. >=3.1.1) versions
of `geoipupdate`. Be sure to select the correct version for your system.
:::

:::{note}
To check the version of `geoipupdate` that is installed, run:

```bash
geoipupdate -V
```

:::

You can use `parsedmarc` as the description for the key.

Once you have generated a key, download the config pre-filled
configuration file. This file should be saved at `/etc/GeoIP.conf`
on Linux or macOS systems, or at
`%SystemDrive%\ProgramData\MaxMind\GeoIPUpdate\GeoIP.conf` on
Windows systems.

Then run

```bash
sudo geoipupdate
```

To download the databases for the first time.

The GeoLite2 Country, City, and ASN databases are updated weekly,
every Tuesday. `geoipupdate` can be run weekly by adding a cron
job or scheduled task.

More information about `geoipupdate` can be found at the
[MaxMind geoipupdate page].

### Installing parsedmarc

On Debian or Ubuntu systems, run:

```bash
sudo apt-get install -y python3-pip python3-virtualenv python3-dev libxml2-dev libxslt-dev
```

On CentOS or RHEL systems, run:

```bash
sudo dnf install -y python39 python3-virtualenv python3-setuptools python3-devel libxml2-devel libxslt-devel
```

Python 3 installers for Windows and macOS can be found at
<https://www.python.org/downloads/>

Create a system user

```bash
sudo mkdir /opt
sudo useradd parsedmarc -r -s /bin/false -m -b /opt
```

Install parsedmarc in a virtualenv

```bash
sudo -u parsedmarc virtualenv /opt/parsedmarc/venv
```

CentOS/RHEL 8 systems use Python 3.6 by default, so on those systems
explicitly tell `virtualenv` to use `python3.9` instead

```bash
sudo -u parsedmarc virtualenv -p python3.9  /opt/parsedmarc/venv
```

Activate the virtualenv

```bash
source /opt/parsedmarc/venv/bin/activate
```

To install or upgrade `parsedmarc` inside the virtualenv, run:

```bash
sudo -u parsedmarc /opt/parsedmarc/venv/bin/pip install -U parsedmarc
```

### Optional dependencies

If you would like to be able to parse emails saved from Microsoft
Outlook (i.e. OLE .msg files), install `msgconvert`:

On Debian or Ubuntu systems, run:

```bash
sudo apt-get install libemail-outlook-message-perl
```

### Testing multiple report analyzers

If you would like to test parsedmarc and another report processing
solution at the same time, you can have up to two `mailto` URIs in each of the rua and ruf
tags in your DMARC record, separated by commas.

### Accessing an inbox using OWA/EWS

:::{note}
Starting in 8.0.0, parsedmarc supports accessing Microsoft/Office 365
inboxes via the Microsoft Graph API, which is preferred over Davmail.
:::

Some organizations do not allow IMAP or the Microsoft Graph API,
and only support Exchange Web Services (EWS)/Outlook Web Access (OWA).
In that case, Davmail will need to be set up
as a local EWS/OWA IMAP gateway. It can even work where
[Modern Auth/multi-factor authentication] is required.

To do this, download the latest `davmail-version.zip` from
<https://sourceforge.net/projects/davmail/files/>

Extract the zip using the `unzip` command.

Install Java:

```bash
sudo apt-get install default-jre-headless
```

Configure Davmail by creating a `davmail.properties` file

```properties
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
```

#### Running DavMail as a systemd service

Use systemd to run `davmail` as a service.

Create a system user

```bash
sudo useradd davmail -r -s /bin/false
```

Protect the `davmail` configuration file from prying eyes

```bash
sudo chown root:davmail /opt/davmail/davmail.properties
sudo chmod u=rw,g=r,o= /opt/davmail/davmail.properties
```

Create the service configuration file

```bash
sudo nano /etc/systemd/system/davmail.service
```

```ini
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
```

Then, enable the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable parsedmarc.service
sudo service davmail restart
```

:::{note}
You must also run the above commands whenever you edit
`davmail.service`.
:::

:::{warning}
Always restart the service every time you upgrade to a new version of
`davmail`:

```bash
sudo service davmail restart
```

:::

To check the status of the service, run:

```bash
service davmail status
```

:::{note}
In the event of a crash, systemd will restart the service after 5
minutes, but the `service davmail status` command will only show the
logs for the current process. To vew the logs for previous runs as
well as the current process (newest to oldest), run:

```bash
journalctl -u davmail.service -r
```

:::

#### Configuring parsedmarc for DavMail

Because you are interacting with DavMail server over the loopback
(i.e. `127.0.0.1`), add the following options to `parsedmarc.ini`
config file:

```ini
[imap]
host=127.0.0.1
port=1143
ssl=False
watch=True
```

### Elasticsearch and Kibana

:::{note}
Splunk is also supported starting with `parsedmarc` 4.3.0
:::

To set up visual dashboards of DMARC data, install Elasticsearch and Kibana.

:::{note}
Elasticsearch and Kibana 6 or later are required
:::

On Debian/Ubuntu based systems, run:

```bash
sudo apt-get install -y apt-transport-https
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update
sudo apt-get install -y elasticsearch kibana
```

For CentOS, RHEL, and other RPM systems, follow the Elastic RPM guides for
[Elasticsearch] and [Kibana].

:::{note}
Previously, the default JVM heap size for Elasticsearch was very small (1g),
which will cause it to crash under a heavy load. To fix this, increase the
minimum and maximum JVM heap sizes in `/etc/elasticsearch/jvm.options` to
more reasonable levels, depending on your server's resources.

Make sure the system has at least 2 GB more RAM then the assigned JVM
heap size.

Always set the minimum and maximum JVM heap sizes to the same
value.

For example, to set a 4 GB heap size, set

```bash
-Xms4g
-Xmx4g
```

See <https://www.elastic.co/guide/en/elasticsearch/reference/current/important-settings.html#heap-size-settings>
for more information.
:::

```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl enable kibana.service
sudo service elasticsearch start
sudo service kibana start
```

To create a self-signed certificate, run:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout kibana.key -out kibana.crt
```

Or, to create a Certificate Signing Request (CSR) for a CA, run:

```bash
openssl req -newkey rsa:4096-nodes -keyout kibana.key -out kibana.csr
```

Fill in the prompts. Watch out for Common Name (e.g. server FQDN or YOUR
domain name), which is the IP address or domain name that you will bebana on. it is the most important field.

If you generated a CSR, remove the CSR after you have your certs

```bash
rm -f kibana.csr
```

Move the keys into place and secure them:

```bash
sudo mv kibana.* /etc/kibana
sudo chmod 660 /etc/kibana/kibana.key
```

Activate the HTTPS server in Kibana
```bash
sudo vim /etc/kibana/kibana.yml
```
Add the following configuration
```
server.host: "SERVER_IP"
server.publicBaseUrl: "https://SERVER_IP"
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/kibana.crt
server.ssl.key: /etc/kibana/kibana.key
```
```bash
sudo systemctl restart kibana
```

Enroll Kibana in Elasticsearch
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
```
Then access to your webserver at https://SERVER_IP:5601, accept the self-signed
certificate and paste the token in the "Enrollment token" field.
```bash
sudo /usr/share/kibana/bin/kibana-verification-code
```
Then put the verification code to your web browser.

End Kibana configuration
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive
sudo /usr/share/kibana/bin/kibana-encryption-keys generate
sudo vim /etc/kibana/kibana.yml
```
Add previously generated encryption keys
```
xpack.encryptedSavedObjects.encryptionKey: xxxx...xxxx
xpack.reporting.encryptionKey: xxxx...xxxx
xpack.security.encryptionKey: xxxx...xxxx
```
```bash
sudo systemctl restart kibana
sudo systemctl restart elasticsearch
```

Now that Elasticsearch is up and running, use `parsedmarc` to send data to
it.

Download (right click the link and click save as) [export.ndjson].

Connect to kibana using the "elastic" user and the password you previously provide
on the console ("End Kibana configuration" part).

Import `export.ndjson` the Saved Objects tab of the Stack management
page of Kibana. (Hamburger menu -> "Management" -> "Stack Management" -> 
"Kibana" -> "Saved Objects")

It will give you the option to overwrite existing saved dashboards or
visualizations, which could be used to restore them if you or someone else
breaks them, as there are no permissions/access controls in Kibana without
the commercial [X-Pack].

```{image} _static/screenshots/saved-objects.png
:align: center
:alt: A screenshot of setting the Saved Objects Stack management UI in Kibana
:target: _static/screenshots/saved-objects.png
```

```{image} _static/screenshots/confirm-overwrite.png
:align: center
:alt: A screenshot of the overwrite conformation prompt
:target: _static/screenshots/confirm-overwrite.png
```

#### Upgrading Kibana index patterns

`parsedmarc` 5.0.0 makes some changes to the way data is indexed in
Elasticsearch. if you are upgrading from a previous release of
`parsedmarc`, you need to complete the following steps to replace the
Kibana index patterns with versions that match the upgraded indexes:

1. Login in to Kibana, and click on Management
2. Under Kibana, click on Saved Objects
3. Check the checkboxes for the `dmarc_aggregate` and `dmarc_forensic`
   index patterns
4. Click Delete
5. Click Delete on the conformation message
6. Download (right click the link and click save as)
   the latest version of [export.ndjson]
7. Import `export.ndjson` by clicking Import from the Kibana
   Saved Objects page

#### Records retention

Starting in version 5.0.0, `parsedmarc` stores data in a separate
index for each day to make it easy to comply with records
retention regulations such as GDPR. For fore information,
check out the Elastic guide to [managing time-based indexes efficiently](https://www.elastic.co/blog/managing-time-based-indices-efficiently).

### Splunk

Starting in version 4.3.0 `parsedmarc` supports sending aggregate and/or
forensic DMARC data to a Splunk [HTTP Event collector (HEC)].

The project repository contains [XML files] for premade Splunk
dashboards for aggregate and forensic DMARC reports.

Copy and paste the contents of each file into a separate Splunk
dashboard XML editor.

:::{warning}
Change all occurrences of `index="email"` in the XML to
match your own index name.
:::

The Splunk dashboards display the same content and layout as the
Kibana dashboards, although the Kibana dashboards have slightly
easier and more flexible filtering options.

### Running parsedmarc as a systemd service

Use systemd to run `parsedmarc` as a service and process reports as
they arrive.

Protect the `parsedmarc` configuration file from prying eyes

```bash
sudo chown root:parsedmarc /etc/parsedmarc.ini
sudo chmod u=rw,g=r,o= /etc/parsedmarc.ini
```

Create the service configuration file

```bash
sudo nano /etc/systemd/system/parsedmarc.service
```

```ini
[Unit]
Description=parsedmarc mailbox watcher
Documentation=https://domainaware.github.io/parsedmarc/
Wants=network-online.target
After=network.target network-online.target elasticsearch.service

[Service]
ExecStart=/opt/parsedmarc/venv/bin/parsedmarc -c /etc/parsedmarc.ini
User=parsedmarc
Group=parsedmarc
Restart=always
RestartSec=5m

[Install]
WantedBy=multi-user.target
```

Then, enable the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable parsedmarc.service
sudo service parsedmarc restart
```

:::{note}
You must also run the above commands whenever you edit
`parsedmarc.service`.
:::

:::{warning}
Always restart the service every time you upgrade to a new version of
`parsedmarc`:

```bash
sudo service parsedmarc restart
```

:::

To check the status of the service, run:

```bash
service parsedmarc status
```

:::{note}
In the event of a crash, systemd will restart the service after 10
minutes, but the `service parsedmarc status` command will only show
the logs for the current process. To view the logs for previous runs
as well as the current process (newest to oldest), run:

```bash
journalctl -u parsedmarc.service -r
```

:::

## Using the Kibana dashboards

The Kibana DMARC dashboards are a human-friendly way to understand the
results from incoming DMARC reports.

:::{note}
The default dashboard is DMARC Summary. To switch between dashboards,
click on the Dashboard link in the left side menu of Kibana.
:::

### DMARC Summary

As the name suggests, this dashboard is the best place to start
reviewing your aggregate DMARC data.

Across the top of the dashboard, three pie charts display the percentage of
alignment pass/fail for SPF, DKIM, and DMARC. Clicking on any chart segment
will filter for that value.

:::{note}
Messages should not be considered malicious just because they failed to pass
DMARC; especially if you have just started collecting data. It may be a
legitimate service that needs SPF and DKIM configured correctly.
:::

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

:::{note}
If you have a lot of B2C customers, you may see a high volume of emails as
your domains coming from consumer email services, such as Google/Gmail and
Yahoo! This occurs when customers have mailbox rules in place that forward
emails from an old account to a new account, which is why DKIM
authentication is so important, as mentioned earlier. Similar patterns may
be observed with businesses who send from reverse DNS addressees of
parent, subsidiary, and outdated brands.
:::

Further down the dashboard, you can filter by source country or source IP
address.

Tables showing SPF and DKIM alignment details are located under the IP address
table.

:::{note}
Previously, the alignment tables were included in a separate dashboard
called DMARC Alignment Failures. That dashboard has been consolidated into
the DMARC Summary dashboard. To view failures only, use the pie chart.
:::

Any other filters work the same way. You can also add your own custom temporary
filters by clicking on Add Filter at the upper right of the page.

### DMARC Forensic Samples

The DMARC Forensic Samples dashboard contains information on DMARC forensic
reports (also known as failure reports or ruf reports). These reports contain
samples of emails that have failed to pass DMARC.

:::{note}
Most recipients do not send forensic/failure/ruf reports at all to avoid
privacy leaks. Some recipients (notably Chinese webmail services) will only
supply the headers of sample emails. Very few provide the entire email.
:::

## DMARC Alignment Guide

DMARC ensures that SPF and DKM authentication mechanisms actually authenticate
against the same domain that the end user sees.

A message passes a DMARC check by passing DKIM or SPF, **as long as the related
indicators are also in alignment**.

```{eval-rst}
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
```

## What if a sender won't support DKIM/DMARC?

1. Some vendors don't know about DMARC yet; ask about SPF and DKIM/email
   authentication.
2. Check if they can send through your email relays instead of theirs.
3. Do they really need to spoof your domain? Why not use the display
   name instead?
4. Worst case, have that vendor send email as a specific subdomain of
   your domain (e.g. `noreply@news.example.com`), and then create
   separate SPF and DMARC records on `news.example.com`, and set
   `p=none` in that DMARC record.

:::{warning}
Do not alter the `p` or `sp` values of the DMARC record on the
Top-Level Domain (TLD) – that would leave you vulnerable to
spoofing of your TLD and/or any subdomain.
:::

## What about mailing lists?

When you deploy DMARC on your domain, you might find that messages
relayed by mailing lists are failing DMARC, most likely because the mailing
list is spoofing your from address, and modifying the subject,
footer, or other part of the message, thereby breaking the
DKIM signature.

### Mailing list list best practices

Ideally, a mailing list should forward messages without altering the
headers or body content at all. [Joe Nelson] does a fantastic job of
explaining exactly what mailing lists should and shouldn't do to be
fully DMARC compliant. Rather than repeat his fine work, here's a
summary:

#### Do

- Retain headers from the original message

- Add [RFC 2369] List-Unsubscribe headers to outgoing messages, instead of
  adding unsubscribe links to the body

> List-Unsubscribe: <https://list.example.com/unsubscribe-link>

- Add [RFC 2919] List-Id headers instead of modifying the subject

  > List-Id: Example Mailing List <list.example.com>

Modern mail clients and webmail services generate unsubscribe buttons based on
these headers.

#### Do not

- Remove or modify any existing headers from the original message, including
  From, Date, Subject, etc.
- Add to or remove content from the message body, **including traditional
  disclaimers and unsubscribe footers**

In addition to complying with DMARC, this configuration ensures that Reply
and Reply All actions work like they would with any email message. Reply
replies to the message sender, and Reply All replies to the sender and the
list.

Even without a subject prefix or body footer, mailing list users can still
tell that a message came from the mailing list, because the message was sent
to the mailing list post address, and not their email address.

Configuration steps for common mailing list platforms are listed below.

#### Mailman 2

Navigate to General Settings, and configure the settings below

```{eval-rst}
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
```

Navigate to Non-digest options, and configure the settings below

```{eval-rst}
=================== ==========
**Setting**         **Value**
**msg_header**
**msg_footer**
**scrub_nondigest**  No
=================== ==========
```

Navigate to Privacy Options> Sending Filters, and configure the settings below

```{eval-rst}
====================================== ==========
**Setting**                            **Value**
**dmarc_moderation_action**            Accept
**dmarc_quarantine_moderation_action** Yes
**dmarc_none_moderation_action**       Yes
====================================== ==========
```

#### Mailman 3

Navigate to Settings> List Identity

Make Subject prefix blank.

Navigate to Settings> Alter Messages

Configure the settings below

```{eval-rst}
====================================== ==========
**Setting**                            **Value**
**Convert html to plaintext**          No
**Include RFC2369 headers**            Yes
**Include the list post header**       Yes
**Explicit reply-to address**
**First strip replyto**                 No
**Reply goes to list**                 No munging
====================================== ==========
```

Navigate to Settings> DMARC Mitigation

Configure the settings below

```{eval-rst}
================================== ===============================
**Setting**                            **Value**
**DMARC mitigation action**            No DMARC mitigations
**DMARC mitigate unconditionally** No
================================== ===============================
```

Create a blank footer template for your mailing list to remove the message
footer. Unfortunately, the Postorius mailing list admin UI will not allow you
to create an empty template, so you'll have to create one using the system's
command line instead, for example:

```bash
touch var/templates/lists/list.example.com/en/list:member:regular:footer
```

Where `list.example.com` the list ID, and `en` is the language.

Then restart mailman core.

### Workarounds

If a mailing list must go **against** best practices and
modify the message (e.g. to add a required legal footer), the mailing
list administrator must configure the list to replace the From address of the
message (also known as munging) with the address of the mailing list, so they
no longer spoof email addresses with domains protected by DMARC.

Configuration steps for common mailing list platforms are listed below.

#### Mailman 2

Navigate to Privacy Options> Sending Filters, and configure the settings below

```{eval-rst}
====================================== ==========
**Setting**                            **Value**
**dmarc_moderation_action**            Munge From
**dmarc_quarantine_moderation_action** Yes
**dmarc_none_moderation_action**       Yes
====================================== ==========
```

:::{note}
Message wrapping could be used as the DMARC mitigation action instead. In
that case, the original message is added as an attachment to the mailing
list message, but that could interfere with inbox searching, or mobile
clients.

On the other hand, replacing the From address might cause users to
accidentally reply to the entire list, when they only intended to reply to
the original sender.

Choose the option that best fits your community.
:::

#### Mailman 3

In the DMARC Mitigations tab of the Settings page, configure the settings below

```{eval-rst}
================================== ===============================
**Setting**                            **Value**
**DMARC mitigation action**            Replace From: with list address
**DMARC mitigate unconditionally** No
================================== ===============================
```

:::{note}
Message wrapping could be used as the DMARC mitigation action instead. In
that case, the original message is added as an attachment to the mailing
list message, but that could interfere with inbox searching, or mobile
clients.

On the other hand, replacing the From address might cause users to
accidentally reply to the entire list, when they only intended to reply to
the original sender.
:::

#### LISTSERV

[LISTSERV 16.0-2017a] and higher will rewrite the From header for domains
that enforce with a DMARC quarantine or reject policy.

Some additional steps are needed for Linux hosts.

## API

```{eval-rst}
.. automodule:: parsedmarc
   :members:
```

### parsedmarc.elastic

```{eval-rst}
.. automodule:: parsedmarc.elastic
   :members:
```

```{toctree}
:caption: 'Contents:'
:maxdepth: 2
```

### parsedmarc.splunk

```{eval-rst}
.. automodule:: parsedmarc.splunk
   :members:
```

```{toctree}
:caption: 'Contents:'
:maxdepth: 2
```

### parsedmarc.utils

```{eval-rst}
.. automodule:: parsedmarc.utils
   :members:
```

```{toctree}
:caption: 'Contents:'
:maxdepth: 2
```

## Indices and tables

- {ref}`genindex`
- {ref}`modindex`
- {ref}`search`

[cloudflare's public resolvers]: https://1.1.1.1/
[Component "contrib"]: https://wiki.debian.org/SourcesList#Component
[contributors]: https://github.com/domainaware/parsedmarc/graphs/contributors
[creative commons attribution 4.0 international license]: https://creativecommons.org/licenses/by/4.0/
[demystifying dmarc]: https://seanthegeek.net/459/demystifying-dmarc/
[elasticsearch]: https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html
[export.ndjson]: https://raw.githubusercontent.com/domainaware/parsedmarc/master/kibana/export.ndjson
[geoipupdate]: https://github.com/maxmind/geoipupdate
[geoipupdate releases page on github]: https://github.com/maxmind/geoipupdate/releases
[http event collector (hec)]: http://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHEC
[ip to country lite database]: https://db-ip.com/db/download/ip-to-country-lite
[issues]: https://github.com/domainaware/parsedmarc/issues
[joe nelson]: https://begriffs.com/posts/2018-09-18-dmarc-mailing-list.html
[kibana]: https://www.elastic.co/guide/en/kibana/current/rpm.html
[license keys]: https://www.maxmind.com/en/accounts/current/license-key
[listserv 16.0-2017a]: https://www.lsoft.com/news/dmarc-issue1-2018.asp
[maxmind geoipupdate page]: https://dev.maxmind.com/geoip/geoipupdate/
[maxmind geolite2 country database]: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
[modern auth/multi-factor authentication]: http://davmail.sourceforge.net/faq.html
[readonlyrest]: https://readonlyrest.com/
[registering for a free geolite2 account]: https://www.maxmind.com/en/geolite2/signup
[rfc 2369]: https://tools.ietf.org/html/rfc2369
[rfc 2919]: https://tools.ietf.org/html/rfc2919
[to comply with various privacy regulations]: https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/
[url encoded]: https://en.wikipedia.org/wiki/Percent-encoding#Percent-encoding_reserved_characters
[x-pack]: https://www.elastic.co/products/x-pack
[xml files]: https://github.com/domainaware/parsedmarc/tree/master/splunk
