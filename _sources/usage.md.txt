# Using parsedmarc

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

[opensearch]
hosts = https://admin:admin@127.0.0.1:9200
ssl = True

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
  - `save_smtp_sts` - bool: Save SMTP-STS report data to
      Elasticsearch, Splunk and/or S3
  - `strip_attachment_payloads` - bool: Remove attachment
      payloads from results
  - `output` - str: Directory to place JSON and CSV files in.  This is required if you set either of the JSON output file options.
  - `aggregate_json_filename` - str: filename for the aggregate
      JSON output file
  - `forensic_json_filename` - str: filename for the forensic
      JSON output file
  - `ip_db_path` - str: An optional custom path to a MMDB file
      from MaxMind or DBIP
  - `offline` - bool: Do not use online queries for geolocation
      or DNS
  - `always_use_local_files` - Disables the download of the reverse DNS map
  - `local_reverse_dns_map_path` - Overrides the default local file path to use for the reverse DNS map
  - `reverse_dns_map_url` - Overrides the default download URL for the reverse DNS map
  - `nameservers` - str: A comma separated list of
      DNS resolvers (Default: `[Cloudflare's public resolvers]`)
  - `dns_timeout` - float: DNS timeout period
  - `debug` - bool: Print debugging messages
  - `silent` - bool: Only print errors (Default: `True`)
  - `log_file` - str: Write log messages to a file at this path
  - `n_procs` - int: Number of process to run in parallel when
      parsing in CLI mode (Default: `1`)

    :::{note}
    Setting this to a number larger than one can improve
    performance when processing thousands of files
    :::

- `mailbox`
  - `reports_folder` - str: The mailbox folder (or label for
      Gmail) where the incoming reports can be found
      (Default: `INBOX`)
  - `archive_folder` - str: The mailbox folder (or label for
      Gmail) to sort processed emails into (Default: `Archive`)
  - `watch` - bool: Use the IMAP `IDLE` command to process
      messages as they arrive or poll MS Graph for new messages
  - `delete` - bool: Delete messages after processing them,
      instead of archiving them
  - `test` - bool: Do not move or delete messages
  - `batch_size` - int: Number of messages to read and process
      before saving. Default `10`. Use `0` for no limit.
  - `check_timeout` - int: Number of seconds to wait for a IMAP
      IDLE response or the number of seconds until the next
      mail check (Default: `30`)
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
      (Default: `True`)
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
  - `allow_unencrypted_storage` - bool: Allows the Azure Identity
      module to fall back to unencrypted token cache (Default: `False`).
      Even if enabled, the cache will always try encrypted storage first.

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
  - `user` - str: Basic auth username
  - `password` - str: Basic auth password
  - `apiKey` - str: API key
  - `ssl` - bool: Use an encrypted SSL/TLS connection
    (Default: `True`)
  - `timeout` - float: Timeout in seconds (Default: 60)
  - `cert_path` - str: Path to a trusted certificates
  - `index_suffix` - str: A suffix to apply to the index names
  - `monthly_indexes` - bool: Use monthly indexes instead of daily indexes
  - `number_of_shards` - int: The number of shards to use when
    creating the index (Default: `1`)
  - `number_of_replicas` - int: The number of replicas to use when
    creating the index (Default: `0`)
- `opensearch`
  - `hosts` - str: A comma separated list of hostnames and ports
    or URLs (e.g. `127.0.0.1:9200` or
    `https://user:secret@localhost`)

    :::{note}
    Special characters in the username or password must be
    [URL encoded].
    :::
  - `user` - str: Basic auth username
  - `password` - str: Basic auth password
  - `apiKey` - str: API key
  - `ssl` - bool: Use an encrypted SSL/TLS connection
    (Default: `True`)
  - `timeout` - float: Timeout in seconds (Default: 60)
  - `cert_path` - str: Path to a trusted certificates
  - `index_suffix` - str: A suffix to apply to the index names
  - `monthly_indexes` - bool: Use monthly indexes instead of daily indexes
  - `number_of_shards` - int: The number of shards to use when
    creating the index (Default: `1`)
  - `number_of_replicas` - int: The number of replicas to use when
    creating the index (Default: `0`)
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
  - `ssl` - bool: Use an encrypted SSL/TLS connection (Default: `True`)
  - `skip_certificate_verification` - bool: Skip certificate
    verification (not recommended)
  - `aggregate_topic` - str: The Kafka topic for aggregate reports
  - `forensic_topic` - str: The Kafka topic for forensic reports
- `smtp`
  - `host` - str: The SMTP hostname
  - `port` - int: The SMTP port (Default: `25`)
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
  - `path` - str: The path to upload reports to (Default: `/`)
  - `region_name` - str: The region name (Optional)
  - `endpoint_url` - str: The endpoint URL (Optional)
  - `access_key_id` - str: The access key id (Optional)
  - `secret_access_key` - str: The secret access key (Optional)
- `syslog`
  - `server` - str: The Syslog server name or IP address
  - `port` - int: The UDP port to use (Default: `514`)
- `gmail_api`
  - `credentials_file` - str: Path to file containing the
      credentials, None to disable (Default: `None`)
  - `token_file` - str: Path to save the token file
      (Default: `.token`)
      
    :::{note}
    credentials_file and token_file can be got with [quickstart](https://developers.google.com/gmail/api/quickstart/python).Please change the scope to `https://www.googleapis.com/auth/gmail.modify`.
    :::
  - `include_spam_trash` - bool: Include messages in Spam and
      Trash when searching reports (Default: `False`)
  - `scopes` - str: Comma separated list of scopes to use when
      acquiring credentials
      (Default: `https://www.googleapis.com/auth/gmail.modify`)
  - `oauth2_port` - int: The TCP port for the local server to
      listen on for the OAuth2 response (Default: `8080`)
  - `paginate_messages` - bool: When `True`, fetch all applicable Gmail messages.
      When `False`, only fetch up to 100 new messages per run (Default: `True`)
- `log_analytics`
  - `client_id` - str: The app registration's client ID
  - `client_secret` - str: The app registration's client secret
  - `tenant_id` - str: The tenant id where the app registration resides
  - `dce` - str: The Data Collection Endpoint (DCE). Example: `https://{DCE-NAME}.{REGION}.ingest.monitor.azure.com`.
  - `dcr_immutable_id` - str: The immutable ID of the Data Collection Rule (DCR)
  - `dcr_aggregate_stream` - str: The stream name for aggregate reports in the DCR
  - `dcr_forensic_stream` - str: The stream name for the forensic reports in the DCR
  - `dcr_smtp_tls_stream` - str: The stream name for the SMTP TLS reports in the DCR

  :::{note}
    Information regarding the setup of the Data Collection Rule can be found [here](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal).
    :::

:::{warning}
It is **strongly recommended** to **not** use the `nameservers`
setting. By default, `parsedmarc` uses
[Cloudflare's public resolvers], which are much faster and more
reliable than Google, Cisco OpenDNS, or even most local resolvers.

The `nameservers` option should only be used if your network
blocks DNS requests to outside resolvers.
:::

:::{note}
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
```save_forensic = True``` manually on a separate IMAP folder (using
the ```reports_folder``` option), after you have manually moved
known samples you want to save to that folder
(e.g. malicious samples and non-sensitive legitimate samples).
:::

:::{warning}
Elasticsearch 8 change limits policy for shards, restricting by
default to 1000. parsedmarc use a shard per analyzed day. If you
have more than ~3 years of data, you will need to update this
limit.
Check current usage (from Management -> Dev Tools -> Console):

```text
GET /_cluster/health?pretty
{
...
  "active_primary_shards": 932,
  "active_shards": 932,
...
}
```

Update the limit to 2k per example:

```text
PUT _cluster/settings
{
  "persistent" : {
    "cluster.max_shards_per_node" : 2000 
  }
}
```

Increasing this value increases resource usage.
:::

## Running parsedmarc as a systemd service

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

[cloudflare's public resolvers]: https://1.1.1.1/
[url encoded]: https://en.wikipedia.org/wiki/Percent-encoding#Percent-encoding_reserved_characters
