Changelog
=========

7.0.1
-----

- Fix startup error (PR #254)

7.0.0
-----

- Fix issue #221: Crash when handling invalid reports without root node (PR #248)
- Use UTC datetime objects for Elasticsearch output (PR #245) 
- Fix issues #219, #155, and #103: IMAP connections break on large emails (PR #241)
- Add support for saving reports to S3 buckets (PR #223)
- Pass `offline` parameter to `wait_inbox()` (PR #216)
- Add more details to logging (PR #220)
- Add options customizing the names of output files (Modifications based on PR #225) 
- Wait for 5 seconds before attempting to reconnect to an IMAP server (PR #217)
- Add option to process messages in batches (PR #222)

6.12.0
------

- Limit output filename length to 100 characters (PR #199)
- Add basic auth support for Elasticsearch (PR #191)
- Fix Windows paths when searching for the GeoIP database (PR #190)
- Remove `six` requirement
- Require `mailsuite>=1.6.1`
- Require `dnspython>=2.0.0`
  - Drop Python 3.5 support

6.11.0
------

- Fix parsing failure for some valid forensic reports (PR #170)
- Fix double count of messages in the Grafana dashboard (PR #182)
- Add begin and end date fields for aggregate DMARC reports in Elasticsearch (PR #183 fixes issue #162)
- Fix crash on IMAP timeout (PR #186 fixes issue #163)
- Fix IMAP debugging output
- Fix `User-Agent` string


6.10.0
------

- Ignore unknown forensic report fields when generating CSVs (Closes issue #148)
- Fix crash on IMAP timeout (PR #164 - closes issue #163)
- Use SMTP port from the config file when sending emails (PR #151)
- Add support for Elasticsearch 7.0 (PR #161 - closes issue #149)
- Remove temporary workaround for DMARC aggregate report records missing a SPF domain fields

6.9.0
-----

- Use system nameservers instead of Cloudflare by default
- Parse aggregate report records with missing SPF domains

6.8.2
-----

- Require `mailsuite>=1.5.4`

6.8.1
-----

- Use `match_phrase` instead of `match` when looking for existing strings in Elasticsearch 

6.8.0
-----

- Display warning when `GeoLite2-Country.mmdb` is missing, instead of trying to download it
- Add documentation for MaxMind `geoipupdate` changes on January 30th, 2019 (closes issues #137 and #139)
- Require `mail-parser>=3.11.0`

6.7.4
-----

- Update dependencies 

6.7.3
-----
- Make `dkim_aligned` and `spf_aligned` case insensitive (PR #132)

6.7.2
-----

- Fix SPF results field in CSV output (closes issue #128)

6.7.1
-----

- Parse forensic email samples with non-standard date headers
- Graceful handling of a failure to download the GeoIP database (issue #123) 

6.7.0
-----

- Fix typos (PR #119)
- Make CSV output match JSON output (Issue # 22)
- Graceful processing of invalid aggregate DMARC reports (PR #122)
- Remove Python 3.4 support

6.6.1
-----

- Close files after reading them

6.6.0
-----

- Set a configurable default IMAP timeout of 30 seconds
- Set a configurable maximum of 4 IMAP timeout retry attempts
- Add support for reading ``MBOX`` files
- Set a configurable Elasticsearch timeout of 60 seconds

6.5.5
-----

- Set set minimum `publicsuffix2` version

6.5.4
-----

- Bump required `mailsuite` version to `1.2.1`

6.5.3
-----

- Fix typos in the CLI documentation
- Bump required `mailsuite` version to `1.1.1`

6.5.2
-----

- Merge PR #100 from michaeldavie
  - Correct a bug introduced in 6.5.1 that caused only the last record's data
  to be used for each row in an aggregate report's CSV version.
- Use `mailsuite` 1.1.0 to fix issues with some IMAP servers (closes issue 103)
  - Always use ``/`` as the folder hierarchy separator, and convert to the
  server's hierarchy separator in the background
  - Always remove folder name characters that conflict with the server's
  hierarchy separators
  - Prepend the namespace to the folder path when required

6.5.1
-----

- Merge PR #98 from michaeldavie
  - Add functions
    - `parsed_aggregate_reports_to_csv_row(reports)`
    - `parsed_forensic_reports_to_csv_row(reports)` 
- Require `dnspython>=1.16.0`

6.5.0
-----

- Move mail processing functions to the
  [`mailsuite`](https://seanthegeek.github.io/mailsuite/) package
- Add offline option (closes issue #90)
- Use UDP instead of TCP, and properly set the timeout when querying DNS 
  (closes issue #79 and #92)
- Log the current file path being processed when `--debug` is used 
  (closes issue #95)


6.4.2
-----

- Do not attempt to convert `org_name` to a base domain if `org_name` contains 
  a space (closes issue #94)
- Always lowercase the `header_from`
- Provide a more helpful warning message when `GeoLite2-Country.mmdb` is 
  missing

6.4.1
-----

- Raise `utils.DownloadError` exception when a GeoIP database or Public 
  Suffix List (PSL) download fails (closes issue #73)

6.4.0
-----

- Add ``number_of_shards`` and ``number_of_replicas`` as possible options 
in the ``elasticsearch`` configuration file section (closes issue #78)

6.3.7
-----

- Work around some unexpected IMAP responses reported in issue #75

6.3.6
-----

- Work around some unexpected IMAP responses reported in issue #70
- Show correct destination folder in debug logs when moving aggregate reports

6.3.5
-----

- Normalize `Delivery-Result` value in forensic/failure reports (issue #76)
  Thanks Freddie Leeman of URIports for the troubleshooting assistance

6.3.4
-----

- Fix Elasticsearch index creation (closes issue #74)

6.3.3
-----

- Set `number_of_shards` and `number_of_replicas` to `1` when creating indexes
- Fix dependency conflict

6.3.2
-----

- Fix the `monthly_indexes` option in the `elasticsearch` configuration section

6.3.1
-----

- Fix `strip_attachment_payloads` option

6.3.0
-----

- Fix IMAP IDLE response processing for some mail servers (#67)
- Exit with a critical error when required settings are missing (#68)
- XML parsing fixes (#69)
- Add IMAP responses to debug logging
- Add `smtp` option `skip_certificate_verification`
- Add `kafka` option `skip_certificate_verification`
- Suppress `mailparser` logging output
- Suppress `msgconvert` warnings

6.2.2
-----

- Fix crash when trying to save forensic reports with missing fields to Elasticsearch

6.2.1
-----

- Add missing `tqdm` dependency to `setup.py`

6.2.0
-----

- Add support for multi-process parallelized processing via CLI (Thanks zscholl - PR #62)
- Save sha256 hashes of attachments in forensic samples to Elasticsearch

6.1.8
-----

- Actually fix GeoIP lookups

6.1.7
-----

- Fix GeoIP lookups

6.1.6
-----

- Better GeoIP error handling

6.1.5
-----

- Always use Cloudflare's nameservers by default instead of Google's
- Avoid re-downloading the Geolite2 database (and tripping their DDoS protection)
- Add `geoipupdate` to install instructions

6.1.4
-----

- Actually package requirements

6.1.3
-----

- Fix package requirements

6.1.2
-----

- Use local Public Suffix List file instead of downloading it
- Fix argument name for `send_email()` (closes issue #60)

6.1.1
-----

- Fix aggregate report processing
- Check for the existence of a configuration file if a path is supplied
- Replace `publicsuffix` with `publicsuffix2`
- Add minimum versions to requirements

6.1.0
-----

- Fix aggregate report email parsing regression introduced in 6.0.3 (closes issue #57)
- Fix Davmail support (closes issue #56)

6.0.3
-----

- Don't assume the report is the last part of the email message (issue #55)

6.0.2
----

- IMAP connectivity improvements (issue #53)
- Use a temp directory for temp files (issue #54)

6.0.1
-----

- Fix Elasticsearch output (PR #50 - andrewmcgilvray)

6.0.0
-----

- Move options from CLI to a config file (see updated installation documentation)
- Refactoring to make argument names consistent 

5.3.0
-----

- Fix crash on invalid forensic report sample (Issue #47)
- Fix DavMail support (Issue #45)

5.2.1
-----

- Remove unnecessary debugging code

5.2.0
-----
- Add filename and line number to logging output
- Improved IMAP error handling  
- Add CLI options
  ```
  --elasticsearch-use-ssl
                        Use SSL when connecting to Elasticsearch
  --elasticsearch-ssl-cert-path ELASTICSEARCH_SSL_CERT_PATH
                        Path to the Elasticsearch SSL certificate
  --elasticsearch-monthly-indexes
                        Use monthly Elasticsearch indexes instead of daily
                        indexes
  --log-file LOG_FILE   output logging to a file
  ```

5.1.3
-----

- Remove `urllib3` version upper limit

5.1.2
-----

- Workaround unexpected Office365/Exchange IMAP responses

5.1.1
-----

- Bugfix: Crash when parsing invalid forensic report samples (#38)
- Bugfix: Crash when IMAP connection is lost
- Increase default Splunk HEC response timeout to 60 seconds

5.1.0
-----

- Bugfix: Submit aggregate dates to Elasticsearch as lists, not tuples
- Support `elasticsearch-dsl<=6.3.0`
- Add support for TLS/SSL and username/password auth to Kafka 

5.0.2
-----

- Revert to using `publicsuffix` instead of `publicsuffix2`

5.0.1
-----

- Use `publixsuffix2` (closes issue #4)
- Add Elasticsearch to automated testing
- Lock `elasticsearch-dsl` required version to `6.2.1` (closes issue #25)


5.0.0
-----

**Note**: Re-importing `kibana_saved_objects.json` in Kibana [is required](https://domainaware.github.io/parsedmarc/#upgrading-kibana-index-patterns) when upgrading to this version!

- Bugfix: Reindex the aggregate report index field `published_policy.fo` 
as `text` instead of `long` (Closes issue #31)
- Bugfix: IDLE email processing in Gmail/G-Suite accounts (closes issue #33)
- Bugfix: Fix inaccurate DNS timeout in CLI documentation (closes issue #34)
- Bugfix: Forensic report processing via CLI
- Bugfix: Duplicate aggregate report Elasticsearch query broken 
- Bugfix: Crash when `Arrival-Date` header is missing in a 
forensic/fialure/ruf report 
- IMAP reliability improvements
- Save data in separate indexes each day to make managing data retention easier
- Cache DNS queries in memory

4.4.1
-----

- Don't crash if Elasticsearch returns an unexpected result (workaround for issue #31)

4.4.0
-----

- Packaging fixes

4.3.9
-----

- Kafka output improvements
  - Moved some key values (`report_id`, `org_email`, `org_name`) higher in the JSON structure
  - Recreated the `date_range` values from the ES client for easier parsing.
  - Started sending individual record slices. Kafka default message size is 1 MB, some aggregate reports were exceeding this. Now it appends meta-data and sends record by record.


4.3.8
-----

- Fix decoding of attachments inside forensic samples
- Add CLI option `--imap-skip-certificate-verification`
- Add optional `ssl_context` argument for `get_dmarc_reports_from_inbox()`
and `watch_inbox()`
- Debug logging improvements

4.3.7
-----

- When checking an inbox, always recheck for messages when processing is 
complete


4.3.6
-----

- Be more forgiving for forensic reports with missing fields

4.3.5
-----

- Fix base64 attachment decoding (#26)

4.3.4
-----

- Fix crash on empty aggregate report comments (brakhane - #25)
- Add SHA256 hashes of attachments to output
- Add `strip_attachment_payloads` option to functions and 
`--strip-attachment-payloads` option to the CLI (#23)
- Set `urllib3` version requirements to match `requests`

4.3.3
-----

- Fix forensic report email processing

4.3.2
-----

- Fix normalization of the forensic sample from address

4.3.1
-----

- Fix parsing of some emails
- Fix duplicate forensic report search for Elasticsearch

4.3.0
-----

- Fix bug where `parsedmarc` would always try to save to Elastic search, 
  even if only `--hec` was used
- Add options to save reports as a Kafka topic (mikesiegel  - #21)
- Major refactoring of functions
- Support parsing forensic reports generated by Brightmail
- Make `sample_headers_only` flag more reliable 
- Functions that might be useful to other projects are now stored in 
 `parsedmarc.utils`:
    - `get_base_domain(domain)`
    - `get_filename_safe_string(string)`
    - `get_ip_address_country(ip_address)`
    - `get_ip_address_info(ip_address, nameservers=None, timeout=2.0)`
    - `get_reverse_dns(ip_address, nameservers=None, timeout=2.0)`
    - `human_timestamp_to_datetime(human_timestamp)`
    - `human_timestamp_to_timestamp(human_timestamp)`
    - `parse_email(data)`

4.2.0
------

- Save each aggregate report record as a separate Splunk event
- Fix IMAP delete action (#20)
- Suppress Splunk SSL validation warnings
- Change default logging level to `WARNING`


4.1.9
-----

- Workaround for forensic/ruf reports that are missing `Arrival-Date` and/or 
`Reported-Domain`

4.1.8
-----

- Be more forgiving of weird XML

4.1.7
-----

- Remove any invalid XML schema tags before parsing the XML (#18)

4.1.6
-----

- Fix typo in CLI parser

4.1.5
-----

- Only move or delete IMAP emails after they all have been parsed
- Move/delete messages one at a time - do not exit on error
- Reconnect to IMAP if connection is broken during 
`get_dmarc_reports_from_inbox()` 
- Add`--imap-port` and `--imap-no-ssl` CLI options

4.1.4
-----

- Change default logging level to `ERROR`

4.1.3
-----

- Fix crash introduced in 4.1.0 when creating Elasticsearch indexes (Issue #15) 

4.1.2
-----

- Fix packaging bug

4.1.1
-----

- Add splunk instructions
- Reconnect reset IMAP connections when watching a folder

4.1.0
-----

- Add options for Elasticsearch prefixes and suffixes
- If an aggregate report has the invalid `disposition` value `pass`, change
it to `none`


4.0.2
-----

- Use report timestamps for Splunk timestamps

4.0.1
-----

- When saving aggregate reports in Elasticsearch store `domain` in 
`published_policy`
- Rename `policy_published` to `published_policy`when saving aggregate 
reports to Splunk

4.0.0
-----

- Add support for sending DMARC reports to a Splunk HTTP Events 
Collector (HEC)
- Use a browser-like `User-Agent` when downloading the Public Suffix List and 
GeoIP DB to avoid being blocked by security proxies
- Reduce default DNS timeout to 2.0 seconds
- Add alignment booleans to JSON output
- Fix `.msg` parsing CLI exception when `msgconvert` is not found in the 
system path
- Add `--outgoing-port` and  `--outgoing-ssl` options
- Fall back to plain text SMTP if `--outgoing-ssl` is not used and `STARTTLS` 
is not supported by the server
- Always use `\n` as the newline when generating CSVs
- Workaround for random Exchange/Office365 `Server Unavailable` IMAP errors

3.9.7
-----

- Completely reset IMAP connection when a broken pipe is encountered

3.9.6
-----

- Finish incomplete broken pipe fix

3.9.5
-----

- Refactor to use a shared IMAP connection for inbox watching and message 
downloads

- Gracefully recover from broken pipes in IMAP

3.9.4
-----

- Fix moving/deleting emails

3.9.3
-----

- Fix crash when forensic reports are missing `Arrival-Date`

3.9.2
-----

- Fix PEP 8 spacing
- Update build script to fail when CI tests fail

3.9.1
-----

- Use `COPY` and delete if an IMAP server does not support `MOVE` 
(closes issue #9)

3.9.0
-----

- Reduce IMAP `IDLE` refresh rate to 5 minutes to avoid session timeouts in 
Gmail
- Fix parsing of some forensic/failure/ruf reports
- Include email subject in all warning messages
- Fix example NGINX configuration in the installation documentation 
(closes issue #6)

3.8.2
-----

- Fix `nameservers` option (mikesiegel)
- Move or delete invalid report emails in an IMAP inbox (closes issue #7)

3.8.1
-----

- Better handling of `.msg` files when `msgconvert` is not installed

3.8.0
-----

- Use `.` instead of `/` as the IMAP folder hierarchy separator when `/` 
does not work - fixes dovecot support (#5)
- Fix parsing of base64-encoded forensic report data

3.7.3
-----

- Fix saving attachment from forensic sample to Elasticsearch

3.7.2
-----

- Change uses uses of the `DocType` class to `Document`, to properly support `elasticsearch-dsl` `6.2.0` (this also fixes use in pypy)
- Add documentation for installation under pypy

3.7.1
-----

- Require `elasticsearch>=6.2.1,<7.0.0` and `elasticsearch-dsl>=6.2.1,<7.0.0`
- Update for class changes in `elasticsearch-dsl` `6.2.0`

3.7.0
-----

- Fix bug where PSL would be called before it was downloaded if the PSL was 
older than 24 Hours

3.6.1
-----

- Parse aggregate reports with missing SPF domain

3.6.0
-----

- Much more robust error handling

3.5.1
-----

- Fix dashboard message counts for source IP addresses visualizations
- Improve dashboard loading times
- Improve dashboard layout
- Add country rankings to the dashboards
- Fix crash when parsing report with empty <auth_results></auth_results>


3.5.0
-----
- Use Cloudflare's public DNS resolvers by default instead of Google's
- Fix installation from virtualenv
- Fix documentation typos


3.4.1
-----
- Documentation fixes
- Fix console output

3.4.0
-----
- Maintain IMAP IDLE state when watching the inbox
- The `-i`/`--idle` CLI option is now `-w`/`--watch`
- Improved Exception handling and documentation


3.3.0
-----
- Fix errors when saving to Elasticsearch


3.2.0
-----
- Fix existing aggregate report error message

3.1.0
-----
- Fix existing aggregate report query


3.0.0
-----
### New features
- Add option to select the IMAP folder where reports are stored
- Add options to send data to Elasticsearch

### Changes
- Use Google's public nameservers (`8.8.8.8` and `4.4.4.4`)
by default
- Detect aggregate report email attachments by file content rather than
file extension
- If an aggregate report's `org_name` is a FQDN, the base is used
- Normalize aggregate report IDs

2.1.2
-----
- Rename `parsed_dmarc_forensic_reports_to_csv()` to
 `parsed_forensic_reports_to_csv()` to match other functions
- Rename `parsed_aggregate_report_to_csv()` to
 `parsed_aggregate_reports_to_csv()` to match other functions
- Use local time when generating the default email subject

2.1.1
-----
- Documentation fixes

2.1.0
-----
- Add `get_report_zip()` and `email_results()`
- Add support for sending report emails via the command line

2.0.1
-----
- Fix documentation
- Remove Python 2 code

2.0.0
-----
### New features
- Parse forensic reports
- Parse reports from IMAP inbox

### Changes
- Drop support for Python 2
- Command line output is always a JSON object containing the lists
  `aggregate_reports` and `forensic_reports`
- `-o`/`--output` option is now a path to an output directory, instead of an
  output file

1.1.0
-----
- Add `extract_xml()` and `human_timespamp_to_datetime` methods


1.0.5
-----
- Prefix public suffix and GeoIP2 database filenames with `.`
- Properly format errors list in CSV output

1.0.3
-----
- Fix documentation formatting

1.0.2
-----
- Fix more packaging flaws

1.0.1
-----
- Fix packaging flaw

1.0.0
-----
- Initial release
