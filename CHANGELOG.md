4.0.0
-----

- Add support for sending DMARC reports to a Splunk HTTP Events 
Collector (HEC)
- Use a browser-like `User-Agent` when downloading the Public Suffix List and 
GeoIP DB to avoid being blocked by security proxies
- Reduce default DNS timeout to 2.0 seconds
- Add alignment booleans to JSON output

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
