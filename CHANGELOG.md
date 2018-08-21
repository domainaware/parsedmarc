3.7.4
-----

- Workaround older versions of the dovecot mail server not reporting existing 
folders correctly (#5)
'
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
