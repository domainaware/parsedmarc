# Google SecOps Parser for parsedmarc

A [Google Security Operations (Chronicle)](https://cloud.google.com/security/products/security-operations) custom parser for ingesting [parsedmarc](https://domainaware.github.io/parsedmarc/) syslog events into the Unified Data Model (UDM).

## Overview

parsedmarc sends DMARC aggregate reports, forensic reports, and SMTP TLS reports as JSON-formatted syslog messages. This parser transforms those JSON events into Google SecOps UDM events for threat detection and investigation.

### Supported Report Types

| Report Type | UDM Event Type | Description |
|---|---|---|
| DMARC Aggregate | `EMAIL_TRANSACTION` | Aggregate DMARC authentication results from reporting organizations |
| DMARC Forensic | `EMAIL_TRANSACTION` | Individual email authentication failure reports |
| SMTP TLS | `GENERIC_EVENT` | SMTP TLS session success/failure reports (RFC 8460) |

## UDM Field Mappings

### DMARC Aggregate Reports

| parsedmarc Field | UDM Field | Notes |
|---|---|---|
| `source_ip_address` | `principal.ip` | IP address of the email source |
| `source_reverse_dns` | `principal.hostname` | Reverse DNS of source |
| `source_country` | `principal.location.country_or_region` | GeoIP country of source |
| `header_from` | `network.email.from` | From header domain |
| `envelope_from` | `network.email.mail_from` | Envelope sender |
| `envelope_to` | `network.email.to` | Envelope recipient |
| `domain` | `target.hostname` | Domain the report is about |
| `report_id` | `metadata.product_log_id` | Report identifier |
| `disposition` | `security_result.action` | `none`→`ALLOW`, `quarantine`→`QUARANTINE`, `reject`→`BLOCK` |
| `dmarc_aligned` | `additional.fields` | Whether DMARC passed |
| `spf_aligned` | `additional.fields` | Whether SPF was aligned |
| `dkim_aligned` | `additional.fields` | Whether DKIM was aligned |
| `org_name` | `additional.fields` | Reporting organization name |
| `count` | `additional.fields` | Number of messages |
| `p`, `sp`, `pct` | `additional.fields` | DMARC policy settings |
| `dkim_domains`, `dkim_results` | `additional.fields` | DKIM authentication details |
| `spf_domains`, `spf_results` | `additional.fields` | SPF authentication details |

### DMARC Forensic Reports

| parsedmarc Field | UDM Field | Notes |
|---|---|---|
| `source_ip_address` | `principal.ip` | IP address of the email source |
| `source_reverse_dns` | `principal.hostname` | Reverse DNS of source |
| `source_country` | `principal.location.country_or_region` | GeoIP country of source |
| `original_mail_from` | `network.email.from` | Original sender |
| `original_rcpt_to` | `network.email.to` | Original recipient |
| `subject` | `network.email.subject` | Email subject |
| `reported_domain` | `target.hostname` | Reported domain |
| `message_id` | `metadata.product_log_id` | Email message ID |
| `arrival_date_utc` | `metadata.event_timestamp` | Arrival timestamp (UTC) |
| `auth_failure` | `security_result.description` | Type of authentication failure |
| `feedback_type` | `additional.fields` | Feedback report type |
| `authentication_results` | `additional.fields` | Full authentication results string |
| `delivery_result` | `additional.fields` | Email delivery outcome |

### SMTP TLS Reports

| parsedmarc Field | UDM Field | Notes |
|---|---|---|
| `sending_mta_ip` | `principal.ip` | Sending MTA IP address |
| `receiving_ip` | `target.ip` | Receiving MTA IP address |
| `receiving_mx_hostname` | `target.hostname` | Receiving MX hostname |
| `report_id` | `metadata.product_log_id` | Report identifier |
| `organization_name` | `additional.fields` | Reporting organization |
| `policy_domain` | `additional.fields` | Policy domain |
| `policy_type` | `additional.fields` | TLS policy type |
| `successful_session_count` | `additional.fields` | Count of successful TLS sessions |
| `failed_session_count` | `additional.fields` | Count of failed TLS sessions |
| `result_type` | `additional.fields` | Failure result type |
| `failure_reason_code` | `additional.fields` | Failure reason code |

## Installation

### Prerequisites

- A Google Security Operations (Chronicle) tenant
- parsedmarc configured to send syslog output (see [parsedmarc documentation](https://domainaware.github.io/parsedmarc/))

### Steps

1. **Configure parsedmarc syslog output** in your `parsedmarc.ini`:

   ```ini
   [syslog]
   server = your-chronicle-forwarder.example.com
   port = 514
   ```

2. **Create the log source** in Google SecOps:
   - Navigate to **Settings** → **Feeds** → **Add New**
   - Select **Syslog** as the source type
   - Configure to listen for parsedmarc syslog messages

3. **Upload the custom parser**:
   - Navigate to **Settings** → **Parsers**
   - Click **Create Custom Parser**
   - Set the **Log Type** to match your feed configuration
   - Paste the contents of `parsedmarc.conf`
   - Click **Submit**

4. **Validate** the parser using the Chronicle parser validation tool with sample parsedmarc JSON events.

## Sample Log Events

### Aggregate Report

```json
{"xml_schema": "1.0", "org_name": "Example Inc", "org_email": "noreply@example.net", "report_id": "abc123", "begin_date": "2024-01-01 00:00:00", "end_date": "2024-01-01 23:59:59", "domain": "example.com", "adkim": "r", "aspf": "r", "p": "reject", "sp": "reject", "pct": "100", "fo": "0", "source_ip_address": "203.0.113.1", "source_country": "United States", "source_reverse_dns": "mail.example.org", "source_base_domain": "example.org", "count": 42, "spf_aligned": true, "dkim_aligned": true, "dmarc_aligned": true, "disposition": "none", "header_from": "example.com", "envelope_from": "example.com", "envelope_to": null, "dkim_domains": "example.com", "dkim_selectors": "selector1", "dkim_results": "pass", "spf_domains": "example.com", "spf_scopes": "mfrom", "spf_results": "pass"}
```

### Forensic Report

```json
{"feedback_type": "auth-failure", "user_agent": "Lua/1.0", "version": "1.0", "original_mail_from": "sender@example.com", "original_rcpt_to": "recipient@example.org", "arrival_date": "Mon, 01 Jan 2024 12:00:00 +0000", "arrival_date_utc": "2024-01-01 12:00:00", "source_ip_address": "198.51.100.1", "source_country": "Germany", "source_reverse_dns": "mail.example.com", "source_base_domain": "example.com", "subject": "Test Email", "message_id": "<abc@example.com>", "authentication_results": "dmarc=fail (p=reject; dis=reject) header.from=example.com", "dkim_domain": "example.com", "delivery_result": "reject", "auth_failure": "dmarc", "reported_domain": "example.com", "authentication_mechanisms": "dmarc"}
```

### SMTP TLS Report

```json
{"organization_name": "Example Inc", "begin_date": "2024-01-01 00:00:00", "end_date": "2024-01-01 23:59:59", "report_id": "tls-123", "policy_domain": "example.com", "policy_type": "sts", "policy_strings": "version: STSv1; mode: enforce", "mx_host_patterns": "*.mail.example.com", "successful_session_count": 1000, "failed_session_count": 5, "result_type": "certificate-expired", "sending_mta_ip": "203.0.113.10", "receiving_ip": "198.51.100.20", "receiving_mx_hostname": "mx.example.com", "receiving_mx_helo": "mx.example.com", "failure_reason_code": "X509_V_ERR_CERT_HAS_EXPIRED"}
```

## UDM Reference

For the complete list of UDM fields, see the [Google SecOps UDM field list](https://cloud.google.com/chronicle/docs/reference/udm-field-list).

## License

This parser is part of the [parsedmarc](https://github.com/domainaware/parsedmarc) project and is distributed under the same license.
