# Google SecOps (Chronicle) Output

`parsedmarc` can output DMARC reports to Google SecOps (Chronicle) in UDM (Unified Data Model) format.

## Configuration

To enable Google SecOps output, add a `[google_secops]` section to your configuration file:

### Primary Method: Chronicle Ingestion API

The recommended approach is to send events directly to Chronicle via the Ingestion API:

```ini
[general]
save_aggregate = True
save_forensic = True

[google_secops]
# Required: Path to Google service account JSON credentials file
api_credentials_file = /path/to/service-account-credentials.json

# Required: Chronicle customer ID
api_customer_id = your-customer-id-here

# Optional: Chronicle region (default: us)
# Options: us, europe, asia-southeast1, me-central2, australia-southeast1
api_region = us

# Optional: Log type for Chronicle ingestion (default: DMARC)
api_log_type = DMARC

# Optional: Include forensic report message payload (default: False)
# For privacy, message bodies are excluded by default
include_ruf_payload = False

# Optional: Maximum bytes of forensic message payload to include (default: 4096)
ruf_payload_max_bytes = 4096

# Optional: Static observer name for telemetry identification
static_observer_name = my-parsedmarc-instance

# Optional: Static observer vendor (default: parsedmarc)
static_observer_vendor = parsedmarc

# Optional: Static environment label (e.g., prod, dev)
static_environment = prod
```

### Alternative Method: stdout Output

If you prefer to use an external log shipper (Fluentd, Logstash, Chronicle forwarder), set `use_stdout = True`:

```ini
[google_secops]
# Output to stdout instead of Chronicle API
use_stdout = True

# Other optional configuration options (as above)
include_ruf_payload = False
ruf_payload_max_bytes = 4096
static_observer_name = my-instance
static_observer_vendor = parsedmarc
static_environment = prod
```

## Output Format

The Google SecOps output produces newline-delimited JSON (NDJSON) in Chronicle UDM format, which can be ingested into Google SecOps for hunting and dashboarding.

### Event Types

1. **DMARC_AGGREGATE**: One event per aggregate report row, preserving count and period information
2. **DMARC_FORENSIC**: One event per forensic report
3. **SMTP_TLS_REPORT**: One event per SMTP TLS failure detail
4. **DMARC_PARSE_ERROR**: Generated when parsing fails (does not crash)

### UDM Schema

Each event includes:

- **metadata**: Event timestamp, type, product name, and vendor
- **principal**: Source IP address, location (country), and hostname (reverse DNS)
- **target**: Domain name (from DMARC policy)
- **security_result**: Severity level, description, and detection fields for dashboarding
  - **detection_fields**: Key DMARC dimensions for filtering and grouping (e.g., `dmarc.disposition`, `dmarc.pass`, `dmarc.header_from`, `dmarc.report_org`, `dmarc.source_service_name`, `dmarc.source_service_type`)
  - All dashboard-relevant fields use `dmarc.*` or `smtp_tls.*` prefixes for easy identification
  - Includes IP enrichment data (service name and type from reverse DNS mapping) for enhanced filtering
- **additional.fields** (optional): Low-value context fields (e.g., detailed auth results) not typically used for dashboarding

**Design Rationale**: DMARC dimensions are placed in `security_result[].detection_fields` rather than `additional.fields` because Chronicle dashboards, stats searches, and aggregations work best with UDM label arrays. The `additional.fields` is a protobuf Struct intended for opaque context and is not reliably queryable for dashboard operations.

### Severity Heuristics

- **HIGH**: DMARC disposition = reject
- **MEDIUM**: DMARC disposition = quarantine with partial SPF/DKIM failures
- **LOW**: DMARC disposition = none or pass

## Example Output

### Aggregate Report Event

```json
{
  "event_type": "DMARC_AGGREGATE",
  "metadata": {
    "event_timestamp": "2018-06-19T00:00:00+00:00",
    "event_type": "GENERIC_EVENT",
    "product_name": "parsedmarc",
    "vendor_name": "parsedmarc"
  },
  "principal": {
    "ip": ["199.230.200.36"],
    "location": {"country_or_region": "US"}
  },
  "target": {
    "domain": {"name": "example.com"}
  },
  "security_result": [{
    "severity": "LOW",
    "description": "DMARC fail; SPF=pass; DKIM=pass; SPF not aligned; DKIM not aligned; disposition=none",
    "detection_fields": [
      {"key": "dmarc.disposition", "value": "none"},
      {"key": "dmarc.policy", "value": "none"},
      {"key": "dmarc.pass", "value": false},
      {"key": "dmarc.spf_aligned", "value": false},
      {"key": "dmarc.dkim_aligned", "value": false},
      {"key": "dmarc.header_from", "value": "example.com"},
      {"key": "dmarc.envelope_from", "value": "example.com"},
      {"key": "dmarc.report_org", "value": "example.net"},
      {"key": "dmarc.report_id", "value": "b043f0e264cf4ea995e93765242f6dfb"},
      {"key": "dmarc.report_begin", "value": "2018-06-19 00:00:00"},
      {"key": "dmarc.report_end", "value": "2018-06-19 23:59:59"},
      {"key": "dmarc.row_count", "value": 1},
      {"key": "dmarc.spf_result", "value": "pass"},
      {"key": "dmarc.dkim_result", "value": "pass"},
      {"key": "dmarc.source_service_name", "value": "Example Mail Service"},
      {"key": "dmarc.source_service_type", "value": "email"}
    ]
  }],
  "additional": {
    "fields": [
      {"key": "spf_0_domain", "value": "example.com"},
      {"key": "spf_0_result", "value": "pass"},
      {"key": "dkim_0_domain", "value": "example.com"},
      {"key": "dkim_0_result", "value": "pass"}
    ]
  }
}
```

### Forensic Report Event

```json
{
  "event_type": "DMARC_FORENSIC",
  "metadata": {
    "event_timestamp": "2019-04-30T02:09:00+00:00",
    "event_type": "GENERIC_EVENT",
    "product_name": "parsedmarc",
    "vendor_name": "parsedmarc"
  },
  "principal": {
    "ip": ["10.10.10.10"]
  },
  "target": {
    "domain": {"name": "example.com"}
  },
  "security_result": [{
    "severity": "MEDIUM",
    "description": "DMARC forensic report: authentication failure (dmarc)",
    "detection_fields": [
      {"key": "dmarc.auth_failure", "value": "dmarc"},
      {"key": "dmarc.reported_domain", "value": "example.com"},
      {"key": "dmarc.source_service_name", "value": "Example Mail Provider"},
      {"key": "dmarc.source_service_type", "value": "email"}
    ]
  }],
  "additional": {
    "fields": [
      {"key": "feedback_type", "value": "auth-failure"},
      {"key": "message_id", "value": "<01010101010101010101010101010101@ABAB01MS0016.someserver.loc>"},
      {"key": "authentication_results", "value": "dmarc=fail (p=none; dis=none) header.from=example.com"},
      {"key": "delivery_result", "value": "delivered"}
    ]
  }
}
```

### SMTP TLS Report Event

```json
{
  "event_type": "SMTP_TLS_REPORT",
  "metadata": {
    "event_timestamp": "2016-04-01T00:00:00+00:00",
    "event_type": "GENERIC_EVENT",
    "product_name": "parsedmarc",
    "vendor_name": "parsedmarc"
  },
  "target": {
    "domain": {
      "name": "company-y.example"
    }
  },
  "security_result": [{
    "severity": "LOW",
    "description": "SMTP TLS failure: certificate-expired",
    "detection_fields": [
      {"key": "smtp_tls.policy_domain", "value": "company-y.example"},
      {"key": "smtp_tls.result_type", "value": "certificate-expired"},
      {"key": "smtp_tls.failed_session_count", "value": 100},
      {"key": "smtp_tls.report_org", "value": "Company-X"},
      {"key": "smtp_tls.report_begin", "value": "2016-04-01T00:00:00Z"},
      {"key": "smtp_tls.report_end", "value": "2016-04-01T23:59:59Z"}
    ]
  }],
  "principal": {
    "ip": ["2001:db8:abcd:0012::1"]
  }
}
```

### Parse Error Event

```json
{
  "event_type": "DMARC_PARSE_ERROR",
  "metadata": {
    "event_timestamp": "2026-01-09T16:22:10.933751+00:00",
    "event_type": "GENERIC_EVENT",
    "product_name": "parsedmarc",
    "vendor_name": "parsedmarc"
  },
  "security_result": [{
    "severity": "ERROR",
    "description": "Failed to parse DMARC report: Invalid XML structure"
  }]
}
```

## Google SecOps Searches

Here are some example YARA-L rules you can use in Google SecOps to hunt for DMARC issues:

### Find all DMARC aggregate report failures

```yara-l
rule dmarc_aggregate_failures {
  meta:
    author = "parsedmarc"
    description = "Detect DMARC authentication failures in aggregate reports"
    
  events:
    $e.metadata.product_name = "parsedmarc"
    $e.event_type = "DMARC_AGGREGATE"
    $e.security_result.detection_fields.key = "dmarc.pass"
    $e.security_result.detection_fields.value = false
    
  condition:
    $e
}
```

### Find high severity DMARC events (rejected mail)

```yara-l
rule high_severity_dmarc_events {
  meta:
    author = "parsedmarc"
    description = "Detect high severity DMARC aggregate events (rejected mail)"
    
  events:
    $e.metadata.product_name = "parsedmarc"
    $e.event_type = "DMARC_AGGREGATE"
    $e.security_result.severity = "HIGH"
    
  condition:
    $e
}
```

### Find repeated DMARC failures from same source IP

```yara-l
rule repeated_dmarc_failures {
  meta:
    author = "parsedmarc"
    description = "Detect repeated DMARC failures from the same source IP"
    
  events:
    $e.metadata.product_name = "parsedmarc"
    $e.event_type = "DMARC_AGGREGATE"
    $e.security_result.detection_fields.key = "dmarc.pass"
    $e.security_result.detection_fields.value = false
    $e.principal.ip = $source_ip
    
  match:
    $source_ip over 1h
    
  condition:
    #e > 5
}
```

### Find DMARC forensic reports with authentication failures

```yara-l
rule dmarc_forensic_failures {
  meta:
    author = "parsedmarc"
    description = "Detect DMARC forensic reports with authentication failures"
    
  events:
    $e.metadata.product_name = "parsedmarc"
    $e.event_type = "DMARC_FORENSIC"
    $e.security_result.detection_fields.key = "dmarc.auth_failure"
    
  condition:
    $e
}
```

### Find DMARC failures from specific mail service types

```yara-l
rule dmarc_failures_by_service_type {
  meta:
    author = "parsedmarc"
    description = "Detect DMARC failures from specific mail service types"
    
  events:
    $e.metadata.product_name = "parsedmarc"
    $e.event_type = "DMARC_AGGREGATE"
    $e.security_result.detection_fields.key = "dmarc.pass"
    $e.security_result.detection_fields.value = false
    $e.security_result.detection_fields.key = "dmarc.source_service_type"
    $e.security_result.detection_fields.value = "email"
    
  condition:
    $e
}
```

### Find SMTP TLS failures

```yara-l
rule smtp_tls_failures {
  meta:
    author = "parsedmarc"
    description = "Detect SMTP TLS failures"
    
  events:
    $e.metadata.product_name = "parsedmarc"
    $e.event_type = "SMTP_TLS_REPORT"
    
  condition:
    $e
}
```

## Privacy Considerations

By default, forensic report message bodies are **excluded** from the output to protect privacy. If you need to include message samples for investigation:

1. Set `include_ruf_payload = True` in your configuration
2. Adjust `ruf_payload_max_bytes` to limit the amount of data included (default: 4096 bytes)
3. Message samples will be truncated if they exceed the configured maximum

**Note**: Be aware of data privacy regulations (GDPR, CCPA, etc.) when including message payloads in security telemetry.

## Usage

The Google SecOps output works with all parsedmarc input methods, including file processing and mailbox monitoring.

### Primary Method: Direct API Ingestion

With Chronicle Ingestion API configured, events are sent directly to Chronicle:

```bash
# Process files - events are sent to Chronicle API automatically
parsedmarc -c config.ini samples/aggregate/*.xml

# Monitor mailbox - events are sent to Chronicle API in real-time
parsedmarc -c config.ini
```

No additional log shippers or pipelines are needed. The Google SecOps client handles authentication and batching automatically.

### Alternative Method: stdout Output with Log Shipper

If using `use_stdout = True` in your configuration, output DMARC reports to an external log shipper:

#### Processing Files

```bash
# Output to stdout
parsedmarc -c config.ini samples/aggregate/*.xml > dmarc_events.ndjson

# Stream to file
parsedmarc -c config.ini samples/aggregate/*.xml >> /var/log/dmarc/events.ndjson

# Pipe to log shipper (e.g., Fluentd, Logstash, Chronicle forwarder)
parsedmarc -c config.ini samples/aggregate/*.xml | fluentd
```

#### Monitoring Mailboxes

The Google SecOps output automatically works when monitoring mailboxes via IMAP, Microsoft Graph, or Gmail API. Configure your mailbox connection and enable watching:

```ini
[general]
save_aggregate = True
save_forensic = True

[mailbox]
watch = True
delete = False
batch_size = 10

[imap]
host = imap.example.com
user = dmarc@example.com
password = yourpassword

[google_secops]
# Use stdout mode for log shipper integration
use_stdout = True
include_ruf_payload = False
static_observer_name = mailbox-monitor
static_environment = prod
```

When watching a mailbox with stdout mode, parsedmarc continuously outputs UDM events as new reports arrive:

```bash
parsedmarc -c config.ini | fluentd
```

The output is in newline-delimited JSON format, with one UDM event per line, ready for collection by your log shipper.
