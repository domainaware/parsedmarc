# Google SecOps (Chronicle) Output

`parsedmarc` can output DMARC reports to Google SecOps (Chronicle) in UDM (Unified Data Model) format.

## Configuration

To enable Google SecOps output, add a `[google_secops]` section to your configuration file:

```ini
[general]
save_aggregate = True
save_forensic = True

[google_secops]
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
- **security_result**: Severity level, description, and detection fields
- **additional.fields**: Extended metadata including report details, counts, and authentication results

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
    "description": "DMARC fail; disposition=none",
    "detection_fields": [
      {"key": "dmarc_disposition", "value": "none"},
      {"key": "dmarc_policy", "value": "none"},
      {"key": "dmarc_pass", "value": "false"},
      {"key": "spf_aligned", "value": "false"},
      {"key": "dkim_aligned", "value": "false"}
    ]
  }],
  "additional": {
    "fields": [
      {"key": "report_org", "value": "example.net"},
      {"key": "report_id", "value": "b043f0e264cf4ea995e93765242f6dfb"},
      {"key": "message_count", "value": "1"}
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
      {"key": "auth_failure", "value": "dmarc"}
    ]
  }],
  "additional": {
    "fields": [
      {"key": "arrival_date", "value": "2019-04-30 02:09:00"},
      {"key": "feedback_type", "value": "auth-failure"},
      {"key": "message_id", "value": "<01010101010101010101010101010101@ABAB01MS0016.someserver.loc>"}
    ]
  }
}
```

## Google SecOps Searches

Here are some example YARA-L rules you can use in Google SecOps to hunt for DMARC issues:

### Find all DMARC failures

```yara-l
rule dmarc_failures {
  meta:
    author = "parsedmarc"
    description = "Detect DMARC authentication failures"
    
  events:
    $e.metadata.event_type = "GENERIC_EVENT"
    $e.metadata.product_name = "parsedmarc"
    $e.principal.ip != ""
    $e.additional.fields.key = "dmarc_pass"
    $e.additional.fields.value = "false"
    
  condition:
    $e
}
```

### Find high severity DMARC events (rejected mail)

```yara-l
rule high_severity_dmarc_events {
  meta:
    author = "parsedmarc"
    description = "Detect high severity DMARC events (rejected mail)"
    
  events:
    $e.metadata.event_type = "GENERIC_EVENT"
    $e.metadata.product_name = "parsedmarc"
    $e.security_result.severity = "HIGH"
    
  condition:
    $e
}
```

### Find repeated DMARC failures from same source

```yara-l
rule repeated_dmarc_failures {
  meta:
    author = "parsedmarc"
    description = "Detect repeated DMARC failures from the same source IP"
    
  events:
    $e.metadata.event_type = "GENERIC_EVENT"
    $e.metadata.product_name = "parsedmarc"
    $e.additional.fields.key = "dmarc_pass"
    $e.additional.fields.value = "false"
    $e.principal.ip = $source_ip
    
  match:
    $source_ip over 1h
    
  condition:
    #e > 5
}
```

### Find forensic reports with specific authentication failures

```yara-l
rule forensic_auth_failures {
  meta:
    author = "parsedmarc"
    description = "Detect forensic reports with DMARC authentication failures"
    
  events:
    $e.metadata.event_type = "GENERIC_EVENT"
    $e.metadata.product_name = "parsedmarc"
    $e.additional.fields.key = "auth_failure"
    $e.additional.fields.value = "dmarc"
    
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

To output DMARC reports to Google SecOps, redirect stdout or use the output in your ingestion pipeline:

```bash
# Output to stdout
parsedmarc -c config.ini samples/aggregate/*.xml > dmarc_events.ndjson

# Stream to file
parsedmarc -c config.ini samples/aggregate/*.xml >> /var/log/dmarc/events.ndjson

# Use with a log shipper (e.g., Fluentd, Logstash)
parsedmarc -c config.ini samples/aggregate/*.xml | your-log-shipper
```

The output is in newline-delimited JSON format, with one UDM event per line, ready for ingestion into Google SecOps.
