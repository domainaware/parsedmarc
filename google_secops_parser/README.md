# Google SecOps (Chronicle) parser for parsedmarc

A [Google Security Operations](https://cloud.google.com/security/products/security-operations)
custom parser (configuration-based normalizer / CBN) that maps the JSON events
parsedmarc emits through its built-in `[syslog]` output to the Unified Data
Model (UDM).

This is a **SecOps-side parser only** — it requires no changes to parsedmarc.
parsedmarc already ships structured JSON over syslog; the DMARC→UDM mapping
lives here so that a downstream UDM schema change is a parser edit rather than a
parsedmarc release.

> **New to SecOps parsers?** SecOps ingests a log source by running a *parser*
> that turns each raw log line into a [Unified Data Model](https://cloud.google.com/chronicle/docs/event-processing/udm-overview)
> (UDM) event. These parsers are written in a Logstash-style configuration
> language Google calls a **configuration-based normalizer (CBN)** — the
> `parsedmarc.conf` in this directory is one. You attach it to a custom *log
> type*, and SecOps then runs it on every parsedmarc syslog line. Already fluent
> in CBN? Skip to [Installation](#installation).

## Status

> [!IMPORTANT]
> This parser was written strictly against the official Google documentation
> linked at the bottom of this file, but it has **not yet been validated against
> a live SecOps tenant**. Before using it in production, paste it into the SecOps
> parser-validation tool and confirm each sample event below parses and that the
> assertions in [Caveats](#caveats) hold. Please report fixes back to the
> [parsedmarc](https://github.com/domainaware/parsedmarc) project.

## Supported report types

parsedmarc emits three flat JSON shapes (one object per syslog line). The parser
detects them by a field unique to each and maps them as follows:

| parsedmarc report | Detected by | UDM `metadata.event_type` |
|---|---|---|
| DMARC aggregate | `xml_schema` | `EMAIL_TRANSACTION` |
| DMARC failure | `feedback_type` | `EMAIL_TRANSACTION` |
| SMTP TLS (RFC 8460) | `policy_type` | `GENERIC_EVENT` |

`EMAIL_TRANSACTION` and `GENERIC_EVENT` are both valid `metadata.event_type`
values. Note that **`GENERIC_EVENT` events only appear in raw-log and UDM
search**, not in the curated SecOps views — that is the documented behaviour for
generic events, and it is why SMTP TLS reports surface differently from the two
DMARC types.

## Caveats

1. **Unvalidated** — see [Status](#status).
2. **JSON type handling** — parsedmarc emits `dmarc_aligned` / `spf_aligned` /
   `dkim_aligned` / `testing` / `normalized_timespan` as JSON booleans and
   `count` / `*_session_count` / `source_asn` as numbers. Chronicle's `json{}`
   filter **preserves the original JSON type**, so the parser explicitly
   converts these to strings (`mutate { convert => { … => "string" } }`) before
   any comparison — otherwise `[dmarc_aligned] == "false"` would never match.
   Relatedly, every field tested in an `if` is initialized to `""` *before* the
   `json` filter, because CBN raises `_failed_parsing_` on a conditional that
   references a field absent from the log. A DMARC-fail record
   (`dmarc_aligned=false`) should yield `security_result.category =
   AUTH_VIOLATION` — still worth confirming in the validation tool.
3. **Aggregate count** — a DMARC aggregate record summarizes `count` messages
   from one source IP, not a single message. Each record becomes one
   `EMAIL_TRANSACTION` with `count` carried in `additional.fields`. There is no
   first-class per-message expansion (fanning out `count` copies would
   misrepresent the data).
4. **Address format** — aggregate reports only carry the From *domain*, so
   `network.email.from` holds a bare domain for aggregate events but a full
   address for failure events. UDM email-address fields are expected to be
   `local-mailbox@domain`; downstream consumers should account for the
   aggregate-domain case.

## UDM field mappings

All UDM field names below are from the
[UDM field list](https://cloud.google.com/chronicle/docs/reference/udm-field-list)
and [SecurityResult reference](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/SecurityResult).

### DMARC aggregate → `EMAIL_TRANSACTION`

| parsedmarc field | UDM field |
|---|---|
| `begin_date` | `metadata.event_timestamp` (via `date{}`) |
| `report_id` | `metadata.product_log_id` |
| `source_ip_address` | `principal.ip` |
| `source_reverse_dns` | `principal.hostname` |
| `source_country` | `principal.location.country_or_region` |
| `domain` | `target.hostname` |
| `header_from` | `network.email.from` (domain; see caveat 4) |
| `disposition` | `security_result.action` (`none`→`ALLOW`, `quarantine`→`QUARANTINE`, `reject`→`BLOCK`) |
| `dmarc_aligned=false` | `security_result.category = AUTH_VIOLATION` |
| `org_name`, `org_email`, `count`, `p`, `sp`, `np`, `pct`, `fo`, `adkim`, `aspf`, `testing`, `discovery_method`, `normalized_timespan`, `*_aligned`, `dkim_*`, `spf_*`, `policy_override_*`, `source_base_domain`, `source_name`, `source_type`, `source_asn`, `source_as_name`, `source_as_domain`, `envelope_from`, `envelope_to` | `additional.fields` |

### DMARC failure → `EMAIL_TRANSACTION`

| parsedmarc field | UDM field |
|---|---|
| `arrival_date_utc` | `metadata.event_timestamp` (via `date{}`) |
| `message_id` | `metadata.product_log_id`, `network.email.mail_id` |
| `source_ip_address` | `principal.ip` |
| `source_reverse_dns` | `principal.hostname` |
| `source_country` | `principal.location.country_or_region` |
| `reported_domain` | `target.hostname` |
| `original_mail_from` | `network.email.from` |
| `original_rcpt_to` | `network.email.to` |
| `subject` | `network.email.subject` |
| `auth_failure` | `security_result.category = AUTH_VIOLATION` + description |
| `delivery_result` | `security_result.action` (`reject`→`BLOCK`, `quarantine`→`QUARANTINE`, `delivered`→`ALLOW`) |
| `feedback_type`, `authentication_results`, `authentication_mechanisms`, `user_agent`, `dkim_domain`, `arrival_date` | `additional.fields` |

### SMTP TLS → `GENERIC_EVENT`

| parsedmarc field | UDM field |
|---|---|
| `begin_date` | `metadata.event_timestamp` (ISO 8601, via `date{}`) |
| `report_id` | `metadata.product_log_id` |
| `policy_domain` | `target.hostname` (always present → the noun) |
| `receiving_ip` | `target.ip` (failure rows only) |
| `sending_mta_ip` | `principal.ip` (failure rows only) |
| `result_type` | `security_result` (`action=FAIL`, `category=POLICY_VIOLATION`) |
| `organization_name`, `policy_type`, `policy_strings`, `mx_host_patterns`, `successful_session_count`, `failed_session_count`, `failure_reason_code`, `receiving_mx_hostname`, `receiving_mx_helo`, `additional_info_uri` | `additional.fields` |

> parsedmarc emits SMTP TLS reports as separate rows: one **success** row per
> policy (counts, no MTA IPs) and one **failure** row per failure detail (which
> may also lack MTA IPs, e.g. `sts-policy-fetch-error`). The noun therefore comes
> from `policy_domain`, which is present on every row.

## Installation

### 1. Configure parsedmarc syslog output

```ini
[syslog]
server = your-collector.example.com
port = 514
```

parsedmarc writes each report record as a single-line JSON message.

### 2. Collect the syslog stream into SecOps

Syslog is ingested by a **collector**, not a Feed. Run the
[Bindplane agent](https://cloud.google.com/chronicle/docs/install/install-forwarder)
(Google's recommended on-premises collector; the legacy Chronicle forwarder is
end-of-life) with a **Syslog** collector pointed at the port above, and assign it
a custom log type (for example `PARSEDMARC`).

### 3. Install this parser for that log type

Associate `parsedmarc.conf` with the custom log type via the SecOps parser
management UI or API (see
[Manage parsers](https://cloud.google.com/chronicle/docs/event-processing/manage-parser-updates)).
Validate against the sample events below before activating.

## Sample events for validation

These are **real** single-line outputs from parsedmarc's `[syslog]` serializers
(generated from the project's sample reports). Use them in the parser-validation
tool. A live syslog line will also carry a `<PRI>` prefix; the parser strips any
leading framing before the first `{`.

### DMARC Aggregate — fail (`dmarc_aligned=false`)

```json
{"xml_schema": "draft", "org_name": "accurateplastics.com", "org_email": "administrator@accurateplastics.com", "org_extra_contact_info": "", "report_id": "example.com:1538463741", "begin_date": "2018-10-01 17:07:12", "end_date": "2018-10-01 17:07:12", "normalized_timespan": false, "errors": "", "domain": "example.com", "adkim": "r", "aspf": "r", "p": "none", "sp": "reject", "np": "", "pct": "100", "fo": "", "testing": "", "discovery_method": "", "source_ip_address": "12.20.127.122", "source_country": "US", "source_reverse_dns": "", "source_base_domain": "", "source_name": "AT&T", "source_type": "ISP", "source_asn": 7018, "source_as_name": "AT&T Enterprises, LLC", "source_as_domain": "att.com", "count": 1, "spf_aligned": false, "dkim_aligned": false, "dmarc_aligned": false, "disposition": "none", "policy_override_reasons": "", "policy_override_comments": "", "envelope_from": "", "header_from": "example.com", "envelope_to": "", "dkim_domains": "", "dkim_selectors": "", "dkim_results": "", "spf_domains": "", "spf_scopes": "", "spf_results": ""}
```

### DMARC Aggregate — pass (`dmarc_aligned=true`)

```json
{"xml_schema": "1.0", "org_name": "example.org", "org_email": "noreply-dmarc-support@example.org", "org_extra_contact_info": "https://support.example.org/dmarc", "report_id": "20240125141224705995", "begin_date": "2024-01-25 05:12:24", "end_date": "2024-01-25 12:28:53", "normalized_timespan": false, "errors": "", "domain": "example.com", "adkim": "r", "aspf": "r", "p": "quarantine", "sp": "quarantine", "np": "", "pct": "100", "fo": "1", "testing": "", "discovery_method": "", "source_ip_address": "198.51.100.123", "source_country": "", "source_reverse_dns": "", "source_base_domain": "", "source_name": "", "source_type": "", "source_asn": "", "source_as_name": "", "source_as_domain": "", "count": 2, "spf_aligned": false, "dkim_aligned": true, "dmarc_aligned": true, "disposition": "none", "policy_override_reasons": "none", "policy_override_comments": "none", "envelope_from": "example.edu", "header_from": "example.com", "envelope_to": "example.net", "dkim_domains": "example.com", "dkim_selectors": "example", "dkim_results": "pass", "spf_domains": "example.edu", "spf_scopes": "mfrom", "spf_results": "pass"}
```

### DMARC Failure report

```json
{"feedback_type": "auth-failure", "user_agent": "Lua/1.0", "version": "1.0", "original_mail_from": "sharepoint@domain.de", "original_rcpt_to": "peter.pan@domain.de", "arrival_date": "Mon, 01 Oct 2018 11:20:27 +0200", "message_id": "<38.E7.30937.BD6E1BB5@ mailrelay.de>", "authentication_results": "dmarc=fail (p=none, dis=none) header.from=domain.de", "delivery_result": "policy", "auth_failure": "dmarc", "reported_domain": "domain.de", "arrival_date_utc": "2018-10-01 09:20:27", "authentication_mechanisms": "", "original_envelope_id": null, "dkim_domain": null, "sample_headers_only": false, "source_ip_address": "10.10.10.10", "source_reverse_dns": null, "source_base_domain": null, "source_name": null, "source_type": null, "source_asn": null, "source_as_name": null, "source_as_domain": null, "source_country": null, "subject": "Subject"}
```

### SMTP TLS — success row (counts only)

```json
{"organization_name": "Synametrics Technologies, Inc.", "begin_date": "2025-12-07T19:00:00Z", "end_date": "2025-12-08T18:59:59Z", "report_id": "1765256572301+dmarc-reports.dengage.com", "policy_strings": "version: STSv1|mode: enforce|mx: mta1.inboxsys.net|mx: mta2.inboxsys.net|max_age: 86400", "policy_domain": "dmarc-reports.dengage.com", "policy_type": "sts", "successful_session_count": 2, "failed_session_count": 0}
```

### SMTP TLS — failure-detail row

```json
{"organization_name": "Mail.ru", "begin_date": "2024-02-22T00:00:00Z", "end_date": "2024-02-23T00:00:00Z", "report_id": "b28254de-7b2e-be36-bb5c-4c3b92da8b25@mail.ru", "result_type": "sts-policy-fetch-error", "failed_session_count": 1, "failure_reason_code": "bad https response code: 404"}
```

## Official references

- [Overview of the UDM](https://cloud.google.com/chronicle/docs/event-processing/udm-overview)
- [UDM field list](https://cloud.google.com/chronicle/docs/reference/udm-field-list)
- [SecurityResult reference](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/SecurityResult)
- [Overview of log parsing](https://cloud.google.com/chronicle/docs/event-processing/parsing-overview)
- [Parser syntax reference](https://cloud.google.com/chronicle/docs/reference/parser-syntax)
- [Tips and troubleshooting when writing parsers](https://cloud.google.com/chronicle/docs/event-processing/parser-tips-troubleshooting) — intermediate fields are discarded unless mapped to `@output`; one parser is active per log type.
- [Manage prebuilt and custom parsers](https://cloud.google.com/chronicle/docs/event-processing/manage-parser-updates)
- [UDM search](https://cloud.google.com/chronicle/docs/investigation/udm-search) — `GENERIC_EVENT` events only surface in raw-log / UDM search, not curated views.
- [Install the Bindplane agent (collector)](https://cloud.google.com/chronicle/docs/install/install-forwarder)
- [Feed management](https://cloud.google.com/chronicle/docs/administration/feed-management-overview)

## Additional sources and tooling

Community resources (not official Google documentation) that informed this parser's JSON handling and are useful when validating it:

- [Parsing 101: Best Practices & Tips](https://medium.com/@thatsiemguy/parsing-101-best-practices-tips-c2e8b7ce9db8) (Chris Martin / @thatsiemguy) — basis for initializing every `if`-tested field before the `json` filter to avoid `_failed_parsing_`.
- [Corelight parser for SecOps](https://github.com/corelight/CorelightForSecOps) — a large production CBN parser that demonstrates the "convert JSON booleans/numbers to strings" idiom this parser relies on (the `json` filter preserves the original JSON type).
- [chronicle/cbn-tool](https://github.com/chronicle/cbn-tool) — CLI for the CBN parser APIs (submit and validate a parser).

## License

Distributed under the same license as [parsedmarc](https://github.com/domainaware/parsedmarc).
