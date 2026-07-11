# Google SecOps (Chronicle) parser for parsedmarc

A [Google Security Operations](https://cloud.google.com/security/products/security-operations)
custom parser (configuration-based normalizer / CBN) that maps the JSON events
parsedmarc emits through its built-in `[syslog]` output to the Unified Data
Model (UDM).

> **Prefer an API-based setup?** parsedmarc also ships a `[gsecops]` output
> that sends the same UDM events directly to the Chronicle API
> (`events.import`), with no collector or custom parser to install — see the
> `gsecops` section of the parsedmarc usage documentation. Use this parser
> instead when you want collector-based ingestion with raw-log retention, or
> when you already run a Bindplane pipeline. Both paths use the same UDM
> mapping and the same `additional` field keys, so searches and dashboards
> port between them.

This is a **SecOps-side parser** — parsedmarc already ships structured JSON
over syslog, and the DMARC→UDM mapping lives here so that a downstream UDM
schema change is a parser edit rather than a parsedmarc release. One paired
library fix ships alongside it: SMTP TLS failure-detail rows carry
`policy_domain` / `policy_type` as of the parsedmarc release that includes this
parser. Older parsedmarc versions omit those keys on failure rows; the parser
still detects such rows via `result_type`, but a row that carries neither an
MTA IP nor an MX hostname (e.g. `sts-policy-fetch-error`) then has no UDM noun
and will not produce a valid event.

> **New to SecOps parsers?** SecOps ingests a log source by running a *parser*
> that turns each raw log line into a [Unified Data Model](https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview)
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
| --- | --- | --- |
| DMARC aggregate | `xml_schema` | `EMAIL_TRANSACTION` |
| DMARC failure | `feedback_type` or `arrival_date_utc` | `EMAIL_TRANSACTION` |
| SMTP TLS (RFC 8460) | `policy_type` or `result_type` | `GENERIC_EVENT` |

The `or` fallbacks matter: text-format failure reports have no `Feedback-Type`
field (parsedmarc emits no `feedback_type` key for them, but always computes
`arrival_date_utc`), and SMTP TLS failure-detail rows from parsedmarc versions
older than this parser lack `policy_type` (every RFC 8460 failure detail has a
`result_type`). `xml_schema` needs no fallback: parsedmarc always sets it on
aggregate rows so that output parsers like this one can detect them.

`EMAIL_TRANSACTION` and `GENERIC_EVENT` are both valid `metadata.event_type`
values. Note that **`GENERIC_EVENT` events only appear in raw-log and UDM
search**, not in the curated SecOps views — that is the documented behaviour for
generic events, and it is why SMTP TLS reports surface differently from the two
DMARC types.

## Caveats

1. **Unvalidated** — see [Status](#status).
2. **JSON types** — Chronicle's `json{}` filter **preserves the original JSON
   type**, so parsedmarc's booleans and numbers are handled differently:
   - **Booleans** (`dmarc_aligned` / `spf_aligned` / `dkim_aligned` /
     `normalized_timespan`) are converted to strings because CBN conditionals
     compare against the preserved type, so `[dmarc_aligned] == "false"` needs
     a string. In `additional.fields` they are stored as typed **`bool_value`**
     — built as a string, `convert`-ed back to `boolean`, then renamed — the
     boolean pattern from Google's
     [parser extension examples](https://docs.cloud.google.com/chronicle/docs/event-processing/parser-extension-examples);
     UDM search matches them with `value.bool_value`. Note that `testing` is
     **not** a boolean — parsedmarc emits the RFC 9990 `t=` flag as the string
     `"y"`/`"n"` — so it is passed through as a string and guarded with
     `!= ""`.
   - **Numbers** (`count` / `*_session_count` / `source_asn`) are stored as
     `number_value` — built as a string, `convert`-ed to `uinteger`, then
     renamed — so SecOps can range-query and sort them (parsedmarc's "store
     numbers as numbers" rule). Each numeric interpolation carries `on_error`
     so a tenant where `%{}` rejects non-string fields degrades to a missing
     `additional.fields` entry instead of `_failed_parsing_`.

   Both value types match what the `[gsecops]` API output emits, so UDM
   searches and dashboards port between the two delivery paths unchanged.

   Every `if`-tested field is initialized to `""` *before* `json` and guarded
   with `!= ""`: CBN raises `_failed_parsing_` on a conditional referencing an
   absent field, and treats an initialized-but-empty field as present. A
   DMARC-fail record (`dmarc_aligned=false`) should yield
   `security_result.category = AUTH_VIOLATION` — worth confirming in the
   validation tool.
3. **JSON nulls** — failure-report rows are the only shape that emits JSON
   `null` values (see the failure sample below: `dkim_domain`, `source_*`).
   Google's docs cover *absent* fields (the `""` initialization above) but are
   silent on whether `json{}` overwrites an initialized field with a null.
   This is why the failure sample should be the **first** event pasted into
   the validation tool.
4. **Aggregate count** — a DMARC aggregate record summarizes `count` messages
   from one source IP, not a single message. Each record becomes one
   `EMAIL_TRANSACTION` with `count` carried in `additional.fields`. There is no
   first-class per-message expansion (fanning out `count` copies would
   misrepresent the data).
5. **Address format** — aggregate reports only carry the From *domain*, so
   `network.email.from` holds a bare domain for aggregate events but a full
   address for failure events. UDM email-address fields are expected to be
   `local-mailbox@domain`; downstream consumers should account for the
   aggregate-domain case.

## UDM field mappings

All UDM field names below are from the
[UDM field list](https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list)
and [SecurityResult reference](https://docs.cloud.google.com/chronicle/docs/reference/rest/v1alpha/SecurityResult).

### DMARC aggregate → `EMAIL_TRANSACTION`

| parsedmarc field | UDM field |
| --- | --- |
| `begin_date` | `metadata.event_timestamp` (via `date{}`) |
| `report_id` | `metadata.product_log_id` |
| `source_ip_address` | `principal.ip` |
| `source_reverse_dns` | `principal.hostname` |
| `source_country` | `principal.location.country_or_region` |
| `domain` | `target.hostname` |
| `header_from` | `network.email.from` (domain; see caveat 4) |
| `disposition` | `security_result.action` (`none`→`ALLOW`, `quarantine`→`QUARANTINE`, `reject`→`BLOCK`) |
| `dmarc_aligned=false` | `security_result.category = AUTH_VIOLATION` |
| `org_name`, `org_email`, `org_extra_contact_info`, `errors`, `count`, `p`, `sp`, `np`, `pct`, `fo`, `adkim`, `aspf`, `testing`, `discovery_method`, `normalized_timespan`, `*_aligned`, `dkim_*`, `spf_*`, `policy_override_*`, `source_base_domain`, `source_name`, `source_type`, `source_asn`, `source_as_name`, `source_as_domain`, `envelope_from`, `envelope_to` | `additional.fields` |

### DMARC failure → `EMAIL_TRANSACTION`

| parsedmarc field | UDM field |
| --- | --- |
| `arrival_date_utc` | `metadata.event_timestamp` (via `date{}`) |
| `message_id` | `metadata.product_log_id`, `network.email.mail_id` |
| `source_ip_address` | `principal.ip` |
| `source_reverse_dns` | `principal.hostname` |
| `source_country` | `principal.location.country_or_region` |
| `reported_domain` | `target.hostname` |
| `original_mail_from` | `network.email.from` |
| `original_rcpt_to` | `network.email.to` (repeated field → merged) |
| `subject` | `network.email.subject` (repeated field → merged) |
| `delivery_result` | `security_result.action` (`reject`→`BLOCK`, `quarantine`→`QUARANTINE`, `delivered`→`ALLOW`); `security_result.category` is always `AUTH_VIOLATION` |
| `feedback_type`, `auth_failure`, `delivery_result`, `authentication_results`, `authentication_mechanisms`, `user_agent`, `dkim_domain`, `arrival_date`, `source_base_domain`, `source_name`, `source_type`, `source_asn`, `source_as_name`, `source_as_domain` | `additional.fields` |

### SMTP TLS → `GENERIC_EVENT`

| parsedmarc field | UDM field |
| --- | --- |
| `begin_date` | `metadata.event_timestamp` (ISO 8601, via `date{}`) |
| `report_id` | `metadata.product_log_id` |
| `policy_domain` | `target.hostname` (the noun; falls back to `receiving_mx_hostname` when absent) |
| `receiving_ip` | `target.ip` (failure rows only) |
| `sending_mta_ip` | `principal.ip` (failure rows only) |
| `result_type` | `security_result` (`action=FAIL`, `category=POLICY_VIOLATION`) — failure rows only |
| `organization_name`, `policy_type`, `policy_strings`, `mx_host_patterns`, `successful_session_count`, `failed_session_count`, `failure_reason_code`, `receiving_mx_hostname`, `receiving_mx_helo`, `additional_info_uri` | `additional.fields` |

> parsedmarc emits SMTP TLS reports as separate rows: one **success** row per
> policy (counts, no MTA IPs) and one **failure** row per failure detail (which
> may also lack MTA IPs, e.g. `sts-policy-fetch-error`). As of the parsedmarc
> release that ships this parser, every row — success and failure — carries
> `policy_domain` and `policy_type`, so the noun is always available. Rows from
> older parsedmarc versions omit both on failure details; those are detected
> via `result_type` and fall back to `receiving_mx_hostname` for the noun.

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
[Bindplane agent](https://docs.cloud.google.com/chronicle/docs/install/install-forwarder)
(Google's recommended on-premises collector; the legacy Chronicle forwarder is
end-of-life) with a **Syslog** collector pointed at the port above, and assign it
a custom log type (for example `PARSEDMARC`).

### 3. Install this parser for that log type

Associate `parsedmarc.conf` with the custom log type via the SecOps parser
management UI or API (see
[Manage parsers](https://docs.cloud.google.com/chronicle/docs/event-processing/manage-parser-updates)).
Validate against the sample events below before activating.

## Sample events for validation

These are **real** single-line outputs from parsedmarc's `[syslog]` serializers,
generated from this repository's sample reports (the source file is named on
each event). Use them in the parser-validation tool. A live syslog line will
also carry a `<PRI>` prefix; the parser strips any leading framing before the
first `{`.

Suggested order:

1. **DMARC failure first** — it is the only shape containing JSON `null`
   values (caveat 3), the least-documented `json{}` behaviour this parser
   depends on.
2. The two aggregates — confirm the `dmarc_aligned=false` one yields
   `security_result.category = AUTH_VIOLATION`, that `count` and `source_asn`
   land as `number_value`, and that the alignment booleans land as
   `bool_value` (queryable as `additional.fields["dmarc_aligned"].value.bool_value`).
3. The SMTP TLS rows — confirm the success row produces a `GENERIC_EVENT` with
   `target.hostname` and no `security_result`, and the failure rows produce
   `security_result.action = FAIL`.

### DMARC failure report — from `samples/failure/DMARC Failure Report for domain.de (…).eml` (note the JSON nulls)

```json
{"feedback_type": "auth-failure", "user_agent": "Lua/1.0", "version": "1.0", "original_mail_from": "sharepoint@domain.de", "original_rcpt_to": "peter.pan@domain.de", "arrival_date": "Mon, 01 Oct 2018 11:20:27 +0200", "message_id": "<38.E7.30937.BD6E1BB5@ mailrelay.de>", "authentication_results": "dmarc=fail (p=none, dis=none) header.from=domain.de", "delivery_result": "policy", "auth_failure": "dmarc", "reported_domain": "domain.de", "arrival_date_utc": "2018-10-01 09:20:27", "authentication_mechanisms": "", "original_envelope_id": null, "dkim_domain": null, "sample_headers_only": false, "source_ip_address": "10.10.10.10", "source_reverse_dns": null, "source_base_domain": null, "source_name": null, "source_type": null, "source_asn": null, "source_as_name": null, "source_as_domain": null, "source_country": null, "subject": "Subject"}
```

### DMARC Aggregate — fail (`dmarc_aligned=false`) — from `samples/aggregate/!example.com!1538204542!1538463818.xml`

```json
{"xml_schema": "draft", "org_name": "accurateplastics.com", "org_email": "administrator@accurateplastics.com", "org_extra_contact_info": "", "report_id": "example.com:1538463741", "begin_date": "2018-10-01 17:07:12", "end_date": "2018-10-01 17:07:12", "normalized_timespan": false, "errors": "", "domain": "example.com", "adkim": "r", "aspf": "r", "p": "none", "sp": "reject", "np": "", "pct": "100", "fo": "", "testing": "", "discovery_method": "", "source_ip_address": "12.20.127.122", "source_country": "US", "source_reverse_dns": "", "source_base_domain": "", "source_name": "AT&T", "source_type": "ISP", "source_asn": 7018, "source_as_name": "AT&T Enterprises, LLC", "source_as_domain": "att.com", "count": 1, "spf_aligned": false, "dkim_aligned": false, "dmarc_aligned": false, "disposition": "none", "policy_override_reasons": "", "policy_override_comments": "", "envelope_from": "", "header_from": "example.com", "envelope_to": "", "dkim_domains": "", "dkim_selectors": "", "dkim_results": "", "spf_domains": "", "spf_scopes": "", "spf_results": ""}
```

### DMARC Aggregate — pass (`dmarc_aligned=true`) — from `samples/aggregate/empty_reason.xml`

```json
{"xml_schema": "1.0", "org_name": "example.org", "org_email": "noreply-dmarc-support@example.org", "org_extra_contact_info": "https://support.example.org/dmarc", "report_id": "20240125141224705995", "begin_date": "2024-01-25 05:12:24", "end_date": "2024-01-25 12:28:53", "normalized_timespan": false, "errors": "", "domain": "example.com", "adkim": "r", "aspf": "r", "p": "quarantine", "sp": "quarantine", "np": "", "pct": "100", "fo": "1", "testing": "", "discovery_method": "", "source_ip_address": "198.51.100.123", "source_country": "", "source_reverse_dns": "", "source_base_domain": "", "source_name": "", "source_type": "", "source_asn": "", "source_as_name": "", "source_as_domain": "", "count": 2, "spf_aligned": false, "dkim_aligned": true, "dmarc_aligned": true, "disposition": "none", "policy_override_reasons": "none", "policy_override_comments": "none", "envelope_from": "example.edu", "header_from": "example.com", "envelope_to": "example.net", "dkim_domains": "example.com", "dkim_selectors": "example", "dkim_results": "pass", "spf_domains": "example.edu", "spf_scopes": "mfrom", "spf_results": "pass"}
```

### SMTP TLS — success row (counts only) — from `samples/smtp_tls/rfc8460.json`

```json
{"organization_name": "Company-X", "begin_date": "2016-04-01T00:00:00Z", "end_date": "2016-04-01T23:59:59Z", "report_id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be", "policy_domain": "company-y.example", "policy_type": "sts", "policy_strings": "version: STSv1|mode: testing|mx: *.mail.company-y.example|max_age: 86400", "successful_session_count": 5326, "failed_session_count": 303}
```

### SMTP TLS — failure-detail row with MTA IPs — from `samples/smtp_tls/rfc8460.json`

```json
{"organization_name": "Company-X", "begin_date": "2016-04-01T00:00:00Z", "end_date": "2016-04-01T23:59:59Z", "report_id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be", "policy_domain": "company-y.example", "policy_type": "sts", "policy_strings": "version: STSv1|mode: testing|mx: *.mail.company-y.example|max_age: 86400", "result_type": "starttls-not-supported", "failed_session_count": 200, "sending_mta_ip": "2001:db8:abcd:0013::1", "receiving_ip": "203.0.113.56", "receiving_mx_hostname": "mx2.mail.company-y.example"}
```

### SMTP TLS — failure-detail row without MTA IPs — from `samples/smtp_tls/mail.ru.json`

```json
{"organization_name": "Mail.ru", "begin_date": "2024-02-22T00:00:00Z", "end_date": "2024-02-23T00:00:00Z", "report_id": "b28254de-7b2e-be36-bb5c-4c3b92da8b25@mail.ru", "policy_domain": "example.com", "policy_type": "sts", "result_type": "sts-policy-fetch-error", "failed_session_count": 1, "failure_reason_code": "bad https response code: 404"}
```

## Official references

- [Overview of the UDM](https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview)
- [UDM field list](https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list)
- [SecurityResult reference](https://docs.cloud.google.com/chronicle/docs/reference/rest/v1alpha/SecurityResult)
- [Overview of log parsing](https://docs.cloud.google.com/chronicle/docs/event-processing/parsing-overview)
- [Parser syntax reference](https://docs.cloud.google.com/chronicle/docs/reference/parser-syntax)
- [Tips and troubleshooting when writing parsers](https://docs.cloud.google.com/chronicle/docs/event-processing/parser-tips-troubleshooting) — intermediate fields are discarded unless mapped to `@output`; one parser is active per log type.
- [Manage prebuilt and custom parsers](https://docs.cloud.google.com/chronicle/docs/event-processing/manage-parser-updates)
- [Chronicle content-hub](https://github.com/chronicle/content-hub) — Google's official repository of third-party SecOps parsers. Its CBN parsers (e.g. [`CLOUDFLARE_PAGESHIELD`](https://github.com/chronicle/content-hub/tree/main/content/parsers/third_party/community/CLOUDFLARE_PAGESHIELD)) use the same conventions this one does: initialize fields before `json`, `convert` JSON types to strings, map to `event.idm.read_only_udm.*`, and finalize with `@output`.
- [UDM search](https://docs.cloud.google.com/chronicle/docs/investigation/udm-search) — `GENERIC_EVENT` events only surface in raw-log / UDM search, not curated views.
- [Install the Bindplane agent (collector)](https://docs.cloud.google.com/chronicle/docs/install/install-forwarder)
- [Feed management](https://docs.cloud.google.com/chronicle/docs/administration/feed-management-overview)

## Additional sources and tooling

Community resources (not official Google documentation) that informed this parser's JSON handling and are useful when validating it:

- [Parsing 101: Best Practices & Tips](https://medium.com/@thatsiemguy/parsing-101-best-practices-tips-c2e8b7ce9db8) (Chris Martin / @thatsiemguy) — basis for initializing every `if`-tested field before the `json` filter to avoid `_failed_parsing_`.
- [Corelight parser for SecOps](https://github.com/corelight/CorelightForSecOps) — a large production CBN parser that demonstrates converting type-preserved JSON booleans to strings before testing them in conditionals, which this parser does in step 1b (storage is a separate matter: this parser stores booleans as typed `bool_value` per Google's parser extension examples).
- [chronicle/cbn-tool](https://github.com/chronicle/cbn-tool) — CLI for the CBN parser APIs (submit and validate a parser).

## License

Distributed under the same license as [parsedmarc](https://github.com/domainaware/parsedmarc).
