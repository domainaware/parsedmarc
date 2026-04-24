# Changelog

## 9.10.2

### Fixed

- `MaildirConnection.fetch_message()` now marks messages as read after reading them (sets the `S` flag and moves the file from `new/` to `cur/`), unless `--test` is in effect. Previously, a message was processed but its on-disk maildir state was unchanged, so an MUA scanning the same maildir kept showing it as unread. Mirrors the existing `mark_read=not test` pattern used for `MSGraphConnection`.
- `get_ip_address_info()` no longer caches weak-fallback attributions (no PTR + no ASN-domain map match → raw `as_name` used as `source_name`, `source_type` left null). `get_reverse_dns()` swallows every `DNSException` as `None`, so a transient PTR lookup failure (timeout, SERVFAIL, socket error) is indistinguishable from a genuine no-PTR case at that layer — caching the weak result would poison the 4-hour cache with a misattribution that persisted even after the PTR became resolvable again. PTR-backed matches and ASN-domain matches (both stable attributions) are still cached as before; only the specific `reverse_dns=None AND type=None AND name=as_name` state skips the cache write so the next lookup retries.

## 9.10.1

### Fixed

- Stripped speculative behavior from the IPinfo Lite REST API integration shipped in 9.10.0 after auditing the code against the [Lite API docs](https://ipinfo.io/developers/lite-api). The docs state the Lite API has "no daily or monthly limit and provides unlimited access" and document `?token=` query-parameter auth only; nothing else removed here is documented for Lite. Removed: the 429 rate-limit and 402 quota-exhausted handling, `Retry-After` parsing, cooldown state, and the associated warning/recovery logging; the `https://ipinfo.io/me` account-info probe that expected plan/limit/remaining fields (that endpoint isn't a Lite account endpoint); and the `Authorization: Bearer` header. Auth is now the documented `?token=` query param; the startup probe is a single `/lite/1.1.1.1` lookup that logs `IPinfo API configured` at info level. Retained behavior: 401/403 remains a fatal `InvalidIPinfoAPIKey`, and any other non-2xx or network error falls back to the bundled/cached MMDB per request.

## 9.10.0

### Changes

- Renamed `[general] ip_db_url` to `ipinfo_url` to reflect what it actually overrides (the bundled IPinfo Lite MMDB download URL). The old name is still accepted as a deprecated alias and logs a warning on use; the env-var equivalent is now `PARSEDMARC_GENERAL_IPINFO_URL`, with `PARSEDMARC_GENERAL_IP_DB_URL` also still honored.
- Added an optional IPinfo Lite REST API path for country + ASN lookups, so deployments that want the freshest data can query the API directly instead of waiting for the next MMDB release. Configure `[general] ipinfo_api_token` (or `PARSEDMARC_GENERAL_IPINFO_API_TOKEN`) and every IP lookup hits `https://api.ipinfo.io/lite/<ip>` first. At startup the `https://ipinfo.io/me` account endpoint is hit once to validate the token and log the plan, month-to-date usage, and remaining quota at info level (e.g. `IPinfo API configured — plan: Lite, usage: 12345/50000 this month, 37655 remaining`). An invalid token exits the process with a fatal error. Rate-limit (HTTP 429) and quota-exhausted (HTTP 402) responses put the API in a cooldown (honoring `Retry-After`, with a 5-minute / 1-hour default) and fall through to the bundled/cached MMDB; the first event is logged once at warning level and recovery is logged once at info level when the next lookup succeeds. Transient network errors fall through per-request without triggering a cooldown. The API token is never logged.
- Renamed the ASN name and domain fields to match the IPinfo Lite MMDB's native schema: `asn_name` → `as_name` and `asn_domain` → `as_domain` on every source record (JSON output), and `source_asn_name` → `source_as_name` / `source_asn_domain` → `source_as_domain` in CSV output (aggregate + forensic) and the Elasticsearch / OpenSearch / Splunk integrations. The integer `asn` / `source_asn` field is unchanged. The emitted order is `asn`, `as_name`, `as_domain`.

### Upgrade notes

- CSV / JSON / Elasticsearch / OpenSearch / Splunk consumers that query the 9.9.0 field names (`asn_name`, `asn_domain`, `source_asn_name`, `source_asn_domain`) must switch to `as_name`, `as_domain`, `source_as_name`, `source_as_domain`. Elasticsearch / OpenSearch will add the new mappings on next document write; existing documents indexed under the old names will stay in place until reindexed.

## 9.9.0

### Changes

- Source attribution now has an ASN fallback. Every IP source record carries three new fields — `asn` (integer, e.g. `15169`), `asn_name` (`"Google LLC"`), and `asn_domain` (`"google.com"`) — sourced from the bundled IPinfo Lite MMDB. When an IP has no reverse DNS, `get_ip_address_info()` uses `asn_domain` as a lookup into the same `reverse_dns_map`, and if that misses, falls back to the raw `asn_name`. `reverse_dns` and `base_domain` stay null on ASN-derived rows so consumers can still distinguish PTR-derived from ASN-derived attribution.
- Added `source_asn`, `source_asn_name`, `source_asn_domain` to CSV output (aggregate + forensic), JSON output, and the Elasticsearch / OpenSearch / Splunk integrations. `source_asn` is mapped as `Integer` at the schema level so consumers can do range queries and numeric sorts; dashboards can prepend `"AS"` at display time.
- Expanded `base_reverse_dns_map.csv` with 500 ASN-domain aliases for the most-routed IPv4 ranges. IPv4-weighted coverage of the bundled `ipinfo_lite.mmdb` went from ~34% of routed space matching a map entry via ASN domain to ~85%. Every alias is a brand that was already in the map under a different rDNS-base key (e.g. adding `comcast.com` alongside the existing `comcast.net`), plus a small number of large operators that previously had no entry. 11 entries were also promoted out of `known_unknown_base_reverse_dns.txt` because ASN context made their identity unambiguous.
- Added `get_ip_address_db_record()` in `parsedmarc.utils`, a single-open MMDB reader that returns country + ASN fields together. `get_ip_address_country()` is now a thin wrapper. Supports both IPinfo Lite's schema (`country_code`, `asn` as `"AS15169"`, `as_name`, `as_domain`) and MaxMind's (`country.iso_code`, `autonomous_system_number` as int, `autonomous_system_organization`) in one pass; ASN is normalized to a plain int from either. MaxMind users who drop in their own ASN MMDB get `asn` + `asn_name` populated; `asn_domain` stays null because MaxMind doesn't carry it.

### Fixed

- `get_ip_address_info()` now caches entries for IPs without reverse DNS. Previously the cache write was inside the `if reverse_dns is not None` branch, so every no-PTR IP re-did the MMDB read and DNS attempt on every call.
- Fixed three bugs in `parsedmarc/resources/maps/sortlists.py` that silently disabled the `type`-column validator and sorted the map case-sensitively, contrary to its documented behavior:
  - Validator allowed-values map was keyed on `"Type"` (capital T), but the CSV header is `"type"` (lowercase), so every row bypassed validation.
  - Types were read with trailing newlines via `f.readlines()`, so comparisons would not have matched even if the column name had been right.
  - `sort_csv()` was called without `case_insensitive_sort=True`, which moved the sole mixed-case key (`United-domains.de`) to the top of the file instead of into its alphabetical position.
- Fixed eight pre-existing map rows with invalid or inconsistent `type` values that the now-working validator surfaced: casing corrections for `dhl.com` (`logistics` → `Logistics`), `ghm-grenoble.fr` (`healthcare` → `Healthcare`), and `regusnet.com` (`Real estate` → `Real Estate`); reclassified `lodestonegroup.com` from the nonexistent `Insurance` type to `Finance`; added missing `Religion` and `Utilities` entries to `base_reverse_dns_types.txt` so it matches the README's industry list.
- Fixed the `rt.ru` map entry: was classified as `RT,Government Media`, which conflated Rostelecom (the Russian telco that owns and uses `rt.ru`) with RT / Russia Today (which uses `rt.com`). Corrected to `Rostelecom,ISP`.

### Upgrade notes

- Output schema change: CSV, JSON, Elasticsearch, OpenSearch, and Splunk all gain three new fields per row (`source_asn`, `source_asn_name`, `source_asn_domain`). Existing queries and dashboards keep working; dashboards that want to consume the new fields will need to be updated. Elasticsearch / OpenSearch will add the new mappings on next document write.
- Rows for IPs without reverse DNS now populate `source_name` / `source_type` via ASN fallback. If downstream dashboards treated "null `source_name`" as a signal for "no rDNS", switch to checking `source_reverse_dns IS NULL` instead — that remains the unambiguous signal.

## 9.8.0

### Changes

- Replaced the bundled DB-IP Country Lite database with the [IPinfo Lite] database (`parsedmarc/resources/ipinfo/ipinfo_lite.mmdb`, under the [Creative Commons Attribution-ShareAlike 4.0 License][cc-by-sa-4]) for greater IP-to-country lookup accuracy. The download URL / cached filename / packaged module path have all moved from `dbip/dbip-country-lite.mmdb` to `ipinfo/ipinfo_lite.mmdb`.
- `get_ip_address_country()` now reads MMDBs with `maxminddb` directly and handles both schemas — the IPinfo flat-top-level `country_code` field and the MaxMind/DBIP nested `country.iso_code` field — so users who drop in their own MMDB from any of these providers continue to work. The in-disk search list for user-supplied files still includes `ipinfo_lite.mmdb`, `GeoLite2-Country.mmdb`, and `dbip-country-lite*.mmdb`.
- Dropped the `geoip2` dependency (its only use was the `.country()` helper, which is incompatible with the IPinfo schema). Added `maxminddb` as a direct dependency — it was already installed transitively through `geoip2`, so this is a no-op for most environments.

### Upgrade notes

- Callers that imported `parsedmarc.resources.dbip` directly need to switch to `parsedmarc.resources.ipinfo`. The `parsedmarc.resources.dbip` module has been removed.
- Callers that imported `geoip2` only because `parsedmarc` depended on it will need to add it to their own requirements. `parsedmarc` itself no longer depends on `geoip2`.
- The auto-update download URL used by previous parsedmarc versions (`.../dbip/dbip-country-lite.mmdb`) is no longer hosted on `master`; those versions will fail to download and fall back to their bundled copy, which is the documented behavior of `load_ip_db()`.

[IPinfo Lite]: https://ipinfo.io/lite
[cc-by-sa-4]: https://creativecommons.org/licenses/by-sa/4.0/deed.en

## 9.7.1

### Changes

- Ported DNS lookup reliability improvements from checkdmarc 5.15.x:
  - Per-query UDP timeout is now capped at `min(1.0, timeout)` in `query_dns()`, so a single dropped UDP datagram no longer consumes the entire lifetime budget — dnspython retries UDP within the lifetime window (mirroring `dig`'s default `+tries=3`). With multiple nameservers configured, the same cap also makes a slow or broken nameserver fall through to the next quickly.
  - With multiple nameservers configured, the resolver lifetime is now `timeout × len(nameservers)` so each nameserver gets its own timeout budget for failover rather than sharing one overall deadline.
  - New `retries` kwarg on `query_dns()`, `get_reverse_dns()`, and `get_ip_address_info()` retries the whole query on transient errors (`LifetimeTimeout`, `NoNameservers`/SERVFAIL, and `OSError` during TCP fallback). `NXDOMAIN` and `NoAnswer` remain non-retryable. Default is 0 (no behavior change for existing callers).
  - Threaded `dns_retries` through the parser API (`parse_report_file`, `parse_aggregate_report_xml`, `parse_forensic_report`, `parse_report_email`, `get_dmarc_reports_from_mbox`, `get_dmarc_reports_from_mailbox`, `watch_inbox`).
- Added `--dns-retries N` CLI flag and `dns_retries` INI option (`[general]` section, also surfaced via `PARSEDMARC_GENERAL_DNS_RETRIES` env var).
- Centralized DNS defaults in `parsedmarc.constants`: `DEFAULT_DNS_TIMEOUT`, `DEFAULT_DNS_MAX_RETRIES`, and `RECOMMENDED_DNS_NAMESERVERS` (a cross-provider mix — `("1.1.1.1", "8.8.8.8")` — for callers that want public-resolver failover). The existing default nameservers (all-Cloudflare) are preserved for backward compatibility; callers opt in by passing `nameservers=RECOMMENDED_DNS_NAMESERVERS`.

## 9.7.0

### Changes

- `psl_overrides.txt` is now automatically downloaded at startup (and on SIGHUP in watch mode) by `load_psl_overrides()` in `parsedmarc.utils`, with the same URL / local-file / offline fallback pattern as the reverse DNS map. It is also reloaded whenever `load_reverse_dns_map()` runs, so `base_reverse_dns_map.csv` entries that depend on a recent overrides entry resolve correctly without requiring a new parsedmarc release.
- Added the `local_psl_overrides_path` and `psl_overrides_url` configuration options (`[general]` section, also surfaced via `PARSEDMARC_GENERAL_*` env vars) to override the default PSL overrides source.
- Expanded `base_reverse_dns_map.csv` substantially in this release, following a multi-pass classification pass across the unknown/known-unknown lists (net ~+1,000 entries).
- Added `Religion` and `Utilities` to the allowed `type` values in `base_reverse_dns_types.txt` and documented them in `parsedmarc/resources/maps/README.md`.
- Added `parsedmarc/resources/maps/collect_domain_info.py` — a bulk enrichment collector that runs WHOIS, a size-capped HTTP GET, and A/AAAA + IP-WHOIS for every unmapped reverse-DNS base domain, writing a compact TSV suitable for a single classification pass. Respects `psl_overrides.txt` and skips full-IP entries.
- Added `parsedmarc/resources/maps/detect_psl_overrides.py` — scans `unknown_base_reverse_dns.csv` for IP-containing entries that share a brand suffix, auto-appends the suffix to `psl_overrides.txt`, folds affected entries in all three list files, and removes any remaining full-IP entries for privacy.
- `find_unknown_base_reverse_dns.py` now drops full-IP entries at ingest so customer IPs never enter the pipeline.
- Documented the full map-maintenance workflow (privacy rule, auto-override detection, conservative classification, known-unknown handling) in the top-level `AGENTS.md`.

### Fixed

- Reverse-DNS base domains containing a full IPv4 address (four dotted or dashed octets) are now blocked from entering `base_reverse_dns_map.csv`, `known_unknown_base_reverse_dns.txt`, and `unknown_base_reverse_dns.csv`. Customer IPs were previously possible in these lists as part of ISP-generated reverse-DNS subdomain patterns. The filter is enforced in `find_unknown_base_reverse_dns.py`, `collect_domain_info.py`, and `detect_psl_overrides.py`. The existing lists were swept and all pre-existing IP-containing entries removed.

## 9.6.0

### Changes

- The included DB-IP Country Lite database is now automatically updated at startup (and on SIGHUP in watch mode) by downloading the latest copy from GitHub, unless the `offline` flag is set. Falls back to a previously cached copy or the bundled database on failure. This allows the IP-to-country database to stay current without requiring a new package release.
- Updated the included DB-IP Country Lite database to the 2026-04 release.
- Added the `ip_db_url` configuration option (`PARSEDMARC_GENERAL_IP_DB_URL` env var) to override the default download URL for the IP-to-country database.

## 9.5.5

### Fixed

- Output client initialization now retries up to 4 times with exponential backoff before exiting. This fixes persistent `Connection refused` errors in Docker when OpenSearch or Elasticsearch is momentarily unavailable at startup.
- Use tuple format for `http_auth` in OpenSearch and Elasticsearch connections, matching the documented convention and avoiding potential issues if the password contains a colon.
- Fix current_time format for MSGraphConnection (current-time) (PR #708)

### Changes

- Added debug logging to all output client initialization (S3, syslog, Splunk HEC, Kafka, GELF, webhook, Elasticsearch, OpenSearch).
- `DEBUG=true` and `PARSEDMARC_DEBUG=true` are now accepted as short aliases for `PARSEDMARC_GENERAL_DEBUG=true`.

## 9.5.4

### Fixed

- Maildir `fetch_messages` now respects the `reports_folder` argument. Previously it always read from the top-level Maildir, ignoring the configured reports folder. `fetch_message`, `delete_message`, and `move_message` now also operate on the correct active folder.
- Config key aliases for env var compatibility: `[maildir] create` and `path` are now accepted as aliases for `maildir_create` and `maildir_path`, and `[msgraph] url` for `graph_url`. This allows natural env var names like `PARSEDMARC_MAILDIR_CREATE` to work without the redundant `PARSEDMARC_MAILDIR_MAILDIR_CREATE`.

## 9.5.3

### Fixed

- Fixed `FileNotFoundError` when using Maildir with Docker volume mounts. Python's `mailbox.Maildir(create=True)` only creates `cur/new/tmp` subdirectories when the top-level directory doesn't exist; Docker volume mounts pre-create the directory as empty, skipping subdirectory creation. parsedmarc now explicitly creates the subdirectories when `maildir_create` is enabled.
- Maildir UID mismatch no longer crashes the process. In Docker containers where volume ownership differs from the container UID, parsedmarc now logs a warning instead of raising an exception. Also handles `os.setuid` failures gracefully in containers without `CAP_SETUID`.
- Token file writes (MS Graph and Gmail) now create parent directories automatically, preventing `FileNotFoundError` when the token path points to a directory that doesn't yet exist.
- File paths from config (`token_file`, `credentials_file`, `cert_path`, `log_file`, `output`, `ip_db_path`, `maildir_path`, syslog cert paths, etc.) now expand `~` and `$VAR` references via `os.path.expanduser`/`os.path.expandvars`.

## 9.5.2

### Fixed

- Fixed `ValueError: invalid interpolation syntax` when config values (from env vars or INI files) contain `%` characters, such as in passwords. Disabled ConfigParser's `%`-based string interpolation.

## 9.5.1

### Changes

- Correct ISO format for MSGraphConnection timestamps (PR #706)

## 9.5.0

### Added

- Environment variable configuration support: any config option can now be set via `PARSEDMARC_{SECTION}_{KEY}` environment variables (e.g. `PARSEDMARC_IMAP_PASSWORD`, `PARSEDMARC_SPLUNK_HEC_TOKEN`). Environment variables override config file values but are overridden by CLI arguments.
- `PARSEDMARC_CONFIG_FILE` environment variable to specify the config file path without the `-c` flag.
- Env-only mode: parsedmarc can now run without a config file when `PARSEDMARC_*` environment variables are set, enabling fully file-less Docker deployments.
- Explicit read permission check on config file, giving a clear error message when the container UID cannot read the file (e.g. `chmod 600` with a UID mismatch).

## 9.4.0

### Added

- Extracted `load_reverse_dns_map()` utility function in `utils.py` for loading the reverse DNS map independently of individual IP lookups.
- SIGHUP reload now re-downloads/reloads the reverse DNS map, so changes take effect without restarting.
- Add premade OpenSearch index patterns, visualizations, and dashboards

### Changed

- When `index_prefix_domain_map` is configured, SMTP TLS reports for domains not in the map are now silently dropped instead of being output. Unlike DMARC, TLS-RPT has no DNS authorization records, so this filtering prevents processing reports for unrelated domains.
- Bump OpenSearch support to `< 4`

### Fixed

- Fixed `get_index_prefix` using wrong key (`domain` instead of `policy_domain`) for SMTP TLS reports, which prevented domain map matching from working for TLS reports.
- Domain matching in `get_index_prefix` now lowercases the domain for case-insensitive comparison.

## 9.3.1

### Breaking changes

- Elasticsearch and OpenSearch now verify SSL certificates by default when `ssl = True`, even without a `cert_path`
- Added `skip_certificate_verification` option to the `elasticsearch` and `opensearch` configuration sections for consistency with `splunk_hec`

### Fixed

- Splunk HEC `skip_certificate_verification` now works correctly
- SMTP TLS reports no longer fail when saving to multiple output targets (e.g. Elasticsearch and OpenSearch) due to in-place mutation of the report dict
- Output client initialization errors now identify which module failed (e.g. "OpenSearch: ConnectionError..." instead of generic "Output client error")

## 9.3.0

### Added

- SIGHUP-based configuration reload for watch mode — update output destinations, DNS/GeoIP settings, processing flags, and log level without restarting the service or interrupting in-progress report processing.
  - Use `systemctl reload parsedmarc` when running under `systemd`.
  - On a successful reload, old output clients are closed and recreated.
  - On a failed reload, the previous configuration remains fully active.
- `close()` methods on `GelfClient`, `KafkaClient`, `SyslogClient`, `WebhookClient`, HECClient, and `S3Client` for clean resource teardown on reload.
- `config_reloading` parameter on all `MailboxConnection.watch()` implementations and `watch_inbox()` to ensure SIGHUP never triggers a new email batch mid-reload.
- Elasticsearch and OpenSearch connections are now tracked and cleaned up on reload via `_close_output_clients()`.
- Extracted `_parse_config_file()` and `_init_output_clients()` from `_main()` in `cli.py` to support config reload and reduce code duplication.

### Fixed

- `get_index_prefix()` crashed on forensic reports with `TypeError` due to `report()` instead of `report[]` dict access.
- Missing `exit(1)` after IMAP user/password validation failure allowed execution to continue with `None` credentials.

## 9.2.1

### Added

- Better checking of `msgraph` configuration (PR #695)

### Changed

- Updated `dbip-country-lite` database to version `2026-03`
- DNS query error logging level from `warning` to `debug`

## 9.2.0

### Added

- OpenSearch AWS SigV4 authentication support (PR #673)
- IMAP move/delete compatibility fallbacks (PR #671)
- `fail_on_output_error` CLI option for sink failures (PR #672)
- Gmail service account auth mode for non-interactive runs (PR #676)
- Microsoft Graph certificate authentication support (PRs #692 and #693)
- Microsoft Graph well-known folder fallback for root listing failures (PR #618 and #684 close #609)

### Fixed

- Pass mailbox since filter through `watch_inbox` callback (PR #670 closes issue #581)
- `parsedmarc.mail.gmail.GmailConnection.delete_message` now properly calls the Gmail API (PR #668)
- Avoid extra mailbox fetch in batch and test mode (PR #691 closes #533)

## 9.1.2

### Fixes

- Fix duplicate detection for normalized aggregate reports in Elasticsearch/OpenSearch (PR #666 fixes issue #665)

## 9.1.1

### Fixes

- Fix the use of Elasticsearch and OpenSearch API keys (PR #660 fixes issue #653)

### Changes

- Drop support for Python 3.9 (PR #661)

## 9.1.0

## Enhancements

- Add TCP and TLS support for syslog output. (#656)
- Skip DNS lookups in GitHub Actions to prevent DNS timeouts during tests timeouts. (#657)
- Remove microseconds from DMARC aggregate report time ranges before parsing them.

## 9.0.10

- Support Python 3.14+

## 9.0.9

### Fixes

- Validate that a string is base64-encoded before trying to base64 decode it. (PRs #648 and #649)

## 9.0.8

### Fixes

- Fix logging configuration not propagating to child parser processes (#646).
- Update `mailsuite` dependency to `?=1.11.1` to solve issues with iCloud IMAP (#493).

## 9.0.7

## Fixes

- Fix IMAP `since` option (#PR 645 closes issues #581 and #643).

## 9.0.6

### Fixes

- Fix #638.
- Fix/clarify report extraction and parsing behavior for multiple input types (bytes, base64 strings, and file-like objects).
- Fix type mismatches that could cause runtime issues in SMTP emailing and CLI option handling.

### Improvements

- Improve type hints across the library (Pylance/Pyright friendliness) and reduce false-positive linter errors.
- Emails in Microsoft 365 are now marked read as they are read. This provides constancy with other mailbox types, and gives you a indication of when emails are being read as they are processed in batches. (Close #625)

### Compatibility / Dependencies

- Set Python requirement to `>=3.9,<3.14`.
- Bump `mailsuite` requirement to `>=1.11.0`.

## 9.0.5

## Fixes

- Fix report type detection introduced in `9.0.4`.

## 9.0.4 (Yanked)

### Fixes

- Fix saving reports to OpenSearch ([#637](https://github.com/domainaware/parsedmarc/issues/637))
- Fix parsing certain DMARC failure/forensic reports
- Some fixes to type hints (incomplete, but published as-is due to the above bugs)

## 9.0.3

### Fixes

- Set `requires-python` to `>=3.9, <3.14` to avoid [this bug](https://github.com/python/cpython/issues/142307)

## 9.0.2

## Improvements

- Type hinting is now used properly across the entire library. (#445)

## Fixes

- Decompress report files as needed when passed via the CLI.
- Fixed incomplete removal of the ability for `parsedmarc.utils.extract_report` to accept a file path directly in `8.15.0`.

## Breaking changes

This version of the library requires consumers to pass certain arguments as keyword-only. Internally, the API uses a bare `*` in the function signature. This is standard per [PEP 3102](https://peps.python.org/pep-3102/)  and as documented in the Python Language Reference.

## 9.0.1

### Fixes

- Allow multiple `records` for the same aggregate DMARC report in Elasticsearch and Opensearch

## 9.0.0 (yanked)

- Normalize aggregate DMARC report volumes when a report timespan exceeds 24 hours

## 8.19.1

- Ignore HTML content type in report email parsing (#626)

## 8.19.0

- Add multi-tenant support via an index-prefix domain mapping file
- PSL overrides so that services like AWS are correctly identified
- Additional improvements to report type detection
- Fix webhook timeout parsing (PR #623)
- Output to STDOUT when the new general config boolean `silent` is set to `False` (Close #614)
- Additional services added to `base_reverse_dns_map.csv`

## 8.18.9

- Complete fix for #687 and more robust report type detection

## 8.18.8

- Fix parsing emails with an uncompressed aggregate report attachment (Closes #607)
- Add `--no-prettify-json` CLI option (PR #617)

## 8.18.7

Removed improper spaces from  `base_reverse_dns_map.csv` (Closes #612)

## 8.18.6

- Fix since option to correctly work with weeks (PR #604)
- Add 183 entries to `base_reverse_dns_map.csv`
- Add 57 entries to `known_unknown_base_reverse_dns.txt`
- Check for invalid UTF-8 bytes in `base_reverse_dns_map.csv` at build
- Exclude unneeded items from the `parsedmarc.resources` module at build

## 8.18.5

- Fix CSV download

## 8.18.4

- Fix webhooks

## 8.18.3

- Move `__version__` to `parsedmarc.constants`
- Create a constant `USER_AGENT`
- Use the HTTP `User-Agent` header value `parsedmarc/version` for all HTTP requests

## 8.18.2

- Merged PR #603
  - Fixes issue #595 - CI test fails for Elasticsearch
    - Moved Elasticsearch to a separate Docker service container for CI testing
    - Dropped Python 3.8 from CI testing
  - Fixes lookup and saving of DMARC forensic reports in Elasticsearch and OpenSearch
- Updated fallback `base_reverse_dns_map.csv`, which now includes over 1,400 lines
- Updated included `dbip-country-lite.mmdb` to the June 2025 release
- Automatically fall back to the internal `base_reverse_dns_map.csv` if the received file is not valid (Fixes #602)
  - Print the received data to the debug log

## 8.18.1

- Add missing `https://` to the default Microsoft Graph URL

## 8.18.0

- Add support for Microsoft national clouds via Graph API base URL (PR #590)
- Avoid stopping processing when an invalid DMARC report is encountered (PR #587)
- Increase `http.client._MAXHEADERS` from `100` to `200` to avoid errors connecting to Elasticsearch/OpenSearch (PR #589)

## 8.17.0

- Ignore duplicate aggregate DMARC reports with the same `org_name` and `report_id` seen within the same hour (Fixes #535)
- Fix saving SMTP TLS reports to OpenSearch (PR #585 closed issue #576)
- Add 303 entries to `base_reverse_dns_map.csv`

## 8.16.1

- Failed attempt to ignore aggregate DMARC reports seen within a period of one hour (#535)

## 8.16.0

- Add a `since` option to only search for emails since a certain time (PR #527)

## 8.15.4

- Fix crash if aggregate report timespan is > 24 hours

## 8.15.3

- Ignore aggregate reports with a timespan of > 24 hours (Fixes #282)

## 8.15.2

- Require `mailsuite>=1.9.18`
  - Pins `mail-parser` version at `3.15.0` due to a parsing regression in mail-parser `4.0.0`
  - Parse aggregate reports with empty `<auth_results>`
  - Do not overwrite the log on each run (PR #569 fixes issue #565)

## 8.15.1

- Proper IMAP namespace fix (Closes issue #557 and issue #563)
  - Require `mailsuite>=1.9.17`
  - Revert PR #552
- Add pre-flight check for nameservers (PR #562 closes issue #543)
- Reformat code with `ruff`

## 8.15.0

- Fix processing of SMTP-TLS reports ([#549](https://github.com/domainaware/parsedmarc/issues/549)), which broke in commit [410663d](https://github.com/domainaware/parsedmarc/commit/410663dbcaba019ca3d3744946348b56a635480b)(PR [#530](https://github.com/domainaware/parsedmarc/pull/530))
  - This PR enforced a stricter check for base64-encoded strings, which SMTP TLS reports from Google did not pass
  - Removing the check introduced its own issue, because some file paths were treated as base64-encoded strings
- Create a separate `extract_report_from_file_path()` function for processioning reports based on a file path
- Remove report extraction based on a file path from `extract_report()`

## 8.14.2

- Update `base_reverse_dns_map.csv` to fix over-replacement on [`f3a5f10`](https://github.com/domainaware/parsedmarc/commit/f3a5f10d67b02c5db31ae1f7ced68028f46ca2a3) (PR #553)

## 8.14.1

- Failed attempt to fix processing of SMTP-TLS reports (#549)

## 8.14.0

- Skip invalid aggregate report rows without calling the whole report invalid
  - Some providers such as GoDaddy will send reports with some rows missing a source IP address, while other rows are fine
- Fix Dovecot support by using the separator provided by the IMAP namespace when possible (PR #552 closes #551)
- Only download `base_reverse_dns_map.csv` once (fixes #542)
- Update included `base_reverse_dns_map.csv`
  - Replace University category with Education to be more inclusive
- Update included `dbip-country-lite.mmdb`

## 8.13.0

- Add Elastic/OpenSearch index prefix option (PR #531 closes #159)
- Add GELF output support (PR #532)

## 8.12.0

- Fix for deadlock with large report (#508)
- Build: move to kafka-python-ng (#510)
- Fix new config variables previously not propagated in the code (#524)
- Fixes for kafka integration (#522)
- Fix if base_domain is None before get_service_from_reverse_dns_base_domain (#514)
- Update base_reverse_dns_map.csv

## 8.11.0

- Actually save `source_type` and `source_name` to Elasticsearch and OpenSearch
- Reverse-lookup cache improvements (PR #501 closes issue #498)
- Update the included `dbip-country-lite.mmdb` to the 2024-03 version
- Update `base_reverse_dns_map.csv`
- Add new general config options (closes issue #500)
  - `always_use_local_files` - Disables the download of the reverse DNS map
  - `local_reverse_dns_map_path` - Overrides the default local file path to use for the reverse DNS map
  - `reverse_dns_map_url` - Overrides the default download URL for the reverse DNS map

## 8.10.3

- Fix flaws in `base_reverse_dns_map.csv`

## 8.10.2

- Fix flaws in `base_reverse_dns_map.csv`

## 8.10.1

- Fix flaws in `base_reverse_dns_map.csv`

## 8.10.0

- Fix MSGraph UsernamePassword Authentication (PR #497)
- Attempt to download an updated `base_reverse_dns_map.csv` at runtime
- Update included `base_reverse_dns_map.csv`

## 8.9.4

- Update `base_reverse_dns_map.csv`

## 8.9.3

- Revert change in 8.9.2

## 8.9.2

- Use `Uncategorized` instead of `None` as the service type when a service cannot be identified

## 8.9.1

- Fix broken CLI by removing obsolete parameter from `cli_parse` call (PR #496 closes issue #495)

## 8.9.0

- Fix broken cache (PR #494)
- Add source name and type information based on static mapping of the reverse DNS base domain
  - See [this documentation](https://github.com/domainaware/parsedmarc/tree/master/parsedmarc/resources/maps) for more information, and to learn how to help!
- Replace `multiprocessing.Pool` with `Pipe` + `Process` (PR #491 closes issue #489)
- Remove unused parallel arguments (PR #492 closes issue #490)

## 8.8.0

- Add support for OpenSearch (PR #481 closes #480)
- Fix SMTP TLS reporting to Elasticsearch (PR #470)

## 8.7.0

- Add support for SMTP TLS reports (PR #453 closes issue #71)
- Do not replace content in forensic samples (fix #403)
- Pin `msgraph-core` dependency at version `0.2.2` until Microsoft provides better documentation (PR #466 Close [#464](https://github.com/domainaware/parsedmarc/issues/464))
- Properly handle base64-encoded email attachments (PR #453)
- Do not crash when attempting to parse invalid email content (PR #453)
- Ignore errors when parsing text-based forensic reports (PR #460)
- Add email date to email processing debug logs (PR #462)
- Set default batch size to 10 to match the documentation (PR #465)
- Properly handle none values (PR #468)
- Add Gmail pagination (PR #469)
- Use the correct `msgraph` scope (PR #471)

## 8.6.4

- Properly process aggregate reports that incorrectly call `identifiers` `identities`
- Ignore SPF results in aggregate report records if the domain is not provided

## 8.6.3

- Add an error message instead of raising an exception when an aggregate report time span is greater than 24 hours

## 8.6.2

- Use `zlib` instead of `Gzip` to decompress more `.gz` files, including the ones supplied by Mimecast (Based on #430 closes #429)

## 8.6.1

- Fix handling of non-domain organization names (PR #411 fixes issue #410)
- Skip processing of aggregate reports with a date range that is too long to be valid (PR #408 fixes issue #282)
- Better error handling for Elasticsearch queries and file parsing (PR #417)

## 8.6.0

- Replace publicsuffix2 with publicsuffixlist

## 8.5.0

- Add support for Azure Log Analytics (PR #394)
- Fix a bug in the Microsoft Graph integration that caused a crash when an inbox has 10+ folders (PR #398)
- Documentation fixes

## 8.4.2

- Only initialize the syslog, S3 and Kafka clients once (PR #386 closes issues #289 and #380)

## 8.4.1

- Fix bug introduced in 8.3.1 that caused `No such file or directory` errors if output files didn't exist (PR #385 closes issues #358 and #382)
- Make the `--silent` CLI option only print errors. Add the `--warnings` options to also print warnings (PR #383)

## 8.4.0

- Provide a warning when no file is located at the path specified by the `ip_db_path` option (based on PR #369 with improvements in grammar)
- Add `allow_unencrypted_storage` to possible `msgraph` settings. See documentation for details. (PR #375)
- Use the `check_timeout` value in the event of an IMAP connection error, instead of a static 5 second value (PR #377)
- Update the included DBIP IP to Country Lite database to the December 2022 release

## 8.3.2

- Improvements to the Microsoft Graph integration (PR #352)

## 8.3.1

- Handle unexpected XML parsing errors more gracefully (PR #349)
- Migrate build from `setuptools` to `hatch`

## 8.3.0

- Support MFA for Microsoft Graph (PR #320 closes issue #319)
- Add more options for S3 export (PR #328)
- Provide a helpful error message when the log file cannot be created (closes issue #317)

## 8.2.0

- Support non-standard, text-based forensic reports sent by some mail hosts
- Set forensic report version to `None` (`null` in JSON) if the report was in a non-standard format and/or is missing a version number
- The default value of the `mailbox` `batch_size` option is now `10` (use `0` for no limit)

## 8.1.1

- Fix marking messages as read via Microsoft Graph

## 8.1.0

- Restore compatibility with <8.0.0 configuration files (with deprecation warnings)
- Set default `reports_folder` to `Inbox` (rather than `INBOX`) when `msgraph` is configured
- Mark a message as read when fetching a message from Microsoft Graph

## 8.0.3

- Fix IMAP callback for `IDLE` connections (PR #313 closes issue #311)
- Add warnings in documentation and log output for IMAP configuration changes introduced in 8.0.0 (Closes issue #309)
- Actually pin the `elasticsearch` Python library version at `<7.14.0` (Closes issue #315)
- Separate version numbers in `__init__.py` and `setup.py` to allow `pip` to install directly from `git`
- Update `dateparser` to 1.1.1 (closes issue #273)

## 8.0.2 (yanked)

- Strip leading and trailing whitespaces from Gmail scopes (Closes issue #310)

## 8.0.1 (yanked)

- Fix `ModuleNotFoundError` by adding `parsedmarc.mail` to the list of packages in `setup.py` (PR #308)

## 8.0.0 (yanked)

- Update included copy of `dbip-country-lite.mmdb` to the 2022-04 release
- Add support for Microsoft/Office 365 via Microsoft Graph API (PR #301 closes issue #111)
- Pin `elasticsearch-dsl` version at `>=7.2.0<7.14.0` (PR #297  closes issue #296)
- Properly initialize `ip_dp_path` (PR #294 closes issue #286)
- Remove usage of `logging.basicConfig` (PR #285)
- Add support for the Gmail API (PR #284 and PR #307 close issue #96)

## 7.1.1

- Actually include `dbip-country-lite.mmdb` file in the `parsedmarc.resources` package (PR #281)
- Update `dbip-country-lite.mmdb` to the 2022-01 release

## 7.1.0

- A static copy of the DBIP Country Lite database is now included for use when a copy of the MaxMind GeoLite2 Country database is not installed (Closes #275)
- Add `ip_db_path` to as a parameter and `general` setting for a custom IP geolocation database location (Closes #184)
- Search default Homebrew path when searching for a copy of the MaxMind GeoLite2 Country database (Closes #272)
- Fix log messages written to root logger (PR #276)
- Fix `--offline` option in CLI not being passed as a boolean (PR #265)
- Set Elasticsearch shard replication to `0` (PR #274)
- Add support for syslog output (PR #263 closes #227)
- Do not print TQDDM progress bar when running in a no-interactive TTY (PR #264)

## 7.0.1

- Fix startup error (PR #254)

## 7.0.0

- Fix issue #221: Crash when handling invalid reports without root node (PR #248)
- Use UTC datetime objects for Elasticsearch output (PR #245)
- Fix issues #219, #155, and #103: IMAP connections break on large emails (PR #241)
- Add support for saving reports to S3 buckets (PR #223)
- Pass `offline` parameter to `wait_inbox()` (PR #216)
- Add more details to logging (PR #220)
- Add options customizing the names of output files (Modifications based on PR #225)
- Wait for 5 seconds before attempting to reconnect to an IMAP server (PR #217)
- Add option to process messages in batches (PR #222)

## 6.12.0

- Limit output filename length to 100 characters (PR #199)
- Add basic auth support for Elasticsearch (PR #191)
- Fix Windows paths when searching for the GeoIP database (PR #190)
- Remove `six` requirement
- Require `mailsuite>=1.6.1`
- Require `dnspython>=2.0.0`
  - Drop Python 3.5 support

## 6.11.0

- Fix parsing failure for some valid forensic reports (PR #170)
- Fix double count of messages in the Grafana dashboard (PR #182)
- Add begin and end date fields for aggregate DMARC reports in Elasticsearch (PR #183 fixes issue #162)
- Fix crash on IMAP timeout (PR #186 fixes issue #163)
- Fix IMAP debugging output
- Fix `User-Agent` string

## 6.10.0

- Ignore unknown forensic report fields when generating CSVs (Closes issue #148)
- Fix crash on IMAP timeout (PR #164 - closes issue #163)
- Use SMTP port from the config file when sending emails (PR #151)
- Add support for Elasticsearch 7.0 (PR #161 - closes issue #149)
- Remove temporary workaround for DMARC aggregate report records missing a SPF domain fields

## 6.9.0

- Use system nameservers instead of Cloudflare by default
- Parse aggregate report records with missing SPF domains

## 6.8.2

- Require `mailsuite>=1.5.4`

## 6.8.1

- Use `match_phrase` instead of `match` when looking for existing strings in Elasticsearch

## 6.8.0

- Display warning when `GeoLite2-Country.mmdb` is missing, instead of trying to download it
- Add documentation for MaxMind `geoipupdate` changes on January 30th, 2019 (closes issues #137 and #139)
- Require `mail-parser>=3.11.0`

## 6.7.4

- Update dependencies

## 6.7.3

- Make `dkim_aligned` and `spf_aligned` case-insensitive (PR #132)

## 6.7.2

- Fix SPF results field in CSV output (closes issue #128)

## 6.7.1

- Parse forensic email samples with non-standard date headers
- Graceful handling of a failure to download the GeoIP database (issue #123)

## 6.7.0

- Fix typos (PR #119)
- Make CSV output match JSON output (Issue # 22)
- Graceful processing of invalid aggregate DMARC reports (PR #122)
- Remove Python 3.4 support

## 6.6.1

- Close files after reading them

## 6.6.0

- Set a configurable default IMAP timeout of 30 seconds
- Set a configurable maximum of 4 IMAP timeout retry attempts
- Add support for reading ``MBOX`` files
- Set a configurable Elasticsearch timeout of 60 seconds

## 6.5.5

- Set minimum `publicsuffix2` version

## 6.5.4

- Bump required `mailsuite` version to `1.2.1`

## 6.5.3

- Fix typos in the CLI documentation
- Bump required `mailsuite` version to `1.1.1`

## 6.5.2

- Merge PR #100 from michaeldavie
  - Correct a bug introduced in 6.5.1 that caused only the last record's data
  to be used for each row in an aggregate report's CSV version.
- Use `mailsuite` 1.1.0 to fix issues with some IMAP servers (closes issue 103)
  - Always use ``/`` as the folder hierarchy separator, and convert to the
  server's hierarchy separator in the background
  - Always remove folder name characters that conflict with the server's
  hierarchy separators
  - Prepend the namespace to the folder path when required

## 6.5.1

- Merge PR #98 from michaeldavie
  - Add functions
    - `parsed_aggregate_reports_to_csv_row(reports)`
    - `parsed_forensic_reports_to_csv_row(reports)`
- Require `dnspython>=1.16.0`

## 6.5.0

- Move mail processing functions to the
  [`mailsuite`](https://seanthegeek.github.io/mailsuite/) package
- Add offline option (closes issue #90)
- Use UDP instead of TCP, and properly set the timeout when querying DNS
  (closes issue #79 and #92)
- Log the current file path being processed when `--debug` is used
  (closes issue #95)

## 6.4.2

- Do not attempt to convert `org_name` to a base domain if `org_name` contains
  a space (closes issue #94)
- Always lowercase the `header_from`
- Provide a more helpful warning message when `GeoLite2-Country.mmdb` is
  missing

## 6.4.1

- Raise `utils.DownloadError` exception when a GeoIP database or Public
  Suffix List (PSL) download fails (closes issue #73)

## 6.4.0

- Add ``number_of_shards`` and ``number_of_replicas`` as possible options
in the ``elasticsearch`` configuration file section (closes issue #78)

## 6.3.7

- Work around some unexpected IMAP responses reported in issue #75

## 6.3.6

- Work around some unexpected IMAP responses reported in issue #70
- Show correct destination folder in debug logs when moving aggregate reports

## 6.3.5

- Normalize `Delivery-Result` value in forensic/failure reports (issue #76)
  Thanks Freddie Leeman of URIports for the troubleshooting assistance

## 6.3.4

- Fix Elasticsearch index creation (closes issue #74)

## 6.3.3

- Set `number_of_shards` and `number_of_replicas` to `1` when creating indexes
- Fix dependency conflict

## 6.3.2

- Fix the `monthly_indexes` option in the `elasticsearch` configuration section

## 6.3.1

- Fix `strip_attachment_payloads` option

## 6.3.0

- Fix IMAP IDLE response processing for some mail servers (#67)
- Exit with a critical error when required settings are missing (#68)
- XML parsing fixes (#69)
- Add IMAP responses to debug logging
- Add `smtp` option `skip_certificate_verification`
- Add `kafka` option `skip_certificate_verification`
- Suppress `mailparser` logging output
- Suppress `msgconvert` warnings

## 6.2.2

- Fix crash when trying to save forensic reports with missing fields to Elasticsearch

## 6.2.1

- Add missing `tqdm` dependency to `setup.py`

## 6.2.0

- Add support for multiprocess parallelized processing via CLI (Thanks zscholl - PR #62)
- Save sha256 hashes of attachments in forensic samples to Elasticsearch

## 6.1.8

- Actually fix GeoIP lookups

## 6.1.7

- Fix GeoIP lookups

## 6.1.6

- Better GeoIP error handling

## 6.1.5

- Always use Cloudflare's nameservers by default instead of Google's
- Avoid re-downloading the Geolite2 database (and tripping their DDoS protection)
- Add `geoipupdate` to install instructions

## 6.1.4

- Actually package requirements

## 6.1.3

- Fix package requirements

## 6.1.2

- Use local Public Suffix List file instead of downloading it
- Fix argument name for `send_email()` (closes issue #60)

## 6.1.1

- Fix aggregate report processing
- Check for the existence of a configuration file if a path is supplied
- Replace `publicsuffix` with `publicsuffix2`
- Add minimum versions to requirements

## 6.1.0

- Fix aggregate report email parsing regression introduced in 6.0.3 (closes issue #57)
- Fix Davmail support (closes issue #56)

## 6.0.3

- Don't assume the report is the last part of the email message (issue #55)

## 6.0.2

- IMAP connectivity improvements (issue #53)
- Use a temp directory for temp files (issue #54)

## 6.0.1

- Fix Elasticsearch output (PR #50 - andrewmcgilvray)

## 6.0.0

- Move options from CLI to a config file (see updated installation documentation)
- Refactoring to make argument names consistent

## 5.3.0

- Fix crash on invalid forensic report sample (Issue #47)
- Fix DavMail support (Issue #45)

## 5.2.1

- Remove unnecessary debugging code

## 5.2.0

- Add filename and line number to logging output
- Improved IMAP error handling
- Add CLI options

  ```text
  --elasticsearch-use-ssl
                        Use SSL when connecting to Elasticsearch
  --elasticsearch-ssl-cert-path ELASTICSEARCH_SSL_CERT_PATH
                        Path to the Elasticsearch SSL certificate
  --elasticsearch-monthly-indexes
                        Use monthly Elasticsearch indexes instead of daily
                        indexes
  --log-file LOG_FILE   output logging to a file
  ```

## 5.1.3

- Remove `urllib3` version upper limit

## 5.1.2

- Workaround unexpected Office 365/Exchange IMAP responses

## 5.1.1

- Bugfix: Crash when parsing invalid forensic report samples (#38)
- Bugfix: Crash when IMAP connection is lost
- Increase default Splunk HEC response timeout to 60 seconds

## 5.1.0

- Bugfix: Submit aggregate dates to Elasticsearch as lists, not tuples
- Support `elasticsearch-dsl<=6.3.0`
- Add support for TLS/SSL and username/password auth to Kafka

## 5.0.2

- Revert to using `publicsuffix` instead of `publicsuffix2`

## 5.0.1

- Use `publixsuffix2` (closes issue #4)
- Add Elasticsearch to automated testing
- Lock `elasticsearch-dsl` required version to `6.2.1` (closes issue #25)

## 5.0.0

**Note**: Re-importing `kibana_saved_objects.json` in Kibana [is required](https://domainaware.github.io/parsedmarc/#upgrading-kibana-index-patterns) when upgrading to this version!

- Bugfix: Reindex the aggregate report index field `published_policy.fo`
as `text` instead of `long` (Closes issue #31)
- Bugfix: IDLE email processing in Gmail/G-Suite accounts (closes issue #33)
- Bugfix: Fix inaccurate DNS timeout in CLI documentation (closes issue #34)
- Bugfix: Forensic report processing via CLI
- Bugfix: Duplicate aggregate report Elasticsearch query broken
- Bugfix: Crash when `Arrival-Date` header is missing in a
forensic/failure/ruf report
- IMAP reliability improvements
- Save data in separate indexes each day to make managing data retention easier
- Cache DNS queries in memory

## 4.4.1

- Don't crash if Elasticsearch returns an unexpected result (workaround for issue #31)

## 4.4.0

- Packaging fixes

## 4.3.9

- Kafka output improvements
  - Moved some key values (`report_id`, `org_email`, `org_name`) higher in the JSON structure
  - Recreated the `date_range` values from the ES client for easier parsing.
  - Started sending individual record slices. Kafka default message size is 1 MB, some aggregate reports were exceeding this. Now it appends meta-data and sends record by record.

## 4.3.8

- Fix decoding of attachments inside forensic samples
- Add CLI option `--imap-skip-certificate-verification`
- Add optional `ssl_context` argument for `get_dmarc_reports_from_inbox()`
and `watch_inbox()`
- Debug logging improvements

## 4.3.7

- When checking an inbox, always recheck for messages when processing is
complete

## 4.3.6

- Be more forgiving for forensic reports with missing fields

## 4.3.5

- Fix base64 attachment decoding (#26)

## 4.3.4

- Fix crash on empty aggregate report comments (brakhane - #25)
- Add SHA256 hashes of attachments to output
- Add `strip_attachment_payloads` option to functions and
`--strip-attachment-payloads` option to the CLI (#23)
- Set `urllib3` version requirements to match `requests`

## 4.3.3

- Fix forensic report email processing

## 4.3.2

- Fix normalization of the forensic sample from address

## 4.3.1

- Fix parsing of some emails
- Fix duplicate forensic report search for Elasticsearch

## 4.3.0

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

## 4.2.0

- Save each aggregate report record as a separate Splunk event
- Fix IMAP delete action (#20)
- Suppress Splunk SSL validation warnings
- Change default logging level to `WARNING`

## 4.1.9

- Workaround for forensic/ruf reports that are missing `Arrival-Date` and/or
`Reported-Domain`

## 4.1.8

- Be more forgiving of weird XML

## 4.1.7

- Remove any invalid XML schema tags before parsing the XML (#18)

## 4.1.6

- Fix typo in CLI parser

## 4.1.5

- Only move or delete IMAP emails after they all have been parsed
- Move/delete messages one at a time - do not exit on error
- Reconnect to IMAP if connection is broken during
`get_dmarc_reports_from_inbox()`
- Add`--imap-port` and `--imap-no-ssl` CLI options

## 4.1.4

- Change default logging level to `ERROR`

## 4.1.3

- Fix crash introduced in 4.1.0 when creating Elasticsearch indexes (Issue #15)

## 4.1.2

- Fix packaging bug

## 4.1.1

- Add splunk instructions
- Reconnect reset IMAP connections when watching a folder

## 4.1.0

- Add options for Elasticsearch prefixes and suffixes
- If an aggregate report has the invalid `disposition` value `pass`, change
it to `none`

## 4.0.2

- Use report timestamps for Splunk timestamps

## 4.0.1

- When saving aggregate reports in Elasticsearch store `domain` in
`published_policy`
- Rename `policy_published` to `published_policy`when saving aggregate
reports to Splunk

## 4.0.0

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
- Always use `
` as the newline when generating CSVs
- Workaround for random Exchange/Office 365 `Server Unavailable` IMAP errors

## 3.9.7

- Completely reset IMAP connection when a broken pipe is encountered

## 3.9.6

- Finish incomplete broken pipe fix

## 3.9.5

- Refactor to use a shared IMAP connection for inbox watching and message
downloads

- Gracefully recover from broken pipes in IMAP

## 3.9.4

- Fix moving/deleting emails

## 3.9.3

- Fix crash when forensic reports are missing `Arrival-Date`

## 3.9.2

- Fix PEP 8 spacing
- Update build script to fail when CI tests fail

## 3.9.1

- Use `COPY` and delete if an IMAP server does not support `MOVE`
(closes issue #9)

## 3.9.0

- Reduce IMAP `IDLE` refresh rate to 5 minutes to avoid session timeouts in
Gmail
- Fix parsing of some forensic/failure/ruf reports
- Include email subject in all warning messages
- Fix example NGINX configuration in the installation documentation
(closes issue #6)

## 3.8.2

- Fix `nameservers` option (mikesiegel)
- Move or delete invalid report emails in an IMAP inbox (closes issue #7)

## 3.8.1

- Better handling of `.msg` files when `msgconvert` is not installed

## 3.8.0

- Use `.` instead of `/` as the IMAP folder hierarchy separator when `/`
does not work - fixes dovecot support (#5)
- Fix parsing of base64-encoded forensic report data

## 3.7.3

- Fix saving attachment from forensic sample to Elasticsearch

## 3.7.2

- Change uses of the `DocType` class to `Document`, to properly support `elasticsearch-dsl` `6.2.0` (this also fixes use in pypy)
- Add documentation for installation under pypy

## 3.7.1

- Require `elasticsearch>=6.2.1,<7.0.0` and `elasticsearch-dsl>=6.2.1,<7.0.0`
- Update for class changes in `elasticsearch-dsl` `6.2.0`

## 3.7.0

- Fix bug where PSL would be called before it was downloaded if the PSL was
older than 24 Hours

## 3.6.1

- Parse aggregate reports with missing SPF domain

## 3.6.0

- Much more robust error handling

## 3.5.1

- Fix dashboard message counts for source IP addresses visualizations
- Improve dashboard loading times
- Improve dashboard layout
- Add country rankings to the dashboards
- Fix crash when parsing report with empty <auth_results></auth_results>

## 3.5.0

- Use Cloudflare's public DNS resolvers by default instead of Google's
- Fix installation from virtualenv
- Fix documentation typos

## 3.4.1

- Documentation fixes
- Fix console output

## 3.4.0

- Maintain IMAP IDLE state when watching the inbox
- The `-i`/`--idle` CLI option is now `-w`/`--watch`
- Improved Exception handling and documentation

## 3.3.0

- Fix errors when saving to Elasticsearch

## 3.2.0

- Fix existing aggregate report error message

## 3.1.0

- Fix existing aggregate report query

## 3.0.0

New features

- Add option to select the IMAP folder where reports are stored
- Add options to send data to Elasticsearch

Changes

- Use Google's public nameservers (`8.8.8.8` and `4.4.4.4`)
by default
- Detect aggregate report email attachments by file content rather than
file extension
- If an aggregate report's `org_name` is a FQDN, the base is used
- Normalize aggregate report IDs

## 2.1.2

- Rename `parsed_dmarc_forensic_reports_to_csv()` to
 `parsed_forensic_reports_to_csv()` to match other functions
- Rename `parsed_aggregate_report_to_csv()` to
 `parsed_aggregate_reports_to_csv()` to match other functions
- Use local time when generating the default email subject

## 2.1.1

- Documentation fixes

## 2.1.0

- Add `get_report_zip()` and `email_results()`
- Add support for sending report emails via the command line

## 2.0.1

- Fix documentation
- Remove Python 2 code

## 2.0.0

New features

- Parse forensic reports
- Parse reports from IMAP inbox

Changes

- Drop support for Python 2
- Command line output is always a JSON object containing the lists
  `aggregate_reports` and `forensic_reports`
- `-o`/`--output` option is now a path to an output directory, instead of an
  output file

## 1.1.0

- Add `extract_xml()` and `human_timestamp_to_datetime` methods

## 1.0.5

- Prefix public suffix and GeoIP2 database filenames with `.`
- Properly format errors list in CSV output

## 1.0.3

- Fix documentation formatting

## 1.0.2

- Fix more packaging flaws

## 1.0.1

- Fix packaging flaw

## 1.0.0

- Initial release
