# -*- coding: utf-8 -*-

"""Centralized parser configuration (GitHub issue #503).

This module defines :class:`ParserConfig`, a single frozen dataclass that
carries every parsing/enrichment option (offline mode, IP database path,
reverse DNS map location, PSL overrides location, DNS behavior, etc.) plus
the three caches that the parser and enrichment code share across calls:
the IP address info cache, the seen-aggregate-report-ID cache, and the
reverse DNS map.

``parsedmarc/__init__.py`` re-exports :data:`IP_ADDRESS_CACHE`,
:data:`SEEN_AGGREGATE_REPORT_IDS`, and :data:`REVERSE_DNS_MAP` under the
same names for backward compatibility. That compatibility is
identity-based: ``parsedmarc.IP_ADDRESS_CACHE is parsedmarc.config.IP_ADDRESS_CACHE``
must hold, not merely equal contents, since callers may mutate the caches
in place.

Only :mod:`parsedmarc.constants` and :mod:`parsedmarc.utils` are imported
from the package here — importing :mod:`parsedmarc` itself would be
circular, since ``parsedmarc/__init__.py`` imports from this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields

from expiringdict import ExpiringDict

from parsedmarc.constants import DEFAULT_DNS_MAX_RETRIES, DEFAULT_DNS_TIMEOUT
from parsedmarc.utils import ReverseDNSMap


def _new_ip_address_cache() -> ExpiringDict:
    """Build a fresh IP-address-info cache (4 hour expiry)."""
    return ExpiringDict(max_len=10000, max_age_seconds=14400)


def _new_seen_aggregate_report_ids() -> ExpiringDict:
    """Build a fresh seen-aggregate-report-ID cache (1 hour expiry)."""
    return ExpiringDict(max_len=100000000, max_age_seconds=3600)


# Canonical default caches. parsedmarc/__init__.py re-exports these three
# objects under the same names (IP_ADDRESS_CACHE, SEEN_AGGREGATE_REPORT_IDS,
# REVERSE_DNS_MAP) for backward compatibility with code that imported them
# directly from the top-level package. That compatibility promise is
# identity-based — the re-exported names must point at these very same
# objects, not merely equivalent ones — so that library callers who obtained
# a reference before this refactor keep observing the same mutations as code
# that goes through a ParserConfig built from these defaults (e.g. during
# unpickling in a multiprocessing worker; see ParserConfig.__setstate__).
IP_ADDRESS_CACHE = _new_ip_address_cache()
SEEN_AGGREGATE_REPORT_IDS = _new_seen_aggregate_report_ids()
REVERSE_DNS_MAP: ReverseDNSMap = {}

# The ParserConfig fields excluded from pickling; every other field must
# survive the round-trip, so __getstate__ derives its contents from
# dataclasses.fields() rather than enumerating option fields by hand.
_CACHE_FIELD_NAMES = (
    "ip_address_cache",
    "seen_aggregate_report_ids",
    "reverse_dns_map",
)


@dataclass(frozen=True)
class ParserConfig:
    """Carries all parsing/enrichment options, plus the caches they share.

    When passed as ``config=`` to parsedmarc's public parsing functions, the
    individual option keyword arguments (``offline``, ``ip_db_path``,
    ``nameservers``, etc.) are ignored in favor of the values carried on this
    object.

    Every explicitly constructed ``ParserConfig()`` owns fresh, isolated
    cache objects (``ip_address_cache``, ``seen_aggregate_report_ids``,
    ``reverse_dns_map``) via ``default_factory`` — two independently
    constructed configs never share cache state. To derive a variant of an
    existing config that *does* keep sharing its caches (e.g. to override
    ``offline`` for one call while still benefiting from warm caches), use
    ``dataclasses.replace(cfg, ...)``: since every field, including the three
    cache fields, is an init field, ``replace()`` copies the source's cache
    objects onto the new instance rather than constructing fresh ones.

    Pickling (as happens when a config is captured in a
    ``functools.partial`` payload submitted to a multiprocessing worker)
    intentionally drops cache *contents*: ``__getstate__`` omits the three
    cache fields, and ``__setstate__`` rebinds them to this module's
    :data:`IP_ADDRESS_CACHE`, :data:`SEEN_AGGREGATE_REPORT_IDS`, and
    :data:`REVERSE_DNS_MAP` — the unpickling process's module-default
    caches — rather than either the sender's cache contents (which would be
    expensive and stale to serialize per task) or brand new empty caches per
    unpickle (which would silently defeat per-worker caching, since a
    ``functools.partial`` payload is re-pickled for every task submitted to a
    worker). Binding the module defaults means a freshly spawned worker
    interpreter starts with empty caches and accumulates hits across the
    tasks it handles, matching pre-refactor behavior.

    Note that ``keep_alive`` and ``n_procs`` are deliberately **not** fields
    on this class: those control process/worker orchestration, not parsing
    or enrichment behavior.

    Attributes:
        offline: Do not make online requests (DNS, IP database download,
            reverse DNS map download, PSL overrides download).
        ip_db_path: Path to a local MMDB file from IPinfo, MaxMind, or DBIP.
        always_use_local_files: Always use local/bundled files instead of
            downloading the IP database, reverse DNS map, or PSL overrides.
        reverse_dns_map_path: Path to a local reverse DNS map file.
        reverse_dns_map_url: URL to a reverse DNS map file.
        psl_overrides_path: Path to a local PSL overrides file.
        psl_overrides_url: URL to a PSL overrides file.
        nameservers: A list of one or more nameservers to use for DNS
            queries (Cloudflare's public DNS resolvers by default).
        dns_timeout: DNS query timeout, in seconds.
        dns_retries: Number of times to retry a DNS query after a timeout or
            other transient error.
        strip_attachment_payloads: Remove attachment payloads from parsed
            email results.
        normalize_timespan_threshold_hours: Aggregate reports whose
            timespan exceeds this many hours are normalized/split.
        ip_address_cache: Cache of IP address enrichment results.
        seen_aggregate_report_ids: Cache of already-seen aggregate report
            IDs, used for de-duplication.
        reverse_dns_map: The reverse DNS map used to classify base domains
            found via reverse DNS.
    """

    offline: bool = False
    ip_db_path: str | None = None
    always_use_local_files: bool = False
    reverse_dns_map_path: str | None = None
    reverse_dns_map_url: str | None = None
    psl_overrides_path: str | None = None
    psl_overrides_url: str | None = None
    nameservers: list[str] | None = None
    dns_timeout: float = DEFAULT_DNS_TIMEOUT
    dns_retries: int = DEFAULT_DNS_MAX_RETRIES
    strip_attachment_payloads: bool = False
    normalize_timespan_threshold_hours: float = 24.0
    ip_address_cache: ExpiringDict = field(
        default_factory=_new_ip_address_cache, repr=False, compare=False
    )
    seen_aggregate_report_ids: ExpiringDict = field(
        default_factory=_new_seen_aggregate_report_ids, repr=False, compare=False
    )
    reverse_dns_map: ReverseDNSMap = field(
        default_factory=dict, repr=False, compare=False
    )

    def __getstate__(self) -> dict[str, object]:
        """Return picklable state, excluding the three cache fields.

        Cache contents are process-local and potentially huge; they are
        never serialized. See the class docstring for the full rationale.
        """
        return {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if f.name not in _CACHE_FIELD_NAMES
        }

    def __setstate__(self, state: dict[str, object]) -> None:
        """Restore option fields, then rebind caches to this module's
        process-wide defaults (never fresh empty caches — see the class
        docstring for why that would silently break per-worker caching).

        Non-cache fields are first initialized to their class defaults, so
        unpickling a ``ParserConfig`` serialized by an older parsedmarc
        version (whose state predates fields added since) leaves the newer
        fields at their defaults instead of unset entirely — ``__init__``
        never runs during unpickling, so without this an absent field would
        raise ``AttributeError`` on first access.
        """
        for f in fields(self):
            if f.name not in _CACHE_FIELD_NAMES:
                object.__setattr__(self, f.name, f.default)
        for key, value in state.items():
            object.__setattr__(self, key, value)
        object.__setattr__(self, "ip_address_cache", IP_ADDRESS_CACHE)
        object.__setattr__(self, "seen_aggregate_report_ids", SEEN_AGGREGATE_REPORT_IDS)
        object.__setattr__(self, "reverse_dns_map", REVERSE_DNS_MAP)
