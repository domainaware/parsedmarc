__version__ = "11.2.2"

USER_AGENT = f"parsedmarc/{__version__}"

DEFAULT_DNS_TIMEOUT = 2.0
DEFAULT_DNS_MAX_RETRIES = 0
# Recommended mix of public resolvers for cross-provider DNS failover. Not
# applied automatically — callers opt in by passing
# ``nameservers=RECOMMENDED_DNS_NAMESERVERS``. Mixing providers means a single
# operator's anycast outage or authoritative-server incompatibility falls
# through to a different provider within one resolve() call.
RECOMMENDED_DNS_NAMESERVERS = ("1.1.1.1", "8.8.8.8")

# Limits on the XML of an aggregate report, enforced while expat reads it and
# before xmltodict builds the tree (GHSA-q7gm-8cj9-94hr). A real report is
# fewer than 10 elements deep. Nodes are elements plus attributes; the
# number of "=" characters bounds the attributes, and the samples hold at
# most 3 (namespace declarations). The largest sample has 32,019 nodes
# (909 KB), so the limit is a report of about 28 MB. With the 32 MiB size cap
# (MAX_DECOMPRESSED_REPORT_SIZE), 999,000 distinct elements with 14
# characters of text each (31 MiB, read from disk before the baseline) need
# +399 MiB on the lxml recovery path and +338 to +355 MiB on expat when the
# text is parsed directly, and +500 MiB and +452 MiB through
# parse_report_file(), which also holds the file's bytes.
MAX_XML_DEPTH = 100
MAX_XML_NODES = 1_000_000
# Longest text between a "<" and the next ">" in an aggregate report. expat
# and libxml2 build a start tag's whole attribute list before reporting it,
# so attributes cannot be counted before they cost memory. The longest tag
# in the samples is the root element's namespace declarations, 108
# characters (a 234-character comment is the longest construct).
MAX_XML_TAG_LENGTH = 65_536

# A report's <date_range> longer than this many days is rejected. A real
# aggregate report covers a day (RFC 7489 §6.3: the "ri" tag's default
# interval is 86400 seconds); a year leaves room for mistakes, and
# normalization emits at most one record per day.
MAX_REPORT_SPAN_DAYS = 366
# The date that names a report's dated index (Elasticsearch, OpenSearch) may
# not be more than this many days ahead of the current time. Two days absorb
# a reporter's clock skew and time-zone mistakes. The past is not bounded: an
# archive of old reports is legitimate input.
MAX_REPORT_FUTURE_DAYS = 2
# Most distinct dated indexes one report may create in Elasticsearch or
# OpenSearch (one shard each); further records go to the report's first index.
MAX_INDEXES_PER_REPORT = 31
# Most records per-day normalization may produce from one report (records
# times days). A larger report keeps its records whole, over its own range.
MAX_NORMALIZED_RECORDS = 250_000

# Most seconds one aggregate report may spend in reverse DNS lookups that
# return no PTR or are slow (GHSA-rwfh-ww9c-jm9m). The sender picks each
# record's source IP, and a reverse zone that never answers costs the whole
# DNS lifetime: 2 s per nameserver times the 4 default nameservers, 8 s per
# lookup. 120 s is 15 such lookups, so a black-holed 3,500-record report now
# ends in about two minutes instead of eight hours, while 1,000 fast no-PTR
# answers (about 50 ms each) cost about 50 s and stay under it. Lookups that
# find a PTR are charged here only when they are slow
# (SLOW_REVERSE_DNS_SECONDS), since a sender who controls a reverse zone can
# answer every query just before the timeout; every lookup is also charged
# to MAX_REVERSE_DNS_SECONDS_PER_REPORT. Past either limit, the report's
# remaining records are enriched from the local IP database and reverse DNS
# map only.
MAX_FAILED_REVERSE_DNS_SECONDS_PER_REPORT = 120.0

# A reverse DNS lookup that takes at least this many seconds is charged to
# MAX_FAILED_REVERSE_DNS_SECONDS_PER_REPORT whether or not it returned a
# name. A healthy resolver answers in milliseconds.
SLOW_REVERSE_DNS_SECONDS = 1.0

# Most seconds one aggregate report may spend in all of its reverse DNS
# lookups, answered or not (GHSA-rwfh-ww9c-jm9m). Any per-lookup threshold
# leaves the total unbounded, because the number of records is not: a
# reverse zone that answers every query in just under
# SLOW_REVERSE_DNS_SECONDS is never charged to the failed-or-slow budget.
# 5,000 distinct source IPs resolving in 100 ms each use 500 s, so real
# reports fit; a reverse zone that answers every query slowly is cut off
# after ten minutes.
MAX_REVERSE_DNS_SECONDS_PER_REPORT = 600.0

# Largest message or session count a report may give (GHSA-fxr7-7h9q-v949).
# It matches the PostgreSQL output's INTEGER count columns, signed 32-bit,
# so a larger count was rejected by that output. (The Elasticsearch and
# OpenSearch outputs do not install their document classes' mappings, and
# the mappings they do install declare no counts, so the clusters map every
# count dynamically as long; the aggregate document class declares
# message_count as Long() to match.) No real reporter approaches it.
MAX_MESSAGE_COUNT = 2**31 - 1
