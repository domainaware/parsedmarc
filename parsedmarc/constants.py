__version__ = "11.2.1"

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
# Most distinct dated indexes one report may create in Elasticsearch or
# OpenSearch (one shard each); further records go to the report's first index.
MAX_INDEXES_PER_REPORT = 31
# Most records per-day normalization may produce from one report (records
# times days). A larger report keeps its records whole, over its own range.
MAX_NORMALIZED_RECORDS = 250_000
