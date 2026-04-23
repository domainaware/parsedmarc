__version__ = "9.7.1"

USER_AGENT = f"parsedmarc/{__version__}"

DEFAULT_DNS_TIMEOUT = 2.0
DEFAULT_DNS_MAX_RETRIES = 0
# Recommended mix of public resolvers for cross-provider DNS failover. Not
# applied automatically — callers opt in by passing
# ``nameservers=RECOMMENDED_DNS_NAMESERVERS``. Mixing providers means a single
# operator's anycast outage or authoritative-server incompatibility falls
# through to a different provider within one resolve() call.
RECOMMENDED_DNS_NAMESERVERS = ("1.1.1.1", "8.8.8.8")
