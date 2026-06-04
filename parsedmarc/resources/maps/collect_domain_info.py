#!/usr/bin/env python
"""Collect WHOIS and HTTP metadata for reverse DNS base domains.

Reads a list of domains (defaults to the unmapped entries in
`unknown_base_reverse_dns.csv`) and writes a compact TSV with the fields most
useful for classifying an unknown sender:

    domain, whois_org, whois_country, registrar, title, description,
    rebrand_signal, external_links, final_url, http_status, ips,
    ip_whois_org, ip_whois_netname, ip_whois_country, error

`rebrand_signal` flags rows whose page text matches a phrase like "now X" or
"formerly known as X" — useful both for classifying an unknown sender ("we
became Newfold Digital") and as a drift signal when re-run against existing
map keys via `detect_rebrands.py`. `external_links` carries the homepage's
non-self, non-social outbound link hosts; it catches image-only acquisition
banners that text scanning misses (e.g. bankonitusa.com → navanta.com).

The output is resume-safe: re-running the script only fetches domains that are
not already in the output file. Designed to produce a small file that an LLM
or a human can classify in one pass, rather than re-fetching per domain from
inside a classifier loop.

Usage:
    python collect_domain_info.py [-i INPUT] [-o OUTPUT] \\
        [--workers N] [--timeout S]

Run from the `parsedmarc/resources/maps/` directory so relative paths resolve.
"""

import argparse
import csv
import os
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Optional import — only needed when --use-search-fallback is passed. The
# script runs without ddgs as long as the flag isn't requested. Install via
# `pip install ddgs` (or `pip install .[build]` from the repo root).
try:
    from ddgs import DDGS as _DDGS
except ImportError:
    _DDGS = None

# Suppress the InsecureRequestWarning emitted whenever the fallback fetch
# uses verify=False. It is a known and intentional fallback-only signal.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_INPUT = "unknown_base_reverse_dns.csv"
DEFAULT_OUTPUT = "domain_info.tsv"
MAP_FILE = "base_reverse_dns_map.csv"
PSL_OVERRIDES_FILE = "psl_overrides.txt"

FIELDS = [
    "domain",
    "whois_org",
    "whois_country",
    "registrar",
    "title",
    "description",
    "rebrand_signal",
    "external_links",
    "final_url",
    "http_status",
    "ips",
    "ip_whois_org",
    "ip_whois_netname",
    "ip_whois_country",
    "error",
    "title_source",
    "link_target_domain",
]

USER_AGENT = (
    "Mozilla/5.0 (compatible; parsedmarc-domain-info/1.0; "
    "+https://github.com/domainaware/parsedmarc)"
)
# Used only by the fallback fetch (when the polite UA above gets blocked or
# the site ships a misconfigured TLS cert / weak DH params / legacy TLS).
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class _PermissiveSSLAdapter(HTTPAdapter):
    """HTTPAdapter that accepts misconfigured TLS, used by the fallback fetch.

    Real-world ISP and government homepages routinely ship one of:
    self-signed certs, hostname-mismatched certs, weak Diffie-Hellman
    parameters that trip Python's default ``DH_KEY_TOO_SMALL``, missing
    legacy-renegotiation support, or restricted cipher suites. The
    primary requests.get() in :func:`_fetch_homepage` correctly rejects
    these. This adapter — used only for the fallback retry — relaxes
    the SSL context to a configuration roughly equivalent to
    ``curl -k`` plus ``DEFAULT@SECLEVEL=0`` so we can still scrape
    enough of the page to classify the operator.
    """

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            # Some OpenSSL builds reject SECLEVEL=0; fall through with the
            # default cipher list. Most cert-error sites work without it.
            pass
        # OP_LEGACY_SERVER_CONNECT — accept unsafe legacy TLS renegotiation.
        # Exposed as a constant on Python 3.12+; fall back to its raw value
        # (0x4) on older interpreters that the project still supports.
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


WHOIS_ORG_KEYS = (
    "registrant organization",
    "registrant org",
    "registrant name",
    "organization",
    "org-name",
    "orgname",
    "owner",
    "registrant",
    "descr",
)
WHOIS_COUNTRY_KEYS = ("registrant country", "country")
WHOIS_REGISTRAR_KEYS = ("registrar",)

# IP-WHOIS field keys (ARIN/RIPE/APNIC/LACNIC/AFRINIC all differ slightly)
IP_WHOIS_ORG_KEYS = (
    "orgname",
    "org-name",
    "organization",
    "organisation",
    "owner",
    "descr",
    "netname",
    "customer",
)
IP_WHOIS_NETNAME_KEYS = ("netname", "network-name")
IP_WHOIS_COUNTRY_KEYS = ("country",)

MAX_BODY_BYTES = 256 * 1024  # truncate responses so a hostile page can't blow up RAM
MAX_BODY_TEXT_CHARS = 100 * 1024  # cap on extracted visible body text

# Privacy filter: drop entries containing a full IPv4 address (four dotted or
# dashed octets). Full IPs in a reverse-DNS base domain reveal a specific
# customer address and must never enter the map.
_FULL_IP_RE = re.compile(
    r"(?<![\d])(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?![\d])"
)

# Rebrand-signal scan. Triggered phrases are followed by a captured brand name
# (capitalized, non-noise word). The reviewer ultimately judges whether a hit
# is a real rebrand banner — the regex's job is to not miss the obvious ones.
# Real cases: "BankOnIT is now Navanta", "is now part of Lumen", "we are now
# Cencora", "formerly known as Symantec Email Security", "we became Newfold
# Digital".
#
# A bare leading "now <Capital>" was tried and dropped — modern marketing
# pages saturate the body text with CTA fragments like "Buy Now PROMO",
# "Order Now Free Shipping", "Apply Now Who We Are", which all match a bare
# `now <Capital>` and are 95%+ false positives. Requiring a copular verb
# (`is/are/was/were/am now`) keeps the linguistic shape of an actual
# announcement and rules out CTA buttons. The same is true in reverse for
# bare "formerly <Capital>" — kept because "formerly" virtually never
# appears in a CTA context, but the same noise list catches the residual
# "Formerly Available" / "Formerly Open" cases.
REBRAND_RE = re.compile(
    r"\b(?:"
    r"formerly(?: known as)? "
    r"|"
    r"(?:is|are|was|were|am) now (?:(?:a )?part of )?"
    r"|"
    r"(?:we became|rebranded(?: as| to)?|merged with|"
    r"acquired by|previously known as|previously operated as|"
    r"new name for) "
    r")"
    r"([A-Za-z][A-Za-z0-9&]+)\b",
    re.IGNORECASE,
)

# Path-style rebrand markers that appear in URL slugs and image alt text.
# Real-world image-only rebrand banners (the typical "we got acquired"
# treatment) put the announcement in a slug like
# `/brand-launch-frequently-asked-questions/` and an alt like
# "Brand announcement – Learn more", neither of which the body-text
# REBRAND_RE can see. Phrasing here is deliberately narrow — "brand"
# alone is far too common; we require it joined to launch / announcement /
# change / etc. by a space, dash, or underscore, which virtually never
# occurs outside a rebrand context.
REBRAND_PATH_RE = re.compile(
    r"\b(?:"
    r"brand[ _-](?:launch|announcement|reveal)"
    r"|our[ _-]new[ _-](?:name|brand)"
    r"|(?:acquisition|merger)[ _-]announcement"
    r")\b",
    re.IGNORECASE,
)

# Words that commonly follow "now"/"formerly" outside a rebrand context. The
# regex would otherwise hit "Now Available", "Formerly Open", etc. Add to
# this set if review surfaces a recurring false positive — keep the set
# narrow so real one-word brand names (Navanta, Lumen, Sykt, etc.) survive.
_REBRAND_NOISE = frozenset(
    {
        # Past-participles / present-participles that the "are now <Cap>"
        # / "is now <Cap>" pattern picks up from ordinary marketing prose.
        # Compared case-insensitively against the captured brand, so a
        # single entry covers any casing the page emits ("LIVE", "Live",
        # "live"). Add lowercase forms here.
        "available",
        "accepting",
        "active",
        "booking",
        "closed",
        "complete",
        "enrolling",
        "expanding",
        "free",
        "hiring",
        "installed",
        "live",
        "loading",
        "offering",
        "online",
        "open",
        "operating",
        "part",  # "is now Part of [our family]" already filtered by structure;
        # this catches inverted phrasing where "Part" is the captured token.
        "pending",
        "playing",
        "powered",
        "secure",  # "is now Secure Managed Wi-Fi" / "is now Secure Login"
        "selling",
        "serving",
        "shipping",
        "showing",
        "streaming",
        "supporting",
        "trending",
        "underway",
        # Short prepositions / pronouns that grammatically follow the verb
        # but are not brand names: "are now In Control", "is now On the air".
        "down",
        "in",
        "off",
        "on",
        "out",
        "up",
        "you",
        "your",
        # Standards / certifications that follow "is now <CERT> certified"
        # in marketing copy (compliance announcements).
        "iso",
        # Social-media platform rebrands that ubiquitously appear in
        # footers as "X (formerly Twitter)", "Meta (formerly Facebook)",
        # "Block (formerly Square)". The mention is real but it's almost
        # never about the page operator's own rebrand.
        "twitter",
        "facebook",
        "square",
    }
)


# Hostnames that overwhelmingly appear as outbound links on virtually every
# homepage and carry no signal about the operator's identity. Keeping these
# out of `external_links` means the column is dominated by hosts that
# actually tell us something — e.g. an outbound link to navanta.com from
# bankonitusa.com (the rebrand's banner is an image-only `<a href>` with
# no visible "Navanta" text, so href scanning is the only cheap way to
# catch it without rendering JavaScript).
_NOISE_LINK_HOSTS = frozenset(
    {
        "facebook.com",
        "fb.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "instagram.com",
        "youtube.com",
        "youtu.be",
        "tiktok.com",
        "pinterest.com",
        "vimeo.com",
        "reddit.com",
        "medium.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "google.com",
        "googleapis.com",
        "googletagmanager.com",
        "googleadservices.com",
        "google-analytics.com",
        "gstatic.com",
        "doubleclick.net",
        "play.google.com",
        "apps.apple.com",
        "apple.com",
        "microsoft.com",
        "office.com",
        "cloudflare.com",
        "jsdelivr.net",
        "unpkg.com",
        "bootstrapcdn.com",
        "fontawesome.com",
        "wp.com",
        "w.org",
        "wordpress.org",
        "schema.org",
        "ogp.me",
    }
)

_HREF_RE = re.compile(
    r"""href\s*=\s*['"]https?://([^/'"\s>]+)""",
    re.IGNORECASE,
)


def _hostname_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_noise_host(host: str) -> bool:
    for noise in _NOISE_LINK_HOSTS:
        if host == noise or host.endswith("." + noise):
            return True
    return False


def _external_link_hosts(self_domain: str, text: str, limit: int = 5) -> list:
    """Return up to `limit` distinct external hostnames found in <a href> URLs.

    Skips hosts that match the input domain (or any of its subdomains) and
    common social/CDN/analytics/utility hosts that appear on practically every
    page. Hosts are returned in first-appearance order; a host whose
    registered domain matches the input but happens to be a different
    subdomain (e.g. login.example.com on example.com's homepage) is treated
    as self.
    """
    self_domain = (self_domain or "").lower()
    seen = []
    seen_set = set()
    for m in _HREF_RE.finditer(text):
        host = m.group(1).lower()
        if not host or host in seen_set:
            continue
        if self_domain and (host == self_domain or host.endswith("." + self_domain)):
            continue
        if _is_noise_host(host):
            continue
        seen_set.add(host)
        seen.append(host)
        if len(seen) >= limit:
            break
    return seen


def _rebrand_signal(*texts: str) -> str:
    """Return first ~120-char context of a rebrand-keyword hit, or ''.

    Scans each input text in order. Returns the first hit whose captured
    brand-name token is not on the noise list — keeps the surrounding
    sentence so a reviewer can decide at a glance whether the match is a
    real banner ("BankOnIT is now Navanta") or residual noise.
    """
    for text in texts:
        if not text:
            continue
        for m in REBRAND_RE.finditer(text):
            brand = m.group(1)
            # Real brand names in rebrand banners are virtually always written
            # with an initial capital. Filtering on case lets us match the
            # trigger phrase case-insensitively while still rejecting common
            # post-trigger noise like "now hiring" / "formerly available".
            if not brand or not brand[0].isupper():
                continue
            if brand.lower() in _REBRAND_NOISE:
                continue
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 80)
            return _strip_field(text[start:end])
    return ""


def _rebrand_path_signal(text: str) -> str:
    """Return first ~120-char context of a rebrand-themed path/alt-text hit.

    Runs ``REBRAND_PATH_RE`` against the unescaped page text — the same
    blob ``_external_link_hosts`` consumes — so URL slugs (`href=
    "https://navanta.com/brand-launch-..."`) and image alt attributes
    (`alt="Brand announcement"`) are both visible. The regex's phrasing
    is narrow enough that hitting it almost always corresponds to a real
    rebrand artifact rather than ordinary marketing copy.
    """
    if not text:
        return ""
    m = REBRAND_PATH_RE.search(text)
    if not m:
        return ""
    start = max(0, m.start() - 40)
    end = min(len(text), m.end() + 80)
    return _strip_field(text[start:end])


def _has_full_ip(s: str) -> bool:
    for m in _FULL_IP_RE.finditer(s):
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return True
    return False


def _strip_field(value: str) -> str:
    value = value.strip().strip('"').strip()
    # collapse internal whitespace so the TSV stays on one line
    value = re.sub(r"\s+", " ", value)
    return value[:300]


def _parse_whois(text: str) -> dict:
    out = {"whois_org": "", "whois_country": "", "registrar": ""}
    if not text:
        return out
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = _strip_field(value)
        if not value or value.lower() in ("redacted for privacy", "redacted"):
            continue
        if not out["whois_org"] and key in WHOIS_ORG_KEYS:
            out["whois_org"] = value
        elif not out["whois_country"] and key in WHOIS_COUNTRY_KEYS:
            out["whois_country"] = value
        elif not out["registrar"] and key in WHOIS_REGISTRAR_KEYS:
            out["registrar"] = value
    return out


def _run_whois(target: str, timeout: float) -> str:
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return result.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _resolve_ips(domain: str) -> list:
    """Return a deduplicated list of A/AAAA addresses for domain, or []."""
    ips = []
    seen = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
        except (socket.gaierror, socket.herror, UnicodeError, OSError):
            continue
        for info in infos:
            addr = info[4][0]
            if addr and addr not in seen:
                seen.add(addr)
                ips.append(addr)
    return ips


def _parse_ip_whois(text: str) -> dict:
    """Extract org / netname / country from an IP-WHOIS response.

    IP-WHOIS formats vary widely across registries: ARIN uses `OrgName`, RIPE
    uses `descr`/`netname`, APNIC uses `descr`/`country`, LACNIC uses `owner`,
    AFRINIC mirrors RIPE. We take the first value for each category and stop.
    """
    out = {"ip_whois_org": "", "ip_whois_netname": "", "ip_whois_country": ""}
    if not text:
        return out
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = _strip_field(value)
        if not value or value.lower() in ("redacted for privacy", "redacted"):
            continue
        if not out["ip_whois_netname"] and key in IP_WHOIS_NETNAME_KEYS:
            out["ip_whois_netname"] = value
        if not out["ip_whois_country"] and key in IP_WHOIS_COUNTRY_KEYS:
            out["ip_whois_country"] = value
        if not out["ip_whois_org"] and key in IP_WHOIS_ORG_KEYS:
            out["ip_whois_org"] = value
    return out


def _lookup_ip(ip: str, timeout: float) -> dict:
    """WHOIS one IP address, return parsed fields (empty dict on failure)."""
    return _parse_ip_whois(_run_whois(ip, timeout))


class _PageParser(HTMLParser):
    """Extract <title>, the first description-like meta tag, and body text.

    Body text excludes the contents of <script>/<style>/<noscript>/<template>
    elements — those rarely correspond to anything visible and routinely
    contain large embedded JSON blobs that would crowd out the actual page
    text under the body-text cap. Whitespace is collapsed at join time.
    """

    _SKIP_TAGS = ("script", "style", "noscript", "template")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self._body_parts = []
        self._body_chars = 0
        self._in_title = False
        self._in_body = False
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs}
            name = a.get("name", "").lower()
            prop = a.get("property", "").lower()
            if not self.description and (
                name == "description"
                or prop == "og:description"
                or name == "twitter:description"
            ):
                self.description = _strip_field(a.get("content", ""))
        elif tag == "body":
            self._in_body = True

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self._SKIP_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if tag == "title":
            self._in_title = False
        elif tag == "body":
            self._in_body = False

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title and not self.title:
            self.title = _strip_field(data)
        if self._in_body and self._body_chars < MAX_BODY_TEXT_CHARS:
            self._body_parts.append(data)
            self._body_chars += len(data)

    @property
    def body_text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self._body_parts)).strip()


def _extract_metadata(domain: str, body: bytes, encoding: str) -> dict:
    """Decode the response body once and extract every per-page signal.

    Returns ``title``, ``description``, ``rebrand_signal``, ``external_links``.
    Decoding once and running both the HTML parser and the href regex on the
    same string avoids paying the decode cost twice.
    """
    out = {
        "title": "",
        "description": "",
        "rebrand_signal": "",
        "external_links": "",
    }
    try:
        text = body.decode(encoding, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    parser = _PageParser()
    try:
        parser.feed(text)
    except Exception:
        pass
    out["title"] = parser.title
    out["description"] = parser.description
    # Many sites embed serialized HTML inside <script> blocks (block-editor /
    # Elementor templates, JSON-LD, hydration payloads) where quotes and
    # slashes are JSON-escaped: `href=\"https:\/\/...\"`. The parser already
    # skipped that content for body_text, but the URLs and alt-text inside
    # it still signal where the page is pointing — bankonitusa.com's "now
    # Navanta" banner is image-only `<a href>` with `alt="Brand
    # announcement"` and slug `/brand-launch-.../`, all sitting inside an
    # escaped Elementor blob. Unescape so the path-style rebrand regex and
    # the link-host regex both see them.
    unescaped = text.replace('\\"', '"').replace("\\/", "/").replace("\\'", "'")
    text_signal = _rebrand_signal(parser.title, parser.description, parser.body_text)
    path_signal = _rebrand_path_signal(unescaped)
    out["rebrand_signal"] = text_signal or path_signal
    out["external_links"] = ",".join(_external_link_hosts(domain, unescaped))
    return out


def _browser_fallback_fetch(url: str, timeout: float) -> dict:
    """Fallback fetch with relaxed TLS and a real-browser User-Agent.

    Triggered when the primary requests-based fetch errors out or returns a
    non-2xx status. Useful for sites that filter on User-Agent, ship
    self-signed / hostname-mismatched / weak-DH / legacy-renegotiation TLS
    that the polite primary stack correctly rejects. Best-effort — returns
    the same shape as ``_fetch_homepage``; an empty title and description
    means the fallback also failed.

    Implementation note: this used to shell out to curl. The pure-Python
    path uses :class:`_PermissiveSSLAdapter` to relax the urllib3 SSL
    context to the same effective configuration (skip cert verify, allow
    weak ciphers, allow legacy renegotiation), plus ``verify=False`` and
    a browser User-Agent. The result covers ~95% of curl's recovery rate
    on cert/UA failures; the residual gap (TLS JA3 fingerprinting, exact
    cipher ordering) is bot-detection territory that needs a headless
    browser anyway.
    """
    out = {
        "title": "",
        "description": "",
        "rebrand_signal": "",
        "external_links": "",
        "final_url": "",
        "http_status": "",
        "error": "",
    }
    headers = {"User-Agent": BROWSER_UA, "Accept": "text/html,*/*;q=0.5"}
    sess = requests.Session()
    sess.mount("https://", _PermissiveSSLAdapter(max_retries=0))
    sess.mount("http://", HTTPAdapter(max_retries=0))
    sess.max_redirects = 5
    try:
        with sess.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
            verify=False,
        ) as r:
            out["http_status"] = str(r.status_code)
            out["final_url"] = r.url
            body = b""
            for chunk in r.iter_content(chunk_size=8192):
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break
            meta = _extract_metadata(
                _hostname_from_url(url), body, r.encoding or "utf-8"
            )
            out["title"] = meta["title"]
            out["description"] = meta["description"]
            out["rebrand_signal"] = meta["rebrand_signal"]
            out["external_links"] = meta["external_links"]
    except requests.RequestException as e:
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    except (ssl.SSLError, OSError) as e:
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        sess.close()
    return out


def _fetch_homepage(domain: str, timeout: float) -> dict:
    out = {
        "title": "",
        "description": "",
        "rebrand_signal": "",
        "external_links": "",
        "final_url": "",
        "http_status": "",
        "error": "",
    }
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"}
    last_err = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        primary_status = ""
        primary_url = ""
        primary_meta = {
            "title": "",
            "description": "",
            "rebrand_signal": "",
            "external_links": "",
        }
        primary_err = ""
        try:
            with requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            ) as r:
                primary_status = str(r.status_code)
                primary_url = r.url
                body = b""
                for chunk in r.iter_content(chunk_size=8192):
                    body += chunk
                    if len(body) >= MAX_BODY_BYTES:
                        break
                primary_meta = _extract_metadata(domain, body, r.encoding or "utf-8")
        except requests.RequestException as e:
            primary_err = f"{type(e).__name__}: {e}"
        except socket.error as e:
            primary_err = f"socket: {e}"

        # Happy path: requests got a 2xx with parseable head metadata.
        if primary_status.startswith("2") and (
            primary_meta["title"] or primary_meta["description"]
        ):
            out.update(primary_meta)
            out["final_url"] = primary_url
            out["http_status"] = primary_status
            out["error"] = ""
            return out

        # Self-signed-cert detection: TLS-intercepting firewalls present
        # their own self-signed cert specifically when *blocking* a
        # request. The verify=False browser fallback would succeed but
        # return the firewall's block page, not the real operator's
        # content — that block page would then poison the row's title /
        # description and mislead the classifier. Skip the fallback for
        # this row so `_looks_bot_blocked` returns True (empty meta) and
        # the search-fallback path can recover real content.
        # Cert errors NOT covered here (hostname mismatch, weak DH,
        # legacy renegotiation) keep the existing fallback path because
        # they're typically real operators with misconfigured TLS rather
        # than firewall interception.
        if primary_err and (
            "self-signed" in primary_err.lower() or "self signed" in primary_err.lower()
        ):
            last_err = (primary_err + " | firewall-blocked, skipped fallback")[:200]
            continue

        # Curl fallback: trigger on errors or non-2xx. A 2xx with empty head
        # is left alone (likely a parked page; retrying rarely helps).
        non_success = primary_status and not primary_status.startswith("2")
        if primary_err or non_success:
            cf = _browser_fallback_fetch(url, timeout)
            if cf["title"] or cf["description"]:
                out["title"] = cf["title"]
                out["description"] = cf["description"]
                out["rebrand_signal"] = cf.get("rebrand_signal", "")
                out["external_links"] = cf.get("external_links", "")
                out["final_url"] = cf["final_url"] or primary_url
                out["http_status"] = cf["http_status"] or primary_status
                out["error"] = ""
                return out
            # Cap each error string before joining so a long primary error
            # doesn't truncate the fallback suffix out of the final 200-char field.
            if primary_err:
                last_err = primary_err[:150]
            if cf.get("error"):
                last_err = (last_err + " | fallback: " + cf["error"][:80]).strip(" |")
            # Carry forward any partial info from primary so a 4xx still
            # shows up in the TSV when both attempts fail.
            if primary_status and not out["http_status"]:
                out["http_status"] = primary_status
                out["final_url"] = primary_url
            continue

        # 2xx with empty head — accept whatever we got and stop.
        out.update(primary_meta)
        out["final_url"] = primary_url
        out["http_status"] = primary_status
        out["error"] = ""
        return out

    out["error"] = last_err[:200]
    return out


# Title patterns that indicate the homepage fetch returned a bot-block /
# WAF interstitial / parked / placeholder page rather than the real
# operator's content. Triggers a search-fallback lookup when
# --use-search-fallback is passed. The patterns intentionally overlap with
# classify_unknown_domains.py's TITLE_NOISE_RE / PARKED_PAGE_RE — search
# fallback is the recovery path for exactly the rows that filter excludes.
_SEARCH_FALLBACK_TRIGGER_RE = re.compile(
    r"(?i)(?:"
    # Cloudflare / WAF / bot-detection interstitials
    r"attention required! \| cloudflare|"
    r"just a moment|are you a robot|checking your browser|"
    r"please enable javascript|"
    r"ddos[- ]guard|px-captcha|vercel security checkpoint|"
    r"\bcaptcha\b|"
    # Local firewall / DNS-filter block pages — corporate firewalls (Fortinet,
    # Palo Alto, Cisco Umbrella, Sophos, etc.) typically present a generic
    # block page with one of these phrases. The page is the *firewall's*,
    # not the operator's, so search-fallback is the only way to recover.
    r"web filter violation|web filter block|fortinet secure dns service|"
    r"this site has been blocked|access blocked by|"
    r"blocked by your network|blocked by administrator|"
    r"this content is blocked|"
    # Generic blocked / unavailable
    r"access denied|access to this page has been denied|"
    r"site is not available|page is not available|"
    r"403 forbidden|401 unauthorized|"
    r"bad gateway|503 service|"
    # Registrar / hosting parking placeholders
    r"this domain (?:name )?(?:has been |is )registered with|"
    r"your domain (?:is |has )(?:expired|parked)|"
    r"domain (?:has )?expired|domain (?:is )?parked|"
    r"this domain is parked|parked free, courtesy of|"
    r"domain parking|"
    # Default-server / unconfigured pages
    r"automatically generated default|default server page|"
    r"default landing page|default web page|"
    r"successfully deployed by|"
    r"welcome to apache|apache http server test page|welcome to nginx|"
    r"just another wordpress site|"
    r"hostinger horizons|"
    # For-sale parking
    r"website is for sale|domain is for sale|domain (?:name )?for sale|"
    r"buy this domain"
    r")"
)


def _registrable_root(host: str) -> str:
    """Return a coarse 'registrable' root for SEO-spam matching.

    We compare the *last two* labels of the input domain to the *last two*
    labels of the search result's host. That's not a full PSL lookup — it
    correctly equates `www.foo.com` with `foo.com` and `sub.foo.co.uk` with
    `foo.co.uk` for ccTLD pairs we care about, but it would equate
    `foo.com.au` with `com.au`. The same-root check is paired with an exact
    second-level match where available, so the false-equate risk is bounded.
    """
    parts = host.lower().strip().split(".")
    if len(parts) <= 2:
        return host.lower().strip()
    return ".".join(parts[-2:])


def _hosts_match(input_domain: str, result_host: str) -> bool:
    """Return True iff the search-result host belongs to the input domain.

    Anti-SEO-spam guard: the search engine often returns multiple results
    for a `site:foo.com` query, and the top hit isn't always on `foo.com`
    — sometimes it's a third-party page that scraped or talks about the
    domain. We accept a result only when the result's host is exactly the
    input domain or a subdomain of it.
    """
    if not result_host:
        return False
    a = input_domain.lower().strip().rstrip(".")
    b = result_host.lower().strip().rstrip(".")
    if a == b:
        return True
    return b.endswith("." + a)


def _search_fallback_fetch(domain: str, max_results: int = 5) -> dict:
    """Recover title + description from a DuckDuckGo search result.

    Returns the same shape as ``_fetch_homepage`` (minus the rebrand_signal /
    external_links extraction, which both require body HTML we don't have
    when going through search). Rate-limited by ddgs's own internal
    throttling — no extra sleep needed.

    The same-domain guard (`_hosts_match`) is the SEO-spam defense:
    search results that point at a *different* host than the input
    domain are silently skipped, and we keep walking down the result
    list until we find one whose host belongs to the input domain or
    we exhaust the result set.

    If `_DDGS` is None (ddgs not installed) the function returns an
    empty result rather than raising — the caller decides how to handle
    that (the CLI flag check happens upstream).
    """
    out = {
        "title": "",
        "description": "",
        "final_url": "",
        "title_source": "",
    }
    if _DDGS is None:
        return out
    try:
        with _DDGS() as engine:
            results = list(engine.text(f"site:{domain}", max_results=max_results))
    except Exception as e:
        # Network / rate-limit / parse errors all fall through. The
        # caller treats an empty result the same way as a no-search-result.
        out["error"] = f"search: {type(e).__name__}: {e}"[:200]
        return out
    for r in results:
        href = r.get("href", "") or ""
        host = _hostname_from_url(href)
        if not _hosts_match(domain, host):
            continue
        out["title"] = (r.get("title") or "").strip()
        # ddgs's body field is the search snippet — DDG calls it "abstract"
        # in the JSON API; the python wrapper exposes it as 'body'.
        out["description"] = (r.get("body") or "").strip()
        out["final_url"] = href
        out["title_source"] = "search"
        return out
    return out


# When a DDG search result's title is just a hostname pointer — either
# the literal "Link to <hostname>" snippet DDG sometimes emits for
# subdomains it has indexed, or a bare hostname with no other words —
# the title has no classifier signal. The right move is to follow the
# pointer: fetch the target hostname directly and use *its* content.
# These two regexes recognize the patterns.
_LINK_TO_TITLE_RE = re.compile(r"^link to\s+(\S+?)\s*$", re.IGNORECASE)
_BARE_HOSTNAME_RE = re.compile(
    r"^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\.?$",
    re.IGNORECASE,
)


def _extract_link_target(title: str) -> str:
    """Return target hostname when the title is just a link/domain pointer.

    Two patterns:
    - "Link to <hostname>" — DDG's literal snippet for some subdomain
      results, e.g. "Link to fcs.health.gov.il".
    - Just a hostname — the entire title *is* the hostname, e.g.
      "yangon.mfa.gov.il".

    Returns "" when neither pattern matches (the search snippet has
    real classifier-relevant content and we should use it as-is).
    """
    title = (title or "").strip()
    if not title:
        return ""
    m = _LINK_TO_TITLE_RE.match(title)
    if m:
        candidate = m.group(1).rstrip(".")
        if _BARE_HOSTNAME_RE.match(candidate):
            return candidate.lower()
    if _BARE_HOSTNAME_RE.match(title):
        return title.rstrip(".").lower()
    return ""


def _looks_bot_blocked(meta: dict) -> bool:
    """Decide whether a homepage-fetch result warrants a search-fallback.

    Triggers when the title/description match one of the bot-block /
    parking patterns OR both fields are empty (typical of WAF interstitials
    that strip <title>/<meta> entirely). The combined check is broader
    than just the regex because some interstitials produce no extractable
    metadata at all.
    """
    title = (meta.get("title") or "").strip()
    desc = (meta.get("description") or "").strip()
    if not (title or desc):
        return True
    return bool(
        _SEARCH_FALLBACK_TRIGGER_RE.search(title)
        or _SEARCH_FALLBACK_TRIGGER_RE.search(desc)
    )


def _collect_one(
    domain: str,
    whois_timeout: float,
    http_timeout: float,
    use_search_fallback: bool = False,
) -> dict:
    row = {k: "" for k in FIELDS}
    row["domain"] = domain
    row.update(_parse_whois(_run_whois(domain, whois_timeout)))
    row.update(_fetch_homepage(domain, http_timeout))
    if row.get("title") or row.get("description"):
        row["title_source"] = "homepage"
    # Search fallback: when the homepage fetch returned a bot-block /
    # parked / placeholder / empty result, ask DuckDuckGo for the
    # `site:<domain>` snippet. Same-domain guard prevents SEO-spam
    # contamination (a third-party page that scraped the domain).
    if use_search_fallback and _looks_bot_blocked(row):
        sf = _search_fallback_fetch(domain)
        if sf["title"] or sf["description"]:
            row["title"] = sf["title"]
            row["description"] = sf["description"]
            # Preserve the homepage-fetched final_url if we had one — it
            # represents what the *server* redirected us to, which is more
            # useful for redirect-target / rebrand analysis than the search
            # result's href.
            if not row.get("final_url"):
                row["final_url"] = sf["final_url"]
            row["title_source"] = "search"
        # Link-following: if the search snippet is just a hostname pointer
        # ("Link to fcs.health.gov.il" or bare "yangon.mfa.gov.il") it
        # carries no classifier signal — the snippet is DDG's placeholder
        # for a subdomain it indexed but didn't fully snapshot. Fetch the
        # target hostname directly and replace title/desc with its real
        # content. The link target is recorded in `link_target_domain` so
        # downstream tooling can emit alias map rows when the target is on
        # a different registrable domain than the input.
        target = _extract_link_target(row.get("title", ""))
        if target and target != domain:
            row["link_target_domain"] = target
            target_meta = _fetch_homepage(target, http_timeout)
            if (
                target_meta.get("title") or target_meta.get("description")
            ) and not _looks_bot_blocked(target_meta):
                row["title"] = target_meta["title"]
                row["description"] = target_meta["description"]
                row["rebrand_signal"] = target_meta.get("rebrand_signal", "")
                row["external_links"] = target_meta.get("external_links", "")
                row["final_url"] = target_meta.get("final_url") or row.get(
                    "final_url", ""
                )
                row["title_source"] = f"search→{target}"
    ips = _resolve_ips(domain)
    row["ips"] = ",".join(ips[:4])
    # WHOIS the first resolved IP — usually reveals the hosting ASN / provider,
    # which often identifies domains whose homepage and domain-WHOIS are empty.
    if ips:
        row.update(_lookup_ip(ips[0], whois_timeout))
    return row


def _load_mapped(map_path: str) -> set:
    mapped = set()
    if not os.path.exists(map_path):
        return mapped
    with open(map_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            d = row.get("base_reverse_dns", "").strip().lower()
            if d:
                mapped.add(d)
    return mapped


def _load_psl_overrides(path: str) -> list:
    """Return the PSL override suffixes as a list (preserving file order).

    Each entry is a suffix such as `.linode.com` or `-applefibernet.com`. A
    domain matching one of these is folded to the override with its leading
    `.`/`-` stripped — consistent with `find_unknown_base_reverse_dns.py`.
    """
    if not os.path.exists(path):
        return []
    overrides = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip().lower()
            if s:
                overrides.append(s)
    return overrides


def _apply_psl_override(domain: str, overrides: list) -> str:
    for ov in overrides:
        if domain.endswith(ov):
            return ov.strip(".").strip("-")
    return domain


def _load_input_domains(input_path: str, mapped: set, overrides: list) -> list:
    domains = []
    seen = set()

    def _add(raw: str):
        d = raw.strip().lower()
        if not d:
            return
        d = _apply_psl_override(d, overrides)
        if _has_full_ip(d):
            # privacy: refuse to research entries that carry a full IPv4
            return
        if d in seen or d in mapped:
            return
        seen.add(d)
        domains.append(d)

    with open(input_path, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        first = next(reader, None)
        if first and first[0].strip().lower() not in ("source_name", "domain"):
            _add(first[0])
        for row in reader:
            if row:
                _add(row[0] if row else "")
    return domains


def _load_existing_output(output_path: str) -> set:
    done = set()
    if not os.path.exists(output_path):
        return done
    with open(output_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            d = (row.get("domain") or "").strip().lower()
            if d:
                done.add(d)
    return done


def _main():
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("-i", "--input", default=DEFAULT_INPUT)
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    p.add_argument(
        "-m",
        "--map",
        default=MAP_FILE,
        help="Existing map file; domains already mapped are skipped",
    )
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--whois-timeout", type=float, default=10.0)
    p.add_argument("--http-timeout", type=float, default=8.0)
    p.add_argument(
        "--psl-overrides",
        default=PSL_OVERRIDES_FILE,
        help=(
            "Path to psl_overrides.txt — input domains matching one of "
            "these suffixes are folded to the override's base (same logic "
            "as find_unknown_base_reverse_dns.py). Pass an empty string to "
            "disable."
        ),
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process the first N pending domains (0 = all)",
    )
    p.add_argument(
        "--use-search-fallback",
        action="store_true",
        help=(
            "When the homepage fetch returns a bot-block / parked / "
            "placeholder / empty page, fall back to a DuckDuckGo "
            "site:<domain> search and use the top result's title and "
            "description (only if the result host belongs to the input "
            "domain, anti-SEO-spam guard). Requires the `ddgs` package "
            "(pip install ddgs, or pip install .[build]). Off by default "
            "because it adds ~0.5–1s of latency per fallback row and "
            "depends on a third-party search service."
        ),
    )
    args = p.parse_args()
    if args.use_search_fallback and _DDGS is None:
        print(
            "error: --use-search-fallback requires the `ddgs` package "
            "(pip install ddgs, or pip install .[build]).",
            file=sys.stderr,
        )
        sys.exit(1)

    mapped = _load_mapped(args.map)
    overrides = _load_psl_overrides(args.psl_overrides) if args.psl_overrides else []
    all_domains = _load_input_domains(args.input, mapped, overrides)
    done = _load_existing_output(args.output)
    pending = [d for d in all_domains if d not in done]
    if args.limit > 0:
        pending = pending[: args.limit]

    print(
        f"Input: {len(all_domains)} domains | "
        f"already in output: {len(done)} | "
        f"to fetch: {len(pending)}",
        file=sys.stderr,
    )
    if not pending:
        return

    write_header = not os.path.exists(args.output) or os.path.getsize(args.output) == 0
    with open(args.output, "a", encoding="utf-8", newline="") as out_f:
        writer = csv.DictWriter(
            out_f,
            fieldnames=FIELDS,
            delimiter="\t",
            lineterminator="\n",
            quoting=csv.QUOTE_MINIMAL,
        )
        if write_header:
            writer.writeheader()
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {
                ex.submit(
                    _collect_one,
                    d,
                    args.whois_timeout,
                    args.http_timeout,
                    args.use_search_fallback,
                ): d
                for d in pending
            }
            for i, fut in enumerate(as_completed(futures), 1):
                d = futures[fut]
                try:
                    row = fut.result()
                except Exception as e:
                    row = {k: "" for k in FIELDS}
                    row["domain"] = d
                    row["error"] = f"unhandled: {type(e).__name__}: {e}"[:200]
                writer.writerow(row)
                out_f.flush()
                if i % 25 == 0 or i == len(pending):
                    print(f"  {i}/{len(pending)}: {d}", file=sys.stderr)


if __name__ == "__main__":
    _main()
