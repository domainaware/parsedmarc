#!/usr/bin/env python
"""Collect WHOIS and HTTP metadata for reverse DNS base domains.

Reads a list of domains (defaults to the unmapped entries in
`unknown_base_reverse_dns.csv`) and writes a compact TSV with the fields most
useful for classifying an unknown sender:

    domain, whois_org, whois_country, registrar, title, description,
    final_url, http_status, error

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

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

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
    "final_url",
    "http_status",
    "ips",
    "ip_whois_org",
    "ip_whois_netname",
    "ip_whois_country",
    "error",
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
        # OP_LEGACY_SERVER_CONNECT (0x4) — accept unsafe legacy renegotiation.
        # Available as ssl.OP_LEGACY_SERVER_CONNECT on Python 3.12+; defined
        # by raw value here for portability across stdlib versions.
        ctx.options |= 0x4
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

# Privacy filter: drop entries containing a full IPv4 address (four dotted or
# dashed octets). Full IPs in a reverse-DNS base domain reveal a specific
# customer address and must never enter the map.
_FULL_IP_RE = re.compile(
    r"(?<![\d])(\d{1,3})[-.](\d{1,3})[-.](\d{1,3})[-.](\d{1,3})(?![\d])"
)


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


class _HeadParser(HTMLParser):
    """Extract <title> and the first description-like meta tag."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self._in_title = False
        self._stop = False

    def handle_starttag(self, tag, attrs):
        if self._stop:
            return
        tag = tag.lower()
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
            # everything useful is in <head>; stop parsing once we hit <body>
            self._stop = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = _strip_field(data)


def _parse_head(body: bytes, encoding: str) -> tuple:
    try:
        text = body.decode(encoding, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    parser = _HeadParser()
    try:
        parser.feed(text)
    except Exception:
        pass
    return parser.title, parser.description


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
            out["title"], out["description"] = _parse_head(body, r.encoding or "utf-8")
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
        primary_title = ""
        primary_description = ""
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
                primary_title, primary_description = _parse_head(
                    body, r.encoding or "utf-8"
                )
        except requests.RequestException as e:
            primary_err = f"{type(e).__name__}: {e}"
        except socket.error as e:
            primary_err = f"socket: {e}"

        # Happy path: requests got a 2xx with parseable head metadata.
        if primary_status.startswith("2") and (primary_title or primary_description):
            out["title"] = primary_title
            out["description"] = primary_description
            out["final_url"] = primary_url
            out["http_status"] = primary_status
            out["error"] = ""
            return out

        # Curl fallback: trigger on errors or non-2xx. A 2xx with empty head
        # is left alone (likely a parked page; retrying rarely helps).
        non_success = primary_status and not primary_status.startswith("2")
        if primary_err or non_success:
            cf = _browser_fallback_fetch(url, timeout)
            if cf["title"] or cf["description"]:
                out["title"] = cf["title"]
                out["description"] = cf["description"]
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
        out["title"] = primary_title
        out["description"] = primary_description
        out["final_url"] = primary_url
        out["http_status"] = primary_status
        out["error"] = ""
        return out

    out["error"] = last_err[:200]
    return out


def _collect_one(domain: str, whois_timeout: float, http_timeout: float) -> dict:
    row = {k: "" for k in FIELDS}
    row["domain"] = domain
    row.update(_parse_whois(_run_whois(domain, whois_timeout)))
    row.update(_fetch_homepage(domain, http_timeout))
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
    args = p.parse_args()

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
                ex.submit(_collect_one, d, args.whois_timeout, args.http_timeout): d
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
