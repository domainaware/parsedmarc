#!/usr/bin/env python
"""Re-fetch mapped reverse-DNS base domains and surface possible rebrand signals.

Walks `base_reverse_dns_map.csv`, fetches each domain's homepage with the same
machinery used by `collect_domain_info.py`, and writes a TSV listing rows where
one of two default drift signals fired:

- `rebrand_signal` — the homepage's title / description / body text matched a
  rebrand-keyword phrase ("is now X", "formerly known as X", "we became X",
  ...) *or* a rebrand-themed URL slug or image-alt phrase ("brand-launch",
  "brand-announcement", "rebrand", "name-change", "our-new-name", ...). The
  path/alt-text scan catches image-only banners — bankonitusa.com's "now
  Navanta" banner is an image inside `<a href="https://navanta.com/brand-launch-...">`
  with `alt="Brand announcement"` — that pure body-text scanning misses.
- `redirect_changed` — the homepage redirected to a host whose registered
  domain is different from the input. Common acquisition pattern (e.g.
  vodafone.is → syn.is, apogee.us → boldyn.com) where the original brand is
  now served by the acquirer's primary site.

`external_links` is captured into the output for context — the homepage's
non-self, non-social outbound link hosts — but is *not* a default flag
trigger. Most external links are to partners / customers / vendors and do
not indicate a rebrand; flagging on them would flood review with noise.
Pass `--flag-external-links` to also flag on this signal during a thorough
sweep where missing an image-only banner that lacks rebrand-themed slug
or alt text is worse than the noise.

The output is meant for periodic review, not automated map mutation. Treat
each hit as a candidate for manual verification per AGENTS.md case-1 / case-2
rules — a single signal is *one* corroborating source; a real map update
still needs two.

Run from the `parsedmarc/resources/maps/` directory:

    python detect_rebrands.py [-m base_reverse_dns_map.csv] \\
        [-o rebrand_drift.tsv] [--workers N] [--limit N]

Resume-safe: re-running only re-fetches domains not already in the output.
"""

import argparse
import csv
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from collect_domain_info import (
    MAP_FILE,
    _fetch_homepage,
)

DEFAULT_OUTPUT = "rebrand_drift.tsv"

OUTPUT_FIELDS = [
    "domain",
    "current_name",
    "current_type",
    "rebrand_signal",
    "external_links",
    "final_url",
    "redirect_changed",
    "title",
    "description",
    "http_status",
    "error",
]


def _final_host(final_url: str) -> str:
    if not final_url:
        return ""
    try:
        return (urlparse(final_url).hostname or "").lower()
    except Exception:
        return ""


def _redirect_changed(domain: str, final_url: str) -> bool:
    """True when the homepage's final hostname is not under the input domain.

    The map keys are already base domains, so any redirect that lands outside
    the input domain's name space is a candidate signal — typical case-1
    acquisition redirect (vodafone.is → syn.is). Subdomain redirects under
    the same base (www.example.com → example.com) are not flagged. False
    positives from generic CDN / login subdomains on a sister-brand host are
    accepted; the reviewer judges per AGENTS.md case-2 rules.
    """
    host = _final_host(final_url)
    if not host:
        return False
    if host == domain or host.endswith("." + domain):
        return False
    return True


def _load_map(map_path: str) -> list:
    """Return [(domain, name, type), ...] from base_reverse_dns_map.csv."""
    rows = []
    with open(map_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            d = (row.get("base_reverse_dns") or "").strip().lower()
            if d:
                rows.append(
                    (
                        d,
                        (row.get("name") or "").strip(),
                        (row.get("type") or "").strip(),
                    )
                )
    return rows


def _load_existing(output_path: str) -> set:
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


def _check_one(domain: str, name: str, type_: str, http_timeout: float) -> dict:
    page = _fetch_homepage(domain, http_timeout)
    return {
        "domain": domain,
        "current_name": name,
        "current_type": type_,
        "rebrand_signal": page.get("rebrand_signal", ""),
        "external_links": page.get("external_links", ""),
        "final_url": page.get("final_url", ""),
        "redirect_changed": "1"
        if _redirect_changed(domain, page.get("final_url", ""))
        else "",
        "title": page.get("title", ""),
        "description": page.get("description", ""),
        "http_status": page.get("http_status", ""),
        "error": page.get("error", ""),
    }


def _main():
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("-m", "--map", default=MAP_FILE)
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--http-timeout", type=float, default=8.0)
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only check the first N pending domains (0 = all)",
    )
    p.add_argument(
        "--include-clean",
        action="store_true",
        help=(
            "Write every fetched row to the output, not just the ones with a "
            "rebrand_signal or redirect_changed hit. Useful for spot-checking "
            "the no-signal majority."
        ),
    )
    p.add_argument(
        "--flag-external-links",
        action="store_true",
        help=(
            "Also flag rows whose homepage links to any non-self, non-noise "
            "external host. Off by default because most external links are "
            "to partners / customers / vendors and don't indicate a rebrand "
            "— a partner case study would otherwise produce a noisy hit. "
            "Useful for thorough sweeps where missing an image-only banner "
            "(no rebrand-themed slug or alt text) is worse than the noise."
        ),
    )
    args = p.parse_args()

    map_rows = _load_map(args.map)
    done = _load_existing(args.output)
    pending = [r for r in map_rows if r[0] not in done]
    if args.limit > 0:
        pending = pending[: args.limit]

    print(
        f"Map: {len(map_rows)} domains | "
        f"already in output: {len(done)} | "
        f"to fetch: {len(pending)}",
        file=sys.stderr,
    )
    if not pending:
        return

    write_header = not os.path.exists(args.output) or os.path.getsize(args.output) == 0
    flagged = 0
    with open(args.output, "a", encoding="utf-8", newline="") as out_f:
        writer = csv.DictWriter(
            out_f,
            fieldnames=OUTPUT_FIELDS,
            delimiter="\t",
            lineterminator="\n",
            quoting=csv.QUOTE_MINIMAL,
        )
        if write_header:
            writer.writeheader()
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {
                ex.submit(_check_one, d, n, t, args.http_timeout): d
                for (d, n, t) in pending
            }
            for i, fut in enumerate(as_completed(futures), 1):
                d = futures[fut]
                try:
                    row = fut.result()
                except Exception as e:
                    row = {k: "" for k in OUTPUT_FIELDS}
                    row["domain"] = d
                    row["error"] = f"unhandled: {type(e).__name__}: {e}"[:200]
                hit = bool(row.get("rebrand_signal") or row.get("redirect_changed"))
                if args.flag_external_links and row.get("external_links"):
                    hit = True
                if hit or args.include_clean:
                    writer.writerow(row)
                    out_f.flush()
                if hit:
                    flagged += 1
                if i % 100 == 0 or i == len(pending):
                    print(
                        f"  {i}/{len(pending)} fetched, {flagged} flagged: {d}",
                        file=sys.stderr,
                    )

    print(f"Done. {flagged} flagged rows written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    _main()
