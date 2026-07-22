#!/usr/bin/env python3
"""Screenshot the dev dashboards served by docker-compose.dashboard-dev.yml.

Companion to dashboard-dev-bootstrap.sh: after editing a dashboard and
re-running the bootstrap (which re-imports it), run this to capture how each
UI actually renders the current sample data. Screenshots land in
dashboard-screenshots/ (gitignored).

Usage:
    pip install playwright && playwright install chromium   # one-time
    set -a; . ./.env; set +a                                # load credentials
    ./dashboard-dev-screenshots.py [kibana osd grafana splunk]

Hard-won details encoded here:
- Kibana/OSD dashboards poll forever, so Playwright's "networkidle" never
  fires; navigate with "domcontentloaded" and give visualizations a fixed
  render wait instead.
- The bootstrap imports OSD saved objects into the *global* tenant, but a
  fresh admin login lands in the private tenant, which can hold stale
  copies; pin ?security_tenant=global in the URL or you will screenshot
  old dashboards.
- Grafana ignores HTTP basic auth for its UI; drive the login form.
- Splunk panels are the slowest to populate; wait ~25s before capturing.
"""

import os
import sys
import traceback

from playwright.sync_api import sync_playwright

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard-screenshots")
os.makedirs(OUT, exist_ok=True)

GRAFANA_USER = os.environ.get("GRAFANA_USER", "admin")
GRAFANA_PASS = os.environ.get("GRAFANA_PASSWORD", "admin")

# Env vars each target cannot run without; checked up front for the selected
# targets only, so e.g. `./dashboard-dev-screenshots.py grafana` works in a
# shell that never loaded .env.
REQUIRED_ENV = {
    "osd": "OPENSEARCH_INITIAL_ADMIN_PASSWORD",
    "splunk": "SPLUNK_PASSWORD",
}

# Absolute range covering every bundled sample report.
KB_TIME = "_g=(time:(from:'2017-01-01T00:00:00.000Z',to:'2026-07-01T00:00:00.000Z'))"
GRAFANA_RANGE = "from=2017-01-01T00:00:00.000Z&to=2026-07-01T00:00:00.000Z"
AGG_DASH_ID = "50c317b0-262e-11f1-96a6-fb3734bd0b21"
VIEWPORT = {"width": 1720, "height": 1200}


def shot(page, name, full=True):
    path = os.path.join(OUT, name)
    page.screenshot(path=path, full_page=full)
    print("saved", name)


def kibana(pw):
    b = pw.chromium.launch(headless=True)
    try:
        page = b.new_page(viewport=VIEWPORT)
        page.goto(
            f"http://localhost:5601/app/dashboards#/view/{AGG_DASH_ID}?{KB_TIME}",
            wait_until="domcontentloaded",
            timeout=120000,
        )
        page.wait_for_timeout(20000)
        shot(page, "kibana_aggregate.png")
    finally:
        b.close()


def osd(pw):
    os_pass = os.environ["OPENSEARCH_INITIAL_ADMIN_PASSWORD"]
    b = pw.chromium.launch(headless=True)
    try:
        ctx = b.new_context(
            viewport=VIEWPORT,
            http_credentials={"username": "admin", "password": os_pass},
            ignore_https_errors=True,
        )
        page = ctx.new_page()
        page.goto("http://localhost:5602/app/login", timeout=120000)
        page.wait_for_timeout(3000)
        if page.locator('input[data-test-subj="user-name"]').count():
            page.fill('input[data-test-subj="user-name"]', "admin")
            page.fill('input[data-test-subj="password"]', os_pass)
            page.click('button[data-test-subj="submit"]')
            page.wait_for_timeout(6000)
        page.goto(
            "http://localhost:5602/app/dashboards?security_tenant=global"
            f"#/view/{AGG_DASH_ID}?{KB_TIME}",
            wait_until="domcontentloaded",
            timeout=120000,
        )
        page.wait_for_timeout(20000)
        shot(page, "osd_aggregate.png")
    finally:
        # Closing the browser also closes the context and its pages.
        b.close()


def grafana(pw):
    b = pw.chromium.launch(headless=True)
    try:
        page = b.new_page(viewport=VIEWPORT)
        page.goto("http://localhost:3000/login", timeout=120000)
        page.wait_for_timeout(2000)
        page.fill('input[name="user"]', GRAFANA_USER)
        page.fill('input[name="password"]', GRAFANA_PASS)
        page.click('button[type="submit"]')
        page.wait_for_timeout(5000)
        base = "http://localhost:3000/d/SDksirRWz/dmarc-reports"
        page.goto(
            f"{base}?{GRAFANA_RANGE}&kiosk",
            wait_until="domcontentloaded",
            timeout=120000,
        )
        page.wait_for_timeout(10000)
        shot(page, "grafana_dashboard.png")
        # Zoomed views of the alignment-detail panels.
        for pid, name in ((40, "dkim_details"), (16, "spf_details"), (41, "overview")):
            page.goto(
                f"{base}?{GRAFANA_RANGE}&kiosk&viewPanel={pid}",
                wait_until="domcontentloaded",
                timeout=120000,
            )
            page.wait_for_timeout(8000)
            shot(page, f"grafana_panel_{name}.png", full=False)
    finally:
        b.close()


def splunk(pw):
    b = pw.chromium.launch(headless=True)
    try:
        page = b.new_page(viewport=VIEWPORT)
        page.goto("http://localhost:8000/en-US/account/login", timeout=120000)
        page.wait_for_timeout(3000)
        page.fill("input#username", "admin")
        page.fill("input#password", os.environ["SPLUNK_PASSWORD"])
        page.keyboard.press("Enter")
        page.wait_for_timeout(8000)
        page.goto(
            "http://localhost:8000/en-US/app/DMARC/dmarc_aggregate"
            "?form.time_range.earliest=0&form.time_range.latest=now",
            wait_until="domcontentloaded",
            timeout=180000,
        )
        page.wait_for_timeout(25000)
        shot(page, "splunk_aggregate.png")
    finally:
        b.close()


TARGETS = {"kibana": kibana, "osd": osd, "grafana": grafana, "splunk": splunk}

if __name__ == "__main__":
    names = sys.argv[1:] or list(TARGETS)
    unknown = [n for n in names if n not in TARGETS]
    if unknown:
        sys.exit(f"unknown target(s) {unknown}; choose from {list(TARGETS)}")
    missing = sorted(
        {
            REQUIRED_ENV[n]
            for n in names
            if n in REQUIRED_ENV and not os.environ.get(REQUIRED_ENV[n])
        }
    )
    if missing:
        sys.exit(
            f"missing environment variable(s) {missing}; "
            "load credentials first: set -a; . ./.env; set +a"
        )
    failures = []
    with sync_playwright() as pw:
        for n in names:
            try:
                TARGETS[n](pw)
            except Exception:  # keep going; report at the end
                failures.append(n)
                print(f"FAILED {n}:", file=sys.stderr)
                traceback.print_exc()
    if failures:
        sys.exit(f"failed: {failures}")
