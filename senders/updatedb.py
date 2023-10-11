import requests

import sqlite3

from bs4 import BeautifulSoup


db = sqlite3.connect("senders.sqlite")
db.execute("""
CREATE TABLE IF NOT EXISTS "senders" (
    "id" INTEGER UNIQUE NOT NULL,
    "name" TEXT UNIQUE NOT NULL,
    "spf_aligned" INTEGER,
    "dkim_aligned" INTEGER,
    "known_to_forward" INTEGER,
    "forward_dkim_intact" INTEGER,
    "forward_own_envelope_domain" INTEGER,
    "support_url" TEXT,
    "dmarc_io_uri" TEXT UNIQUE,
    PRIMARY KEY("id" AUTOINCREMENT),
    CHECK("spf_aligned" = 0 or "spf_aligned" = 1),
    CHECK("dkim_aligned" = 0 or "dkim_aligned" = 1),
    CHECK("known_to_forward" = 0 or "known_to_forward" = 1),
    CHECK("forward_dkim_intact" = 0 or "forward_dkim_intact" = 1),
    CHECK(
    "forward_own_envelope_domain" = 0 or "forward_own_envelope_domain" = 1
    )
)
""")
db.execute("""
CREATE TABLE IF NOT EXISTS "reverse_dns" (
    "id" INTEGER UNIQUE NOT NULL,
    "base_domain" TEXT UNIQUE NOT NULL,
    "sender_id" INTEGER NOT NULL,
    PRIMARY KEY("id" AUTOINCREMENT),
    FOREIGN KEY(sender_id) REFERENCES senders(id)
)
""")
curser = db.cursor()
content = requests.get("http://localhost:8050/render.html",
                       params=dict(url="https://dmarc.io/sources/")).content
soup = BeautifulSoup(content, "html.parser")
table = soup.find("tbody")
rows = table.find_all("tr")
for row in rows:
    data = row.find_all("td")
    link = data[0].find("a")
    name = link.text
    dmarc_io_uri = link.get("href")
    spf_aligned = len(data[1].find_all("i"))
    dkim_aligned = len(data[2].find_all("i"))
    params = (name, spf_aligned, dkim_aligned, 0,
              dmarc_io_uri)
    curser.execute("""
    UPDATE senders
    SET name = ?,
        spf_aligned = ?,
        dkim_aligned = ?,
        known_to_forward = ?
    WHERE dmarc_io_uri = ?""", params)
    db.commit()
    curser.execute("""
    INSERT OR IGNORE INTO senders(name, spf_aligned, dkim_aligned,
    known_to_forward, dmarc_io_uri) values (?,?,?,?,?)""", params)
    db.commit()
content = requests.get("http://localhost:8050/render.html",
                       params=dict(url="https://dmarc.io/forwarders/")).content
soup = BeautifulSoup(content, "html.parser")
table = soup.find("tbody")
rows = table.find_all("tr")
for row in rows:
    data = row.find_all("td")
    link = data[0].find("a")
    name = link.text
    dmarc_io_uri = link.get("href")
    forward_dkim_intact = len(data[1].find_all("i"))
    forward_own_envelope_domain = len(data[2].find_all("i"))
    params = (name, forward_dkim_intact, forward_own_envelope_domain, 1,
              dmarc_io_uri)
    curser.execute("""
    UPDATE senders
    SET name = ?,
        forward_dkim_intact = ?,
        forward_own_envelope_domain = ?,
        known_to_forward = ?
    WHERE dmarc_io_uri = ?""", params)
    db.commit()
    curser.execute("""
    INSERT OR IGNORE INTO senders(name, spf_aligned, dkim_aligned,
    known_to_forward, dmarc_io_uri) values (?,?,?,?,?)""", params)
    db.commit()
