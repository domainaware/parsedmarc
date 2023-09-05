import urllib.parse
import sqlite3

from bs4 import BeautifulSoup

dmarc_io = "https://dmarc.io"
with open("sources.html") as sources_file:
    content = sources_file.read()
soup = BeautifulSoup(content, "html.parser")
table = soup.find("tbody")
rows = table.find_all("tr")
for row in rows:
    data = row.find_all("td")
    link = data[0].find("a")
    name = link.text
    dmarc_io_url = urllib.parse.urljoin(dmarc_io, link.get("href"))
    spf_aligned = len(data[1].find_all("i"))
    dkim_aligned = len(data[2].find_all("i"))
    print(name)
