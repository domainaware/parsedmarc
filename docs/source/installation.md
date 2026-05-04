# Installation

## Prerequisites

`parsedmarc` works with Python 3 only.

### Testing multiple report analyzers

If you would like to test parsedmarc and another report processing
solution at the same time, you can have up to two `mailto` URIs in each of the rua and ruf
tags in your DMARC record, separated by commas.

### Using a web proxy

If your system is behind a web proxy, you need to configure your system
to use that proxy. To do this, edit `/etc/environment` and add your
proxy details there, for example:

```bash
http_proxy=http://user:password@prox-server:3128
https_proxy=https://user:password@prox-server:3128
ftp_proxy=http://user:password@prox-server:3128
```

Or if no credentials are needed:

```bash
http_proxy=http://prox-server:3128
https_proxy=https://prox-server:3128
ftp_proxy=http://prox-server:3128
```

This will set the proxy up for use system-wide, including for `parsedmarc`.

### Using Microsoft Exchange

If your mail server is Microsoft Exchange, ensure that it is patched to at
least:

- Exchange Server 2010 Update Rollup 22 ([KB4295699])
- Exchange Server 2013 Cumulative Update 21 ([KB4099855])
- Exchange Server 2016 Cumulative Update 11 ([KB4134118])

### geoipupdate setup

:::{note}
Starting in `parsedmarc` 9.8.0, a static copy of the
[IPinfo Lite] database is distributed with `parsedmarc`, under the
terms of the [Creative Commons Attribution-ShareAlike 4.0 License],
as a fallback if the [MaxMind GeoLite2 Country database] is not
installed. Prior versions bundled the DB-IP Country Lite database
instead; both share the same MMDB format, so users who have installed
either (or a MaxMind GeoLite2) database locally will continue to work
without changes.

The bundled database is automatically updated at startup by downloading
the latest copy from GitHub, unless the `offline` flag is set. The
database is cached locally and refreshed on each run (or on `SIGHUP`
in watch mode). If the download fails, a previously cached copy or the
bundled database is used as a fallback.

The download URL can be overridden with the `ip_db_url` setting, and
the location of a local database file can be overridden with the
`ip_db_path` setting.
:::

On Debian 10 (Buster) or later, run:

```bash
sudo apt-get install -y geoipupdate
```

:::{note}
[Component "contrib"] is required in your apt sources.
:::

On Ubuntu systems run:

```bash
sudo add-apt-repository ppa:maxmind/ppa
sudo apt update
sudo apt install -y geoipupdate
```

On CentOS or RHEL systems, run:

```bash
sudo dnf install -y geoipupdate
```

The latest builds for Linux, macOS, and Windows can be downloaded
from the [geoipupdate releases page on GitHub].

On December 30th, 2019, MaxMind started requiring free accounts to
access the free Geolite2 databases, in order 
[to comply with various privacy regulations].

Start by [registering for a free GeoLite2 account], and signing in.

Then, navigate to the [License Keys] page under your account,
and create a new license key for the version of
`geoipupdate` that was installed.

:::{warning}
The configuration file format is different for older (i.e. \<=3.1.1) and newer (i.e. >=3.1.1) versions
of `geoipupdate`. Be sure to select the correct version for your system.
:::

:::{note}
To check the version of `geoipupdate` that is installed, run:

```bash
geoipupdate -V
```

:::

You can use `parsedmarc` as the description for the key.

Once you have generated a key, download the config pre-filled
configuration file. This file should be saved at `/etc/GeoIP.conf`
on Linux or macOS systems, or at
`%SystemDrive%\ProgramData\MaxMind\GeoIPUpdate\GeoIP.conf` on
Windows systems.

Then run

```bash
sudo geoipupdate
```

To download the databases for the first time.

The GeoLite2 Country, City, and ASN databases are updated weekly,
every Tuesday. `geoipupdate` can be run weekly by adding a cron
job or scheduled task.

More information about `geoipupdate` can be found at the
[MaxMind geoipupdate page].

## Installing parsedmarc

On Debian or Ubuntu systems, run:

```bash
sudo apt-get install -y python3-pip python3-venv python3-dev libxml2-dev libxslt-dev
```

On CentOS or RHEL systems, run:

```bash
sudo dnf install -y python3 python3-pip python3-devel libxml2-devel libxslt-devel
```

Python 3 installers for Windows and macOS can be found at
<https://www.python.org/downloads/>.

`parsedmarc` requires Python 3.10 or newer. If your distribution's
default `python3` is older, install a newer interpreter (e.g.
`python3.12`) and substitute it for `python3` in the commands below.

Create a dedicated system user, with `/opt/parsedmarc` as its home
directory so the directory is created with the correct ownership in
the same step

```bash
sudo useradd --system --create-home --home-dir /opt/parsedmarc \
    --shell /usr/sbin/nologin --skel /dev/null parsedmarc
```

Create a virtualenv and install `parsedmarc` into it as that user, so
any files created later are also owned by `parsedmarc`

```bash
sudo -u parsedmarc python3 -m venv /opt/parsedmarc/venv
sudo -u parsedmarc /opt/parsedmarc/venv/bin/pip install --upgrade pip
sudo -u parsedmarc /opt/parsedmarc/venv/bin/pip install --upgrade parsedmarc
```

To upgrade `parsedmarc` later, re-run the last command above and then
restart the service.

## Optional dependencies

If you would like to be able to parse emails saved from Microsoft
Outlook (i.e. OLE .msg files), install `msgconvert`:

On Debian or Ubuntu systems, run:

```bash
sudo apt-get install libemail-outlook-message-perl
```

[KB4295699]: https://support.microsoft.com/KB/4295699
[KB4099855]: https://support.microsoft.com/KB/4099855
[KB4134118]: https://support.microsoft.com/kb/4134118
[Component "contrib"]: https://wiki.debian.org/SourcesList#Component
[geoipupdate]: https://github.com/maxmind/geoipupdate
[geoipupdate releases page on github]: https://github.com/maxmind/geoipupdate/releases
[ipinfo lite]: https://ipinfo.io/lite
[creative commons attribution-sharealike 4.0 license]: https://creativecommons.org/licenses/by-sa/4.0/deed.en
[license keys]: https://www.maxmind.com/en/accounts/current/license-key
[maxmind geoipupdate page]: https://dev.maxmind.com/geoip/updating-databases/
[maxmind geolite2 country database]: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
[registering for a free geolite2 account]: https://www.maxmind.com/en/geolite2/signup
[to comply with various privacy regulations]: https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/
