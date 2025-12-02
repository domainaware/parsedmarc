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
Starting in `parsedmarc` 7.1.0, a static copy of the
[IP to Country Lite database] from IPDB is distributed with
`parsedmarc`, under the terms of the
[Creative Commons Attribution 4.0 International License].
as a fallback if the [MaxMind GeoLite2 Country database] is not
installed. However, `parsedmarc` cannot install updated versions of
these databases as they are released, so MaxMind's databases and the
[geoipupdate] tool is still the preferable solution.

The location of the database file can be overridden by using the
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
sudo apt-get install -y python3-pip python3-virtualenv python3-dev libxml2-dev libxslt-dev
```

On CentOS or RHEL systems, run:

```bash
sudo dnf install -y python39 python3-virtualenv python3-setuptools python3-devel libxml2-devel libxslt-devel
```

Python 3 installers for Windows and macOS can be found at
<https://www.python.org/downloads/>.

Create a system user

```bash
sudo mkdir /opt
sudo useradd parsedmarc -r -s /bin/false -m -b /opt
```

Install parsedmarc in a virtualenv

```bash
sudo -u parsedmarc virtualenv /opt/parsedmarc/venv
```

CentOS/RHEL 8 systems use Python 3.6 by default, so on those systems
explicitly tell `virtualenv` to use `python3.9` instead

```bash
sudo -u parsedmarc virtualenv -p python3.9  /opt/parsedmarc/venv
```

Activate the virtualenv

```bash
source /opt/parsedmarc/venv/bin/activate
```

To install or upgrade `parsedmarc` inside the virtualenv, run:

```bash
sudo -u parsedmarc /opt/parsedmarc/venv/bin/pip install -U parsedmarc
```

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
[ip to country lite database]: https://db-ip.com/db/download/ip-to-country-lite
[license keys]: https://www.maxmind.com/en/accounts/current/license-key
[maxmind geoipupdate page]: https://dev.maxmind.com/geoip/updating-databases/
[maxmind geolite2 country database]: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
[registering for a free geolite2 account]: https://www.maxmind.com/en/geolite2/signup
[to comply with various privacy regulations]: https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/
