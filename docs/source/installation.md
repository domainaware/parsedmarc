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

### IP-to-country database

`parsedmarc` ships with a copy of the [IPinfo Lite] database (under
the terms of the [Creative Commons Attribution-ShareAlike 4.0
License]), which is automatically refreshed from GitHub at startup
(and on `SIGHUP` in watch mode) unless the `offline` flag is set. No
IP database setup is required for the default configuration.

If you would prefer to use MaxMind's GeoLite2 Country database
instead, see [Using MaxMind GeoLite2](#using-maxmind-geolite2-optional)
below.

## Installing parsedmarc

On Debian or Ubuntu systems, run:

```bash
sudo apt-get install -y python3-pip python3-venv python3-dev libxml2-dev libxslt-dev
```

On CentOS, RHEL, oR Rocky Linux systems, run:

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

On CentOS, RHEL, or Rocky Linux, the `Email::Outlook::Message` Perl
module is not packaged in the base repositories or EPEL, so install
it from CPAN:

```bash
sudo dnf install -y perl perl-CPAN make gcc
sudo cpan -i Email::Outlook::Message
```

This installs the `msgconvert` script to `/usr/local/bin/msgconvert`.

## Using MaxMind GeoLite2 (optional)

`parsedmarc` will pick up the [MaxMind GeoLite2 Country database] if
it is installed at one of the standard system paths (e.g.
`/usr/share/GeoIP/GeoLite2-Country.mmdb`,
`/var/lib/GeoIP/GeoLite2-Country.mmdb`, or the equivalent location on
Windows). **Use this only if you specifically prefer MaxMind data over
the bundled IPinfo Lite database — most users do not need it.**

Install [geoipupdate] for your platform:

```bash
# Debian 10+ (requires the contrib component in apt sources)
sudo apt-get install -y geoipupdate

# Ubuntu
sudo add-apt-repository ppa:maxmind/ppa
sudo apt update
sudo apt install -y geoipupdate

# CentOS, RHEL, or Rocky Linux
sudo dnf install -y geoipupdate
```

Builds for Linux, macOS, and Windows are also available on the
[geoipupdate releases page on GitHub].

Since December 2019, MaxMind has required a free account to download
the GeoLite2 databases ([to comply with various privacy regulations]).
[Register for a free GeoLite2 account][registering for a free
geolite2 account], sign in, then create a new key on the [License
Keys] page (you can use `parsedmarc` as the description). Download the
pre-filled config file and save it to `/etc/GeoIP.conf` on Linux/macOS
or `%SystemDrive%\ProgramData\MaxMind\GeoIPUpdate\GeoIP.conf` on
Windows.

Then run

```bash
sudo geoipupdate
```

to download the databases for the first time. The GeoLite2 databases
are updated weekly (every Tuesday); add a cron job or scheduled task
to re-run `geoipupdate` weekly. More detail at the [MaxMind
geoipupdate page].

[KB4295699]: https://support.microsoft.com/KB/4295699
[KB4099855]: https://support.microsoft.com/KB/4099855
[KB4134118]: https://support.microsoft.com/kb/4134118
[geoipupdate]: https://github.com/maxmind/geoipupdate
[geoipupdate releases page on github]: https://github.com/maxmind/geoipupdate/releases
[ipinfo lite]: https://ipinfo.io/lite
[creative commons attribution-sharealike 4.0 license]: https://creativecommons.org/licenses/by-sa/4.0/deed.en
[license keys]: https://www.maxmind.com/en/accounts/current/license-key
[maxmind geoipupdate page]: https://dev.maxmind.com/geoip/updating-databases/
[maxmind geolite2 country database]: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
[registering for a free geolite2 account]: https://www.maxmind.com/en/geolite2/signup
[to comply with various privacy regulations]: https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/
