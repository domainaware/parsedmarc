# Accessing an inbox using OWA/EWS

:::{note}
Starting in 8.0.0, parsedmarc supports accessing Microsoft/Office 365
inboxes via the Microsoft Graph API, which is preferred over Davmail.
:::

Some organizations do not allow IMAP or the Microsoft Graph API,
and only support Exchange Web Services (EWS)/Outlook Web Access (OWA).
In that case, Davmail will need to be set up
as a local EWS/OWA IMAP gateway. It can even work where
[Modern Auth/multi-factor authentication] is required.

To do this, download the latest `davmail-version.zip` from
<https://sourceforge.net/projects/davmail/files/>

Extract the zip using the `unzip` command.

Install Java:

```bash
sudo apt-get install default-jre-headless
```

Configure Davmail by creating a `davmail.properties` file

```properties
# DavMail settings, see http://davmail.sourceforge.net/ for documentation

#############################################################
# Basic settings

# Server or workstation mode
davmail.server=true

# connection mode auto, EWS or WebDav
davmail.enableEws=auto

# base Exchange OWA or EWS url
davmail.url=https://outlook.office365.com/EWS/Exchange.asmx

# Listener ports
davmail.imapPort=1143

#############################################################
# Network settings

# Network proxy settings
davmail.enableProxy=false
davmail.useSystemProxies=false
davmail.proxyHost=
davmail.proxyPort=
davmail.proxyUser=
davmail.proxyPassword=

# proxy exclude list
davmail.noProxyFor=

# block remote connection to DavMail
davmail.allowRemote=false

# bind server sockets to the loopback address
davmail.bindAddress=127.0.0.1

# disable SSL for specified listeners
davmail.ssl.nosecureimap=true

# Send keepalive character during large folder and messages download
davmail.enableKeepalive=true

# Message count limit on folder retrieval
davmail.folderSizeLimit=0

#############################################################
# IMAP settings

# Delete messages immediately on IMAP STORE \Deleted flag
davmail.imapAutoExpunge=true

# Enable IDLE support, set polling delay in minutes
davmail.imapIdleDelay=1

# Always reply to IMAP RFC822.SIZE requests with Exchange approximate
# message size for performance reasons
davmail.imapAlwaysApproxMsgSize=true

# Client connection timeout in seconds - default 300, 0 to disable
davmail.clientSoTimeout=0

#############################################################
```

## Running DavMail as a systemd service

Use systemd to run `davmail` as a service.

Create a system user

```bash
sudo useradd davmail -r -s /bin/false
```

Protect the `davmail` configuration file from prying eyes

```bash
sudo chown root:davmail /opt/davmail/davmail.properties
sudo chmod u=rw,g=r,o= /opt/davmail/davmail.properties
```

Create the service configuration file

```bash
sudo nano /etc/systemd/system/davmail.service
```

```ini
[Unit]
Description=DavMail gateway service
Documentation=https://sourceforge.net/projects/davmail/
Wants=network-online.target
After=syslog.target network.target

[Service]
ExecStart=/opt/davmail/davmail /opt/davmail/davmail.properties
User=davmail
Group=davmail
Restart=always
RestartSec=5m

[Install]
WantedBy=multi-user.target
```

Then, enable the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable parsedmarc.service
sudo service davmail restart
```

:::{note}
You must also run the above commands whenever you edit
`davmail.service`.
:::

:::{warning}
Always restart the service every time you upgrade to a new version of
`davmail`:

```bash
sudo service davmail restart
```

:::

To check the status of the service, run:

```bash
service davmail status
```

:::{note}
In the event of a crash, systemd will restart the service after 5
minutes, but the `service davmail status` command will only show the
logs for the current process. To vew the logs for previous runs as
well as the current process (newest to oldest), run:

```bash
journalctl -u davmail.service -r
```

:::

## Configuring parsedmarc for DavMail

Because you are interacting with DavMail server over the loopback
(i.e. `127.0.0.1`), add the following options to `parsedmarc.ini`
config file:

```ini
[imap]
host=127.0.0.1
port=1143
ssl=False
watch=True
```

[modern auth/multi-factor authentication]: https://davmail.sourceforge.net/faq.html
