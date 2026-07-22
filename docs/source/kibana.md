
# Using the Kibana dashboards

The Kibana DMARC dashboards are a human-friendly way to understand the
results from incoming DMARC reports.

There is no separate Kibana export — Kibana 8.x's saved-object migration
handlers accept the OpenSearch Dashboards format directly, so Kibana
users import the bundled
[`dashboards/opensearch/opensearch_dashboards.ndjson`](https://raw.githubusercontent.com/domainaware/parsedmarc/master/dashboards/opensearch/opensearch_dashboards.ndjson)
in *Stack Management → Saved Objects → Import*. A CI check imports the
same file into a Kibana 8.x container on every change so this stays
compatible.

:::{note}
The default dashboard is DMARC aggregate reports. To switch between
dashboards, click on the Dashboard link on the left side menu of Kibana.
:::

## DMARC aggregate reports

As the name suggests, this dashboard is the best place to start
reviewing your aggregate DMARC data.

Across the top of the dashboard, three pie charts display the percentage of
alignment pass/fail for SPF, DKIM, and DMARC. Clicking on any chart segment
will filter for that value.

:::{note}
Messages should not be considered malicious just because they failed to pass
DMARC; especially if you have just started collecting data. It may be a
legitimate service that needs SPF and DKIM configured correctly.
:::

Start by filtering the results to only show failed DKIM alignment. While DMARC
passes if a message passes SPF or DKIM alignment, only DKIM alignment remains
valid when a message is forwarded without changing the from address, which is
often caused by a mailbox forwarding rule. This is because DKIM signatures are
part of the message headers, whereas SPF relies on SMTP session headers.

Underneath the pie charts. you can see graphs of DMARC passage and message
disposition over time.

Under the graphs you will find the most useful data tables on the dashboard. On
the left, there is a list of organizations that are sending you DMARC reports.
In the center, there is a list of sending servers grouped by the base domain
in their reverse DNS. On the right, there is the "Message volume and DMARC
compliance by from domain" table, which lists email from domains with their
message volume and a percentage of those messages that passed DMARC.

By hovering your mouse over a data table value and using the magnifying glass
icons, you can filter on or filter out different values. Start by looking at
the Message Sources by Reverse DNS table. Find a sender that you recognize,
such as an email marketing service, hover over it, and click on the plus (+)
magnifying glass icon, to add a filter that only shows results for that sender.
Now, look at the Message volume and DMARC compliance by from domain table to
the right. That shows you the domains that a sender is sending as, and what
share of that traffic is passing DMARC, which might tell you which
brand/business is using a particular service. With that information, you can
contact them and have them set up DKIM.

:::{note}
The "Message volume and DMARC compliance by from domain" table is a TSVB
visualization, used because per-domain compliance percentages require a
Filter Ratio metric that agg-based data tables can't compute. It renders
correctly on Kibana 8.x as imported, but *editing* it requires first enabling
the `metrics:allowStringIndices` advanced setting, since it references the
`dmarc_aggregate*` index as a string pattern, which Elastic has deprecated.
:::

:::{note}
If you have a lot of B2C customers, you may see a high volume of emails as
your domains coming from consumer email services, such as Google/Gmail and
Yahoo! This occurs when customers have mailbox rules in place that forward
emails from an old account to a new account, which is why DKIM
authentication is so important, as mentioned earlier. Similar patterns may
be observed with businesses who send from reverse DNS addressees of
parent, subsidiary, and outdated brands.
:::

Further down the dashboard, you can filter by source country or source IP
address.

Tables showing SPF and DKIM alignment details are located under the IP address
table. Each row of the DKIM details table is one real DKIM signature, shown
as a combined `selector / domain / result` value; the SPF details table
shows `scope / domain / result` the same way. Combining the values into one
column keeps each signature's selector, domain, and result paired together,
rather than aggregating them as separate columns. Because a message that
carries multiple DKIM signatures appears once per signature, summing the
messages column across rows can exceed the total number of messages.

:::{note}
The alignment tables (SPF details, DKIM details) and the per-IP source
table live on the same dashboard, further down. To view failures only,
use the pie chart at the top of the page as a filter.
:::

Any other filters work the same way. You can also add your own custom temporary
filters by clicking on Add Filter at the upper right of the page.

## DMARC failure reports

The DMARC failure reports dashboard (formerly DMARC Forensic Samples) contains
information on DMARC failure reports (also known as forensic or ruf reports).
These reports contain samples of emails that have failed to pass DMARC.

:::{note}
Most recipients do not send failure/ruf reports at all to avoid
privacy leaks. Some recipients (notably Chinese webmail services) will only
supply the headers of sample emails. Very few provide the entire email.
:::

## SMTP TLS reporting

The SMTP TLS reporting dashboard surfaces aggregate counts of TLS-RPT
reporting organizations, the policy domains they report on, and the
specific failure types — certificate expiry, STARTTLS not supported,
STS policy fetch errors, validation failures, and similar — together with
the sending and receiving MTA addresses involved.
