
# Using the Kibana dashboards

The Kibana DMARC dashboards are a human-friendly way to understand the
results from incoming DMARC reports.

:::{note}
The default dashboard is DMARC Summary. To switch between dashboards,
click on the Dashboard link on the left side menu of Kibana.
:::

## DMARC Summary

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
in their reverse DNS. On the right, there is a list of email from domains,
sorted by message volume.

By hovering your mouse over a data table value and using the magnifying glass
icons, you can filter on our filter out different values. Start by looking at
the Message Sources by Reverse DNS table. Find a sender that you recognize,
such as an email marketing service, hover over it, and click on the plus (+)
magnifying glass icon, to add a filter that only shows results for that sender.
Now, look at the Message From Header table to the right. That shows you the
domains that a sender is sending as, which might tell you which brand/business
is using a particular service. With that information, you can contact them and
have them set up DKIM.

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
table.

:::{note}
Previously, the alignment tables were included in a separate dashboard
called DMARC Alignment Failures. That dashboard has been consolidated into
the DMARC Summary dashboard. To view failures only, use the pie chart.
:::

Any other filters work the same way. You can also add your own custom temporary
filters by clicking on Add Filter at the upper right of the page.

## DMARC Failure Samples

The DMARC Failure Samples dashboard contains information on DMARC failure
reports (also known as ruf reports). These reports contain
samples of emails that have failed to pass DMARC.

:::{note}
Most recipients do not send failure/ruf reports at all to avoid
privacy leaks. Some recipients (notably Chinese webmail services) will only
supply the headers of sample emails. Very few provide the entire email.
:::
