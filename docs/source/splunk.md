# Splunk

Starting in version 4.3.0 `parsedmarc` supports sending aggregate and/or
forensic DMARC data to a Splunk [HTTP Event collector (HEC)].

The project repository contains [XML files] for premade Splunk
dashboards for aggregate and forensic DMARC reports.

Copy and paste the contents of each file into a separate Splunk
dashboard XML editor.

:::{warning}
Change all occurrences of `index="email"` in the XML to
match your own index name.
:::

The Splunk dashboards display the same content and layout as the
Kibana dashboards, although the Kibana dashboards have slightly
easier and more flexible filtering options.

[xml files]: https://github.com/domainaware/parsedmarc/tree/master/splunk
[http event collector (hec)]: http://docs.splunk.com/Documentation/Splunk/latest/Data/AboutHEC
