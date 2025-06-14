# About

A mapping is meant to make it easier to identify who or what a sending source is. Please consider contributing
additional mappings in a GitHub Pull Request.

Do not open these CSV files in Excel. It will replace Unicode characters with question marks. Use LibreOffice Calc instead.

## base_reverse_dns_map.csv

A CSV file with three fields: `base_reverse_dns`, `name`, and `type`.
Most of the time the base reverse DNS of sending service is closely related to the name of the
service, but not always. Sometimes services will use multiple reverse DNS domains for the same service. For example,
Intuit Mailchimp uses the base domains `mcdlv.net`, `mcsv.net`,
and `rsgsv.net`. Having all of these mapped to the same service name and type makes it easier to answer questions like:
"How many emails is Intuit Mailchimp sending as my domains?"

The `service_type` is based on the following rule precedence:

1. All email security services are identified as `Email Security`, no matter how or where they are hosted.
2. All marketing services are identified as `Marketing`, no matter how or where they are hosted.
3. All telecommunications providers that offer internet access are identified as `ISP`, even if they also offer other services, such as web hosting or email hosting.
4. All web hosting providers are identified as `Web Hosting`, even if the service also offers email hosting.
5. All email account providers are identified as `Email Provider`, no matter how or where they are hosted
6. All legitimate platforms offering their Software as a Service (SaaS) are identified as `SaaS`, regardless of industry. This helps simplify metrics.
7. All other senders that use their own domain as a Reverse DNS base domain should be identified based on their industry

- Agriculture
- Automotive
- Beauty
- Conglomerate
- Construction
- Consulting
- Defense
- Education
- Email Provider
- Email Security
- Entertainment
- Event Planning
- Finance
- Food
- Government
- Government Media
- Healthcare
- IaaS
- Industrial
- ISP
- Legal
- Logistics
- Manufacturing
- Marketing
- MSP
- MSSP
- News
- Nonprofit
- PaaS
- Photography
- Physical Security
- Print
- Publishing
- Real Estate
- Retail
- SaaS
- Science
- Search Engine
- Social Media
- Sports
- Staffing
- Technology
- Travel
- Web Host

The file currently contains over 1,400 mappings from a wide variety of email sending sources.

## known_unknown_base_reverse_dns.txt

A list of reverse DNS base domains that could not be identified as belonging to a particular organization, service, or industry.

## base_reverse_dns.csv

A CSV with the fields `source_name` and optionally `message_count`. This CSV can be generated byy exporting the base DNS data from the Kibana on Splunk dashboards provided by parsedmarc. This file is not tracked by Git.

## unknown_base_reverse_dns.csv

A CSV file with the fields `source_name` and `message_count`. This file is not tracked by Git.

## find_unknown_base_reverse_dns.py

This is a python script that reads the domains in `base_reverse_dns.csv` and writes the domains that are not in `base_reverse_dns_map.csv` or `known_unknown_base_reverse_dns.txt` to `unknown_base_reverse_dns.csv`. This is useful for identifying potential additional domains to contribute to `base_reverse_dns_map.csv` and `known_unknown_base_reverse_dns.txt`.
