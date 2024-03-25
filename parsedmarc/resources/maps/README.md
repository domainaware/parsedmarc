# About

These files are meant to make it easier to identify who or what a sending source is. Please consider contributing
additional mappings in a GitHub Pull Request.

## base_reverse_dns_map.csv

A CSV file with three fields: `base_reverse_dns`, `service_name`, and `service_type`.
Most of the time the base reverse DNS of sending service is closely related to the name of the
service, but not always. Sometimes services will use multiple reverse DNS domains for the same service. For example,
Intuit Mailchimp uses the base domains `mcdlv.net`, `mcsv.net`,
and `rsgsv.net`. Having all of these mapped makes it easier to answer questions like: "How many emails is
Intuit Mailchimp sending as my domains?"

The `service_type` is based on the primary service provided by that entity. For example, most ISPs provide email
hosting to their customers , but the primary purpose of the service is to provide internet access. Likewise, nearly all
email `Marketing` services are `SaaS` platforms, but it is more useful to identify them as marketing platforms. For
individual entities that use their own reverse DNS domain names but do not provide a `SaaS` platform, setting the 
`service_type` to the industry is most useful, with the notable exception on `Email Security` services. The
current `service_type` values in use are:

Email Provider
Email Security
Entertainment
Finance
Food
Government
Government Media
Healthcare
Industrial
ISP
Logistics
Marketing
MSP
Nonprofit
Print
Real Estate
Retail
SaaS
Social Media
Technology
Travel
University
Web Host

The file currently contains over 400 mappings from a wide variety of email sending services, including large email
providers, SaaS platforms, small web hosts, and healthcare companies. Ideally this mapping will continuously grow to
include many other services and industries.
