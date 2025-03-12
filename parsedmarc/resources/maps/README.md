# About

A mapping is meant to make it easier to identify who or what a sending source is. Please consider contributing
additional mappings in a GitHub Pull Request.

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
6. All legitimate platforms offering their Software as a Service SaaS) are identified as `SaaS`, regardless of industry. This helps simplify metrics.
7. All other senders that use their own domain as a Reverse DNS base domain should be identified based on their industry

- Email Provider
- Email Security
- Education
- Entertainment
- Finance
- Food
- Government
- Government Media
- Healthcare
- Industrial
- ISP
- Logistics
- Marketing
- MSP
- Nonprofit
- Print
- Real Estate
- Retail
- SaaS
- Social Media
- Technology
- Travel
- Web Host

The file currently contains over 600 mappings from a wide variety of email sending services, including large email
providers, SaaS platforms, small web hosts, and healthcare companies. Ideally this mapping will continuously grow to
include many other services and industries.
