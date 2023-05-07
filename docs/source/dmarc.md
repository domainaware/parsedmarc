# Understanding DMARC

## Resources

### DMARC guides

- [Demystifying DMARC] - A complete guide to SPF, DKIM, and DMARC

[demystifying dmarc]: https://seanthegeek.net/459/demystifying-dmarc/

### SPF and DMARC record validation

If you are looking for SPF and DMARC record validation and parsing,
check out the sister project,
[checkdmarc](https://domainaware.github.io/checkdmarc/).

### Lookalike domains

DMARC protects against domain spoofing, not lookalike domains. for open source
lookalike domain monitoring, check out [DomainAware](https://github.com/seanthegeek/domainaware).

## DMARC Alignment Guide

DMARC ensures that SPF and DKM authentication mechanisms actually authenticate
against the same domain that the end user sees.

A message passes a DMARC check by passing DKIM or SPF, **as long as the related
indicators are also in alignment**.

```{eval-rst}
+-----------------------+-----------------------+-----------------------+
|                       | **DKIM**              | **SPF**               |
+-----------------------+-----------------------+-----------------------+
| **Passing**           | The signature in the  | The mail server's IP  |
|                       | DKIM header is        | address is listed in  |
|                       | validated using a     | the SPF record of the |
|                       | public key that is    | domain in the SMTP    |
|                       | published as a DNS    | envelope's mail from  |
|                       | record of the domain  | header                |
|                       | name specified in the |                       |
|                       | signature             |                       |
+-----------------------+-----------------------+-----------------------+
| **Alignment**         | The signing domain    | The domain in the     |
|                       | aligns with the       | SMTP envelope's mail  |
|                       | domain in the         | from header aligns    |
|                       | message's from header | with the domain in    |
|                       |                       | the message's from    |
|                       |                       | header                |
+-----------------------+-----------------------+-----------------------+
```

## What if a sender won't support DKIM/DMARC?

1. Some vendors don't know about DMARC yet; ask about SPF and DKIM/email
   authentication.
2. Check if they can send through your email relays instead of theirs.
3. Do they really need to spoof your domain? Why not use the display
   name instead?
4. Worst case, have that vendor send email as a specific subdomain of
   your domain (e.g. `noreply@news.example.com`), and then create
   separate SPF and DMARC records on `news.example.com`, and set
   `p=none` in that DMARC record.

:::{warning}
Do not alter the `p` or `sp` values of the DMARC record on the
Top-Level Domain (TLD) – that would leave you vulnerable to
spoofing of your TLD and/or any subdomain.
:::

```{include} mailing-lists.md
```
