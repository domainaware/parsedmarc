## What about mailing lists?

When you deploy DMARC on your domain, you might find that messages
relayed by mailing lists are failing DMARC, most likely because the mailing
list is spoofing your from address, and modifying the subject,
footer, or other part of the message, thereby breaking the
DKIM signature.

### Mailing list best practices

Ideally, a mailing list should forward messages without altering the
headers or body content at all. [Joe Nelson] does a fantastic job of
explaining exactly what mailing lists should and shouldn't do to be
fully DMARC compliant. Rather than repeat his fine work, here's a
summary:

#### Do

- Retain headers from the original message

- Add [RFC 2369] List-Unsubscribe headers to outgoing messages, instead of
  adding unsubscribe links to the body

> List-Unsubscribe: <https://list.example.com/unsubscribe-link>

- Add [RFC 2919] List-Id headers instead of modifying the subject

  > List-Id: Example Mailing List <list.example.com>

Modern mail clients and webmail services generate unsubscribe buttons based on
these headers.

#### Do not

- Remove or modify any existing headers from the original message, including
  From, Date, Subject, etc.
- Add to or remove content from the message body, **including traditional
  disclaimers and unsubscribe footers**

In addition to complying with DMARC, this configuration ensures that Reply
and Reply All actions work like they would with any email message. Reply
replies to the message sender, and Reply All replies to the sender and the
list.

Even without a subject prefix or body footer, mailing list users can still
tell that a message came from the mailing list, because the message was sent
to the mailing list post address, and not their email address.

Configuration steps for common mailing list platforms are listed below.

#### Mailman 2

Navigate to General Settings, and configure the settings below

```{eval-rst}
============================ ==========
**Setting**                  **Value**
**subject_prefix**
**from_is_list**             No
**first_strip_reply_to**     No
**reply_goes_to_list**       Poster
**include_rfc2369_headers**  Yes
**include_list_post_header** Yes
**include_sender_header**    No
============================ ==========
```

Navigate to Non-digest options, and configure the settings below

```{eval-rst}
=================== ==========
**Setting**         **Value**
**msg_header**
**msg_footer**
**scrub_nondigest**  No
=================== ==========
```

Navigate to Privacy Options> Sending Filters, and configure the settings below

```{eval-rst}
====================================== ==========
**Setting**                            **Value**
**dmarc_moderation_action**            Accept
**dmarc_quarantine_moderation_action** Yes
**dmarc_none_moderation_action**       Yes
====================================== ==========
```

#### Mailman 3

Navigate to Settings> List Identity

Make Subject prefix blank.

Navigate to Settings> Alter Messages

Configure the settings below

```{eval-rst}
====================================== ==========
**Setting**                            **Value**
**Convert html to plaintext**          No
**Include RFC2369 headers**            Yes
**Include the list post header**       Yes
**Explicit reply-to address**
**First strip replyto**                 No
**Reply goes to list**                 No munging
====================================== ==========
```

Navigate to Settings> DMARC Mitigation

Configure the settings below

```{eval-rst}
================================== ===============================
**Setting**                            **Value**
**DMARC mitigation action**            No DMARC mitigations
**DMARC mitigate unconditionally** No
================================== ===============================
```

Create a blank footer template for your mailing list to remove the message
footer. Unfortunately, the Postorius mailing list admin UI will not allow you
to create an empty template, so you'll have to create one using the system's
command line instead, for example:

```bash
touch var/templates/lists/list.example.com/en/list:member:regular:footer
```

Where `list.example.com` the list ID, and `en` is the language.

Then restart mailman core.

#### LISTSERV

[LISTSERV 16.0-2017a] and higher will rewrite the From header for domains
that enforce with a DMARC quarantine or reject policy.

Some additional steps are needed for Linux hosts.

#### Workarounds

If a mailing list must go **against** best practices and
modify the message (e.g. to add a required legal footer), the mailing
list administrator must configure the list to replace the From address of the
message (also known as munging) with the address of the mailing list, so they
no longer spoof email addresses with domains protected by DMARC.

Configuration steps for common mailing list platforms are listed below.

##### Mailman 2

Navigate to Privacy Options> Sending Filters, and configure the settings below

```{eval-rst}
====================================== ==========
**Setting**                            **Value**
**dmarc_moderation_action**            Munge From
**dmarc_quarantine_moderation_action** Yes
**dmarc_none_moderation_action**       Yes
====================================== ==========
```

:::{note}
Message wrapping could be used as the DMARC mitigation action instead. In
that case, the original message is added as an attachment to the mailing
list message, but that could interfere with inbox searching, or mobile
clients.

On the other hand, replacing the From address might cause users to
accidentally reply to the entire list, when they only intended to reply to
the original sender.

Choose the option that best fits your community.
:::

##### Mailman 3

In the DMARC Mitigations tab of the Settings page, configure the settings below

```{eval-rst}
================================== ===============================
**Setting**                            **Value**
**DMARC mitigation action**            Replace From: with list address
**DMARC mitigate unconditionally** No
================================== ===============================
```

:::{note}
Message wrapping could be used as the DMARC mitigation action instead. In
that case, the original message is added as an attachment to the mailing
list message, but that could interfere with inbox searching, or mobile
clients.

On the other hand, replacing the From address might cause users to
accidentally reply to the entire list, when they only intended to reply to
the original sender.
:::

[joe nelson]: https://begriffs.com/posts/2018-09-18-dmarc-mailing-list.html
[listserv 16.0-2017a]: https://www.lsoft.com/news/dmarc-issue1-2018.asp
[rfc 2369]: https://tools.ietf.org/html/rfc2369
[rfc 2919]: https://tools.ietf.org/html/rfc2919
