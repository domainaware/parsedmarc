# Sample outputs

## Sample aggregate report output

Here are the results from parsing the [example](https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F)
report from the dmarc.org wiki. It's actually an older draft of
the 1.0 report schema standardized in
[RFC 7480 Appendix C](https://tools.ietf.org/html/rfc7489#appendix-C).
This draft schema is still in wide use.

`parsedmarc` produces consistent, normalized output, regardless
of the report schema.

### JSON aggregate report

```json
{
  "xml_schema": "draft",
  "report_metadata": {
    "org_name": "acme.com",
    "org_email": "noreply-dmarc-support@acme.com",
    "org_extra_contact_info": "http://acme.com/dmarc/support",
    "report_id": "9391651994964116463",
    "begin_date": "2012-04-27 20:00:00",
    "end_date": "2012-04-28 19:59:59",
    "timespan_requires_normalization": false,
    "original_timespan_seconds": 86399,
    "errors": []
  },
  "policy_published": {
    "domain": "example.com",
    "adkim": "r",
    "aspf": "r",
    "p": "none",
    "sp": "none",
    "pct": "100",
    "fo": "0"
  },
  "records": [
    {
      "source": {
        "ip_address": "72.150.241.94",
        "country": "US",
        "reverse_dns": null,
        "base_domain": null,
        "name": null,
        "type": null
      },
      "count": 2,
      "alignment": {
        "spf": true,
        "dkim": false,
        "dmarc": true
      },
      "policy_evaluated": {
        "disposition": "none",
        "dkim": "fail",
        "spf": "pass",
        "policy_override_reasons": []
      },
      "identifiers": {
        "header_from": "example.com",
        "envelope_from": "example.com",
        "envelope_to": null
      },
      "auth_results": {
        "dkim": [
          {
            "domain": "example.com",
            "selector": "none",
            "result": "fail"
          }
        ],
        "spf": [
          {
            "domain": "example.com",
            "scope": "mfrom",
            "result": "pass"
          }
        ]
      },
      "normalized_timespan": false,
      "interval_begin": "2012-04-28 00:00:00",
      "interval_end": "2012-04-28 23:59:59"
    }
  ]
}
```

### CSV aggregate report

```text
xml_schema,org_name,org_email,org_extra_contact_info,report_id,begin_date,end_date,normalized_timespan,errors,domain,adkim,aspf,p,sp,pct,fo,source_ip_address,source_country,source_reverse_dns,source_base_domain,source_name,source_type,count,spf_aligned,dkim_aligned,dmarc_aligned,disposition,policy_override_reasons,policy_override_comments,envelope_from,header_from,envelope_to,dkim_domains,dkim_selectors,dkim_results,spf_domains,spf_scopes,spf_results
draft,acme.com,noreply-dmarc-support@acme.com,http://acme.com/dmarc/support,9391651994964116463,2012-04-28 00:00:00,2012-04-28 23:59:59,False,,example.com,r,r,none,none,100,0,72.150.241.94,US,,,,,2,True,False,True,none,,,example.com,example.com,,example.com,none,fail,example.com,mfrom,pass
draft,acme.com,noreply-dmarc-support@acme.com,http://acme.com/dmarc/support,9391651994964116463,2012-04-28 00:00:00,2012-04-28 23:59:59,False,,example.com,r,r,none,none,100,0,72.150.241.94,US,,,,,2,True,False,True,none,,,example.com,example.com,,example.com,none,fail,example.com,mfrom,pass

```

## Sample failure report output

Thanks to GitHub user [xennn](https://github.com/xennn) for the anonymized
[failure report email sample](<https://github.com/domainaware/parsedmarc/raw/master/samples/forensic/DMARC%20Failure%20Report%20for%20domain.de%20(mail-from%3Dsharepoint%40domain.de%2C%20ip%3D10.10.10.10).eml>).

### JSON failure report

```json
{
     "feedback_type": "auth-failure",
     "user_agent": "Lua/1.0",
     "version": "1.0",
     "original_mail_from": "sharepoint@domain.de",
     "original_rcpt_to": "peter.pan@domain.de",
     "arrival_date": "Mon, 01 Oct 2018 11:20:27 +0200",
     "message_id": "<38.E7.30937.BD6E1BB5@ mailrelay.de>",
     "authentication_results": "dmarc=fail (p=none, dis=none) header.from=domain.de",
     "delivery_result": "policy",
     "auth_failure": [
       "dmarc"
     ],
     "reported_domain": "domain.de",
     "arrival_date_utc": "2018-10-01 09:20:27",
     "source": {
       "ip_address": "10.10.10.10",
       "country": null,
       "reverse_dns": null,
       "base_domain": null
     },
     "authentication_mechanisms": [],
     "original_envelope_id": null,
     "dkim_domain": null,
     "sample_headers_only": false,
     "sample": "Received: from Servernameone.domain.local (Servernameone.domain.local [10.10.10.10])\n\tby  mailrelay.de (mail.DOMAIN.de) with SMTP id 38.E7.30937.BD6E1BB5; Mon,  1 Oct 2018 11:20:27 +0200 (CEST)\nDate: 01 Oct 2018 11:20:27 +0200\nMessage-ID: <38.E7.30937.BD6E1BB5@ mailrelay.de>\nTo: <peter.pan@domain.de>\nfrom: \"=?utf-8?B?SW50ZXJha3RpdmUgV2V0dGJld2VyYmVyLcOcYmVyc2ljaHQ=?=\" <sharepoint@domain.de>\nSubject: Subject\nMIME-Version: 1.0\nX-Mailer: Microsoft SharePoint Foundation 2010\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\n<html><head><base href=3D'\nwettbewerb' /></head><body><!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\"=\n><HTML><HEAD><META NAME=3D\"Generator\" CONTENT=3D\"MS Exchange Server version=\n 08.01.0240.003\"></html>\n",
     "parsed_sample": {
       "from": {
         "display_name": "Interaktive Wettbewerber-Übersicht",
         "address": "sharepoint@domain.de",
         "local": "sharepoint",
         "domain": "domain.de"
       },
       "to_domains": [
         "domain.de"
       ],
       "to": [
         {
           "display_name": null,
           "address": "peter.pan@domain.de",
           "local": "peter.pan",
           "domain": "domain.de"
         }
       ],
       "subject": "Subject",
       "timezone": "+2",
       "mime-version": "1.0",
       "date": "2018-10-01 09:20:27",
       "content-type": "text/html; charset=utf-8",
       "x-mailer": "Microsoft SharePoint Foundation 2010",
       "body": "<html><head><base href='\nwettbewerb' /></head><body><!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\"><HTML><HEAD><META NAME=\"Generator\" CONTENT=\"MS Exchange Server version 08.01.0240.003\"></html>",
       "received": [
         {
           "from": "Servernameone.domain.local Servernameone.domain.local 10.10.10.10",
           "by": "mailrelay.de mail.DOMAIN.de",
           "with": "SMTP id 38.E7.30937.BD6E1BB5",
           "date": "Mon, 1 Oct 2018 11:20:27 +0200 CEST",
           "hop": 1,
           "date_utc": "2018-10-01 09:20:27",
           "delay": 0
         }
       ],
       "content-transfer-encoding": "quoted-printable",
       "message-id": "<38.E7.30937.BD6E1BB5@ mailrelay.de>",
       "has_defects": false,
       "headers": {
         "Received": "from Servernameone.domain.local (Servernameone.domain.local [10.10.10.10])\n\tby  mailrelay.de (mail.DOMAIN.de) with SMTP id 38.E7.30937.BD6E1BB5; Mon,  1 Oct 2018 11:20:27 +0200 (CEST)",
         "Date": "01 Oct 2018 11:20:27 +0200",
         "Message-ID": "<38.E7.30937.BD6E1BB5@ mailrelay.de>",
         "To": "<peter.pan@domain.de>",
         "from": "\"Interaktive Wettbewerber-Übersicht\" <sharepoint@domain.de>",
         "Subject": "Subject",
         "MIME-Version": "1.0",
         "X-Mailer": "Microsoft SharePoint Foundation 2010",
         "Content-Type": "text/html; charset=utf-8",
         "Content-Transfer-Encoding": "quoted-printable"
       },
       "reply_to": [],
       "cc": [],
       "bcc": [],
       "attachments": [],
       "filename_safe_subject": "Subject"
     }
   }
```

### CSV failure report

```text
feedback_type,user_agent,version,original_envelope_id,original_mail_from,original_rcpt_to,arrival_date,arrival_date_utc,subject,message_id,authentication_results,dkim_domain,source_ip_address,source_country,source_reverse_dns,source_base_domain,delivery_result,auth_failure,reported_domain,authentication_mechanisms,sample_headers_only
auth-failure,Lua/1.0,1.0,,sharepoint@domain.de,peter.pan@domain.de,"Mon, 01 Oct 2018 11:20:27 +0200",2018-10-01 09:20:27,Subject,<38.E7.30937.BD6E1BB5@ mailrelay.de>,"dmarc=fail (p=none, dis=none) header.from=domain.de",,10.10.10.10,,,,policy,dmarc,domain.de,,False
```

### JSON SMTP TLS report

```json
[
  {
    "organization_name": "Example Inc.",
    "begin_date": "2024-01-09T00:00:00Z",
    "end_date": "2024-01-09T23:59:59Z",
    "report_id": "2024-01-09T00:00:00Z_example.com",
    "policies": [
      {
        "policy_domain": "example.com",
        "policy_type": "sts",
        "policy_strings": [
          "version: STSv1",
          "mode: testing",
          "mx: example.com",
          "max_age: 86400"
        ],
        "successful_session_count": 0,
        "failed_session_count": 3,
        "failure_details": [
          {
            "result_type": "validation-failure",
            "failed_session_count": 2,
            "sending_mta_ip": "209.85.222.201",
            "receiving_ip": "173.212.201.41",
            "receiving_mx_hostname": "example.com"
          },
          {
            "result_type": "validation-failure",
            "failed_session_count": 1,
            "sending_mta_ip": "209.85.208.176",
            "receiving_ip": "173.212.201.41",
            "receiving_mx_hostname": "example.com"
          }
        ]
      }
    ]
  }
]
```