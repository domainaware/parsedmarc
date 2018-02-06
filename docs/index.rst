.. parsedmarc documentation master file, created by
   sphinx-quickstart on Mon Feb  5 18:25:39 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

======================================
Welcome to parsedmarc's documentation!
======================================

|Build Status|

``pasedmarc`` is a Python module and CLI utility for parsing aggregate DMARC reports.

Features
========

* Parses draft and 1.0 standard aggregate reports
* Transparently handles gzip or zip compressed reports
* Consistent data structures
* Simple JSON or CSV output
* Python 2 and 3 support

CLI help
========

::

    usage: parsedmarc.py [-h] [-f FORMAT] [-o OUTPUT]
                         [-n NAMESERVER [NAMESERVER ...]] [-t TIMEOUT] [-v]
                         file_path [file_path ...]

    Parses aggregate DMARC reports

    positional arguments:
      file_path             one or more paths of aggregate report files
                            (compressed or uncompressed)

    optional arguments:
      -h, --help            show this help message and exit
      -f FORMAT, --format FORMAT
                            specify JSON or CSV output format
      -o OUTPUT, --output OUTPUT
                            output to a file path rather than printing to the
                            screen
      -n NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                            nameservers to query
      -t TIMEOUT, --timeout TIMEOUT
                            number of seconds to wait for an answer from DNS
                            (default 6.0)
      -v, --version         show program's version number and exit


Sample output
=============

Here are the results from parsing the `example <https://dmarc.org/wiki/FAQ#I_need_to_implement_aggregate_reports.2C_what_do_they_look_like.3F>`_
report from the dmarc.org wiki. It's actually an older draft of the the 1.0
report schema standardized in
`RFC 7480 Appendix C <https://tools.ietf.org/html/rfc7489#appendix-C>`_.
This draft schema is still in wide use.

``parsedmarc`` produces consistent, normalized output, regardless of the report schema.

JSON
----

.. code-block:: json

    {
      "xml_schema": "draft",
      "report_metadata": {
        "org_name": "acme.com",
        "org_email": "noreply-dmarc-support@acme.com",
        "org_extra_contact_info": "http://acme.com/dmarc/support",
        "report_id": "9391651994964116463",
        "begin_date": "2012-04-27 20:00:00",
        "end_date": "2012-04-28 19:59:59",
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
            "reverse_dns": "adsl-72-150-241-94.shv.bellsouth.net",
            "base_domain": "bellsouth.net"
          },
          "count": 2,
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
          }
        }
      ]
    }

CSV
---

::

    xml_schema,org_name,org_email,org_extra_contact_info,report_id,begin_date,end_date,errors,domain,adkim,aspf,p,sp,pct,fo,source_ip_address,source_country,source_reverse_dns,source_base_domain,count,disposition,dkim_alignment,spf_alignment,policy_override_reasons,policy_override_comments,envelope_from,header_from,envelope_to,dkim_domains,dkim_selectors,dkim_results,spf_domains,spf_scopes,spf_results
    draft,acme.com,noreply-dmarc-support@acme.com,http://acme.com/dmarc/support,9391651994964116463,2012-04-27 20:00:00,2012-04-28 19:59:59,[],example.com,r,r,none,none,100,0,72.150.241.94,US,adsl-72-150-241-94.shv.bellsouth.net,bellsouth.net,2,none,fail,pass,,,example.com,example.com,,example.com,none,fail,example.com,mfrom,pass

What about forensic DMARC reports?
==================================

Forensic DMARC reports are emails with an attached email sample that failed a
DMARC check. You can parse them with any email message parser, such as
`mail-parser <https://pypi.python.org/pypi/mail-parser/>`_.

Very few recipients send forensic reports, and even those who do will often
provide only the message headers, and not the message's content, for privacy
reasons.

Bug reports
===========

Please report bugs on the GitHub issue tracker

https://github.com/domainaware/parsedmarc/issues

Installation
============

``parsedmarc`` works with Python 2 or 3, but Python 3 is preferred.

On Debian or Ubuntu systems, run:

.. code-block:: bash

    $ sudo apt-get install python3-pip


Python 3 installers for Windows and macOS can be found at https://www.python.org/downloads/

To install or upgrade to the latest stable release of ``parsedmarc`` on macOS or Linux, run

.. code-block:: bash

    $ sudo -H pip3 install -U checkdmarc

Or, install the latest development release directly from GitHub:

.. code-block:: bash

    $ sudo -H pip3 install -U git+https://github.com/domainaware/parsedmarc.git

.. note::

    On Windows, ``pip3`` is ``pip``, even with Python 3. So on Windows, simply
    substitute ``pip`` as an administrator in place of ``sudo pip3``, in the above commands.

API
===

.. automodule:: parsedmarc
   :members:

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


.. |Build Status| image:: https://travis-ci.org/domainaware/parsedmarc.svg?branch=master
   :target: https://travis-ci.org/domainaware/parsedmarc