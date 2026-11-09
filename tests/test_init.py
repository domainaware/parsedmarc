"""Tests for the top-level parsedmarc package (parsedmarc/__init__.py).

Covers the public parsing surface: parse_report_file, parse_report_email,
parse_aggregate_report_xml, parse_failure_report, parse_smtp_tls_report_json,
extract_report, get_dmarc_reports_from_mbox, and the CSV / JSON renderers.
"""

import base64
import binascii
import csv
import email
import email.errors
import gc
import gzip
import inspect
import json
import logging
import mailbox
import os
import quopri
import time
import traceback
import tracemalloc
import unittest
import zipfile
import weakref
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.nonmultipart import MIMENonMultipart
from email.mime.text import MIMEText
from glob import glob
from io import BytesIO, StringIO
from pathlib import Path
from shutil import rmtree
from tempfile import NamedTemporaryFile, mkdtemp
from typing import Any, BinaryIO, cast
from unittest.mock import MagicMock, patch

from lxml import etree  # type: ignore[import-untyped]

import parsedmarc
import parsedmarc.constants as constants
from parsedmarc.attempts import MAX_PARSE_ATTEMPTS, attempt_key
from parsedmarc.mail import IMAPConnection, MaildirConnection, MSGraphConnection
from parsedmarc.parallel import _parse_report_email_job
from parsedmarc.types import (
    AggregateReport,
    FailureReport,
    ParsingResults,
    SMTPTLSReport,
)
from tests.timing import budget

# Detect if running in GitHub Actions to skip DNS lookups
OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"


def minify_xml(xml_string):
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.fromstring(xml_string.encode("utf-8"), parser)
    return etree.tostring(tree, pretty_print=False).decode("utf-8")


FEEDBACK_REPORT_HEADERS = (
    "Feedback-Type: auth-failure\r\n"
    "User-Agent: parsedmarc-tests/1.0\r\n"
    "Version: 1\r\n"
    "Original-Mail-From: <bounce@example.com>\r\n"
    "Arrival-Date: Thu, 27 Aug 2026 10:00:00 +0000\r\n"
    "Source-IP: 203.0.113.10\r\n"
    "Authentication-Results: mx.example.com; dmarc=fail\r\n"
)

# Long, folded headers, so that quoted-printable encoding of this sample
# introduces soft line breaks (RFC 2045 section 6.7) that split lines without
# the RFC 5322 folding whitespace a header parser needs.
SAMPLE_HEADERS = (
    "Received: from mail.example.com (mail.example.com [203.0.113.10])\r\n"
    "\tby mx.example.com with ESMTPS id abc123;\r\n"
    "\tThu, 27 Aug 2026 10:00:00 +0000\r\n"
    "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;\r\n"
    "\ts=selector1; h=from:to:subject;\r\n"
    "\tbh=" + "a" * 76 + "=;\r\n"
    "\tb=" + "b" * 120 + "\r\n"
    "From: victim@example.com\r\n"
    "To: someone@example.org\r\n"
    "Subject: hello\r\n"
)


def build_failure_report_email(
    feedback_report=FEEDBACK_REPORT_HEADERS,
    sample=SAMPLE_HEADERS,
    feedback_report_cte=None,
    sample_cte=None,
):
    """Builds an RFC 6591 multipart/report failure report message.

    ``feedback_report_cte`` and ``sample_cte`` optionally encode the
    corresponding part's body and declare a matching
    ``Content-Transfer-Encoding`` header; ``None`` leaves the part
    unencoded (7bit).
    """

    def encode(text, cte):
        if cte == "quoted-printable":
            return quopri.encodestring(text.encode()).decode("ascii")
        if cte == "base64":
            return base64.b64encode(text.encode()).decode("ascii")
        raise ValueError(f"Unsupported test encoding: {cte}")

    msg = MIMEMultipart("report", report_type="feedback-report")
    msg["From"] = "dmarc-noreply@example.org"
    msg["To"] = "dmarc-reports@example.com"
    msg["Subject"] = "DMARC Authentication Failure Report"
    msg.attach(MIMEText("This is a DMARC authentication failure report.", "plain"))

    report_part = MIMENonMultipart("message", "feedback-report")
    if feedback_report_cte is None:
        report_part.set_payload(feedback_report)
    else:
        report_part.set_payload(encode(feedback_report, feedback_report_cte))
        report_part["Content-Transfer-Encoding"] = feedback_report_cte
    msg.attach(report_part)

    sample_part = MIMEText(sample, _subtype="rfc822-headers")
    if sample_cte is not None:
        sample_part.set_payload(encode(sample, sample_cte))
        del sample_part["Content-Transfer-Encoding"]
        sample_part["Content-Transfer-Encoding"] = sample_cte
    msg.attach(sample_part)

    return msg.as_string()


def build_raw_failure_report_email(sample, sample_charset="utf-8"):
    """Assembles the MIME source of a failure report by hand.

    ``MIMEText`` re-encodes any non-ASCII body it is handed, so a raw 8bit
    sample part — non-ASCII text with no transfer encoding declared, which is
    the case under test — cannot be built with it. Writing the source out
    directly leaves the sample text unencoded.
    """
    return "\n".join(
        [
            "From: dmarc-noreply@example.org",
            "To: dmarc-reports@example.com",
            "Subject: DMARC Authentication Failure Report",
            "MIME-Version: 1.0",
            "Content-Type: multipart/report; report-type=feedback-report;",
            '\tboundary="BOUNDARY"',
            "",
            "--BOUNDARY",
            "Content-Type: text/plain; charset=us-ascii",
            "",
            "This is a DMARC authentication failure report.",
            "",
            "--BOUNDARY",
            "Content-Type: message/feedback-report",
            "",
            FEEDBACK_REPORT_HEADERS,
            "--BOUNDARY",
            f'Content-Type: text/rfc822-headers; charset="{sample_charset}"',
            "",
            sample,
            "--BOUNDARY--",
            "",
        ]
    )


def compare_xml(xml1, xml2):
    parser = etree.XMLParser(remove_blank_text=True)
    tree1 = etree.fromstring(xml1.encode("utf-8"), parser)
    tree2 = etree.fromstring(xml2.encode("utf-8"), parser)
    return etree.tostring(tree1) == etree.tostring(tree2)


# GHSA-qxwv-2vwj-v828 fixtures. A failure report whose message/rfc822 sample
# has a header containing \x1c, which str.splitlines() treats as a line
# break, so re-serializing the sample raises email.errors.HeaderWriteError.
POISON_HEADER_EMAIL = (
    "From: a@example.com\nSubject: x\nDate: Mon, 1 Jan 2024 00:00:00 +0000\n"
    "MIME-Version: 1.0\n"
    "Content-Type: multipart/report; report-type=feedback-report; boundary=B\n\n"
    "--B\nContent-Type: text/plain\n\nhi\n"
    "--B\nContent-Type: message/feedback-report\n\n"
    "Feedback-Type: auth-failure\nVersion: 1\nSource-IP: 192.0.2.1\n"
    "Arrival-Date: Mon, 1 Jan 2024 00:00:00 +0000\nReported-Domain: example.com\n"
    "Authentication-Results: x\n\n"
    "--B\nContent-Type: message/rfc822\n\nFrom: a@b\nX-A: a\x1cb\n\nbody\n--B--\n"
).encode()


# Far past the recursion limit wherever the message is re-serialized: the
# email generator recurses a few frames per level, so the smallest failing
# depth is about 247 levels from a shallow main thread and drops with every
# frame already on the stack (about 222 at +100 frames), while mail-parser's
# own nesting guard only trips far above this. Still parses in milliseconds.
POISON_NESTING_LEVELS = 400
# Comfortably below the limit even from a deep stack.
SHALLOW_NESTING_LEVELS = 50


def _nested_multipart_email(levels: int) -> bytes:
    """A message with ``levels`` nested ``multipart/mixed`` parts around one
    text part; re-serializing ``POISON_NESTING_LEVELS`` levels exceeds the
    recursion limit."""
    message = "Subject: s\n"
    for i in range(levels):
        message += f"Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n"
    message += "Content-Type: text/plain\n\nx\n"
    for i in range(levels - 1, -1, -1):
        message += f"--b{i}--\n"
    return message.encode()


def _reserializes(raw: bytes) -> bool:
    """Whether this Python can parse and re-serialize ``raw``; a Python
    predating the header-injection check (CVE-2024-6923) writes
    POISON_HEADER_EMAIL without raising."""
    try:
        email.message_from_bytes(raw).as_string()
    except (email.errors.MessageError, RecursionError):
        return False
    return True


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

    def testExtractReportXMLComparator(self):
        """Test XML comparator function"""
        with open("samples/extract_report/nice-input.xml") as f:
            xmlnice = f.read()
        with open("samples/extract_report/changed-input.xml") as f:
            xmlchanged = minify_xml(f.read())
        self.assertTrue(compare_xml(xmlnice, xmlnice))
        self.assertTrue(compare_xml(xmlchanged, xmlchanged))
        self.assertFalse(compare_xml(xmlnice, xmlchanged))
        self.assertFalse(compare_xml(xmlchanged, xmlnice))
        print("Passed!")

    def testExtractReportBytes(self):
        """Test extract report function for bytes string input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        with open(file, "rb") as f:
            data = f.read()
        print(f"Testing {file}: ", end="")
        xmlout = parsedmarc.extract_report(data)
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = f.read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportXML(self):
        """Test extract report function for XML input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        print(f"Testing {file}: ", end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = f.read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportXMLFromPath(self):
        """Test extract report function for pathlib.Path input"""
        report_path = Path("samples/extract_report/nice-input.xml")
        xmlout = parsedmarc.extract_report_from_file_path(report_path)
        with open("samples/extract_report/nice-input.xml") as xmlin_file:
            xmlin = xmlin_file.read()
        self.assertTrue(compare_xml(xmlout, xmlin))

    def testExtractReportGZip(self):
        """Test extract report function for gzip input"""
        print()
        file = "samples/extract_report/nice-input.xml.gz"
        print(f"Testing {file}: ", end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = f.read()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportZip(self):
        """Test extract report function for zip input"""
        print()
        file = "samples/extract_report/nice-input.xml.zip"
        print(f"Testing {file}: ", end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        with open("samples/extract_report/nice-input.xml") as f:
            xmlin = minify_xml(f.read())
        self.assertTrue(compare_xml(xmlout, xmlin))
        with open("samples/extract_report/changed-input.xml") as f:
            xmlin = f.read()
        self.assertFalse(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testParseReportFileAcceptsPathForXML(self):
        report_path = Path(
            "samples/aggregate/protection.outlook.com!example.com!1711756800!1711843200.xml"
        )
        result = parsedmarc.parse_report_file(
            report_path,
            offline=True,
        )
        assert result["report_type"] == "aggregate"
        report = cast(AggregateReport, result["report"])
        self.assertEqual(report["report_metadata"]["org_name"], "outlook.com")

    def testParseReportFileAcceptsPathForEmail(self):
        report_path = Path(
            "samples/aggregate/Report domain- borschow.com Submitter- google.com Report-ID- 949348866075514174.eml"
        )
        result = parsedmarc.parse_report_file(
            report_path,
            offline=True,
        )
        assert result["report_type"] == "aggregate"
        report = cast(AggregateReport, result["report"])
        self.assertEqual(report["report_metadata"]["org_name"], "google.com")

    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        print()
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print(f"Testing {sample_path}: ", end="")
            with self.subTest(sample=sample_path):
                result = parsedmarc.parse_report_file(
                    sample_path, always_use_local_files=True, offline=OFFLINE_MODE
                )
                assert result["report_type"] == "aggregate"
                parsedmarc.parsed_aggregate_reports_to_csv(
                    cast(AggregateReport, result["report"])
                )
            print("Passed!")

    def testAggregateResultWordsAreLowercase(self):
        """Reporter-supplied result words are lowercased at ingest; RFC 7489
        Appendix C and RFC 9990 define the result and disposition types as
        lowercase enum tokens (issue #288).
        """
        result = parsedmarc.parse_report_file(
            "samples/aggregate_invalid/report_with_upper_cased_pass.xml",
            offline=True,
        )
        assert result["report_type"] == "aggregate"
        report = cast(AggregateReport, result["report"])
        record = report["records"][0]

        self.assertEqual(record["policy_evaluated"]["dkim"], "pass")
        self.assertEqual(record["policy_evaluated"]["spf"], "pass")
        self.assertEqual(record["auth_results"]["dkim"][0]["result"], "pass")
        self.assertEqual(record["auth_results"]["spf"][0]["result"], "pass")
        self.assertEqual(record["policy_evaluated"]["disposition"], "none")

    def testEmptySample(self):
        """Test empty/unparseable report"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_file("samples/empty.xml", offline=OFFLINE_MODE)

    def testFailureSamples(self):
        """Test sample failure/ruf DMARC reports"""
        print()
        sample_paths = glob("samples/failure/*.eml")
        for sample_path in sample_paths:
            print(f"Testing {sample_path}: ", end="")
            with self.subTest(sample=sample_path):
                with open(sample_path) as sample_file:
                    sample_content = sample_file.read()
                    email_result = parsedmarc.parse_report_email(
                        sample_content, offline=OFFLINE_MODE
                    )
                    assert email_result["report_type"] == "failure"
                result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
                assert result["report_type"] == "failure"
                parsedmarc.parsed_failure_reports_to_csv(
                    cast(FailureReport, result["report"])
                )
            print("Passed!")

    def testFailureSampleWithoutFeedbackReportPart(self):
        """A plain-text-only failure report (no message/feedback-report part)
        must still contain every field the Elasticsearch/OpenSearch outputs
        access with hard key lookups (issue #332)"""
        sample_path = "samples/failure/exim_plain_text_only_no_arf_part.eml"
        result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
        assert result["report_type"] == "failure"
        report = cast(FailureReport, result["report"])
        assert report["feedback_type"] == "auth-failure"
        assert "authentication_results" in report
        assert report["source"]["ip_address"] == "203.0.113.68"

    def testFailureSampleQuotedPrintableSamplePart(self):
        """A quoted-printable ``text/rfc822-headers`` sample part is decoded
        before it is parsed (issue #882).

        ``parse_report_email()`` read part payloads without ``decode=True``,
        so the sample kept its RFC 2045 section 6.7 soft line breaks (``=``
        followed by CRLF, with no RFC 5322 folding whitespace). That split the
        ``From`` header mid-value, leaving it unparseable, and the whole
        failure report was discarded."""
        message = build_failure_report_email(sample_cte="quoted-printable")
        result = parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        self.assertEqual(report["reported_domain"], "example.com")
        sample_from = report["parsed_sample"].get("from")
        assert sample_from is not None
        self.assertEqual(sample_from["address"], "victim@example.com")

    def testFailureSampleBase64SamplePart(self):
        """A base64 ``text/rfc822-headers`` sample part is decoded before it is
        parsed (issue #882)."""
        message = build_failure_report_email(sample_cte="base64")
        result = parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        self.assertEqual(report["reported_domain"], "example.com")
        sample_from = report["parsed_sample"].get("from")
        assert sample_from is not None
        self.assertEqual(sample_from["address"], "victim@example.com")

    def testFailureQuotedPrintableFeedbackReportPart(self):
        """A quoted-printable ``message/feedback-report`` part is decoded
        before its fields are read (issue #882).

        A composite part carrying a real Content-Transfer-Encoding is illegal
        per RFC 2045 section 6.4, but reporters send them; the standard
        library nests the still-encoded text as a child message. Without
        decoding, the report parsed "successfully" with silently corrupted
        values (``dmarc=3Dfail`` instead of ``dmarc=fail``)."""
        message = build_failure_report_email(feedback_report_cte="quoted-printable")
        result = parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        authentication_results = report["authentication_results"]
        self.assertEqual(authentication_results, "mx.example.com; dmarc=fail")
        assert authentication_results is not None
        self.assertNotIn("=3D", authentication_results)

    def testFailureReportFieldsHaveNoTrailingCarriageReturn(self):
        """Feedback report field values never keep the CR of a CRLF line
        ending.

        A ``message/feedback-report`` part is a MIME body part, so its lines
        end with CRLF per RFC 5322 section 2.1. ``re.MULTILINE``'s ``$``
        matches before the LF but not before the CR, so a greedy ``.+`` value
        swallows it. This sample's part is base64, and once it is decoded per
        its Content-Transfer-Encoding (issue #882) the CRLF reaches the field
        regex intact."""
        sample_path = "samples/failure/[Netease DMARC Failure Report] Rent Reminder.eml"
        result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        self.assertEqual(report["feedback_type"], "auth-failure")
        self.assertEqual(report["user_agent"], "NtesDmarcReporter/1.0")
        self.assertEqual(report["version"], "1")
        self.assertEqual(report["arrival_date"], "Fri, 28 Sep 2018 16:48:42 +0800")
        self.assertEqual(report["reported_domain"], "cardinal.com")
        # "sample" is the raw sample message rather than a feedback report
        # field, so its line endings are deliberately left alone.
        for key, value in report.items():
            if key != "sample" and isinstance(value, str):
                self.assertNotIn("\r", value, msg=f"carriage return in {key}")

    def testFailureReportWithNoReportedDomainAndNoSampleFrom(self):
        """A failure report with no ``Reported-Domain`` field whose sample has
        no usable ``From`` header is rejected with a clear message.

        ``reported_domain`` is a required ``str`` in the ``FailureReport``
        contract (``parsedmarc/types.py``) and is read directly by the
        Elasticsearch and OpenSearch outputs, so it cannot be defaulted to
        ``None``. The error must survive un-wrapped by the generic
        ``except Exception`` handler in ``parse_failure_report()``."""
        sample = "To: someone@example.org\r\nSubject: hello\r\n"
        message = build_failure_report_email(sample=sample)
        with self.assertRaises(parsedmarc.InvalidFailureReport) as context:
            parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        error = str(context.exception)
        self.assertIn("Reported-Domain", error)
        self.assertIn("From header", error)
        self.assertNotIn("Unexpected error", error)

    def testFailureBase64FeedbackReportBodyWithoutCTE(self):
        """A ``message/feedback-report`` part whose body is bare base64 text,
        with no ``Content-Transfer-Encoding`` declaring it, is still decoded.

        There is nothing for ``_decode_mime_payload()`` to undo here, so the
        long-standing "no ``Feedback-Type`` in the payload means it is base64"
        fallback in ``parse_report_email()`` must keep handling it."""
        encoded = base64.b64encode(FEEDBACK_REPORT_HEADERS.encode()).decode("ascii")
        message = build_failure_report_email(feedback_report=encoded)
        result = parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        self.assertEqual(report["feedback_type"], "auth-failure")
        self.assertEqual(report["authentication_results"], "mx.example.com; dmarc=fail")

    def testFailureQuotedPrintableFeedbackReportMissingFeedbackType(self):
        """When the base64 fallback in ``parse_report_email()`` fails, the
        payload it falls back to is the transfer-decoded one (issue #882).

        ``Feedback-Type`` is REQUIRED per RFC 5965 section 3.1, but gateways
        omit it (issue #332). Without it the parser tries to base64-decode the
        part, that fails, and the payload is used as-is -- which must be the
        quoted-printable-decoded text, not the raw ``=3D``-riddled source."""
        feedback_report = FEEDBACK_REPORT_HEADERS.replace(
            "Feedback-Type: auth-failure\r\n", ""
        ).replace("User-Agent: parsedmarc-tests/1.0\r\n", "")
        # The fallback path under test is only reached because this payload is
        # not decodable as base64; assert that precondition rather than
        # relying on it silently.
        with self.assertRaises(binascii.Error):
            base64.b64decode(feedback_report)
        message = build_failure_report_email(
            feedback_report=feedback_report,
            feedback_report_cte="quoted-printable",
        )
        result = parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        self.assertEqual(report["feedback_type"], "auth-failure")
        authentication_results = report["authentication_results"]
        self.assertEqual(authentication_results, "mx.example.com; dmarc=fail")
        assert authentication_results is not None
        self.assertNotIn("=3D", authentication_results)
        self.assertEqual(report["source"]["ip_address"], "203.0.113.10")

    def testFailureSampleNonASCIIWithoutTransferEncoding(self):
        """A raw 8bit sample part's non-ASCII characters survive intact.

        The message is parsed from a ``str``, so a part with no
        quoted-printable or base64 Content-Transfer-Encoding has nothing to
        undo. Asking ``compat32`` for ``get_payload(decode=True)`` there
        round-trips the already-correct text through ``raw-unicode-escape``
        bytes, and re-decoding those as the declared charset replaces every
        non-ASCII character with U+FFFD."""
        sample = (
            "From: Jérôme <victim@example.com>\r\n"
            "To: someone@example.org\r\n"
            "Subject: café résumé\r\n"
        )
        message = build_raw_failure_report_email(sample)
        result = parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        parsed_sample = report["parsed_sample"]
        sample_from = parsed_sample.get("from")
        assert sample_from is not None
        self.assertEqual(sample_from["display_name"], "Jérôme")
        self.assertEqual(sample_from["address"], "victim@example.com")
        self.assertEqual(parsed_sample.get("subject"), "café résumé")
        self.assertNotIn("�", str(parsed_sample))

    def testFailureQuotedPrintableFeedbackReportSoftLineBreak(self):
        """A quoted-printable field value split across a soft line break is
        reassembled whole (issue #882).

        Quoted-printable lines are at most 76 characters (RFC 2045 section
        6.7), so a long field is split with a trailing ``=``. The standard
        library parses the still-encoded text as a message, and the
        continuation line -- no colon, no leading whitespace -- makes it record
        a ``MissingHeaderBodySeparatorDefect`` and treat the rest as the body,
        so re-serializing inserts a blank line the encoded text never had.
        Decoding consumes the soft break but leaves that inserted newline
        mid-value, truncating it at the first split."""
        authentication_results = (
            "mx.example.com; dkim=fail header.d=example.com header.s=selector1 "
            'reason="signature verification failed"; spf=fail '
            "smtp.mailfrom=bounce@example.com; dmarc=fail"
        )
        feedback_report = FEEDBACK_REPORT_HEADERS.replace(
            "Authentication-Results: mx.example.com; dmarc=fail\r\n",
            f"Authentication-Results: {authentication_results}\r\n",
        )
        message = build_failure_report_email(
            feedback_report=feedback_report,
            feedback_report_cte="quoted-printable",
        )
        # The defect under test only appears once the value is long enough to
        # be split; assert that precondition rather than relying on it.
        self.assertIn("=\n", message)
        result = parsedmarc.parse_report_email(message, offline=OFFLINE_MODE)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        parsed_results = report["authentication_results"]
        self.assertEqual(parsed_results, authentication_results)
        assert parsed_results is not None
        self.assertNotIn("=3D", parsed_results)

    def testDecodeMimePayloadUnknownCharset(self):
        """``_decode_mime_payload()`` falls back to UTF-8 when a part declares
        a charset Python does not know.

        The part must carry a real transfer encoding, since that is the only
        case in which the helper decodes bytes and therefore needs a charset
        at all."""
        part = MIMEText("hello", _subtype="rfc822-headers")
        part.set_payload(quopri.encodestring(b"hello").decode("ascii"))
        del part["Content-Type"]
        del part["Content-Transfer-Encoding"]
        part["Content-Type"] = 'text/rfc822-headers; charset="x-not-a-real-charset"'
        part["Content-Transfer-Encoding"] = "quoted-printable"
        with self.assertRaises(LookupError):
            "hello".encode("x-not-a-real-charset")
        self.assertEqual(parsedmarc._decode_mime_payload(part, "fallback"), "hello")

    def testDecodeMimePayloadWithoutTransferEncodingReturnsFallback(self):
        """``_decode_mime_payload()`` returns the payload text untouched when
        the part declares no quoted-printable or base64 transfer encoding."""
        part = MIMEText("hello", _subtype="rfc822-headers")
        self.assertEqual(part.get("Content-Transfer-Encoding"), "7bit")
        self.assertEqual(parsedmarc._decode_mime_payload(part, "fallback"), "fallback")

    def testDecodeMimePayloadUndecodableBase64FallsBack(self):
        """``_decode_mime_payload()`` returns the fallback unchanged when a
        nested ``message/*`` part declares base64 but its body cannot be
        decoded, so a report that parsed before cannot start failing."""
        outer = MIMEMultipart("report", report_type="feedback-report")
        inner = MIMENonMultipart("message", "feedback-report")
        inner.set_payload("AAAAA")
        inner["Content-Transfer-Encoding"] = "base64"
        outer.attach(inner)
        parsed = email.message_from_string(outer.as_string())
        parts = [
            part
            for part in parsed.walk()
            if part.get_content_type() == "message/feedback-report"
        ]
        self.assertEqual(len(parts), 1)
        # The standard library nests message/* parts, so decode=True is
        # unavailable and the by-hand base64 decode is what runs -- and fails.
        self.assertIsNone(parts[0].get_payload(decode=True))
        self.assertEqual(
            parsedmarc._decode_mime_payload(parts[0], "AAAAA"),
            "AAAAA",
        )

    def testFailureReportBackwardCompat(self):
        """Test that old forensic function aliases still work"""
        self.assertIs(
            parsedmarc.parse_forensic_report,
            parsedmarc.parse_failure_report,
        )
        self.assertIs(
            parsedmarc.parsed_forensic_reports_to_csv,
            parsedmarc.parsed_failure_reports_to_csv,
        )
        self.assertIs(
            parsedmarc.parsed_forensic_reports_to_csv_rows,
            parsedmarc.parsed_failure_reports_to_csv_rows,
        )
        self.assertIs(
            parsedmarc.InvalidForensicReport,
            parsedmarc.InvalidFailureReport,
        )

    def testRFC9990SampleReport(self):
        """Test parsing the sample report from RFC 9990 Appendix B"""
        print()
        sample_path = "samples/aggregate/rfc9990-sample.xml"
        print(f"Testing {sample_path}: ", end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = cast(AggregateReport, result["report"])

        # Verify report_type
        self.assertEqual(result["report_type"], "aggregate")

        # Verify xml_schema
        self.assertEqual(report["xml_schema"], "1.0")

        # Verify report_metadata
        metadata = report["report_metadata"]
        self.assertEqual(metadata["org_name"], "Sample Reporter")
        self.assertEqual(metadata["org_email"], "report_sender@example-reporter.com")
        self.assertEqual(metadata["org_extra_contact_info"], "...")
        self.assertEqual(metadata["report_id"], "3v98abbp8ya9n3va8yr8oa3ya")
        self.assertEqual(
            metadata["generator"],
            "Example DMARC Aggregate Reporter v1.2",
        )

        # Verify RFC 9990 policy_published fields
        pp = report["policy_published"]
        self.assertEqual(pp["domain"], "example.com")
        self.assertEqual(pp["p"], "quarantine")
        self.assertEqual(pp["sp"], "none")
        self.assertEqual(pp["np"], "none")
        self.assertEqual(pp["testing"], "n")
        self.assertEqual(pp["discovery_method"], "treewalk")
        # adkim/aspf default when not in XML
        self.assertEqual(pp["adkim"], "r")
        self.assertEqual(pp["aspf"], "r")
        # pct is removed in RFC 9989 (and so absent from the RFC 9990
        # sample); fo is still part of RFC 9990's PolicyPublishedType but
        # the appendix sample happens not to set it.
        self.assertIsNone(pp["pct"])
        self.assertIsNone(pp["fo"])

        # Verify record
        self.assertEqual(len(report["records"]), 1)
        rec = report["records"][0]
        self.assertEqual(rec["source"]["ip_address"], "192.0.2.123")
        self.assertEqual(rec["count"], 123)
        self.assertEqual(rec["policy_evaluated"]["disposition"], "pass")
        self.assertEqual(rec["policy_evaluated"]["dkim"], "pass")
        self.assertEqual(rec["policy_evaluated"]["spf"], "fail")

        # Verify DKIM auth result with human_result
        self.assertEqual(len(rec["auth_results"]["dkim"]), 1)
        dkim = rec["auth_results"]["dkim"][0]
        self.assertEqual(dkim["domain"], "example.com")
        self.assertEqual(dkim["selector"], "abc123")
        self.assertEqual(dkim["result"], "pass")
        self.assertIsNone(dkim["human_result"])

        # Verify SPF auth result with human_result
        self.assertEqual(len(rec["auth_results"]["spf"]), 1)
        spf = rec["auth_results"]["spf"][0]
        self.assertEqual(spf["domain"], "example.com")
        self.assertEqual(spf["result"], "fail")
        self.assertIsNone(spf["human_result"])

        # Verify CSV output includes new fields
        csv = parsedmarc.parsed_aggregate_reports_to_csv(report)
        header = csv.split("\n")[0]
        self.assertIn("np", header.split(","))
        self.assertIn("testing", header.split(","))
        self.assertIn("discovery_method", header.split(","))
        print("Passed!")

    def testRFC9990FieldsAbsentFromRFC7489Report(self):
        """Test that RFC 7489 reports have None for RFC 9990-only fields"""
        print()
        sample_path = (
            "samples/aggregate/example.net!example.com!1529366400!1529452799.xml"
        )
        print(f"Testing {sample_path}: ", end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = cast(AggregateReport, result["report"])
        pp = report["policy_published"]

        # RFC 7489 fields present
        self.assertEqual(pp["pct"], "100")
        self.assertEqual(pp["fo"], "0")

        # RFC 9990-only fields absent (None)
        self.assertIsNone(pp["np"])
        self.assertIsNone(pp["testing"])
        self.assertIsNone(pp["discovery_method"])

        # generator absent (None)
        self.assertIsNone(report["report_metadata"]["generator"])
        print("Passed!")

    def testRFC9990WithExplicitFields(self):
        """Test RFC 9990 report with explicit testing and discovery_method"""
        print()
        sample_path = (
            "samples/aggregate/"
            "rfc9990-example.net!example.com!1700000000!1700086399.xml"
        )
        print(f"Testing {sample_path}: ", end="")
        result = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True, offline=True
        )
        report = cast(AggregateReport, result["report"])
        pp = report["policy_published"]

        self.assertEqual(pp["np"], "reject")
        self.assertEqual(pp["testing"], "y")
        self.assertEqual(pp["discovery_method"], "treewalk")
        print("Passed!")

    def testRFC9990NamespaceCaptured(self):
        """The dmarc-2.0 namespace on <feedback> is preserved on the
        parsed report so consumers can distinguish RFC 9990 from RFC 7489
        reports without inferring from the version element value."""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/rfc9990-sample.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
        self.assertEqual(
            report["xml_namespace"],
            "urn:ietf:params:xml:ns:dmarc-2.0",
        )

    def testRFC9990NamespaceAbsentOnRFC7489Report(self):
        """RFC 7489 reports don't declare the dmarc-2.0 namespace, so
        xml_namespace is None."""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/example.net!example.com!1529366400!1529452799.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
        self.assertIsNone(report["xml_namespace"])

    def testRFC9990DetectionAcceptsNamespacelessReports(self):
        """A report that follows the RFC 9990 shape without declaring the
        namespace (e.g. emits np/testing/discovery_method) is still
        treated as RFC 9990 for validation purposes — warnings fire,
        the namespace field reports it honestly as absent."""
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_aggregate_report_xml(
                """<?xml version="1.0"?>
                <feedback>
                    <report_metadata>
                        <org_name>Test</org_name>
                        <email>t@example.com</email>
                        <report_id>r1</report_id>
                        <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
                    </report_metadata>
                    <policy_published>
                        <domain>example.com</domain>
                        <p>none</p>
                        <np>reject</np>
                    </policy_published>
                    <record>
                        <row>
                            <source_ip>192.0.2.1</source_ip>
                            <count>1</count>
                            <policy_evaluated>
                                <disposition>none</disposition>
                                <dkim>pass</dkim>
                                <spf>pass</spf>
                            </policy_evaluated>
                        </row>
                        <identifiers><header_from>example.com</header_from></identifiers>
                        <auth_results>
                            <dkim>
                                <domain>example.com</domain>
                                <result>pass</result>
                            </dkim>
                        </auth_results>
                    </record>
                </feedback>""",
                offline=True,
            )
        # Namespace honestly None because none was declared.
        self.assertIsNone(report["xml_namespace"])
        # RFC 9990 detection still fired (DKIM selector warning emitted).
        self.assertTrue(
            any("selector" in msg for msg in cm.output),
            f"Expected DKIM selector warning; got: {cm.output}",
        )

    def testRFC9990DKIMMissingSelectorWarning(self):
        """A DKIM auth result with no <selector> in an RFC 9990 report
        (namespace declared) emits a warning since selector is REQUIRED."""
        xml = """<?xml version="1.0"?>
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
            <version>1.0</version>
            <report_metadata>
                <org_name>Test</org_name>
                <email>t@example.com</email>
                <report_id>r1</report_id>
                <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <dkim>
                        <domain>example.com</domain>
                        <result>pass</result>
                    </dkim>
                </auth_results>
            </record>
        </feedback>"""
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertTrue(
            any("selector" in m and "REQUIRED" in m for m in cm.output),
            f"Expected selector REQUIRED warning; got: {cm.output}",
        )

    def testRFC9990LegacyOverrideTypeWarning(self):
        """`forwarded` and `sampled_out` were removed in RFC 9990;
        a warning fires when they appear in an RFC 9990 report."""
        xml = """<?xml version="1.0"?>
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
            <report_metadata>
                <org_name>Test</org_name>
                <email>t@example.com</email>
                <report_id>r1</report_id>
                <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                        <reason><type>forwarded</type></reason>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <dkim>
                        <domain>example.com</domain>
                        <selector>s</selector>
                        <result>pass</result>
                    </dkim>
                </auth_results>
            </record>
        </feedback>"""
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertTrue(
            any("forwarded" in m and "removed in RFC 9990" in m for m in cm.output),
            f"Expected legacy override warning; got: {cm.output}",
        )

    def testRFC9990LangAttrStringUnwrapped(self):
        """When a langAttrString element (extra_contact_info, error,
        comment, human_result) carries a lang attribute, xmltodict turns
        it into {"#text": "...", "@lang": "en"}; the parser must unwrap
        to the text payload so the report stays comparable to one
        without the lang attribute."""
        xml = """<?xml version="1.0"?>
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
            <report_metadata>
                <org_name>Test</org_name>
                <email>t@example.com</email>
                <extra_contact_info xml:lang="en">contact-here</extra_contact_info>
                <report_id>r1</report_id>
                <date_range><begin>1700000000</begin><end>1700086399</end></date_range>
                <error xml:lang="en">a problem</error>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                        <reason>
                            <type>local_policy</type>
                            <comment xml:lang="en">a comment</comment>
                        </reason>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <dkim>
                        <domain>example.com</domain>
                        <selector>s</selector>
                        <result>pass</result>
                        <human_result xml:lang="en">looks fine</human_result>
                    </dkim>
                    <spf>
                        <domain>example.com</domain>
                        <result>pass</result>
                        <human_result xml:lang="en">spf-detail</human_result>
                    </spf>
                </auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(
            report["report_metadata"]["org_extra_contact_info"], "contact-here"
        )
        self.assertEqual(report["report_metadata"]["errors"], ["a problem"])
        rec = report["records"][0]
        reasons = rec["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(reasons[0]["comment"], "a comment")
        self.assertEqual(rec["auth_results"]["dkim"][0]["human_result"], "looks fine")
        self.assertEqual(rec["auth_results"]["spf"][0]["human_result"], "spf-detail")

    def testSmtpTlsSamples(self):
        """Test sample SMTP TLS reports"""
        print()
        sample_paths = glob("samples/smtp_tls/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print(f"Testing {sample_path}: ", end="")
            with self.subTest(sample=sample_path):
                result = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
                assert result["report_type"] == "smtp_tls"
                parsedmarc.parsed_smtp_tls_reports_to_csv(
                    cast(SMTPTLSReport, result["report"])
                )
            print("Passed!")

    def testSmtpTlsRfc8460SampleReadsAdditionalInformation(self):
        """samples/smtp_tls/rfc8460.json is RFC 8460 §4.4's own worked
        example, whose second failure-details entry sets
        "additional-information" (not the non-RFC "additional-info-uri").
        Before the fix, the parser only read "additional-info-uri", so this
        URI was silently dropped even from the RFC's own example."""
        result = parsedmarc.parse_report_file(
            "samples/smtp_tls/rfc8460.json", offline=True
        )
        report = cast(SMTPTLSReport, result["report"])
        failure_details = report["policies"][0].get("failure_details", [])
        starttls_detail = next(
            d for d in failure_details if d["result_type"] == "starttls-not-supported"
        )
        self.assertEqual(
            starttls_detail.get("additional_info_uri"),
            "https://reports.company-x.example/report_info?"
            "id=5065427c-23d3#StarttlsNotSupported",
        )

    def testSmtpTlsCsvStripsNulFromFields(self):
        """A NUL character in an SMTP TLS report text field is stripped
        from CSV output instead of reaching the ``csv`` writer.

        Python 3.10's ``csv`` module raises ``_csv.Error: need to escape,
        but no escapechar set`` on any field containing NUL
        (https://github.com/python/cpython/issues/97503, a 3.10 regression
        fixed in 3.11). This test fails on unfixed code on 3.10 with that
        error, and on unfixed code on 3.11+ because the NUL passes through
        to the CSV text uncleaned."""
        result = parsedmarc.parse_report_file(
            "samples/smtp_tls/smtp_tls.json", offline=True
        )
        report = cast(SMTPTLSReport, result["report"])
        report["organization_name"] = "Example\x00Inc."

        csv_text = parsedmarc.parsed_smtp_tls_reports_to_csv(report)

        self.assertNotIn("\x00", csv_text)
        reader = csv.DictReader(StringIO(csv_text))
        row = next(reader)
        self.assertEqual(row["organization_name"], "ExampleInc.")

    def testCsvSafeNeutralizesFormulaPrefixes(self):
        """_csv_safe prefixes a string starting with any spreadsheet
        formula trigger with ``'`` (CWE-1236; OWASP CSV Injection,
        https://owasp.org/www-community/attacks/CSV_Injection) and leaves
        everything else alone, including non-strings."""
        cases = [
            ("=1+1", "'=1+1"),
            ("+1", "'+1"),
            ("-1", "'-1"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\tcmd", "'\tcmd"),
            ("\rcmd", "'\rcmd"),
            ("\x00=1+1", "'=1+1"),
            ("Example Inc.", "Example Inc."),
            ("a-b=c+d@e", "a-b=c+d@e"),
            ("", ""),
            (15169, 15169),
            (None, None),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(parsedmarc._csv_safe(value), expected)

    def testAggregateCsvNeutralizesFormulaInOrgName(self):
        """A reporter-supplied ``=HYPERLINK(...)`` org_name is written to
        the aggregate CSV with a leading apostrophe, while ordinary
        values and numeric columns are unchanged."""
        payload = '=HYPERLINK("http://evil","x")'
        escaped = payload.replace('"', "&quot;")
        xml = (
            "<feedback><report_metadata>"
            f"<org_name>{escaped}</org_name>"
            "<email>a@example.com</email><report_id>r-1</report_id>"
            "<date_range><begin>1529366400</begin><end>1529452799</end>"
            "</date_range></report_metadata><policy_published>"
            "<domain>example.com</domain><p>none</p></policy_published>"
            "<record><row><source_ip>192.0.2.1</source_ip><count>3</count>"
            "<policy_evaluated><disposition>none</disposition>"
            "<dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>"
            "<identifiers><header_from>example.com</header_from>"
            "</identifiers><auth_results></auth_results></record></feedback>"
        )
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["org_name"], payload)

        csv_text = parsedmarc.parsed_aggregate_reports_to_csv(report)

        row = next(csv.DictReader(StringIO(csv_text)))
        self.assertEqual(row["org_name"], "'" + payload)
        self.assertEqual(row["domain"], "example.com")
        self.assertEqual(row["count"], "3")

        report["report_metadata"]["org_name"] = "Example-Org Inc."
        row = next(
            csv.DictReader(StringIO(parsedmarc.parsed_aggregate_reports_to_csv(report)))
        )
        self.assertEqual(row["org_name"], "Example-Org Inc.")

    def testFailureReportCsvNeutralizesFormulaInSubject(self):
        """A failure report sample subject starting with ``@`` is written
        with a leading apostrophe."""
        parsed_report = cast(
            FailureReport,
            parsedmarc.parse_report_file(
                "samples/failure/dmarc_ruf_report_linkedin.eml", offline=True
            )["report"],
        )
        parsed_report["parsed_sample"]["subject"] = "@evil"

        csv_text = parsedmarc.parsed_failure_reports_to_csv(parsed_report)

        row = next(csv.DictReader(StringIO(csv_text)))
        self.assertEqual(row["subject"], "'@evil")

    def testSmtpTlsCsvNeutralizesFormulaInOrganizationName(self):
        """An SMTP TLS report string field starting with ``+`` is written
        with a leading apostrophe."""
        result = parsedmarc.parse_report_file(
            "samples/smtp_tls/smtp_tls.json", offline=True
        )
        report = cast(SMTPTLSReport, result["report"])
        report["organization_name"] = "+1-555-0100"

        csv_text = parsedmarc.parsed_smtp_tls_reports_to_csv(report)

        row = next(csv.DictReader(StringIO(csv_text)))
        self.assertEqual(row["organization_name"], "'+1-555-0100")

    def testAggregateCsvExposesASNColumns(self):
        """The aggregate CSV output should include source_asn, source_as_name,
        and source_as_domain columns."""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/!example.com!1538204542!1538463818.xml",
            always_use_local_files=True,
            offline=True,
        )
        csv_text = parsedmarc.parsed_aggregate_reports_to_csv(
            cast(AggregateReport, result["report"])
        )
        header = csv_text.splitlines()[0].split(",")
        self.assertIn("source_asn", header)
        self.assertIn("source_as_name", header)
        self.assertIn("source_as_domain", header)

    def testBucketIntervalBeginAfterEnd(self):
        """begin > end should raise ValueError"""
        begin = datetime(2024, 1, 2, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalNaiveDatetime(self):
        """Non-timezone-aware datetimes should raise ValueError"""
        begin = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalDifferentTzinfo(self):
        """Different tzinfo objects should raise ValueError"""
        tz1 = timezone.utc
        tz2 = timezone(timedelta(hours=5))
        begin = datetime(2024, 1, 1, tzinfo=tz1)
        end = datetime(2024, 1, 2, tzinfo=tz2)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, 100)

    def testBucketIntervalNegativeCount(self):
        """Negative total_count should raise ValueError"""
        begin = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        with self.assertRaises(ValueError):
            parsedmarc._bucket_interval_by_day(begin, end, -1)

    def testBucketIntervalZeroCount(self):
        """Zero total_count should return empty list"""
        begin = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 0)
        self.assertEqual(result, [])

    def testBucketIntervalSameBeginEnd(self):
        """Same begin and end (zero interval) should return empty list"""
        dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(dt, dt, 100)
        self.assertEqual(result, [])

    def testBucketIntervalSingleDay(self):
        """Single day interval should return one bucket with total count"""
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 23, 59, 59, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 100)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["count"], 100)
        self.assertEqual(result[0]["begin"], begin)

    def testBucketIntervalMultiDay(self):
        """Multi-day interval should distribute counts proportionally"""
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 100)
        self.assertEqual(len(result), 2)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 100)
        # Equal days => equal distribution
        self.assertEqual(result[0]["count"], 50)
        self.assertEqual(result[1]["count"], 50)

    def testBucketIntervalRemainderDistribution(self):
        """Odd count across equal days distributes remainder correctly"""
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 4, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 10)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 10)
        self.assertEqual(len(result), 3)

    def testBucketIntervalPartialDays(self):
        """Partial days: 12h on day1, 24h on day2 => 1/3 vs 2/3 split"""
        begin = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        result = parsedmarc._bucket_interval_by_day(begin, end, 90)
        total = sum(b["count"] for b in result)
        self.assertEqual(total, 90)
        # day1: 12h, day2: 24h => 1/3 vs 2/3
        self.assertEqual(result[0]["count"], 30)
        self.assertEqual(result[1]["count"], 60)

    def testAppendParsedRecordNoNormalize(self):
        """No normalization: record appended as-is with interval fields"""
        records = []
        rec = {"count": 10, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, False)
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0]["normalized_timespan"])  # type: ignore[typeddict-item]
        self.assertEqual(records[0]["interval_begin"], "2024-01-01 00:00:00")
        self.assertEqual(records[0]["interval_end"], "2024-01-02 00:00:00")

    def testAppendParsedRecordNormalize(self):
        """Normalization: record split into daily buckets"""
        records = []
        rec = {"count": 100, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, True)
        self.assertEqual(len(records), 2)
        total = sum(r["count"] for r in records)
        self.assertEqual(total, 100)
        for r in records:
            self.assertTrue(r["normalized_timespan"])  # type: ignore[typeddict-item]

    def testAppendParsedRecordNormalizeZeroCount(self):
        """Normalization with zero count: nothing appended"""
        records = []
        rec = {"count": 0, "source": {"ip_address": "1.2.3.4"}}
        begin = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
        parsedmarc._append_parsed_record(rec, records, begin, end, True)
        self.assertEqual(len(records), 0)

    def testParseReportRecordNoneSourceIP(self):
        """Record with None source_ip should raise ValueError"""
        record = {
            "row": {
                "source_ip": None,
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        with self.assertRaises(ValueError):
            parsedmarc._parse_report_record(
                record, config=parsedmarc.ParserConfig(offline=True)
            )

    def testParseReportRecordMissingDkimSpf(self):
        """Record with missing dkim/spf auth results defaults correctly"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "5",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "fail",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {},
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertEqual(result["auth_results"]["dkim"], [])
        self.assertEqual(result["auth_results"]["spf"], [])

    def testParseReportRecordReasonHandling(self):
        """Reasons in policy_evaluated get normalized with comment default"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                    "reason": {"type": "forwarded"},
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        reasons = result["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(len(reasons), 1)
        self.assertEqual(reasons[0]["type"], "forwarded")
        self.assertIsNone(reasons[0]["comment"])

    def testParseReportRecordReasonList(self):
        """Multiple reasons as a list are preserved"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                    "reason": [
                        {"type": "forwarded", "comment": "relay"},
                        {"type": "local_policy"},
                    ],
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        reasons = result["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(len(reasons), 2)
        self.assertEqual(reasons[0]["comment"], "relay")
        self.assertIsNone(reasons[1]["comment"])

    def testParseReportRecordIdentities(self):
        """'identities' key is mapped to 'identifiers'"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identities": {
                "header_from": "Example.COM",
                "envelope_from": "example.com",
            },
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertIn("identifiers", result)
        self.assertEqual(result["identifiers"]["header_from"], "example.com")

    def testParseReportRecordDkimDefaults(self):
        """DKIM result defaults: selector='none', result='none' when missing"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "fail",
                    "spf": "fail",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": {"domain": "example.com"},
                "spf": [],
            },
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        dkim = result["auth_results"]["dkim"][0]
        self.assertEqual(dkim["selector"], "none")
        self.assertEqual(dkim["result"], "none")
        self.assertIsNone(dkim["human_result"])

    def testParseReportRecordSpfDefaults(self):
        """SPF result defaults: scope='mfrom', result='none' when missing"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "fail",
                    "spf": "fail",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [],
                "spf": {"domain": "example.com"},
            },
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        spf = result["auth_results"]["spf"][0]
        self.assertEqual(spf["scope"], "mfrom")
        self.assertEqual(spf["result"], "none")
        self.assertIsNone(spf["human_result"])

    def testParseReportRecordHumanResult(self):
        """human_result field is included when present"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [
                    {
                        "domain": "example.com",
                        "selector": "s1",
                        "result": "pass",
                        "human_result": "good key",
                    }
                ],
                "spf": [
                    {
                        "domain": "example.com",
                        "scope": "mfrom",
                        "result": "pass",
                        "human_result": "sender valid",
                    }
                ],
            },
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertEqual(result["auth_results"]["dkim"][0]["human_result"], "good key")
        self.assertEqual(
            result["auth_results"]["spf"][0]["human_result"], "sender valid"
        )

    def testParseReportRecordEnvelopeFromFallback(self):
        """envelope_from falls back to last SPF domain when missing"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {
                "dkim": [],
                "spf": [
                    {"domain": "Bounce.Example.COM", "scope": "mfrom", "result": "pass"}
                ],
            },
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertEqual(result["identifiers"]["envelope_from"], "bounce.example.com")

    def testParseReportRecordEnvelopeFromNullFallback(self):
        """envelope_from None value falls back to SPF domain"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {
                "header_from": "example.com",
                "envelope_from": None,
            },
            "auth_results": {
                "dkim": [],
                "spf": [
                    {"domain": "SPF.Example.COM", "scope": "mfrom", "result": "pass"}
                ],
            },
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertEqual(result["identifiers"]["envelope_from"], "spf.example.com")

    def testParseReportRecordEnvelopeFromNullNoSpfDomain(self):
        """envelope_from=None with SPF results that carry no domain must not
        raise IndexError (regression: the branch gated on the raw SPF list but
        indexed the filtered list, which is empty when no result has a domain)"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {
                "header_from": "example.com",
                "envelope_from": None,
            },
            # A raw SPF result with no "domain" -> filtered list is empty.
            "auth_results": {
                "dkim": [],
                "spf": [{"scope": "mfrom", "result": "pass"}],
            },
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertIsNone(result["identifiers"]["envelope_from"])

    def testParseReportRecordEnvelopeTo(self):
        """envelope_to is preserved and moved correctly"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "pass",
                },
            },
            "identifiers": {
                "header_from": "example.com",
                "envelope_from": "bounce@example.com",
                "envelope_to": "recipient@example.com",
            },
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertEqual(result["identifiers"]["envelope_to"], "recipient@example.com")

    def testParseReportRecordAlignment(self):
        """Alignment fields computed correctly from policy_evaluated"""
        record = {
            "row": {
                "source_ip": "192.0.2.1",
                "count": "1",
                "policy_evaluated": {
                    "disposition": "none",
                    "dkim": "pass",
                    "spf": "fail",
                },
            },
            "identifiers": {"header_from": "example.com"},
            "auth_results": {"dkim": [], "spf": []},
        }
        result = parsedmarc._parse_report_record(
            record, config=parsedmarc.ParserConfig(offline=True)
        )
        self.assertTrue(result["alignment"]["dkim"])
        self.assertFalse(result["alignment"]["spf"])
        self.assertTrue(result["alignment"]["dmarc"])

    def testParseSmtpTlsFailureDetailsMinimal(self):
        """Minimal failure details with just required fields"""
        details = {
            "result-type": "certificate-expired",
            "failed-session-count": 5,
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(result["result_type"], "certificate-expired")
        self.assertEqual(result["failed_session_count"], 5)
        self.assertNotIn("sending_mta_ip", result)

    def testParseSmtpTlsFailureDetailsAllOptional(self):
        """All optional fields included"""
        details = {
            "result-type": "starttls-not-supported",
            "failed-session-count": 3,
            "sending-mta-ip": "10.0.0.1",
            "receiving-ip": "10.0.0.2",
            "receiving-mx-hostname": "mx.example.com",
            "receiving-mx-helo": "mx.example.com",
            "additional-info-uri": "https://example.com/info",
            "failure-reason-code": "TLS_ERROR",
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(result["sending_mta_ip"], "10.0.0.1")
        self.assertEqual(result["receiving_ip"], "10.0.0.2")
        self.assertEqual(result["receiving_mx_hostname"], "mx.example.com")
        self.assertEqual(result["receiving_mx_helo"], "mx.example.com")
        self.assertEqual(result["additional_info_uri"], "https://example.com/info")
        self.assertEqual(result["failure_reason_code"], "TLS_ERROR")

    def testParseSmtpTlsFailureDetailsBlankOptionalFieldsOmitted(self):
        """Empty-string and whitespace-only optional fields are treated as
        absent, not passed through.

        Real-world reporters send "" for sending-mta-ip/receiving-ip on
        results like sts-policy-fetch-error (see samples/smtp_tls/
        empty_failure_detail_fields.json). An empty string is not a valid
        IP address, so it previously reached PostgreSQL's INET columns
        verbatim and crashed the PostgreSQL save, and would also have
        crashed the Elasticsearch/OpenSearch saves' Ip() field validation
        with a bare ValueError (issue #915).
        """
        details = {
            "result-type": "sts-policy-fetch-error",
            "failed-session-count": 1,
            "sending-mta-ip": "",
            "receiving-ip": "   ",
            "receiving-mx-hostname": "",
            "receiving-mx-helo": "\t",
            "additional-information": "",
            "additional-info-uri": "",
            "failure-reason-code": "",
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(result["result_type"], "sts-policy-fetch-error")
        self.assertEqual(result["failed_session_count"], 1)
        self.assertNotIn("sending_mta_ip", result)
        self.assertNotIn("receiving_ip", result)
        self.assertNotIn("receiving_mx_hostname", result)
        self.assertNotIn("receiving_mx_helo", result)
        self.assertNotIn("additional_info_uri", result)
        self.assertNotIn("failure_reason_code", result)

    def testParseSmtpTlsFailureDetailsAdditionalInformationKey(self):
        """RFC 8460 §4.4's JSON key is "additional-information" (its value
        is described as an "additional-info-uri"); it is read into the
        parser's additional_info_uri field.
        """
        details = {
            "result-type": "starttls-not-supported",
            "failed-session-count": 1,
            "additional-information": "https://example.com/rfc-key-info",
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(
            result["additional_info_uri"], "https://example.com/rfc-key-info"
        )

    def testParseSmtpTlsFailureDetailsAdditionalInformationWinsOverLegacy(self):
        """When both the RFC key and the legacy key are present and
        non-blank, the RFC key's value wins."""
        details = {
            "result-type": "starttls-not-supported",
            "failed-session-count": 1,
            "additional-information": "https://example.com/rfc-key-info",
            "additional-info-uri": "https://example.com/legacy-key-info",
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(
            result["additional_info_uri"], "https://example.com/rfc-key-info"
        )

    def testParseSmtpTlsFailureDetailsAdditionalInformationBlankFallsBack(self):
        """A blank RFC-key value falls back to a non-blank legacy value."""
        details = {
            "result-type": "starttls-not-supported",
            "failed-session-count": 1,
            "additional-information": "",
            "additional-info-uri": "https://example.com/legacy-key-info",
        }
        result = parsedmarc._parse_smtp_tls_failure_details(details)
        self.assertEqual(
            result["additional_info_uri"], "https://example.com/legacy-key-info"
        )

    def testParseSmtpTlsFailureDetailsMissingRequired(self):
        """Missing required field raises InvalidSMTPTLSReport"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc._parse_smtp_tls_failure_details({"result-type": "err"})

    def testParseSmtpTlsFailureDetailsNonDict(self):
        """A non-dict failure-details value hits the catch-all (TypeError,
        not KeyError) and is wrapped as InvalidSMTPTLSReport"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            # Deliberate wrong type to exercise the non-KeyError catch-all.
            parsedmarc._parse_smtp_tls_failure_details("not a dict")  # pyright: ignore[reportArgumentType]
        self.assertIsInstance(ctx.exception.__cause__, TypeError)

    def testParseSmtpTlsReportPolicyValid(self):
        """Valid STS policy parses correctly"""
        policy = {
            "policy": {
                "policy-type": "sts",
                "policy-domain": "example.com",
                "policy-string": ["version: STSv1", "mode: enforce"],
                "mx-host-pattern": ["*.example.com"],
            },
            "summary": {
                "total-successful-session-count": 100,
                "total-failure-session-count": 2,
            },
        }
        result = parsedmarc._parse_smtp_tls_report_policy(policy)
        self.assertEqual(result["policy_type"], "sts")
        self.assertEqual(result["policy_domain"], "example.com")
        self.assertEqual(result["policy_strings"], ["version: STSv1", "mode: enforce"])
        self.assertEqual(result["mx_host_patterns"], ["*.example.com"])
        self.assertEqual(result["successful_session_count"], 100)
        self.assertEqual(result["failed_session_count"], 2)

    def testParseSmtpTlsReportPolicyInvalidType(self):
        """Invalid policy type raises InvalidSMTPTLSReport"""
        policy = {
            "policy": {
                "policy-type": "invalid",
                "policy-domain": "example.com",
            },
            "summary": {
                "total-successful-session-count": 0,
                "total-failure-session-count": 0,
            },
        }
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc._parse_smtp_tls_report_policy(policy)

    def testParseSmtpTlsReportPolicyEmptyPolicyString(self):
        """Empty policy-string list is not included"""
        policy = {
            "policy": {
                "policy-type": "sts",
                "policy-domain": "example.com",
                "policy-string": [],
                "mx-host-pattern": [],
            },
            "summary": {
                "total-successful-session-count": 50,
                "total-failure-session-count": 0,
            },
        }
        result = parsedmarc._parse_smtp_tls_report_policy(policy)
        self.assertNotIn("policy_strings", result)
        self.assertNotIn("mx_host_patterns", result)

    def testParseSmtpTlsReportPolicyWithFailureDetails(self):
        """Policy with failure-details parses nested details"""
        policy = {
            "policy": {
                "policy-type": "sts",
                "policy-domain": "example.com",
            },
            "summary": {
                "total-successful-session-count": 10,
                "total-failure-session-count": 1,
            },
            "failure-details": [
                {
                    "result-type": "certificate-expired",
                    "failed-session-count": 1,
                }
            ],
        }
        result = parsedmarc._parse_smtp_tls_report_policy(policy)
        self.assertEqual(len(result["failure_details"]), 1)
        self.assertEqual(
            result["failure_details"][0]["result_type"], "certificate-expired"
        )

    def testParseSmtpTlsReportPolicyMissingField(self):
        """Missing required policy field raises InvalidSMTPTLSReport"""
        policy = {"policy": {"policy-type": "sts"}, "summary": {}}
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc._parse_smtp_tls_report_policy(policy)

    def testParseSmtpTlsReportJsonValid(self):
        """Valid SMTP TLS JSON report parses correctly"""
        report = json.dumps(
            {
                "organization-name": "Example Corp",
                "date-range": {
                    "start-datetime": "2024-01-01T00:00:00Z",
                    "end-datetime": "2024-01-02T00:00:00Z",
                },
                "contact-info": "admin@example.com",
                "report-id": "report-123",
                "policies": [
                    {
                        "policy": {
                            "policy-type": "sts",
                            "policy-domain": "example.com",
                        },
                        "summary": {
                            "total-successful-session-count": 50,
                            "total-failure-session-count": 0,
                        },
                    }
                ],
            }
        )
        result = parsedmarc.parse_smtp_tls_report_json(report)
        self.assertEqual(result["organization_name"], "Example Corp")
        self.assertEqual(result["report_id"], "report-123")
        self.assertEqual(len(result["policies"]), 1)

    def testParseSmtpTlsReportJsonBytes(self):
        """SMTP TLS report as bytes parses correctly"""
        report = json.dumps(
            {
                "organization-name": "Org",
                "date-range": {
                    "start-datetime": "2024-01-01",
                    "end-datetime": "2024-01-02",
                },
                "contact-info": "a@b.com",
                "report-id": "r1",
                "policies": [
                    {
                        "policy": {"policy-type": "tlsa", "policy-domain": "a.com"},
                        "summary": {
                            "total-successful-session-count": 1,
                            "total-failure-session-count": 0,
                        },
                    }
                ],
            }
        ).encode("utf-8")
        result = parsedmarc.parse_smtp_tls_report_json(report)
        self.assertEqual(result["organization_name"], "Org")

    def testParseSmtpTlsReportJsonMissingField(self):
        """Missing required field raises InvalidSMTPTLSReport"""
        report = json.dumps({"organization-name": "Org"})
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(report)

    def testParseSmtpTlsReportJsonPoliciesNotList(self):
        """Non-list policies raises InvalidSMTPTLSReport"""
        report = json.dumps(
            {
                "organization-name": "Org",
                "date-range": {
                    "start-datetime": "2024-01-01",
                    "end-datetime": "2024-01-02",
                },
                "contact-info": "a@b.com",
                "report-id": "r1",
                "policies": "not-a-list",
            }
        )
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(report)

    def testAggregateReportInvalidNpWarning(self):
        """Invalid np value is preserved but logs warning"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <version>1.0</version>
            <report_metadata>
                <org_name>Test Org</org_name>
                <email>test@example.com</email>
                <report_id>test-np-invalid</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
                <np>banana</np>
                <testing>maybe</testing>
                <discovery_method>magic</discovery_method>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <spf><domain>example.com</domain><result>pass</result></spf>
                </auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        # Invalid values are still stored
        self.assertEqual(report["policy_published"]["np"], "banana")
        self.assertEqual(report["policy_published"]["testing"], "maybe")
        self.assertEqual(report["policy_published"]["discovery_method"], "magic")

    def testAggregateReportPassDisposition(self):
        """'pass' as valid disposition is preserved"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-pass</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>reject</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated>
                        <disposition>pass</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                    </policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results>
                    <spf><domain>example.com</domain><result>pass</result></spf>
                </auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(
            report["records"][0]["policy_evaluated"]["disposition"], "pass"
        )

    def testAggregateReportMultipleRecords(self):
        """Reports with multiple records are all parsed"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-multi</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>10</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
            <record>
                <row>
                    <source_ip>192.0.2.2</source_ip>
                    <count>5</count>
                    <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>fail</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(len(report["records"]), 2)
        self.assertEqual(report["records"][0]["count"], 10)
        self.assertEqual(report["records"][1]["count"], 5)

    def testAggregateReportInvalidXmlRecovery(self):
        """Badly formed XML is recovered via lxml"""
        xml = '<?xml version="1.0"?><feedback><report_metadata><org_name>Test</org_name><email>t@e.com</email><report_id>r1</report_id><date_range><begin>1704067200</begin><end>1704153599</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>'
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["report_id"], "r1")

    def testAggregateReportCsvRowsContainRFC9990Fields(self):
        """CSV rows include np, testing, discovery_method columns"""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/rfc9990-sample.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
        rows = parsedmarc.parsed_aggregate_reports_to_csv_rows(report)
        self.assertGreater(len(rows), 0)
        row = rows[0]
        self.assertIn("np", row)
        self.assertIn("testing", row)
        self.assertIn("discovery_method", row)
        self.assertIn("source_ip_address", row)
        self.assertIn("dkim_domains", row)
        self.assertIn("spf_domains", row)

    def testAggregateReportSchemaVersion(self):
        """RFC 9990 report with <version> returns correct xml_schema"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <version>1.0</version>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-version</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["xml_schema"], "1.0")

    def testAggregateReportDraftSchema(self):
        """Report without <version> defaults to 'draft' schema"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-draft</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["xml_schema"], "draft")

    def testAggregateReportGeneratorField(self):
        """Generator field is correctly extracted"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-gen</report_id>
                <generator>My Reporter v1.0</generator>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["generator"], "My Reporter v1.0")

    def testAggregateReportReportErrors(self):
        """Report errors in metadata are captured"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-err</report_id>
                <error>Some error</error>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIn("Some error", report["report_metadata"]["errors"])

    def testAggregateReportPolicyDefaults(self):
        """Policy defaults: adkim/aspf='r', sp=p, pct/fo=None"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-defaults</report_id>
                <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>reject</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>1</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        pp = report["policy_published"]
        self.assertEqual(pp["adkim"], "r")
        self.assertEqual(pp["aspf"], "r")
        self.assertEqual(pp["sp"], "reject")  # defaults to p
        self.assertIsNone(pp["pct"])
        self.assertIsNone(pp["fo"])
        self.assertIsNone(pp["np"])
        self.assertIsNone(pp["testing"])
        self.assertIsNone(pp["discovery_method"])

    def testMagicXmlTagDetection(self):
        """XML without declaration (starting with '<') is extracted"""
        xml_no_decl = b"<feedback><report_metadata><org_name>T</org_name><email>a@b.com</email><report_id>r1</report_id><date_range><begin>1704067200</begin><end>1704153599</end></date_range></report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers><auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record></feedback>"
        self.assertTrue(xml_no_decl.startswith(parsedmarc.MAGIC_XML_TAG))
        # Ensure it extracts as XML
        result = parsedmarc.extract_report(xml_no_decl)
        self.assertIn("<feedback>", result)

    def testSmtpTlsCsvRows(self):
        """parsed_smtp_tls_reports_to_csv_rows produces correct rows"""
        report_json = json.dumps(
            {
                "organization-name": "Org",
                "date-range": {
                    "start-datetime": "2024-01-01T00:00:00Z",
                    "end-datetime": "2024-01-02T00:00:00Z",
                },
                "contact-info": "a@b.com",
                "report-id": "r1",
                "policies": [
                    {
                        "policy": {
                            "policy-type": "sts",
                            "policy-domain": "example.com",
                            "policy-string": ["v: STSv1"],
                            "mx-host-pattern": ["*.example.com"],
                        },
                        "summary": {
                            "total-successful-session-count": 10,
                            "total-failure-session-count": 1,
                        },
                        "failure-details": [
                            {"result-type": "cert-expired", "failed-session-count": 1}
                        ],
                    }
                ],
            }
        )
        parsed = parsedmarc.parse_smtp_tls_report_json(report_json)
        rows = parsedmarc.parsed_smtp_tls_reports_to_csv_rows(parsed)
        self.assertGreaterEqual(len(rows), 2)
        self.assertEqual(rows[0]["organization_name"], "Org")
        self.assertEqual(rows[0]["policy_domain"], "example.com")

    def testParsedAggregateReportsToCsvRowsList(self):
        """parsed_aggregate_reports_to_csv_rows handles list of reports"""
        result = parsedmarc.parse_report_file(
            "samples/aggregate/rfc9990-sample.xml",
            always_use_local_files=True,
            offline=True,
        )
        report = cast(AggregateReport, result["report"])
        # Pass as a list
        rows = parsedmarc.parsed_aggregate_reports_to_csv_rows([report])
        self.assertGreater(len(rows), 0)
        # Verify non-str/int/bool values are cleaned
        for row in rows:
            for v in row.values():
                self.assertIn(type(v), [str, int, bool])

    def testExceptionHierarchy(self):
        """Exception class hierarchy is correct"""
        self.assertTrue(issubclass(parsedmarc.ParserError, RuntimeError))
        self.assertTrue(
            issubclass(parsedmarc.InvalidDMARCReport, parsedmarc.ParserError)
        )
        self.assertTrue(
            issubclass(parsedmarc.InvalidAggregateReport, parsedmarc.InvalidDMARCReport)
        )
        self.assertTrue(
            issubclass(parsedmarc.InvalidFailureReport, parsedmarc.InvalidDMARCReport)
        )
        self.assertTrue(
            issubclass(parsedmarc.InvalidSMTPTLSReport, parsedmarc.ParserError)
        )
        self.assertIs(parsedmarc.InvalidForensicReport, parsedmarc.InvalidFailureReport)

    def testAggregateReportNormalization(self):
        """Reports spanning >24h get normalized per day"""
        xml = """<?xml version="1.0"?>
        <feedback>
            <report_metadata>
                <org_name>TestOrg</org_name>
                <email>test@example.com</email>
                <report_id>test-norm</report_id>
                <date_range><begin>1704067200</begin><end>1704326400</end></date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>192.0.2.1</source_ip>
                    <count>90</count>
                    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
                </row>
                <identifiers><header_from>example.com</header_from></identifiers>
                <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
            </record>
        </feedback>"""
        # Span is 259200 seconds (3 days), exceeds default 24h threshold
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertTrue(report["report_metadata"]["timespan_requires_normalization"])
        # Records should be split across days
        self.assertGreater(len(report["records"]), 1)
        total = sum(r["count"] for r in report["records"])
        self.assertEqual(total, 90)
        for r in report["records"]:
            self.assertTrue(r["normalized_timespan"])  # type: ignore[typeddict-item]

    def testExtractReportFromFilePathNotFound(self):
        """extract_report_from_file_path raises ParserError for missing file"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report_from_file_path("nonexistent_file.xml")

    def testExtractReportInvalidArchive(self):
        """extract_report raises ParserError for unrecognized binary content"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report(b"\x00\x01\x02\x03\x04\x05\x06\x07")

    def testParseAggregateReportFile(self):
        """parse_aggregate_report_file parses bytes input directly"""
        print()
        sample_path = "samples/aggregate/rfc9990-sample.xml"
        print(f"Testing {sample_path}: ", end="")
        with open(sample_path, "rb") as f:
            data = f.read()
        report = parsedmarc.parse_aggregate_report_file(
            data,
            offline=True,
            always_use_local_files=True,
        )
        self.assertEqual(report["report_metadata"]["org_name"], "Sample Reporter")
        self.assertEqual(report["policy_published"]["domain"], "example.com")
        print("Passed!")

    def testParseAggregateReportFileLeavesCallerStreamOpen(self):
        """A caller-supplied BytesIO passed to parse_aggregate_report_file
        is left open (never closed), both on a successful parse and when
        unrecognized content raises InvalidAggregateReport.

        parse_aggregate_report_file() forwards ``_input`` straight to
        extract_report() (see both functions' docstrings), so it inherits
        extract_report()'s contract of never closing a caller-supplied
        file-like object, on either the success or the exception path.
        This is a regression test for that contract reached through the
        public parse_aggregate_report_file() entry point -- extract_report()
        and parse_report_file() are covered by their own direct tests, but
        neither exercises parse_aggregate_report_file() with a stream, only
        with bytes (see testParseAggregateReportFile above). A real BytesIO
        is used, not a mock, so the assertion is on real observable state
        (``closed``), and because MagicMock auto-implements ``__fspath__``.
        """
        sample_path = "samples/aggregate/rfc9990-sample.xml"
        with open(sample_path, "rb") as f:
            data = f.read()

        success_stream = BytesIO(data)
        report = parsedmarc.parse_aggregate_report_file(
            success_stream, offline=True, always_use_local_files=True
        )
        self.assertEqual(report["report_metadata"]["org_name"], "Sample Reporter")
        self.assertFalse(success_stream.closed)

        garbage_stream = BytesIO(b"this is not a valid report")
        with self.assertRaises(parsedmarc.InvalidAggregateReport):
            parsedmarc.parse_aggregate_report_file(garbage_stream, offline=True)
        self.assertFalse(garbage_stream.closed)

    def testParseInvalidAggregateSample(self):
        """Test invalid aggregate samples are handled"""
        print()
        sample_paths = glob("samples/aggregate_invalid/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print(f"Testing {sample_path}: ", end="")
            with self.subTest(sample=sample_path):
                parsed_report = cast(
                    AggregateReport,
                    parsedmarc.parse_report_file(
                        sample_path, always_use_local_files=True, offline=OFFLINE_MODE
                    )["report"],
                )
                parsedmarc.parsed_aggregate_reports_to_csv(parsed_report)
            print("Passed!")

    def testParseReportFileWithBytes(self):
        """parse_report_file handles bytes input"""
        with open("samples/aggregate/rfc9990-sample.xml", "rb") as f:
            data = f.read()
        result = parsedmarc.parse_report_file(
            data, always_use_local_files=True, offline=True
        )
        self.assertEqual(result["report_type"], "aggregate")

    def testFailureReportCsvRoundtrip(self):
        """Failure report CSV generation works on sample reports"""
        print()
        sample_paths = glob("samples/failure/*.eml")
        for sample_path in sample_paths:
            print(f"Testing CSV for {sample_path}: ", end="")
            with self.subTest(sample=sample_path):
                parsed_report = cast(
                    FailureReport,
                    parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)[
                        "report"
                    ],
                )
                csv_output = parsedmarc.parsed_failure_reports_to_csv(parsed_report)
                self.assertIsNotNone(csv_output)
                self.assertIn(",", csv_output)
                rows = parsedmarc.parsed_failure_reports_to_csv_rows(parsed_report)
                self.assertGreater(len(rows), 0)
            print("Passed!")

    def testFailureReportCsvStripsNulFromFields(self):
        """A NUL character in a failure report text field is stripped from
        CSV output instead of reaching the ``csv`` writer.

        Python 3.10's ``csv`` module raises ``_csv.Error: need to escape,
        but no escapechar set`` on any field containing NUL
        (https://github.com/python/cpython/issues/97503, a 3.10 regression
        fixed in 3.11). This test fails on unfixed code on 3.10 with that
        error, and on unfixed code on 3.11+ because the NUL passes through
        to the CSV text uncleaned."""
        parsed_report = cast(
            FailureReport,
            parsedmarc.parse_report_file(
                "samples/failure/dmarc_ruf_report_linkedin.eml", offline=True
            )["report"],
        )
        parsed_report["parsed_sample"]["subject"] = "re\x00port"
        parsed_report["user_agent"] = "Agent\x00X"

        csv_text = parsedmarc.parsed_failure_reports_to_csv(parsed_report)

        self.assertNotIn("\x00", csv_text)
        reader = csv.DictReader(StringIO(csv_text))
        row = next(reader)
        self.assertEqual(row["subject"], "report")
        self.assertEqual(row["user_agent"], "AgentX")


class TestExtractReport(unittest.TestCase):
    """Tests for parsedmarc.extract_report()"""

    def testExtractReportFromBytes(self):
        """extract_report handles raw XML bytes"""
        xml = b'<?xml version="1.0"?><feedback><report_metadata></report_metadata></feedback>'
        result = parsedmarc.extract_report(xml)
        self.assertIn("<feedback>", result)

    def testExtractReportFromBase64Xml(self):
        """extract_report handles base64-encoded XML string"""
        import base64

        xml = b'<?xml version="1.0"?><feedback></feedback>'
        b64 = base64.b64encode(xml).decode()
        result = parsedmarc.extract_report(b64)
        self.assertIn("<feedback>", result)

    def testExtractReportFromGzip(self):
        """extract_report handles gzip compressed content"""
        import gzip

        xml = b'<?xml version="1.0"?><feedback></feedback>'
        compressed = gzip.compress(xml)
        result = parsedmarc.extract_report(compressed)
        self.assertIn("<feedback>", result)

    def testExtractReportFromPlainJson(self):
        """extract_report passes uncompressed JSON bytes through as text.

        Regression test: MAGIC_JSON was written as b"\\7b", which Python
        reads as the octal escape \\7 (BEL, 0x07) followed by a literal
        "b" -- not 0x7B, the "{" every RFC 8259 JSON object begins with --
        so plain JSON was rejected as "Not a valid zip, gzip, json, or
        xml file". Every in-tree caller pre-guarded with its own zip/gzip
        or "{" check, which masked the dead branch."""
        json_bytes = b'{"organization-name": "Example"}'
        result = parsedmarc.extract_report(json_bytes)
        self.assertEqual(result, '{"organization-name": "Example"}')

    def testExtractReportFromZip(self):
        """extract_report handles zip compressed content"""
        import zipfile

        xml = b'<?xml version="1.0"?><feedback></feedback>'
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("report.xml", xml)
        result = parsedmarc.extract_report(buf.getvalue())
        self.assertIn("<feedback>", result)

    def testExtractReportFromBinaryIO(self):
        """extract_report handles file-like BinaryIO objects"""
        xml = b'<?xml version="1.0"?><feedback></feedback>'
        bio = BytesIO(xml)
        result = parsedmarc.extract_report(bio)
        self.assertIn("<feedback>", result)

    def testExtractReportLeavesSeekableCallerStreamOpen(self):
        """A caller-supplied seekable stream is left open after a
        successful call, and remains usable afterward.

        Before this fix, extract_report's seekable-stream branch set
        file_object = stream (aliasing the caller's own handle) and then
        unconditionally closed file_object in its `finally` block on
        every path, success included -- closing a handle it did not open.
        This asserts the real observable state of a real BytesIO handle
        (``closed`` and a post-seek re-read), not a mock's bookkeeping.
        """
        xml = b'<?xml version="1.0"?><feedback></feedback>'
        bio = BytesIO(xml)

        result = parsedmarc.extract_report(bio)

        self.assertIn("<feedback>", result)
        self.assertFalse(bio.closed)
        bio.seek(0)
        self.assertEqual(bio.read(), xml)

    def testExtractReportLeavesSeekableCallerStreamOpenOnError(self):
        """A caller-supplied seekable stream is left open when
        extract_report raises ParserError, the other half of the "never
        closed on success or failure" claim above.

        Before this fix, extract_report's seekable-stream branch aliased
        file_object to the caller's own stream and its `finally` block
        closed file_object unconditionally -- including on this
        exception path, since content matching no known format still
        reaches the header sniff, `stream.seek(0)`, and the `finally`
        close before raising. Uses a real BytesIO so the assertion is on
        its own observable ``closed`` state, not a mock's bookkeeping.
        """
        bio = BytesIO(b"this is not a valid archive")

        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report(bio)

        self.assertFalse(bio.closed)

    def testExtractReportFromNonSeekableStream(self):
        """extract_report handles non-seekable streams"""
        xml = b'<?xml version="1.0"?><feedback></feedback>'

        class NonSeekable:
            def __init__(self, data):
                self._data = data
                self._pos = 0

            def read(self, n=-1):
                if n == -1:
                    result = self._data[self._pos :]
                    self._pos = len(self._data)
                else:
                    result = self._data[self._pos : self._pos + n]
                    self._pos += n
                return result

            def seekable(self):
                return False

            def close(self):
                pass

        result = parsedmarc.extract_report(cast(BinaryIO, NonSeekable(xml)))
        self.assertIn("<feedback>", result)

    def testExtractReportInvalidContent(self):
        """extract_report raises ParserError for invalid content"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report(b"this is not a valid archive")

    def testExtractReportTextModeRaises(self):
        """extract_report raises ParserError for text-mode streams"""

        class TextStream:
            def read(self, n=-1):
                return "text data"

            def seekable(self):
                return True

            def seek(self, pos):
                pass

            def close(self):
                pass

        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.extract_report(cast(BinaryIO, TextStream()))

    def testExtractReportGzipOverLimitRejected(self):
        """A gzip attachment that inflates past
        MAX_DECOMPRESSED_REPORT_SIZE raises ParserError instead of being
        decompressed.

        Regression test for GHSA-43qf-f35w-2x4r: extract_report inflated
        gzip with a single unbounded zlib.decompress(), so a small
        attachment from any sender a monitored mailbox accepts could
        allocate hundreds of MB. The limit is patched down here so the test
        stays fast; the real 32 MiB cap is the same code path."""
        limit = 4096
        compressed = gzip.compress(b"a" * (limit + 1))
        # The attack is amplification: the wire form is far below the cap.
        self.assertLess(len(compressed), limit)
        with patch("parsedmarc.MAX_DECOMPRESSED_REPORT_SIZE", limit):
            with self.assertRaises(parsedmarc.ParserError) as ctx:
                parsedmarc.extract_report(compressed)
        self.assertIn(
            f"Decompressed report exceeds the {limit} byte limit", str(ctx.exception)
        )

    def testExtractReportGzipAtLimitIsExtracted(self):
        """A gzip attachment inflating to exactly the limit is still
        extracted in full, so the cap rejects only what is over it"""
        limit = 4096
        with patch("parsedmarc.MAX_DECOMPRESSED_REPORT_SIZE", limit):
            result = parsedmarc.extract_report(gzip.compress(b"a" * limit))
        self.assertEqual(result, "a" * limit)

    def testExtractReportZipOverLimitRejected(self):
        """A zip attachment whose member inflates past
        MAX_DECOMPRESSED_REPORT_SIZE raises ParserError.

        Regression test for GHSA-43qf-f35w-2x4r, zip half: the member was
        read with an unbounded .read()."""
        import zipfile

        limit = 4096
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("report.xml", b"a" * (limit + 1))
        compressed = buf.getvalue()
        self.assertLess(len(compressed), limit)
        with patch("parsedmarc.MAX_DECOMPRESSED_REPORT_SIZE", limit):
            with self.assertRaises(parsedmarc.ParserError) as ctx:
                parsedmarc.extract_report(compressed)
        self.assertIn(
            f"Decompressed report exceeds the {limit} byte limit", str(ctx.exception)
        )

    def testExtractReportZipAtLimitIsExtracted(self):
        """A zip member inflating to exactly the limit is still extracted in
        full"""
        import zipfile

        limit = 4096
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("report.xml", b"a" * limit)
        with patch("parsedmarc.MAX_DECOMPRESSED_REPORT_SIZE", limit):
            result = parsedmarc.extract_report(buf.getvalue())
        self.assertEqual(result, "a" * limit)

    def testExtractReportTruncatedGzipRaises(self):
        """A gzip stream cut short still raises ParserError.

        Behavior parity check for the bounded-decompression change: the old
        one-shot zlib.decompress() raised "Error -5 ... incomplete or
        truncated stream" here, while a zlib.decompressobj() stops silently,
        so the replacement has to detect the missing end-of-stream marker
        itself."""
        xml = b'<?xml version="1.0"?><feedback></feedback>'
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.extract_report(gzip.compress(xml)[:-8])
        self.assertIn("truncated", str(ctx.exception))

    def testExtractReportGzipWithTrailingBytesIsExtracted(self):
        """Bytes after the end of the gzip member are ignored, exactly as
        the old one-shot zlib.decompress() ignored them.

        Behavior parity check for the bounded-decompression change: verified
        against the unmodified code, which returned the report text and did
        not raise."""
        xml = b'<?xml version="1.0"?><feedback></feedback>'
        result = parsedmarc.extract_report(gzip.compress(xml) + b"trailing garbage")
        self.assertEqual(result, xml.decode())


class TestMalformedXmlRecovery(unittest.TestCase):
    """Tests for XML recovery in parse_aggregate_report_xml"""

    def testRecoversMalformedXml(self):
        """Malformed XML triggers recovery path and still parses"""
        # XML with a broken tag that xmltodict will reject but lxml can recover
        malformed_xml = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>12345</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>none</p>
  </policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
  <broken_tag
</feedback>"""
        # lxml recovery may succeed or fail depending on how broken the XML is
        # Either way, no unhandled exception should escape
        try:
            report = parsedmarc.parse_aggregate_report_xml(malformed_xml, offline=True)
            self.assertIn("report_metadata", report)
        except parsedmarc.InvalidAggregateReport:
            pass  # Also acceptable

    def testBytesXmlInput(self):
        """XML bytes input is decoded"""
        xml = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>test-bytes-input</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>none</p>
  </policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml.decode(), offline=True)
        self.assertEqual(report["report_metadata"]["report_id"], "test-bytes-input")

    def testExpatErrorRaises(self):
        """Completely invalid XML raises InvalidAggregateReport"""
        with self.assertRaises(parsedmarc.InvalidAggregateReport):
            parsedmarc.parse_aggregate_report_xml("not xml at all {}", offline=True)

    def testMissingOrgName(self):
        """Missing org_name raises InvalidAggregateReport"""
        xml = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <email>dmarc@example.com</email>
    <report_id>missing-org</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>1.2.3.4</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        # The missing-field error chains the underlying KeyError so a library
        # caller can inspect which field was absent.
        self.assertIsInstance(ctx.exception.__cause__, KeyError)

    def testReportMetadataNotAStructureRaises(self):
        """A non-structured report_metadata trips the AttributeError branch"""
        # report_metadata is plain text rather than nested elements, so the
        # parser's attribute access on it fails with AttributeError.
        xml = (
            "<feedback><report_metadata>x</report_metadata>"
            "<policy_published><domain>x.com</domain></policy_published>"
            "<record></record></feedback>"
        )
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIn("missing required section", str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, AttributeError)

    def testXmlSchemaRegexRejectsRepeatedTagsQuickly(self):
        """A report made of repeated ``<xs:schema`` is rejected in linear
        time.

        Regression test for GHSA-4h9r-c435-j834: xml_schema_regex was
        ``</??xs:schema.*>``, whose unanchored greedy ``.*>`` rescanned to the
        end of the line for every ``<xs:schema`` — quadratic, so 1 MB took
        19 s and this 5 MB input would take minutes. The 10 s bound is not
        flaky: the fixed pattern handles it in milliseconds, orders of
        magnitude below both the bound and the old pattern's cost."""
        limit = budget(10)
        start = time.perf_counter()
        with self.assertRaises(parsedmarc.InvalidAggregateReport):
            parsedmarc.parse_aggregate_report_xml(
                "<xs:schema" * 500_000, offline=OFFLINE_MODE
            )
        self.assertLess(time.perf_counter() - start, limit)

    def testMinifiedAggregateReportWithSchemaTag(self):
        """A report minified onto one line still parses when it carries an
        ``<xs:schema>`` tag.

        The old greedy ``</??xs:schema.*>`` (GHSA-4h9r-c435-j834) deleted
        from the schema tag to the last ``>`` on the line, which on a
        single-line document discarded the whole report."""
        path = "samples/aggregate/ikea.com!example.de!1538690400!1538776800.xml"
        with open(path, encoding="utf-8") as f:
            original = f.read()
        minified = "".join(line.strip() for line in original.splitlines())
        self.assertIn("<xs:schema", minified)
        self.assertNotIn("\n", minified)
        expected = parsedmarc.parse_aggregate_report_xml(
            original, always_use_local_files=True, offline=OFFLINE_MODE
        )
        report = parsedmarc.parse_aggregate_report_xml(
            minified, always_use_local_files=True, offline=OFFLINE_MODE
        )
        self.assertEqual(
            report["report_metadata"]["org_name"],
            expected["report_metadata"]["org_name"],
        )
        self.assertEqual(
            report["report_metadata"]["report_id"],
            expected["report_metadata"]["report_id"],
        )
        self.assertEqual(len(report["records"]), len(expected["records"]))
        self.assertGreater(len(report["records"]), 0)

    DOCTYPE_SAMPLE = "samples/aggregate/!example.com!1538204542!1538463818.xml"

    def _sample_with_doctype(self, doctype, declaration=None):
        """The sample report with ``doctype`` inserted right after its XML
        declaration, which is replaced by ``declaration`` when given"""
        with open(self.DOCTYPE_SAMPLE, encoding="utf-8") as f:
            original = f.read()
        self.assertTrue(original.startswith("<?xml"))
        header, body = original.split("?>", 1)
        return (declaration or header + "?>") + doctype + body

    def testDoctypeIsRejected(self):
        """An aggregate report carrying any DOCTYPE is rejected.

        Regression test for GHSA-m47j-wp78-fqjg: an internal DTD subset can
        declare default attributes that expat applies to every matching
        element, so the parser used to accept, and expand, this report.
        Real aggregate reports never carry a DOCTYPE."""
        # The sample parses without the DOCTYPE, so only it is rejected.
        parsedmarc.parse_aggregate_report_xml(
            self._sample_with_doctype(""), offline=OFFLINE_MODE
        )
        for doctype in (
            '<!DOCTYPE feedback [<!ATTLIST record a CDATA "x">]>',
            "<!DOCTYPE feedback>",
        ):
            with self.subTest(doctype=doctype):
                with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
                    parsedmarc.parse_aggregate_report_xml(
                        self._sample_with_doctype(doctype), offline=OFFLINE_MODE
                    )
                self.assertIn("DOCTYPE", str(ctx.exception))

    def testDoctypeIsRejectedOnTheRecoveryPath(self):
        """A DOCTYPE behind a malformed XML declaration is rejected too.

        The malformed declaration makes the first parse fail before expat
        reaches the DOCTYPE, so the document goes through the lxml recovery
        path, which must apply the same check (GHSA-m47j-wp78-fqjg)."""
        declaration = '<?xml version="1.0" foo?>'
        # Without a DOCTYPE, the recovery path parses the report.
        report = parsedmarc.parse_aggregate_report_xml(
            self._sample_with_doctype("", declaration=declaration),
            offline=OFFLINE_MODE,
        )
        self.assertTrue(
            any(
                e.startswith("Invalid XML") for e in report["report_metadata"]["errors"]
            )
        )
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(
                self._sample_with_doctype(
                    '<!DOCTYPE feedback [<!ATTLIST record a CDATA "x">]>',
                    declaration=declaration,
                ),
                offline=OFFLINE_MODE,
            )
        self.assertIn("DOCTYPE", str(ctx.exception))

    def testEmptyDocumentIsInvalid(self):
        """A document lxml cannot recover anything from (it raises "Document
        is empty") is still reported as an InvalidAggregateReport."""
        with self.assertRaises(parsedmarc.InvalidAggregateReport):
            parsedmarc.parse_aggregate_report_xml("", offline=OFFLINE_MODE)

    def testAttlistDefaultAttributeAmplificationIsRejectedQuickly(self):
        """The advisory's default-attribute amplification document is
        rejected before expat expands it.

        Regression test for GHSA-m47j-wp78-fqjg: ``<!ATTLIST z>`` declaring
        1,000 default attributes, followed by 10,000 ``<z/>`` elements (64 KB
        of XML), made xmltodict build 10 million dict entries. Measured
        locally, the old code took 4.0 s and 1.4 GB RSS on this input; the
        reporter measured 29 s and 1.4 GB from a 3.8 KB gzip email. The fixed
        code rejects it in about 0.1 ms, so the 1 s bound is not flaky."""
        attributes = " ".join(f'a{i} CDATA "vvvvvvvvvv"' for i in range(1000))
        xml = (
            f"<!DOCTYPE feedback [<!ATTLIST z {attributes}>]>"
            f"<feedback><record>{'<z/>' * 10_000}</record></feedback>"
        )
        limit = budget(1)
        start = time.perf_counter()
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=OFFLINE_MODE)
        self.assertLess(time.perf_counter() - start, limit)
        self.assertIn("DOCTYPE", str(ctx.exception))


class TestPolicyPublishedEdgeCases(unittest.TestCase):
    """Tests for edge cases in policy_published parsing"""

    VALID_XML_TEMPLATE = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>test-{tag}</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
    {extra_metadata}
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>reject</p>
    {policy_extra}
  </policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""

    def _parse(self, tag="default", policy_extra="", extra_metadata=""):
        xml = self.VALID_XML_TEMPLATE.format(
            tag=tag, policy_extra=policy_extra, extra_metadata=extra_metadata
        )
        return parsedmarc.parse_aggregate_report_xml(xml, offline=True)

    def testPolicyPublishedListHandled(self):
        """policy_published as a list uses first element"""
        # The code checks `if type(policy_published) is list`
        # This is tested implicitly when xmltodict returns a list;
        # we test via the np field presence
        report = self._parse(tag="np", policy_extra="<np>quarantine</np>")
        self.assertEqual(report["policy_published"]["np"], "quarantine")

    def testNpFieldValues(self):
        """np field is parsed correctly"""
        for val in ["none", "quarantine", "reject"]:
            report = self._parse(tag=f"np-{val}", policy_extra=f"<np>{val}</np>")
            self.assertEqual(report["policy_published"]["np"], val)

    def testTestingField(self):
        """testing field is parsed correctly"""
        for val in ["y", "n"]:
            report = self._parse(
                tag=f"testing-{val}", policy_extra=f"<testing>{val}</testing>"
            )
            self.assertEqual(report["policy_published"]["testing"], val)

    def testDiscoveryMethodField(self):
        """discovery_method field is parsed correctly"""
        for val in ["psl", "treewalk"]:
            report = self._parse(
                tag=f"disc-{val}",
                policy_extra=f"<discovery_method>{val}</discovery_method>",
            )
            self.assertEqual(report["policy_published"]["discovery_method"], val)

    def testGeneratorField(self):
        """generator field in report_metadata is parsed"""
        report = self._parse(
            tag="gen", extra_metadata="<generator>TestGen/1.0</generator>"
        )
        self.assertEqual(report["report_metadata"]["generator"], "TestGen/1.0")

    def testPctFieldNone(self):
        """pct defaults to None when absent (removed in RFC 9989)"""
        report = self._parse(tag="no-pct")
        self.assertIsNone(report["policy_published"]["pct"])

    def testFoFieldNone(self):
        """fo defaults to None when absent (RFC 9990 keeps it optional)"""
        report = self._parse(tag="no-fo")
        self.assertIsNone(report["policy_published"]["fo"])

    def testReportMetadataErrors(self):
        """Report metadata errors are captured"""
        report = self._parse(
            tag="errors",
            extra_metadata="<error>DNS timeout</error>",
        )
        self.assertIn("DNS timeout", report["report_metadata"]["errors"])

    def testReportMetadataErrorsList(self):
        """Report metadata errors as list are captured"""
        report = self._parse(
            tag="errors-list",
            extra_metadata="<error>error1</error><error>error2</error>",
        )
        self.assertIn("error1", report["report_metadata"]["errors"])
        self.assertIn("error2", report["report_metadata"]["errors"])

    def testRecordParseFailureSkipped(self):
        """Bad records are skipped with a warning, not crashing"""
        xml = """<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>bad-records</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>bad-ip</source_ip><count>not-a-number</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        # At least the valid record should be parsed
        self.assertGreaterEqual(len(report["records"]), 1)


class TestParseReportFile(unittest.TestCase):
    """Tests for parse_report_file with various input types"""

    def testParseReportFileFromBytes(self):
        """parse_report_file works with bytes input"""
        xml_path = "samples/aggregate/!example.com!1538204542!1538463818.xml"
        with open(xml_path, "rb") as f:
            content = f.read()
        result = parsedmarc.parse_report_file(content, offline=True)
        self.assertEqual(result["report_type"], "aggregate")

    def testParseReportFileFromBinaryIO(self):
        """parse_report_file works with BinaryIO input"""
        xml_path = "samples/aggregate/!example.com!1538204542!1538463818.xml"
        with open(xml_path, "rb") as f:
            result = parsedmarc.parse_report_file(f, offline=True)
        self.assertEqual(result["report_type"], "aggregate")

    def testParseReportFileFromPathlib(self):
        """parse_report_file works with pathlib.Path input"""
        xml_path = Path("samples/aggregate/!example.com!1538204542!1538463818.xml")
        result = parsedmarc.parse_report_file(xml_path, offline=True)
        self.assertEqual(result["report_type"], "aggregate")

    def testParseReportFileSmtpTls(self):
        """parse_report_file detects SMTP TLS reports"""
        result = parsedmarc.parse_report_file(
            "samples/smtp_tls/smtp_tls.json", offline=True
        )
        self.assertEqual(result["report_type"], "smtp_tls")

    def testParseReportFileEmail(self):
        """parse_report_file detects failure reports in email format"""
        eml_path = "samples/failure/dmarc_ruf_report_linkedin.eml"
        result = parsedmarc.parse_report_file(eml_path, offline=True)
        self.assertEqual(result["report_type"], "failure")

    def testParseReportFileInvalid(self):
        """parse_report_file raises ParserError for invalid content"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_file(b"this is not a report", offline=True)

    def testParseReportFileInvalidAggregateReason(self):
        """Malformed aggregate XML explains the aggregate-specific reason"""
        xml = (
            b'<?xml version="1.0"?>\n<feedback>\n'
            b"<report_metadata><email>dmarc@example.com</email>"
            b"<report_id>no-org</report_id></report_metadata>\n"
            b"<policy_published><domain>example.com</domain><p>none</p>"
            b"</policy_published>\n</feedback>"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(xml, offline=True)
        message = str(ctx.exception)
        # The reason must name the aggregate format and the missing field,
        # not collapse to a bare "Not a valid report".
        self.assertIn("aggregate", message.lower())
        self.assertIn("org_name", message)
        self.assertNotIn("Not a valid report", message)

    def testParseReportFileInvalidSmtpTlsReason(self):
        """Malformed SMTP TLS JSON explains the SMTP-TLS-specific reason"""
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b'{"organization-name": "x"}', offline=True)
        message = str(ctx.exception)
        self.assertIn("SMTP TLS", message)
        self.assertIn("date-range", message)

    def testParseReportFileInvalidFailureReason(self):
        """A malformed failure report (email path) explains the reason"""
        # A real DMARC failure report arrives as a multipart/report email;
        # parse_report_file reaches it only via the email branch. Omit the
        # required Source-IP so parse_failure_report rejects it.
        eml = (
            b"From: dmarc-noreply@example.com\n"
            b"Subject: DMARC Failure Report\n"
            b"MIME-Version: 1.0\n"
            b"Content-Type: multipart/report; "
            b'report-type=feedback-report; boundary="b"\n\n'
            b"--b\n"
            b"Content-Type: text/plain\n\n"
            b"This is a DMARC failure report.\n"
            b"--b\n"
            b"Content-Type: message/feedback-report\n\n"
            b"Feedback-Type: auth-failure\n"
            b"Version: 1\n"
            b"--b\n"
            b"Content-Type: message/rfc822\n\n"
            b"From: spoof@victim.example\n"
            b"Subject: hi\n"
            b"--b--\n"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(eml, offline=True)
        message = str(ctx.exception)
        # The reason must name the failure format and the missing field,
        # not collapse to a bare "Not a valid report".
        self.assertIn("failure", message.lower())
        self.assertIn("source_ip", message)
        self.assertNotIn("Not a valid report", message)

    def testParseReportFileUnrecognizedGzip(self):
        """Gzipped junk decompresses to a str that matches no format.

        Exercises the str branch of the content sniff (the decompressed
        payload is a str, not bytes).
        """
        blob = gzip.compress(b"plain junk not a report")
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(blob, offline=True)
        self.assertIn("recognized report format", str(ctx.exception))

    def testParseReportFileUnrecognizedFormat(self):
        """Content matching no known format says so explicitly"""
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b"this is not a report", offline=True)
        self.assertIn("recognized report format", str(ctx.exception))

    def testParseReportFileRejectsOversizedXmlWithoutTheEmailParser(self):
        """A file the size cap rejects was handed whole to the email parser,
        which has no size cap: 200 MiB of <x/> reached +2,801 MiB in 4.6 s.
        Content that sniffs as XML or JSON, or is over the cap, is not tried
        as an email."""
        content = b"<feedback>" + b"<x/>" * (10 * 2**20) + b"</feedback>"
        limit = budget(2.0)
        tracemalloc.start()
        try:
            start = time.perf_counter()
            with patch("parsedmarc.parse_report_email") as email_parser:
                with self.assertRaises(parsedmarc.ParserError) as ctx:
                    parsedmarc.parse_report_file(content, offline=True)
            elapsed = time.perf_counter() - start
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        email_parser.assert_not_called()
        self.assertIn("exceeds the 33554432 byte limit", str(ctx.exception))
        self.assertLess(elapsed, limit)
        self.assertLess(peak, 100 * 2**20)

    def testParseReportFileCapsTextForTheEmailParser(self):
        """Text over the size cap that does not look like XML or JSON is not
        handed to the email parser either."""
        content = b"From: a@example.com\n\n" + b"x" * (
            parsedmarc.MAX_DECOMPRESSED_REPORT_SIZE + 1
        )
        with patch("parsedmarc.parse_report_email") as email_parser:
            with self.assertRaises(parsedmarc.ParserError) as ctx:
                parsedmarc.parse_report_file(content, offline=True)
        email_parser.assert_not_called()
        self.assertEqual(
            str(ctx.exception), "Invalid report email: the report is larger than 32 MiB"
        )

    def testParseReportFileSkipsParsersThatCannotMatch(self):
        """Content that begins with "<" is not tried as JSON or as an email,
        and content that begins with "{" is not tried as an email, however
        small."""
        with (
            patch("parsedmarc.parse_smtp_tls_report_json") as smtp_tls_parser,
            patch("parsedmarc.parse_report_email") as email_parser,
            self.assertRaises(parsedmarc.ParserError),
        ):
            parsedmarc.parse_report_file(b"<feedback></feedback>", offline=True)
        smtp_tls_parser.assert_not_called()
        email_parser.assert_not_called()
        with (
            patch("parsedmarc.parse_report_email") as email_parser,
            self.assertRaises(parsedmarc.ParserError) as ctx,
        ):
            parsedmarc.parse_report_file(b'{"a": 1}', offline=True)
        email_parser.assert_not_called()
        self.assertIsInstance(ctx.exception.__cause__, parsedmarc.InvalidSMTPTLSReport)

    def testParseReportFileReleasesEachFailedParse(self):
        """parse_report_file() kept the aggregate parser's exception, and its
        traceback's frames holding the parsed tree, while it tried the other
        formats: a 31 MiB file at the cap cost +1,046 MiB there
        against +399 MiB parsing the XML directly."""

        class _Tree(dict):
            pass

        trees: list[weakref.ref] = []
        alive_at_report: list[bool] = []
        original_parse = parsedmarc._parse_limited_xml
        original_describe = parsedmarc._describe_parse_failure

        def parse(xml):
            parsed = original_parse(xml)
            tree = _Tree(parsed["feedback"] or {})
            trees.append(weakref.ref(tree))
            parsed["feedback"] = tree
            return parsed

        def describe(*args):
            gc.collect()
            alive_at_report.append(any(ref() is not None for ref in trees))
            return original_describe(*args)

        with (
            patch.object(parsedmarc, "_parse_limited_xml", parse),
            patch.object(parsedmarc, "_describe_parse_failure", describe),
            self.assertRaises(parsedmarc.ParserError),
        ):
            parsedmarc.parse_report_file(b"<feedback><x>1</x></feedback>", offline=True)
        self.assertTrue(trees)
        self.assertEqual(alive_at_report, [False])

    def testParseReportFilePreservesCause(self):
        """The raised ParserError chains the underlying parse failure"""
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b"<feedback></feedback>", offline=True)
        # raise ... from email_error must populate __cause__ for callers and
        # tracebacks, even though the cross-format message is content-sniffed.
        self.assertIsNotNone(ctx.exception.__cause__)

    def _parse_unexpected_error(self):
        # <feedback></feedback> parses as XML but trips a NoneType subscript
        # deep in the aggregate parser, hitting the catch-all "Unexpected
        # error" branch (not a narrow KeyError/ExpatError).
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_file(b"<feedback></feedback>", offline=True)
        return str(ctx.exception)

    def testUnexpectedErrorOmitsOriginWhenNotDebug(self):
        """Catch-all errors stay clean when the logger is above DEBUG"""
        logger = logging.getLogger("parsedmarc.log")
        previous = logger.level
        logger.setLevel(logging.WARNING)
        try:
            message = self._parse_unexpected_error()
        finally:
            logger.setLevel(previous)
        self.assertIn("Unexpected error", message)
        self.assertNotIn("raised at", message)

    def testUnexpectedErrorCitesOriginInDebug(self):
        """Catch-all errors cite the source file:line when the logger is DEBUG"""
        logger = logging.getLogger("parsedmarc.log")
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            message = self._parse_unexpected_error()
        finally:
            logger.setLevel(previous)
        self.assertIn("raised at", message)
        self.assertIn("__init__.py:", message)

    def testExcOriginEmptyWhenNoTraceback(self):
        """_exc_origin returns '' for an exception with no traceback"""
        logger = logging.getLogger("parsedmarc.log")
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            # A never-raised exception has __traceback__ is None, so there is
            # no origin frame to cite even though debug logging is on.
            self.assertEqual(parsedmarc._exc_origin(ValueError("x")), "")
        finally:
            logger.setLevel(previous)

    def testParseReportFileClosesHandleOnReadError(self):
        """A file opened internally by parse_report_file is closed even
        when reading it raises (the pattern CodeQL's py/file-not-closed
        query flags, found in a local code-quality scan).

        parse_report_file's path branch does `open(file_path, "rb")` and
        then `.read()`; before the fix, `.close()` sat on the line after
        `.read()` with no try/finally (and no `with`), so a read()-time
        exception skipped close() and leaked the descriptor. Patch
        builtins.open (the SDK boundary) to return a handle whose read()
        raises, and assert the handle was still closed. The fake handle
        implements the context-manager protocol itself (mirroring a real
        file object's __exit__ calling close()), rather than relying on
        MagicMock's default __enter__/__exit__, which would return a
        different mock object from __enter__ and never call close().
        """

        class _RaisingHandle:
            def __init__(self):
                self.closed = False

            def read(self):
                raise OSError("boom")

            def close(self):
                self.closed = True

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        fake_handle = _RaisingHandle()

        with patch("builtins.open", return_value=fake_handle) as mock_open:
            with self.assertRaises(OSError):
                parsedmarc.parse_report_file("some/path.xml", offline=True)

        mock_open.assert_called_once_with("some/path.xml", "rb")
        self.assertTrue(fake_handle.closed)

    def testParseReportFileLeavesCallerHandleOpenOnReadError(self):
        """A caller-supplied file-like object is left open (not closed)
        when reading it raises.

        Only a path input (opened internally by parse_report_file) is
        closed on the exception path; a handle the caller passed in is
        never closed by parse_report_file, on success or failure -- the
        caller may want to seek(0) and retry, log tell(), or reuse the
        handle otherwise.

        A plain class is used instead of MagicMock because MagicMock
        auto-implements ``__fspath__`` (supported since Python 3.8's
        unittest.mock), which would make ``isinstance(fake, os.PathLike)``
        true and route the object through the path branch instead of the
        caller-supplied-object branch this test targets.
        """

        class _RaisingCallerHandle:
            def __init__(self):
                self.close_called = False

            def read(self):
                raise OSError("boom")

            def close(self):
                self.close_called = True

        fake_handle = _RaisingCallerHandle()

        with self.assertRaises(OSError):
            parsedmarc.parse_report_file(cast(BinaryIO, fake_handle), offline=True)

        self.assertFalse(fake_handle.close_called)

    def testParseReportFileLeavesCallerHandleOpenOnSuccess(self):
        """A caller-supplied file-like object is left open after a
        successful parse, and remains usable afterward.

        Before this fix, parse_report_file called .close() on any
        caller-supplied file object once it had been read, on the success
        path only. A function must not close a handle it did not open --
        the caller may still want to seek(0) and re-read it, inspect
        tell(), or otherwise reuse it. This asserts the real observable
        state of a real BytesIO handle (``closed`` and post-seek
        ``read()``), not a mock's call-tracking.
        """
        xml_path = "samples/aggregate/!example.com!1538204542!1538463818.xml"
        with open(xml_path, "rb") as f:
            data = f.read()
        handle = BytesIO(data)

        result = parsedmarc.parse_report_file(handle, offline=True)

        self.assertEqual(result["report_type"], "aggregate")
        self.assertFalse(handle.closed)
        handle.seek(0)
        self.assertEqual(handle.read(), data)


class TestParseReportEmail(unittest.TestCase):
    """Tests for parse_report_email edge cases"""

    def testSmtpTlsEmailReport(self):
        """parse_report_email handles SMTP TLS reports in email format"""
        eml_path = "samples/smtp_tls/google.com_smtp_tls_report.eml"
        with open(eml_path, "rb") as f:
            content = f.read()
        result = parsedmarc.parse_report_email(content, offline=True)
        self.assertEqual(result["report_type"], "smtp_tls")

    def testInvalidEmailRaisesError(self):
        """parse_report_email raises error for non-DMARC email"""
        email_str = """From: test@example.com
Subject: Hello World
Content-Type: text/plain

This is not a DMARC report."""
        with self.assertRaises(parsedmarc.InvalidDMARCReport):
            parsedmarc.parse_report_email(email_str, offline=True)

    def testSubjectControlCharactersEscapedInErrorMessage(self):
        """An RFC 2047 subject that decodes to CR LF is escaped in the
        error message, so a sender cannot forge extra log lines (the
        mailbox loops log this message at WARNING)."""
        email_str = (
            "From: test@example.com\n"
            "Subject: =?utf-8?q?line1=0D=0AINJECTED=20fake=20log?=\n"
            "Content-Type: text/plain\n\nNot a report."
        )
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
            parsedmarc.parse_report_email(email_str, offline=True)
        message = str(ctx.exception)
        self.assertIn("line1\\r\\nINJECTED fake log", message)
        self.assertNotIn("\r", message)
        self.assertNotIn("\n", message)

    def testSmtpTlsPolicyTypeControlCharactersEscapedInError(self):
        """A sender-supplied ``policy-type`` containing CR LF is escaped in
        the ``Invalid policy type`` error, which the mailbox loops log."""
        report = json.dumps(
            {
                "organization-name": "Example",
                "date-range": {
                    "start-datetime": "2016-04-01T00:00:00Z",
                    "end-datetime": "2016-04-01T23:59:59Z",
                },
                "contact-info": "tls@example.com",
                "report-id": "r-1",
                "policies": [
                    {
                        "policy": {
                            "policy-type": "sts\r\nWARNING:cli.py:1:INJECTED",
                            "policy-domain": "example.com",
                        },
                        "summary": {
                            "total-successful-session-count": 1,
                            "total-failure-session-count": 0,
                        },
                    }
                ],
            }
        )
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(report)
        message = str(ctx.exception)
        self.assertIn("sts\\r\\nWARNING:cli.py:1:INJECTED", message)
        self.assertNotIn("\r", message)
        self.assertNotIn("\n", message)

    def testFromHeaderControlCharactersEscapedInInfoLog(self):
        """The ``Parsing mail from`` info line escapes control characters
        in the From header.

        The control character is a raw ESC in the display name rather than
        an RFC 2047 encoded word: mail-parser 4.6.2 decodes encoded words
        in ``From`` but 4.8.0 (what CI resolves) leaves them encoded, while
        both keep a raw control character, so the test observes the
        escaping regardless of which mail-parser is installed."""
        email_str = (
            'From: "a\x1bFORGED" <test@example.com>\n'
            "Subject: Hello\n"
            "Content-Type: text/plain\n\nNot a report."
        )
        with self.assertLogs("parsedmarc.log", level="INFO") as logs:
            with self.assertRaises(parsedmarc.InvalidDMARCReport):
                parsedmarc.parse_report_email(email_str, offline=True)
        line = next(m for m in logs.output if "Parsing mail from" in m)
        self.assertIn("\\x1bFORGED", line)
        self.assertNotIn("\x1b", line)
        self.assertEqual(len(line.splitlines()), 1)

    def testUnparseableDateRaisesParserError(self):
        """An unparseable Date header trips the initial mail-parse catch-all"""
        # human_timestamp_to_datetime() raises on a junk Date, which the
        # catch-all around the initial parse turns into a ParserError.
        email_str = "From: a@b.c\nDate: not-a-real-date\nSubject: x\n\nbody"
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_email(email_str, offline=True)
        self.assertIn("not-a-real-date", str(ctx.exception))

    def testOverlongDateHeaderIsInvalidDMARCReport(self):
        """A Date header too long to be a date is an InvalidDMARCReport
        naming the header, where it was a bare ParserError"""
        email_str = "From: a@b.c\nDate: " + "1" * 200 + "\nSubject: x\n\nbody"
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
            parsedmarc.parse_report_email(email_str, offline=True)
        self.assertIn("Date header", str(ctx.exception))

    def testFailureTextReportParses(self):
        """A valid legacy text/plain failure report parses to a failure
        report (the success path that builds the synthetic feedback report
        and extracts the message sample)"""
        # The field-name regex matches letters and spaces only, so the legacy
        # fields are space-separated ("Received Date", "Sender IP Address").
        eml = (
            "From: report@example.com\nSubject: Failure Report\n"
            "Content-Type: text/plain\n\n"
            "A message claiming to be from you has failed authentication.\n"
            "Received Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
            "Sender IP Address: 192.0.2.1\n"
            "detected.\n"
            "From: spoof@example.com\nTo: victim@example.com\nSubject: spam\n"
        )
        result = parsedmarc.parse_report_email(eml, offline=True)
        self.assertEqual(result["report_type"], "failure")
        report = cast(FailureReport, result["report"])
        self.assertEqual(report["source"]["ip_address"], "192.0.2.1")

    def testFailureTextMissingFieldsRaises(self):
        """A text/plain failure report missing its fields is rejected with
        the subject named (not silently dropped)"""
        # Has the trigger phrase and "detected." but none of the
        # Received-Date / Sender-IP-Address fields, so building the synthetic
        # feedback report raises KeyError, surfaced as InvalidDMARCReport.
        eml = (
            "From: a@b.c\nSubject: Failure\nContent-Type: text/plain\n\n"
            "A message claiming to be from you has failed. "
            "No fields here detected. nothing\n"
        )
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
            parsedmarc.parse_report_email(eml, offline=True)
        self.assertIn("Failure", str(ctx.exception))

    def testAttachmentMalformedXmlRaises(self):
        """A base64 attachment of malformed aggregate XML is rejected"""
        att = base64.b64encode(b"<feedback></feedback>").decode()
        eml = (
            "From: a@b.c\nSubject: Agg\nMIME-Version: 1.0\n"
            "Content-Type: application/octet-stream\n"
            "Content-Transfer-Encoding: base64\n\n" + att + "\n"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_email(eml, offline=True)
        self.assertIn("not a valid DMARC report", str(ctx.exception))

    def testAttachmentInvalidJsonRaises(self):
        """A base64 attachment of invalid SMTP TLS JSON is rejected.

        parse_smtp_tls_report_json raises InvalidSMTPTLSReport, a sibling of
        InvalidDMARCReport, so it falls through to the generic catch-all and
        becomes a ParserError naming the subject.
        """
        att = base64.b64encode(b"{not valid json").decode()
        eml = (
            "From: a@b.c\nSubject: Tls\nMIME-Version: 1.0\n"
            "Content-Type: application/octet-stream\n"
            "Content-Transfer-Encoding: base64\n\n" + att + "\n"
        )
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_email(eml, offline=True)
        self.assertIn("Tls", str(ctx.exception))

    def testTextReportRegexRejectsWhitespacePaddingQuickly(self):
        """A plain-text failure notice padded with whitespace is rejected in
        linear time.

        Regression test for GHSA-7grx-mj6g-qxmc: text_report_regex was
        ``\\s*([a-zA-Z\\s]+):\\s(.+)``, whose overlapping, unanchored
        whitespace quantifiers backtracked cubically — 1600 spaces took
        3.3 s, about 8x per doubling, so this 6,400-space body takes about
        210 s: far over the bound, but short enough that a regression fails
        instead of hanging the CI job. The 10 s bound is not flaky:
        the fixed pattern parses it in milliseconds, orders of magnitude
        below both the bound and the old pattern's cost."""
        padding = " " * 6_400
        body = "\n".join(padding[i : i + 70] for i in range(0, len(padding), 70))
        msg = (
            "From: mailer-daemon@example.com\n"
            "To: dmarc@example.com\n"
            "Subject: Failure notice\n"
            "Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
            "Content-Type: text/plain\n\n"
            "A message claiming to be from you has failed\n" + body + "\ndetected."
        )
        limit = budget(10)
        start = time.perf_counter()
        # The required received-date field is missing, so the notice is
        # rejected rather than parsed.
        with self.assertRaises(parsedmarc.InvalidDMARCReport):
            parsedmarc.parse_report_email(msg, offline=OFFLINE_MODE)
        self.assertLess(time.perf_counter() - start, limit)

    def testTextReportFieldNamesMustBeSingleLine(self):
        """text_report_regex matches Exim's one-line ``Name: value`` fields:
        a field name cannot span a line break, leading indentation is
        allowed, and a CRLF line ending is not kept in the value
        (GHSA-7grx-mj6g-qxmc)."""
        matches = parsedmarc.text_report_regex.findall("Sender\nDomain: x")
        self.assertFalse(any("\n" in name for name, _ in matches))
        self.assertEqual(
            parsedmarc.text_report_regex.findall("  Sender IP Address: 1.2.3.4\n"),
            [("Sender IP Address", "1.2.3.4")],
        )
        self.assertEqual(
            parsedmarc.text_report_regex.findall(
                "Received Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
            ),
            [("Received Date", "Mon, 01 Jan 2024 00:00:00 +0000")],
        )

    def testUnserializableSubMessageRaisesParserError(self):
        """A ``message/rfc822`` part whose header holds a control character
        raises ``ParserError``, not ``email.errors.HeaderWriteError``.

        Regression test for GHSA-qxwv-2vwj-v828: re-serializing the part
        raised ``HeaderWriteError``, which escaped the mailbox loop's
        ``except ParserError`` and aborted the whole batch on every run.
        (A Python without the header-injection check instead parses the
        message as an invalid failure report, which is also a
        ``ParserError``.)"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_email(POISON_HEADER_EMAIL, offline=True)

    def testDeeplyNestedMultipartRaisesParserError(self):
        """Multiparts nested past the recursion limit raise ``ParserError``,
        not ``RecursionError`` (GHSA-qxwv-2vwj-v828); a shallow nesting is
        walked without error and rejected as not a report, as before."""
        # The message guard rejects this many multiparts before parsing
        # (GHSA-qcc2-4x3v-v4g7); switch it off to reach the recursion guard
        # behind it.
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
            parsedmarc.parse_report_email(
                _nested_multipart_email(POISON_NESTING_LEVELS), offline=True
            )
        self.assertIn("max_depth (100)", str(ctx.exception))

        with patch("parsedmarc.check_message_limits"):
            # Multiparts are walked, never serialized, so the nesting alone
            # no longer reaches the recursion limit (GHSA-qcc2-4x3v-v4g7).
            with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
                parsedmarc.parse_report_email(
                    _nested_multipart_email(POISON_NESTING_LEVELS), offline=True
                )
            self.assertIn("is not a valid report", str(ctx.exception))
            # A failure report's sample is serialized, so the same nesting as
            # its sample still reaches the recursion guard.
            sample = _nested_multipart_email(POISON_NESTING_LEVELS).decode()
            report = (
                "Subject: s\nContent-Type: multipart/report; boundary=r\n\n"
                "--r\nContent-Type: message/feedback-report\n\n"
                "Feedback-Type: auth-failure\n\n"
                f"--r\nContent-Type: message/rfc822\n\n{sample}--r--\n"
            )
            with self.assertRaises(parsedmarc.ParserError) as ctx:
                parsedmarc.parse_report_email(report, offline=True)
        self.assertIn("recursion", str(ctx.exception))

        with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
            parsedmarc.parse_report_email(
                _nested_multipart_email(SHALLOW_NESTING_LEVELS), offline=True
            )
        self.assertIn("is not a valid report", str(ctx.exception))

    @staticmethod
    def _email_with_attachment(payload: bytes, subtype: str) -> str:
        from email.mime.application import MIMEApplication

        msg = MIMEMultipart()
        msg["From"] = "reports@example.com"
        msg["Subject"] = "Report"
        msg["Date"] = "Mon, 01 Jan 2024 00:00:00 +0000"
        # MIMEApplication base64-encodes the payload.
        msg.attach(MIMEApplication(payload, subtype))
        return msg.as_string()

    def testBase64SmtpTlsJsonPart(self):
        """An ``application/tlsrpt+json`` part sent base64-encoded is decoded
        and parsed as an SMTP TLS report"""
        with open("samples/smtp_tls/rfc8460.json", "rb") as f:
            payload = f.read()
        result = parsedmarc.parse_report_email(
            self._email_with_attachment(payload, "tlsrpt+json"), offline=True
        )
        self.assertEqual(result["report_type"], "smtp_tls")

    def testSmtpTlsJsonInGenericAttachment(self):
        """A JSON report in an attachment of any other type is recognized by
        its leading ``{`` and parsed as an SMTP TLS report"""
        with open("samples/smtp_tls/rfc8460.json", "rb") as f:
            payload = f.read()
        result = parsedmarc.parse_report_email(
            self._email_with_attachment(payload, "octet-stream"), offline=True
        )
        self.assertEqual(result["report_type"], "smtp_tls")

    def testNonBase64AttachmentIsSkipped(self):
        """An attachment whose body is not base64 is not a report attachment:
        it is skipped rather than treated as a parse failure, so a message
        with nothing else in it is simply not a valid report"""
        eml = (
            "From: reports@example.com\n"
            "Subject: Report\n"
            "Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
            "Content-Type: application/octet-stream\n\n"
            # Three base64 characters: b64decode() raises "Incorrect padding".
            "abc\n"
        )
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as ctx:
            parsedmarc.parse_report_email(eml, offline=True)
        self.assertEqual(
            str(ctx.exception), 'Message with subject "Report" is not a valid report'
        )

    def testInvalidAggregateAttachmentRaisesParserError(self):
        """An XML attachment that is not a valid aggregate report raises a
        ParserError naming the message"""
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.parse_report_email(
                self._email_with_attachment(b"<feedback></feedback>", "xml"),
                offline=True,
            )
        self.assertIn(
            'Message with subject "Report" is not a valid DMARC report',
            str(ctx.exception),
        )


class TestFailureReportParsing(unittest.TestCase):
    """Tests for failure report field defaults and edge cases"""

    def _make_feedback_report(self, **overrides):
        """Create a minimal feedback report string"""
        fields = {
            "Feedback-Type": "auth-failure",
            "User-Agent": "test/1.0",
            "Version": "1",
            "Original-Mail-From": "sender@example.com",
            "Arrival-Date": "Thu, 1 Jan 2024 00:00:00 +0000",
            "Source-IP": "203.0.113.1",
            "Reported-Domain": "example.com",
            "Auth-Failure": "dmarc",
        }
        fields.update(overrides)
        return "\n".join(f"{k}: {v}" for k, v in fields.items())

    def _make_sample(self):
        return """From: sender@example.com
To: recipient@example.com
Subject: Test
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test body"""

    def _default_msg_date(self):
        return datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def testMissingVersion(self):
        """Missing version defaults to None"""
        report_str = self._make_feedback_report()
        lines = [ln for ln in report_str.split("\n") if not ln.startswith("Version:")]
        report_str = "\n".join(lines)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertIsNone(report["version"])

    def testOverlongArrivalDateIsInvalidFailureReport(self):
        """An Arrival-Date too long to be a date is an InvalidFailureReport
        naming the field, not an "Unexpected error" from the date parser"""
        report_str = self._make_feedback_report().replace(
            "Arrival-Date: Thu, 1 Jan 2024 00:00:00 +0000",
            "Arrival-Date: " + "1" * 200,
        )
        self.assertIn("Arrival-Date: 111", report_str)
        with self.assertRaises(parsedmarc.InvalidFailureReport) as ctx:
            parsedmarc.parse_failure_report(
                report_str, self._make_sample(), self._default_msg_date(), offline=True
            )
        self.assertIn("Arrival-Date", str(ctx.exception))
        self.assertNotIn("Unexpected error", str(ctx.exception))

    def testMissingUserAgent(self):
        """Missing user_agent defaults to None"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("User-Agent:")
        ]
        report_str = "\n".join(lines)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertIsNone(report["user_agent"])

    def testMissingDeliveryResult(self):
        """Missing delivery_result maps to 'other' when field absent"""
        report_str = self._make_feedback_report()
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        # When delivery_result is not in the parsed report, it's set to None,
        # but then the validation check maps None (not in delivery_results list) to "other"
        self.assertEqual(report["delivery_result"], "other")

    def testDeliveryResultMapped(self):
        """Known delivery_result values are mapped correctly"""
        for val in ["delivered", "spam", "policy", "reject"]:
            report_str = self._make_feedback_report(**{"Delivery-Result": val})
            report = parsedmarc.parse_failure_report(
                report_str, self._make_sample(), self._default_msg_date(), offline=True
            )
            self.assertEqual(report["delivery_result"], val)

    def testDeliveryResultUnknownMapsToOther(self):
        """Unknown delivery_result maps to 'other'"""
        report_str = self._make_feedback_report(**{"Delivery-Result": "unknown-value"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["delivery_result"], "other")

    def testIdentityAlignmentNone(self):
        """identity_alignment='none' results in empty auth mechanisms"""
        report_str = self._make_feedback_report(**{"Identity-Alignment": "none"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["authentication_mechanisms"], [])

    def testIdentityAlignmentMultiple(self):
        """identity_alignment with multiple values is split"""
        report_str = self._make_feedback_report(**{"Identity-Alignment": "dkim,spf"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["authentication_mechanisms"], ["dkim", "spf"])

    def testIdentityAlignmentCFWSWhitespaceStripped(self):
        """RFC 9991 ABNF allows CFWS around the commas in
        Identity-Alignment. The previous parser left leading whitespace
        on the second token ('dkim, spf' -> ['dkim', ' spf']); CFWS-aware
        splitting yields ['dkim', 'spf']."""
        report_str = self._make_feedback_report(**{"Identity-Alignment": "dkim, spf"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["authentication_mechanisms"], ["dkim", "spf"])

    def testAuthFailureCFWSWhitespaceStripped(self):
        """Auth-Failure (also comma-separated per RFC 9991) is whitespace-
        stripped per token."""
        report_str = self._make_feedback_report(**{"Auth-Failure": "dmarc, spf"})
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["auth_failure"], ["dmarc", "spf"])

    def testMissingIdentityAlignmentWarns(self):
        """Identity-Alignment is REQUIRED per RFC 9991; the parser
        defaults silently for permissiveness but logs a warning so the
        broken reporter is visible."""
        report_str = self._make_feedback_report()
        lines = [
            ln
            for ln in report_str.split("\n")
            if not ln.startswith("Identity-Alignment:")
        ]
        report_str = "\n".join(lines)
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_failure_report(
                report_str,
                self._make_sample(),
                self._default_msg_date(),
                offline=True,
            )
        self.assertEqual(report["authentication_mechanisms"], [])
        self.assertTrue(
            any("Identity-Alignment" in m and "RFC 9991" in m for m in cm.output),
            f"Expected Identity-Alignment RFC 9991 warning; got: {cm.output}",
        )

    def testMissingAuthFailureWarns(self):
        """Auth-Failure is REQUIRED per RFC 9991; the parser defaults
        to 'dmarc' but logs a warning."""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Auth-Failure:")
        ]
        report_str = "\n".join(lines)
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_failure_report(
                report_str,
                self._make_sample(),
                self._default_msg_date(),
                offline=True,
            )
        self.assertEqual(report["auth_failure"], ["dmarc"])
        self.assertTrue(
            any("Auth-Failure" in m and "RFC 9991" in m for m in cm.output),
            f"Expected Auth-Failure RFC 9991 warning; got: {cm.output}",
        )

    def testMissingReportedDomainFallback(self):
        """Missing reported_domain falls back to sample from domain"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Reported-Domain:")
        ]
        report_str = "\n".join(lines)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), self._default_msg_date(), offline=True
        )
        self.assertEqual(report["reported_domain"], "example.com")

    def testMissingArrivalDateWithMsgDate(self):
        """Missing arrival_date uses msg_date fallback"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Arrival-Date:")
        ]
        report_str = "\n".join(lines)
        msg_date = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        report = parsedmarc.parse_failure_report(
            report_str, self._make_sample(), msg_date, offline=True
        )
        self.assertIn("2024-06-15", report["arrival_date"])

    def testMissingArrivalDateNoMsgDateRaises(self):
        """Missing arrival_date with no msg_date raises"""
        report_str = self._make_feedback_report()
        lines = [
            ln for ln in report_str.split("\n") if not ln.startswith("Arrival-Date:")
        ]
        report_str = "\n".join(lines)
        with self.assertRaises(parsedmarc.InvalidFailureReport):
            parsedmarc.parse_failure_report(
                report_str,
                self._make_sample(),
                cast(datetime, None),  # intentionally None to test error path
                offline=True,
            )


class TestSmtpTlsReportErrors(unittest.TestCase):
    """Tests for SMTP TLS report error handling"""

    def testMissingRequiredField(self):
        """Missing required field raises InvalidSMTPTLSReport"""
        json_str = json.dumps({"policies": []})
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json(json_str)

    def testInvalidJson(self):
        """Invalid JSON raises InvalidSMTPTLSReport"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
            parsedmarc.parse_smtp_tls_report_json("not json {{{")

    def testInvalidJsonPreservesCause(self):
        """Invalid JSON chains the underlying JSONDecodeError"""
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json("not json {{{")
        self.assertIsInstance(ctx.exception.__cause__, json.JSONDecodeError)

    def testNestedMissingKeyNamesTheField(self):
        """A KeyError on a nested field reports which field was missing"""
        # All five required top-level fields are present, so this gets past the
        # top-level check and raises KeyError on date-range["start-datetime"].
        report = json.dumps(
            {
                "organization-name": "x",
                "date-range": {},
                "contact-info": "x",
                "report-id": "x",
                "policies": [],
            }
        )
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(report)
        self.assertIn("start-datetime", str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, KeyError)


class TestBucketIntervalEdgeCases(unittest.TestCase):
    """Tests for _bucket_interval_by_day edge cases"""

    def testDayCursorAdjustment(self):
        """When begin is before midnight due to tz, day_cursor adjusts back"""
        # Use a timezone where midnight calculation might cause day_cursor > begin
        import pytz

        tz = pytz.FixedOffset(-600)  # UTC-10
        begin = datetime(2024, 1, 1, 23, 30, 0, tzinfo=timezone.utc).astimezone(tz)
        end = datetime(2024, 1, 3, 0, 0, 0, tzinfo=timezone.utc).astimezone(tz)
        buckets = parsedmarc._bucket_interval_by_day(begin, end, 100)
        total = sum(b["count"] for b in buckets)
        self.assertEqual(total, 100)


class TestGetDmarcReportsFromMbox(unittest.TestCase):
    """Tests for mbox parsing"""

    def testEmptyMbox(self):
        """Empty mbox returns empty results"""
        with NamedTemporaryFile(suffix=".mbox", delete=False) as f:
            f.write(b"")
            path = f.name
        try:
            results = parsedmarc.get_dmarc_reports_from_mbox(path, offline=True)
            self.assertEqual(results["aggregate_reports"], [])
            self.assertEqual(results["failure_reports"], [])
            self.assertEqual(results["smtp_tls_reports"], [])
        finally:
            os.remove(path)

    def testMboxWithAggregateReport(self):
        """Mbox with aggregate report email is parsed"""
        from email.mime.multipart import MIMEMultipart
        from email.mime.application import MIMEApplication
        import gzip

        xml = b"""<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <report_id>mbox-test-123</report_id>
    <date_range><begin>1680000000</begin><end>1680086400</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>203.0.113.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"""
        compressed = gzip.compress(xml)

        msg = MIMEMultipart()
        msg["From"] = "dmarc@example.com"
        msg["To"] = "postmaster@example.com"
        msg["Subject"] = "DMARC Aggregate Report"
        msg["Date"] = "Thu, 1 Jan 2024 00:00:00 +0000"
        att = MIMEApplication(compressed, "gzip")
        att.add_header("Content-Disposition", "attachment", filename="report.xml.gz")
        msg.attach(att)

        with NamedTemporaryFile(suffix=".mbox", delete=False, mode="w") as f:
            # mbox format requires "From " line
            f.write("From dmarc@example.com Thu Jan  1 00:00:00 2024\n")
            f.write(msg.as_string())
            f.write("\n")
            path = f.name
        try:
            results = parsedmarc.get_dmarc_reports_from_mbox(path, offline=True)
            self.assertGreaterEqual(len(results["aggregate_reports"]), 1)
        finally:
            os.remove(path)

    def testPoisonMessageRaisesParserError(self):
        """A message that cannot be re-serialized reaches the parser and
        surfaces as a ``ParserError``, sequentially and with n_procs=2.

        Regression test for GHSA-qxwv-2vwj-v828: mbox.get_string()
        re-serializes each message (it is
        ``email.message_from_bytes(get_bytes(key)).as_string()``), so the
        raw email.errors.HeaderWriteError or RecursionError escaped before
        the message reached the parser. get_bytes() returns the stored
        message as-is, and parse_report_email() turns the content error into
        a ``ParserError``. The mbox loop's policy is unchanged: it skips only
        ``InvalidDMARCReport`` and re-raises any other ``ParserError``."""
        # The error text, not __cause__, identifies the content error: an
        # exception returned from a worker process loses its __cause__.
        exercised = 0
        for poison_name, poison, cause in (
            ("header", POISON_HEADER_EMAIL, "folded header contains newline"),
            (
                "nested",
                _nested_multipart_email(POISON_NESTING_LEVELS),
                "maximum recursion depth",
            ),
        ):
            if _reserializes(poison):
                # Not a poison message on this Python (see _reserializes).
                continue
            exercised += 1
            with NamedTemporaryFile(suffix=".mbox", delete=False) as f:
                path = f.name
            self.addCleanup(os.remove, path)
            box = mailbox.mbox(path)
            box.lock()
            try:
                box.add(poison)
                with open("samples/aggregate/twilight.eml", "rb") as source:
                    box.add(source.read())
                box.flush()
            finally:
                box.unlock()
            box.close()
            for n_procs in (1, 2):
                with self.subTest(poison=poison_name, n_procs=n_procs):
                    if poison_name == "nested":
                        # The message guard rejects it as an invalid report
                        # (GHSA-qcc2-4x3v-v4g7), which the loop skips.
                        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
                        result = parsedmarc.get_dmarc_reports_from_mbox(
                            path, offline=True, n_procs=n_procs
                        )
                        self.assertEqual(len(result["aggregate_reports"]), 1)
                        continue
                    with self.assertRaises(parsedmarc.ParserError) as ctx:
                        parsedmarc.get_dmarc_reports_from_mbox(
                            path, offline=True, n_procs=n_procs
                        )
                    self.assertIn("Unable to parse message", str(ctx.exception))
                    self.assertIn(cause, str(ctx.exception))
        # The nested message is a poison on every Python.
        self.assertGreater(exercised, 0)


class TestGetDmarcReportsFromMboxParallel(unittest.TestCase):
    """n_procs=1 vs n_procs=2 parity for get_dmarc_reports_from_mbox, driven
    against a real mbox file built from real sample emails (offline parsing,
    no mocks of parsedmarc internals): one aggregate, one failure, one
    SMTP TLS report, a duplicate copy of the aggregate, and a junk message
    that isn't a report at all.

    Confirms the parallel branch classifies and dedups identically to the
    sequential branch, and that the junk message produces a warning log
    instead of raising -- both branches must only catch InvalidDMARCReport
    (a ParserError subclass) around a single message and continue, since a
    bare ParserError is deliberately re-raised (see the n_procs > 1 branch
    of get_dmarc_reports_from_mbox, which mirrors the sequential branch's
    `except InvalidDMARCReport` scope).
    """

    AGGREGATE = "samples/aggregate/twilight.eml"
    FAILURE = "samples/failure/dmarc_ruf_report_linkedin.eml"
    SMTP_TLS = "samples/smtp_tls/google.com_smtp_tls_report.eml"
    JUNK = b"From: noise@example.com\nSubject: not a report\n\nplain text\n"

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        self._path = os.path.join(self._tmp, "reports.mbox")
        box = mailbox.mbox(self._path)
        box.lock()
        try:
            # AGGREGATE appears twice: dedup must collapse it to one report.
            for source in (self.AGGREGATE, self.FAILURE, self.SMTP_TLS, self.AGGREGATE):
                with open(source, "rb") as source_file:
                    box.add(mailbox.mboxMessage(source_file.read()))
            box.add(mailbox.mboxMessage(self.JUNK))
            box.flush()
        finally:
            box.unlock()
        box.close()

    @staticmethod
    def _aggregate_report_ids(results):
        return {r["report_metadata"]["report_id"] for r in results["aggregate_reports"]}

    def test_parallel_matches_sequential(self):
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        with self.assertLogs("parsedmarc.log", level="WARNING") as sequential_logs:
            sequential = parsedmarc.get_dmarc_reports_from_mbox(
                self._path, offline=True, n_procs=1
            )

        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        with self.assertLogs("parsedmarc.log", level="WARNING") as parallel_logs:
            parallel = parsedmarc.get_dmarc_reports_from_mbox(
                self._path, offline=True, n_procs=2
            )

        # Dedup collapsed the duplicate aggregate to a single report, and
        # both branches picked the same report.
        self.assertEqual(len(sequential["aggregate_reports"]), 1)
        self.assertEqual(len(parallel["aggregate_reports"]), 1)
        self.assertEqual(
            self._aggregate_report_ids(sequential), self._aggregate_report_ids(parallel)
        )

        # Same failure/smtp_tls counts in both branches.
        self.assertEqual(len(sequential["failure_reports"]), 1)
        self.assertEqual(len(parallel["failure_reports"]), 1)
        self.assertEqual(len(sequential["smtp_tls_reports"]), 1)
        self.assertEqual(len(parallel["smtp_tls_reports"]), 1)

        # The junk message warned in both branches without raising.
        self.assertTrue(
            any("not a valid report" in line for line in sequential_logs.output),
            sequential_logs.output,
        )
        self.assertTrue(
            any("not a valid report" in line for line in parallel_logs.output),
            parallel_logs.output,
        )


class TestCentralizedConfig(unittest.TestCase):
    """Regression coverage for the centralize-config-503 refactor
    (parsedmarc/config.py's ``ParserConfig``): the kwargs-style public API
    must keep observing/mutating the same module-default caches it always
    has (via ``_resolve_config`` injecting ``IP_ADDRESS_CACHE`` /
    ``SEEN_AGGREGATE_REPORT_IDS`` / ``REVERSE_DNS_MAP`` rather than letting
    a fresh ``ParserConfig()`` default-factory hand back empty ones), an
    explicit ``config=`` must win over individual option keyword arguments
    when both are given, and the DNS-timeout/retry/normalize-threshold
    defaults must stay consistent between each public function's own
    signature and ``ParserConfig``'s field defaults.
    """

    AGGREGATE = "samples/aggregate/twilight.eml"

    def _build_single_aggregate_mbox(self) -> str:
        """Builds a temporary mbox containing one copy of AGGREGATE."""
        tmp = mkdtemp()
        self.addCleanup(rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "reports.mbox")
        box = mailbox.mbox(path)
        box.lock()
        try:
            with open(self.AGGREGATE, "rb") as source_file:
                box.add(mailbox.mboxMessage(source_file.read()))
            box.flush()
        finally:
            box.unlock()
        box.close()
        return path

    def test_kwargs_path_uses_module_default_caches_not_fresh_ones(self):
        """Regression guard for _resolve_config: calling
        get_dmarc_reports_from_mbox with plain kwargs (no config=) twice in
        a row over the same mbox must dedup the second run's aggregate
        report against the first run's, because both calls must resolve to
        the SAME module-default parsedmarc.SEEN_AGGREGATE_REPORT_IDS cache.
        If _resolve_config ever let the kwargs path fall through to
        ParserConfig's default_factory instead of explicitly injecting the
        module-default caches, each call would get a fresh, empty cache and
        this dedup would silently stop working.
        """
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        self.addCleanup(parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear)
        path = self._build_single_aggregate_mbox()

        first = parsedmarc.get_dmarc_reports_from_mbox(path, offline=True)
        second = parsedmarc.get_dmarc_reports_from_mbox(path, offline=True)

        self.assertEqual(len(first["aggregate_reports"]), 1)
        self.assertEqual(len(second["aggregate_reports"]), 0)

        self.assertEqual(len(parsedmarc.SEEN_AGGREGATE_REPORT_IDS), 1)

    def test_kwargs_and_config_equivalence(self):
        """parse_report_file must produce identical results whether called
        with individual option keyword arguments or an equivalent explicit
        ParserConfig, for one sample of each report type. None of these
        paths touch dedup (that's only in _classify_parsed_email /
        get_dmarc_reports_from_mbox / get_dmarc_reports_from_mailbox), so
        no cache clearing is needed between calls.
        """
        sample_paths = [
            "samples/aggregate/rfc9990-sample.xml",
            "samples/failure/dmarc_ruf_report_linkedin.eml",
            "samples/smtp_tls/google.com_smtp_tls_report.eml",
        ]
        for sample_path in sample_paths:
            with self.subTest(sample=sample_path):
                kwargs_result = parsedmarc.parse_report_file(
                    sample_path, offline=True, always_use_local_files=True
                )
                config_result = parsedmarc.parse_report_file(
                    sample_path,
                    config=parsedmarc.ParserConfig(
                        offline=True, always_use_local_files=True
                    ),
                )
                self.assertEqual(kwargs_result, config_result)

    def test_config_wins_over_kwargs_normalize_threshold(self):
        """When both config= and normalize_timespan_threshold_hours= are
        given, the config's value must win -- per the documented contract,
        an explicit config makes the individual option kwargs inert.

        samples/aggregate/ikea.com!example.de!1538690400!1538776800.xml
        spans exactly 86400 seconds (24h), so a 1.0-hour threshold
        normalizes it and a 1000-hour threshold does not; this makes the
        config-vs-kwarg outcome observable in normalized_timespan.
        """
        sample_path = "samples/aggregate/ikea.com!example.de!1538690400!1538776800.xml"
        with open(sample_path, "rb") as f:
            data = f.read()

        # Config's high threshold must win over the kwarg's low threshold:
        # the report must NOT be normalized.
        report = parsedmarc.parse_aggregate_report_file(
            data,
            offline=True,
            config=parsedmarc.ParserConfig(
                offline=True, normalize_timespan_threshold_hours=1000.0
            ),
            normalize_timespan_threshold_hours=1.0,
        )
        for record in report["records"]:
            self.assertFalse(record["normalized_timespan"])  # type: ignore[typeddict-item]

        # Converse: config's low threshold must win over the kwarg's high
        # threshold: the report MUST be normalized.
        report = parsedmarc.parse_aggregate_report_file(
            data,
            offline=True,
            config=parsedmarc.ParserConfig(
                offline=True, normalize_timespan_threshold_hours=1.0
            ),
            normalize_timespan_threshold_hours=1000.0,
        )
        for record in report["records"]:
            self.assertTrue(record["normalized_timespan"])  # type: ignore[typeddict-item]

    def test_separate_configs_isolate_dedup_state(self):
        """Two independently constructed ParserConfig(offline=True)
        instances must NOT share dedup state (each has its own
        seen_aggregate_report_ids cache), but reusing the SAME instance
        across two calls must dedup, exactly like the module-default-cache
        kwargs path does.
        """
        path = self._build_single_aggregate_mbox()

        cfg_a = parsedmarc.ParserConfig(offline=True)
        cfg_b = parsedmarc.ParserConfig(offline=True)
        result_a = parsedmarc.get_dmarc_reports_from_mbox(path, config=cfg_a)
        result_b = parsedmarc.get_dmarc_reports_from_mbox(path, config=cfg_b)
        self.assertEqual(len(result_a["aggregate_reports"]), 1)
        self.assertEqual(len(result_b["aggregate_reports"]), 1)

        cfg_c = parsedmarc.ParserConfig(offline=True)
        first = parsedmarc.get_dmarc_reports_from_mbox(path, config=cfg_c)
        second = parsedmarc.get_dmarc_reports_from_mbox(path, config=cfg_c)
        self.assertEqual(len(first["aggregate_reports"]), 1)
        self.assertEqual(len(second["aggregate_reports"]), 0)

    def test_dns_and_normalize_defaults_match_constants_and_parser_config(self):
        """DNS timeout/retries and normalize-timespan-threshold defaults
        must match parsedmarc.constants (the authoritative source --
        DEFAULT_DNS_TIMEOUT, DEFAULT_DNS_MAX_RETRIES) and
        parsedmarc.config.ParserConfig's own field defaults, across every
        public function that accepts them.

        Regression guard: before this refactor, get_dmarc_reports_from_mailbox
        and watch_inbox each had a stray literal ``dns_timeout=6.0`` (instead
        of ``DEFAULT_DNS_TIMEOUT == 2.0``) and
        ``normalize_timespan_threshold_hours=24`` (an int, instead of the
        float ``24.0`` used everywhere else) -- exactly the kind of drift
        _resolve_config's shared construction path is meant to prevent from
        silently reappearing.
        """
        functions_and_dns_params = [
            (parsedmarc.parse_aggregate_report_xml, "timeout", "retries"),
            (parsedmarc.parse_aggregate_report_file, "dns_timeout", "dns_retries"),
            (parsedmarc.parse_failure_report, "dns_timeout", "dns_retries"),
            (parsedmarc.parse_report_email, "dns_timeout", "dns_retries"),
            (parsedmarc.parse_report_file, "dns_timeout", "dns_retries"),
            (parsedmarc.get_dmarc_reports_from_mbox, "dns_timeout", "dns_retries"),
            (
                parsedmarc.get_dmarc_reports_from_mailbox,
                "dns_timeout",
                "dns_retries",
            ),
            (parsedmarc.watch_inbox, "dns_timeout", "dns_retries"),
        ]

        default_config = parsedmarc.ParserConfig()

        for func, timeout_param, retries_param in functions_and_dns_params:
            with self.subTest(func=func.__name__, param="dns"):
                sig = inspect.signature(func)
                timeout_default = sig.parameters[timeout_param].default
                retries_default = sig.parameters[retries_param].default
                self.assertEqual(timeout_default, constants.DEFAULT_DNS_TIMEOUT)
                self.assertEqual(retries_default, constants.DEFAULT_DNS_MAX_RETRIES)
                self.assertEqual(timeout_default, default_config.dns_timeout)
                self.assertEqual(retries_default, default_config.dns_retries)

        # parse_failure_report has no normalize_timespan_threshold_hours
        # parameter -- normalization is an aggregate-report-only concept.
        normalize_funcs = [
            parsedmarc.parse_aggregate_report_xml,
            parsedmarc.parse_aggregate_report_file,
            parsedmarc.parse_report_email,
            parsedmarc.parse_report_file,
            parsedmarc.get_dmarc_reports_from_mbox,
            parsedmarc.get_dmarc_reports_from_mailbox,
            parsedmarc.watch_inbox,
        ]
        for func in normalize_funcs:
            with self.subTest(func=func.__name__, param="normalize"):
                sig = inspect.signature(func)
                default = sig.parameters["normalize_timespan_threshold_hours"].default
                self.assertEqual(default, 24.0)
                self.assertIsInstance(default, float)
                self.assertEqual(
                    default, default_config.normalize_timespan_threshold_hours
                )


class TestGetDmarcReportsFromMailboxValidation(unittest.TestCase):
    """Input validation on get_dmarc_reports_from_mailbox.

    These guards prevent two real footguns: the test/delete combo
    would otherwise delete every message after parsing — silently
    destructive — and a None connection would NPE deep in the
    iteration loop with a confusing traceback. Fail fast at the
    door instead."""

    def test_delete_and_test_combination_raises(self):
        from unittest.mock import MagicMock

        with self.assertRaises(ValueError) as ctx:
            parsedmarc.get_dmarc_reports_from_mailbox(
                connection=MagicMock(), delete=True, test=True
            )
        self.assertIn("mutually exclusive", str(ctx.exception))

    def test_inherited_delete_with_test_raises(self):
        """The guard checks the effective per-type flags, so delete=True still
        raises alongside test=True when only *one* per-type flag opts out --
        the remaining three inherit the deletion."""
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.get_dmarc_reports_from_mailbox(
                connection=MagicMock(), delete=True, delete_aggregate=False, test=True
            )
        self.assertIn("mutually exclusive", str(ctx.exception))

    def test_explicit_per_type_delete_with_test_raises(self):
        """Each per-type delete flag on its own is enough to conflict with
        test=True, with the overall delete option left False and the other
        three flags explicitly False."""
        for flag in (
            "delete_aggregate",
            "delete_failure",
            "delete_smtp_tls",
            "delete_invalid",
        ):
            with self.subTest(flag=flag):
                with self.assertRaises(ValueError) as ctx:
                    parsedmarc.get_dmarc_reports_from_mailbox(
                        connection=MagicMock(),
                        test=True,
                        delete_aggregate=flag == "delete_aggregate",
                        delete_failure=flag == "delete_failure",
                        delete_smtp_tls=flag == "delete_smtp_tls",
                        delete_invalid=flag == "delete_invalid",
                    )
                self.assertIn("mutually exclusive", str(ctx.exception))

    def test_none_connection_raises(self):
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.get_dmarc_reports_from_mailbox(
                # Deliberately invalid: exercises the runtime None check
                connection=None  # pyright: ignore[reportArgumentType]
            )
        self.assertIn("connection", str(ctx.exception).lower())

    def test_negative_max_unsaved_retries_raises(self):
        """max_unsaved_retries is user-configurable (INI/env/kwarg), so an
        invalid negative value is rejected at the door with a clear error
        instead of silently behaving like 0 (move to Unsaved on the first
        failed save)."""
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.get_dmarc_reports_from_mailbox(
                connection=MagicMock(), max_unsaved_retries=-1
            )
        self.assertIn("max_unsaved_retries", str(ctx.exception))

    def test_watch_inbox_negative_max_unsaved_retries_raises(self):
        """watch_inbox validates before entering the watch loop: raised
        inside a check, the ValueError would be swallowed and endlessly
        retried by the IMAP and Maildir backends' per-check exception
        handling instead of surfacing to the caller."""
        conn = MagicMock()
        with self.assertRaises(ValueError) as ctx:
            parsedmarc.watch_inbox(
                mailbox_connection=conn,
                callback=lambda batch: None,
                max_unsaved_retries=-1,
            )
        self.assertIn("max_unsaved_retries", str(ctx.exception))
        conn.watch.assert_not_called()

    def test_invalid_parse_timeout_raises_before_fetching_or_watching(self):
        """Like max_unsaved_retries: raised inside a watch check, the
        ValueError would be swallowed and retried on every check."""
        for parse_timeout in (-1.0, float("nan"), float("inf")):
            with self.subTest(parse_timeout=parse_timeout):
                conn = MagicMock()
                with self.assertRaises(ValueError) as ctx:
                    parsedmarc.get_dmarc_reports_from_mailbox(
                        connection=conn, parse_timeout=parse_timeout
                    )
                self.assertIn("parse_timeout", str(ctx.exception))
                conn.fetch_messages.assert_not_called()
                with self.assertRaises(ValueError) as ctx:
                    parsedmarc.watch_inbox(
                        mailbox_connection=conn,
                        callback=lambda batch: None,
                        parse_timeout=parse_timeout,
                    )
                self.assertIn("parse_timeout", str(ctx.exception))
                conn.watch.assert_not_called()


class TestMigrateForensicArchiveFolderErrorHandling(unittest.TestCase):
    """The one migration scenario a real on-disk Maildir can't reproduce: a
    backend that raises mid-operation. _migrate_forensic_archive_folder must
    warn and continue (warn, don't crash) so a mailbox it cannot reorganize
    doesn't abort the whole run.

    The rename / merge / no-op behavior is covered for real (no mocks) in
    TestMigrateForensicArchiveFolderMaildir; only this failure path needs a
    mock, to force a folder operation to raise."""

    def test_backend_error_is_warned_not_raised(self):
        conn = MagicMock()
        conn.folder_exists.side_effect = lambda name: name.endswith("/Forensic")
        conn.rename_folder.side_effect = RuntimeError("server said no")
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            parsedmarc._migrate_forensic_archive_folder(conn, "Archive")
        self.assertTrue(
            any("Could not migrate" in line for line in cm.output),
            cm.output,
        )


class TestMigrateForensicArchiveFolderMaildir(unittest.TestCase):
    """End-to-end migration against a real on-disk Maildir via mailsuite's
    MaildirConnection — no mocks. This exercises the actual mailsuite 2.1.0
    folder API (folder_exists / rename_folder / merge_folders / delete_folder)
    and the on-disk result, so it would catch a real behavioral break that a
    mock-based test cannot (e.g. a signature mismatch, or messages left behind
    in the legacy folder)."""

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        self.conn = MaildirConnection(self._tmp, maildir_create=True)
        # Parent must exist before nested subfolders, as get_dmarc_reports_-
        # from_mailbox creates it (create_folder(archive_folder)) first.
        self.conn.create_folder("Archive")

    def _seed(self, folder, subject):
        """Drop a real RFC 822 message into an on-disk Maildir subfolder."""
        self.conn.create_folder(folder)
        box = mailbox.Maildir(os.path.join(self._tmp, "." + folder))
        box.add(
            mailbox.MaildirMessage(
                "From: reporter@example.com\n"
                "To: dmarc@example.org\n"
                f"Subject: {subject}\n\nbody\n"
            )
        )
        box.flush()

    def test_rename_moves_legacy_folder_and_its_messages(self):
        """Only the legacy folder exists: it (and the message inside it) is
        renamed to Failure, leaving nothing behind in Forensic."""
        self._seed("Archive/Forensic", "legacy failure report")
        self.assertTrue(self.conn.folder_exists("Archive/Forensic"))
        self.assertFalse(self.conn.folder_exists("Archive/Failure"))

        parsedmarc._migrate_forensic_archive_folder(self.conn, "Archive")

        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertTrue(self.conn.folder_exists("Archive/Failure"))
        self.assertEqual(len(self.conn.fetch_messages("Archive/Failure")), 1)

    def test_merge_consolidates_messages_when_both_exist(self):
        """Both folders exist: the legacy folder's messages are merged into
        the existing Failure folder (which keeps its own), and the emptied
        legacy folder is deleted."""
        self._seed("Archive/Failure", "post-rename failure report")
        self._seed("Archive/Forensic", "legacy failure report")

        parsedmarc._migrate_forensic_archive_folder(self.conn, "Archive")

        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertTrue(self.conn.folder_exists("Archive/Failure"))
        self.assertEqual(len(self.conn.fetch_messages("Archive/Failure")), 2)

    def test_no_legacy_folder_is_noop(self):
        """No legacy folder (the common case): nothing is created or changed."""
        parsedmarc._migrate_forensic_archive_folder(self.conn, "Archive")
        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertFalse(self.conn.folder_exists("Archive/Failure"))

    def test_orchestration_migrates_before_creating_folders(self):
        """get_dmarc_reports_from_mailbox runs the migration *before* it
        creates folders: a seeded legacy Forensic folder ends up consolidated
        into the newly-created Failure subfolder (message and all), not split
        across the two. Driven through the real orchestration with an empty
        INBOX, so no parsing or network occurs."""
        self._seed("Archive/Forensic", "legacy failure report")

        result = parsedmarc.get_dmarc_reports_from_mailbox(connection=self.conn)

        self.assertFalse(self.conn.folder_exists("Archive/Forensic"))
        self.assertTrue(self.conn.folder_exists("Archive/Failure"))
        self.assertEqual(len(self.conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(result["failure_reports"], [])


class _FailingDisposalMaildirConnection(MaildirConnection):
    """A MaildirConnection whose first disposal call fails.

    Real mailbox backends can reject an individual delete or move (permission
    denied, a UID that vanished, a dropped connection) while the rest of the
    batch is still fine. Failing only the *first* call, then behaving
    normally, is what makes that observable: the message the failure hit
    stays put, and every message after it must still be disposed of.
    """

    def __init__(self, *args, fail_delete=False, fail_move=False, **kwargs):
        super().__init__(*args, **kwargs)
        self._fail_delete = fail_delete
        self._fail_move = fail_move

    def delete_message(self, message_id):
        if self._fail_delete:
            self._fail_delete = False
            raise RuntimeError("server said no")
        super().delete_message(message_id)

    def move_message(self, message_id, folder_name):
        if self._fail_move:
            self._fail_move = False
            raise RuntimeError("server said no")
        super().move_message(message_id, folder_name)


class _InMemoryMailboxConnection(parsedmarc.MailboxConnection):
    """A mailbox backend held in memory. Like IMAP or Microsoft Graph, it
    returns each message's stored text as-is and moves a message without
    rewriting it, unlike the Maildir backend, which re-serializes both
    ways. ``fetch_errors`` maps a message id to the exception its fetch
    raises."""

    def __init__(self, messages, fetch_errors=None):
        self.folders = {"INBOX": dict(messages)}
        self.fetch_errors = fetch_errors or {}

    def create_folder(self, folder_name):
        self.folders.setdefault(folder_name, {})

    def folder_exists(self, folder_name):
        return folder_name in self.folders

    def fetch_messages(self, reports_folder, **kwargs):
        return list(self.folders[reports_folder])

    def fetch_message(self, message_id, **kwargs):
        if message_id in self.fetch_errors:
            raise self.fetch_errors[message_id]
        return self.folders["INBOX"][message_id]

    def delete_message(self, message_id):
        del self.folders["INBOX"][message_id]

    def move_message(self, message_id, folder_name):
        self.folders[folder_name][message_id] = self.folders["INBOX"].pop(message_id)

    def keepalive(self):
        return None

    def watch(self, check_callback, check_timeout, config_reloading=None):
        return None


class _InMemoryIMAPConnection(_InMemoryMailboxConnection, IMAPConnection):
    """The in-memory backend, typed as an IMAP connection so parsedmarc
    takes its IMAP code paths. Its message ids are ints, as IMAP UIDs are,
    so a lookup with any other type fails."""


class TestGetDmarcReportsFromMailboxContentErrors(unittest.TestCase):
    """GHSA-qxwv-2vwj-v828 on backends that neither fetch nor move a message
    by re-serializing it: a message whose content raises a non-ParserError
    exception is moved to the invalid folder (or deleted), and the rest of
    the batch is processed, sequentially and with n_procs=2."""

    def setUp(self):
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        with open("samples/aggregate/twilight.eml", encoding="utf-8") as f:
            self.aggregate = f.read()

    def _run(self, conn, n_procs, **kwargs):
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            result = parsedmarc.get_dmarc_reports_from_mailbox(
                connection=conn, offline=True, n_procs=n_procs, **kwargs
            )
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(result["failure_reports"], [])
        return cm.output

    def test_fetch_content_error_moves_message_to_invalid(self):
        """A content error raised by the backend's fetch (as the Maildir
        backend raises it) moves that message to the invalid folder, or
        deletes it with delete_invalid; IMAP UIDs stay ints throughout."""
        errors = (
            email.errors.HeaderWriteError("folded header contains newline"),
            RecursionError("maximum recursion depth exceeded"),
        )
        for conn_cls, poison_id, report_id in (
            (_InMemoryMailboxConnection, "poison", "report"),
            (_InMemoryIMAPConnection, 1, 2),
        ):
            for error in errors:
                for n_procs in (1, 2):
                    with self.subTest(
                        backend=conn_cls.__name__,
                        error=type(error).__name__,
                        n_procs=n_procs,
                    ):
                        conn = conn_cls(
                            {poison_id: "unused", report_id: self.aggregate},
                            fetch_errors={poison_id: error},
                        )
                        output = self._run(conn, n_procs)
                        self.assertEqual(conn.folders["INBOX"], {})
                        self.assertEqual(
                            list(conn.folders["Archive/Invalid"]), [poison_id]
                        )
                        self.assertEqual(
                            list(conn.folders["Archive/Aggregate"]), [report_id]
                        )
                        self.assertTrue(
                            any(
                                f"Unable to fetch message UID {poison_id}: "
                                f"{type(error).__name__}" in line
                                for line in output
                            ),
                            output,
                        )

                        conn = conn_cls(
                            {poison_id: "unused", report_id: self.aggregate},
                            fetch_errors={poison_id: error},
                        )
                        self._run(conn, n_procs, delete_invalid=True)
                        self.assertEqual(conn.folders["INBOX"], {})
                        self.assertEqual(conn.folders["Archive/Invalid"], {})
                        self.assertEqual(
                            list(conn.folders["Archive/Aggregate"]), [report_id]
                        )

    def test_unparseable_content_moves_message_to_invalid(self):
        """A backend that returns the raw message, as IMAP does, hands the
        poison content to parse_report_email(), whose ParserError now moves
        the message to the invalid folder instead of a HeaderWriteError or
        RecursionError aborting the batch."""
        exercised = 0
        for poison_name, poison in (
            ("header", POISON_HEADER_EMAIL),
            ("nested", _nested_multipart_email(POISON_NESTING_LEVELS)),
        ):
            if _reserializes(poison):
                # Not a poison message on this Python (see _reserializes).
                continue
            exercised += 1
            for n_procs in (1, 2):
                with self.subTest(poison=poison_name, n_procs=n_procs):
                    conn = _InMemoryIMAPConnection(
                        {1: poison.decode(), 2: self.aggregate}
                    )
                    output = self._run(conn, n_procs)
                    self.assertEqual(conn.folders["INBOX"], {})
                    self.assertEqual(list(conn.folders["Archive/Invalid"]), [1])
                    self.assertEqual(list(conn.folders["Archive/Aggregate"]), [2])
                    expected_text = (
                        "Message rejected"
                        if poison_name == "nested"
                        else "Unable to parse message"
                    )
                    self.assertTrue(
                        any(expected_text in line for line in output),
                        output,
                    )
        # The nested message is a poison on every Python.
        self.assertGreater(exercised, 0)


_SLOW_MESSAGE = (
    "From: reporter@example.net\r\nTo: dmarc@example.com\r\n"
    "Subject: slow to parse\r\nX-Test-Slow: yes\r\n\r\nbody\r\n"
)


def _parallel_map_timing_out(calls):
    """An in-process stand-in for ``parsedmarc.parallel.parallel_map`` that
    runs the real job function on every message except the one carrying
    ``X-Test-Slow``, for which it yields ``timeout_result``, as the real
    ``parallel_map`` does for a job that ran past ``parse_timeout``. Each
    call's keyword arguments and ``n_procs`` are appended to ``calls``."""

    def fake_parallel_map(func, jobs, n_procs, **kwargs):
        calls.append(dict(kwargs, n_procs=n_procs))
        for job in jobs:
            content = job if isinstance(job, bytes) else job.encode()
            if b"X-Test-Slow: yes" in content:
                yield kwargs["timeout_result"](job, kwargs["parse_timeout"])
            else:
                yield func(job)

    return fake_parallel_map


class TestParseTimeoutDisposal(unittest.TestCase):
    """A message whose parse ran past ``parse_timeout`` is handled like any
    other invalid message: moved to the invalid folder by the mailbox loop,
    skipped with a warning by the mbox loop. With a timeout set, ``n_procs``
    1 takes the ``parallel_map`` branch, since only a worker process can be
    stopped. ``parallel_map`` is replaced by a stand-in that times out the
    marked message, because a real parse that slow needs an input the parse
    limits do not already reject; the timeout itself is tested in
    ``tests/test_parallel.py``."""

    def setUp(self):
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        self.addCleanup(parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear)
        with open("samples/aggregate/twilight.eml", encoding="utf-8") as f:
            self.aggregate = f.read()

    def test_mailbox_message_that_times_out_moves_to_invalid(self):
        calls = []
        conn = _InMemoryIMAPConnection({1: _SLOW_MESSAGE, 2: self.aggregate})
        with (
            patch("parsedmarc.parallel.parallel_map", _parallel_map_timing_out(calls)),
            self.assertLogs("parsedmarc.log", level="WARNING") as logs,
        ):
            result = parsedmarc.get_dmarc_reports_from_mailbox(
                connection=conn, offline=True, n_procs=1, parse_timeout=1.0
            )
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(conn.folders["INBOX"], {})
        self.assertEqual(list(conn.folders["Archive/Invalid"]), [1])
        self.assertEqual(list(conn.folders["Archive/Aggregate"]), [2])
        self.assertTrue(
            any(
                "longer than parse_timeout (1 seconds)" in line for line in logs.output
            ),
            logs.output,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["n_procs"], 1)
        self.assertEqual(calls[0]["parse_timeout"], 1.0)
        self.assertEqual(calls[0]["heartbeat"], conn.keepalive)

    def test_mailbox_without_timeout_and_one_process_parses_in_process(self):
        calls = []
        conn = _InMemoryIMAPConnection({2: self.aggregate})
        with patch("parsedmarc.parallel.parallel_map", _parallel_map_timing_out(calls)):
            result = parsedmarc.get_dmarc_reports_from_mailbox(
                connection=conn, offline=True, n_procs=1
            )
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(calls, [])

    def test_mbox_message_that_times_out_is_skipped_with_a_warning(self):
        tmp = mkdtemp()
        self.addCleanup(rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "reports.mbox")
        box = mailbox.mbox(path)
        box.lock()
        try:
            box.add(mailbox.mboxMessage(_SLOW_MESSAGE))
            box.add(mailbox.mboxMessage(self.aggregate))
            box.flush()
        finally:
            box.unlock()
        box.close()

        calls = []
        with (
            patch("parsedmarc.parallel.parallel_map", _parallel_map_timing_out(calls)),
            self.assertLogs("parsedmarc.log", level="WARNING") as logs,
        ):
            result = parsedmarc.get_dmarc_reports_from_mbox(
                path, offline=True, n_procs=1, parse_timeout=1.0
            )
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertTrue(
            any(
                "longer than parse_timeout (1 seconds)" in line for line in logs.output
            ),
            logs.output,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["n_procs"], 1)
        self.assertEqual(calls[0]["parse_timeout"], 1.0)


class _FailingFetchMaildirConnection(MaildirConnection):
    """A MaildirConnection whose every fetch fails like a dropped network
    connection would."""

    def fetch_message(self, message_id, **kwargs):
        raise OSError("connection reset")


class TestGetDmarcReportsFromMailboxMaildir(unittest.TestCase):
    """parsedmarc's real mailbox processing loop, end to end on an on-disk
    Maildir (mailsuite MaildirConnection, no mocks, offline parsing): fetch
    from INBOX, parse and classify each message, then route it to the matching
    archive subfolder — or delete it / leave it, per mode. This path was
    previously untestable without a live IMAP server (see AGENTS.md), so it sat
    uncovered; the Maildir backend lets it run in CI with no network or
    credentials, asserting on the observable result (parsed counts + where each
    message physically ended up), not on mock call records."""

    AGGREGATE = "samples/aggregate/twilight.eml"
    FAILURE = "samples/failure/dmarc_ruf_report_linkedin.eml"
    SMTP_TLS = "samples/smtp_tls/google.com_smtp_tls_report.eml"
    JUNK = b"From: noise@example.com\nSubject: not a report\n\nplain text\n"

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        # Aggregate dedup is a module-global ExpiringDict; reset it so an
        # aggregate report "seen" by an earlier test isn't silently dropped
        # from this test's results.
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        # Use a not-yet-existing subpath so mailbox.Maildir(create=True) builds
        # cur/new/tmp (it skips creation if the directory already exists, which
        # mkdtemp's would). Deliver straight to disk; the connection is built
        # afterwards (in _run) so its first read sees every delivered message.
        self._maildir = os.path.join(self._tmp, "Maildir")
        self._inbox = mailbox.Maildir(self._maildir, create=True)

    def _deliver(self, source):
        if isinstance(source, str):
            with open(source, "rb") as f:
                raw = f.read()
        else:
            raw = source
        self._inbox.add(mailbox.MaildirMessage(raw))
        self._inbox.flush()

    def _run(self, **kwargs):
        conn = MaildirConnection(self._maildir, maildir_create=True)
        result = parsedmarc.get_dmarc_reports_from_mailbox(
            connection=conn, offline=True, **kwargs
        )
        return conn, result

    def _assert_each_report_type_routed(self, conn, result):
        """Shared assertions for one report of each type plus an
        unparseable message: each is filed under the correct subfolder
        (Aggregate / Failure / SMTP-TLS / Invalid) and the INBOX is
        drained. Used by both the sequential and n_procs=2 variants below
        so the two tests share their assertions instead of duplicating
        them."""
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/SMTP-TLS")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)

    def test_each_report_type_routed_to_its_archive_subfolder(self):
        """One report of each type plus an unparseable message: each is filed
        under the correct subfolder (Aggregate / Failure / SMTP-TLS / Invalid)
        and the INBOX is drained."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)
        self._deliver(self.SMTP_TLS)
        self._deliver(self.JUNK)

        conn, result = self._run()

        self._assert_each_report_type_routed(conn, result)

    def test_each_report_type_routed_to_its_archive_subfolder_parallel(self):
        """Same scenario as above, with n_procs=2: fetching and archiving
        stay sequential in the parent, but parsing runs in worker
        processes. The routing outcome must be identical."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)
        self._deliver(self.SMTP_TLS)
        self._deliver(self.JUNK)

        conn, result = self._run(n_procs=2)

        self._assert_each_report_type_routed(conn, result)

    def test_delete_mode_removes_processed_messages(self):
        """delete=True: a parsed message is removed from the INBOX rather than
        archived."""
        self._deliver(self.FAILURE)

        conn, result = self._run(delete=True)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        # The Failure folder is created but nothing is filed there — deleted.
        self.assertEqual(conn.fetch_messages("Archive/Failure"), [])

    def test_delete_mode_removes_processed_messages_parallel(self):
        """Same as above, with n_procs=2 and enough messages (>1) to take
        the parallel branch: invalid-message disposition happens after the
        parse phase for n_procs > 1 (see get_dmarc_reports_from_mailbox's
        docstring), but the end result -- both messages gone from the
        INBOX and nothing archived -- must match delete mode exactly."""
        self._deliver(self.FAILURE)
        self._deliver(self.AGGREGATE)

        conn, result = self._run(delete=True, n_procs=2)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(conn.fetch_messages("Archive/Failure"), [])
        self.assertEqual(conn.fetch_messages("Archive/Aggregate"), [])

    def test_delete_aggregate_overrides_delete_false(self):
        """delete_aggregate=True with delete left at its False default: only
        the aggregate report message is deleted; the other two report types
        (and the unparseable message) are still archived."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)
        self._deliver(self.SMTP_TLS)
        self._deliver(self.JUNK)

        conn, result = self._run(delete_aggregate=True)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(conn.fetch_messages("Archive/Aggregate"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/SMTP-TLS")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)

    def test_delete_failure_false_overrides_delete_true(self):
        """delete=True with delete_failure=False: failure report messages are
        kept (archived) while every other message -- aggregate, SMTP TLS, and
        the unparseable one, all inheriting delete=True -- is deleted. This is
        the motivating case from issue #256."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)
        self._deliver(self.SMTP_TLS)
        self._deliver(self.JUNK)

        conn, result = self._run(delete=True, delete_failure=False)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Aggregate"), [])
        self.assertEqual(conn.fetch_messages("Archive/SMTP-TLS"), [])
        self.assertEqual(conn.fetch_messages("Archive/Invalid"), [])

    def test_delete_invalid_true_deletes_unparseable_messages(self):
        """delete_invalid=True on its own: the unparseable message is deleted
        while the parsed failure report is still archived."""
        self._deliver(self.FAILURE)
        self._deliver(self.JUNK)

        conn, result = self._run(delete_invalid=True)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(conn.fetch_messages("Archive/Invalid"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)

    def test_delete_invalid_false_keeps_unparseable_when_delete_true(self):
        """delete=True with delete_invalid=False: the unparseable message is
        kept in Archive/Invalid for debugging while the parsed failure report
        message is deleted."""
        self._deliver(self.FAILURE)
        self._deliver(self.JUNK)

        conn, result = self._run(delete=True, delete_invalid=False)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Failure"), [])

    def test_per_type_delete_flags_parallel(self):
        """Same per-type semantics on the n_procs=2 branch, where
        invalid-message disposition happens after the parse phase: the
        failure report and the unparseable message are archived (both
        explicitly False) while the aggregate report inherits delete=True and
        is deleted."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)
        self._deliver(self.JUNK)

        conn, result = self._run(
            n_procs=2, delete=True, delete_failure=False, delete_invalid=False
        )

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Aggregate"), [])

    def test_test_mode_allowed_when_all_delete_flags_explicitly_false(self):
        """The test/delete guard fires on the *effective* per-type flags, so
        delete=True alongside all four per-type flags explicitly False is
        valid with test=True: nothing would be deleted. The message is parsed
        and left in the INBOX."""
        self._deliver(self.FAILURE)

        conn, result = self._run(
            delete=True,
            delete_aggregate=False,
            delete_failure=False,
            delete_smtp_tls=False,
            delete_invalid=False,
            test=True,
        )

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertFalse(conn.folder_exists("Archive/Failure"))

    def test_test_mode_parses_without_moving_or_creating_folders(self):
        """test=True: the report is parsed and returned, but the message stays
        in the INBOX and no archive folders are created/touched."""
        self._deliver(self.FAILURE)

        conn, result = self._run(test=True)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertFalse(conn.folder_exists("Archive/Failure"))

    def test_test_mode_parses_without_moving_or_creating_folders_parallel(self):
        """Same as above, with n_procs=2 and enough messages (>1) to take
        the parallel branch: test mode disposes of nothing regardless of
        n_procs, so both messages stay put and no archive folders appear."""
        self._deliver(self.FAILURE)
        self._deliver(self.AGGREGATE)

        conn, result = self._run(test=True, n_procs=2)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 2)
        self.assertFalse(conn.folder_exists("Archive/Failure"))
        self.assertFalse(conn.folder_exists("Archive/Aggregate"))

    def test_duplicate_aggregate_parallel_archives_both_messages(self):
        """Delivering the same aggregate sample twice: dedup means the
        parsed *results* contain only one aggregate report, but the
        sequential caller appends a message's UID to the aggregate archive
        list unconditionally -- including for the duplicate -- so BOTH
        source messages still get archived to Aggregate. The n_procs=2
        branch must match: the helper (_classify_parsed_email) owns the
        dedup, but the caller appends the UID regardless of report_type
        matching "aggregate", exactly as the sequential branch does."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.AGGREGATE)

        conn, result = self._run(n_procs=2)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 2)
        self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_delete_error_is_logged_and_disposal_continues(self):
        """A backend that rejects one delete must not abort the disposal of
        the remaining messages: the error is logged and the loop moves on to
        the next report type. The aggregate message's delete fails, so it
        stays in the INBOX, while the SMTP TLS message is still deleted."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.SMTP_TLS)
        conn = _FailingDisposalMaildirConnection(
            self._maildir, maildir_create=True, fail_delete=True
        )

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            result = parsedmarc.get_dmarc_reports_from_mailbox(
                connection=conn, offline=True, delete=True
            )

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertTrue(
            any(
                "Mailbox error: Error deleting message UID" in line
                for line in cm.output
            ),
            cm.output,
        )
        # Only the message whose delete raised is left behind.
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Aggregate"), [])
        self.assertEqual(conn.fetch_messages("Archive/SMTP-TLS"), [])

    def test_move_error_is_logged_and_disposal_continues(self):
        """The same for the archiving half of the disposal loop: a rejected
        move is logged and the loop continues, so the aggregate message stays
        in the INBOX while the SMTP TLS message still reaches its archive
        subfolder."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.SMTP_TLS)
        conn = _FailingDisposalMaildirConnection(
            self._maildir, maildir_create=True, fail_move=True
        )

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            result = parsedmarc.get_dmarc_reports_from_mailbox(
                connection=conn, offline=True
            )

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertTrue(
            any(
                "Mailbox error: Error moving message UID" in line for line in cm.output
            ),
            cm.output,
        )
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Aggregate"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/SMTP-TLS")), 1)

    def _poison_maildir(self, name, poison):
        """A fresh Maildir holding ``poison`` (delivered byte-for-byte, so the
        stdlib never has to re-serialize it) and the aggregate sample.

        Returns ``(path, poison_key)``."""
        path = os.path.join(self._tmp, name)
        box = mailbox.Maildir(path, create=True)
        poison_key = box.add(poison)
        with open(self.AGGREGATE, "rb") as f:
            box.add(f.read())
        box.flush()
        return path, poison_key

    def _skip_unless_poison(self, poison):
        if _reserializes(poison):
            self.skipTest(
                "this Python re-serializes the message without error, so it "
                "is not a poison message here"
            )

    def test_poison_message_does_not_abort_the_batch(self):
        """A message that cannot be re-serialized no longer aborts the
        batch: the other report is still parsed and archived, sequentially
        and with n_procs=2, and the poison message is moved to
        ``Archive/Invalid``.

        Regression test for GHSA-qxwv-2vwj-v828: parse_report_email()
        serializes the message's parts, so the
        email.errors.HeaderWriteError (a control character in a sub-message
        header) or RecursionError (deeply nested multiparts) escaped from the
        mailbox loop's per-message ``except ParserError`` and every run
        aborted on the same message. parse_report_email() now raises a
        ParserError, which logs "Unable to parse message with subject ..."
        and disposes of the message as invalid.

        mailsuite 2.3.3 (GHSA-9jx3-p8wm-g8vw) returns the stored bytes from
        fetch_message() and renames the file in move_message(), so neither
        step re-serializes the message: the fetch succeeds and the failure
        surfaces in the parser, and the move always succeeds. (Before 2.3.3
        the fetch raised, and the move re-added the message through
        ``mailbox.Maildir.add()``, which left the nested message in the
        inbox.) A Python whose ``Message.as_string()`` can write the
        control-character message is skipped for that message, as it is not
        a poison message there."""
        for poison_name, poison in (
            ("header", POISON_HEADER_EMAIL),
            ("nested", _nested_multipart_email(POISON_NESTING_LEVELS)),
        ):
            if _reserializes(poison):
                # Not a poison message on this Python (see _reserializes).
                continue
            for n_procs in (1, 2):
                with self.subTest(poison=poison_name, n_procs=n_procs):
                    parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
                    path, _ = self._poison_maildir(f"{poison_name}-{n_procs}", poison)
                    conn = MaildirConnection(path, maildir_create=True)
                    with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                        result = parsedmarc.get_dmarc_reports_from_mailbox(
                            connection=conn,
                            reports_folder="INBOX",
                            archive_folder="Archive",
                            offline=True,
                            test=False,
                            n_procs=n_procs,
                        )

                    # The batch completed and the real report was archived.
                    self.assertEqual(len(result["aggregate_reports"]), 1)
                    self.assertEqual(result["failure_reports"], [])
                    self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)
                    expected_text = (
                        "Message rejected"
                        if poison_name == "nested"
                        else "Unable to parse message with subject"
                    )
                    self.assertTrue(
                        any(expected_text in line for line in cm.output),
                        cm.output,
                    )
                    # The poison message was moved, not left to fail again.
                    self.assertEqual(conn.fetch_messages("INBOX"), [])
                    self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)
                    self.assertFalse(
                        [line for line in cm.output if "Mailbox error" in line],
                        cm.output,
                    )

    def test_poison_message_is_deleted_with_delete_invalid(self):
        """With delete_invalid, a message that failed to fetch is deleted
        like any other invalid message (deleting does not re-serialize it),
        sequentially and with n_procs=2 (GHSA-qxwv-2vwj-v828)."""
        self._skip_unless_poison(POISON_HEADER_EMAIL)
        for n_procs in (1, 2):
            with self.subTest(n_procs=n_procs):
                parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
                path, _ = self._poison_maildir(f"delete-{n_procs}", POISON_HEADER_EMAIL)
                conn = MaildirConnection(path, maildir_create=True)
                with self.assertLogs("parsedmarc.log", level="WARNING"):
                    result = parsedmarc.get_dmarc_reports_from_mailbox(
                        connection=conn,
                        offline=True,
                        delete_invalid=True,
                        n_procs=n_procs,
                    )

                self.assertEqual(len(result["aggregate_reports"]), 1)
                self.assertEqual(conn.fetch_messages("INBOX"), [])
                self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)
                self.assertEqual(conn.fetch_messages("Archive/Invalid"), [])

    def test_transport_error_on_fetch_still_propagates(self):
        """Only content errors from the fetch mark a message invalid: a
        transport error such as OSError still propagates, sequentially and
        with n_procs=2, and the message is neither moved nor deleted, since
        a transient failure says nothing about the message itself."""
        for n_procs in (1, 2):
            with self.subTest(n_procs=n_procs):
                path, _ = self._poison_maildir(f"oserror-{n_procs}", self.JUNK)
                conn = _FailingFetchMaildirConnection(path, maildir_create=True)
                with self.assertRaises(OSError):
                    parsedmarc.get_dmarc_reports_from_mailbox(
                        connection=conn,
                        offline=True,
                        delete_invalid=True,
                        n_procs=n_procs,
                    )
                self.assertEqual(len(conn.fetch_messages("INBOX")), 2)
                self.assertEqual(conn.fetch_messages("Archive/Invalid"), [])


class _UncreatableFolderMaildirConnection(MaildirConnection):
    """A MaildirConnection whose folder_exists() always fails.

    Real backends can reject a folder listing (permissions, a dropped
    connection, an IMAP server that dislikes the name). The Unsaved holding
    folder's defensive pre-move check has to warn and carry on rather than
    crash the run, which is only observable with a backend that fails it.
    """

    def folder_exists(self, folder_name: str) -> bool:
        raise RuntimeError("server said no")


class TestGetDmarcReportsFromMailboxMaildirSaveCallback(unittest.TestCase):
    """The save_callback contract of get_dmarc_reports_from_mailbox, on the
    same real on-disk Maildir harness as the class above (no mocks): a batch
    is only archived or deleted once the callback confirms it was saved, and
    a batch that keeps failing eventually moves to the Unsaved holding
    folder instead of being retried forever (#242)."""

    AGGREGATE = "samples/aggregate/twilight.eml"
    FAILURE = "samples/failure/dmarc_ruf_report_linkedin.eml"
    SMTP_TLS = "samples/smtp_tls/google.com_smtp_tls_report.eml"
    JUNK = b"From: noise@example.com\nSubject: not a report\n\nplain text\n"

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        # Both of these are module-global process state: a report "seen" by
        # an earlier test would be dropped from this test's results, and a
        # stale retry count would move messages to Unsaved early.
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        parsedmarc._FAILED_SAVE_ATTEMPTS.clear()
        self.addCleanup(parsedmarc._FAILED_SAVE_ATTEMPTS.clear)
        self._maildir = os.path.join(self._tmp, "Maildir")
        self._inbox = mailbox.Maildir(self._maildir, create=True)

    def _deliver(self, source):
        if isinstance(source, str):
            with open(source, "rb") as source_file:
                raw = source_file.read()
        else:
            raw = source
        self._inbox.add(mailbox.MaildirMessage(raw))
        self._inbox.flush()

    def _run(self, connection=None, **kwargs):
        conn = connection or MaildirConnection(self._maildir, maildir_create=True)
        result = parsedmarc.get_dmarc_reports_from_mailbox(
            connection=conn, offline=True, **kwargs
        )
        return conn, result

    @staticmethod
    def _fail(batch):
        del batch
        return False

    def test_failed_save_callback_leaves_messages_in_inbox(self):
        """A save_callback returning False leaves the batch's messages in the
        INBOX untouched, while the parsed reports are still returned to the
        caller."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)

        conn, result = self._run(save_callback=self._fail)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 2)
        self.assertEqual(conn.fetch_messages("Archive/Aggregate"), [])
        self.assertEqual(conn.fetch_messages("Archive/Failure"), [])

    def test_failed_save_logs_an_error_naming_the_reports_folder(self):
        """The retry is logged at error level, not debug or warning: an
        output destination that keeps rejecting reports is something
        operators alert on."""
        self._deliver(self.AGGREGATE)

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            self._run(save_callback=self._fail)

        self.assertTrue(
            any(
                "Reports were not saved: leaving 1 message(s) in INBOX" in line
                for line in cm.output
            ),
            cm.output,
        )

    def test_failed_save_then_retry_is_not_deduplicated(self):
        """A failed save must not poison the aggregate-report dedup cache:
        the message stays in the INBOX and, on the next run, the same report
        is parsed and handed to save_callback again rather than being
        silently skipped as an already-seen duplicate."""
        self._deliver(self.AGGREGATE)

        conn, result = self._run(save_callback=self._fail)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)

        received = []
        conn, result = self._run(save_callback=received.append)

        self.assertEqual(len(received), 1)
        self.assertEqual(len(received[0]["aggregate_reports"]), 1)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)

    def test_save_callback_exception_leaves_messages(self):
        """An exception raised by save_callback counts as a failed save --
        the batch's messages stay in the reports folder and the attempt is
        recorded against the retry cap -- and is then re-raised to the
        caller."""
        self._deliver(self.AGGREGATE)

        def _boom(batch):
            del batch
            raise RuntimeError("sink is down")

        with self.assertRaises(RuntimeError):
            self._run(save_callback=_boom)

        conn = MaildirConnection(self._maildir, maildir_create=True)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertEqual(len(parsedmarc._FAILED_SAVE_ATTEMPTS), 1)
        # The dedup keys were staged, not committed, so the next run
        # reparses the report instead of dropping it as a duplicate.
        _, result = self._run(save_callback=None)
        self.assertEqual(len(result["aggregate_reports"]), 1)

    def test_save_callback_exception_still_bounded_by_the_retry_cap(self):
        """A callback that always raises -- the CLI's does, under
        fail_on_output_error -- is bounded by max_unsaved_retries exactly
        like one that returns False: the failure bookkeeping runs before the
        exception is re-raised, so the message moves to Archive/Unsaved at
        the cap instead of being re-delivered on every check forever. This
        matters because mailsuite's IMAP and Maildir watch loops swallow the
        exception and keep checking."""
        self._deliver(self.AGGREGATE)

        def _boom(batch):
            del batch
            raise RuntimeError("sink is down")

        with self.assertRaises(RuntimeError):
            self._run(save_callback=_boom, max_unsaved_retries=0)

        conn = MaildirConnection(self._maildir, maildir_create=True)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)
        self.assertEqual(parsedmarc._FAILED_SAVE_ATTEMPTS, {})

    def test_successful_save_callback_archives_messages(self):
        """A save_callback returning None (or any non-False value) commits the
        batch exactly as when no callback is supplied, and is handed that
        batch's parsed reports before any archiving happens."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)
        self._deliver(self.SMTP_TLS)

        conn = MaildirConnection(self._maildir, maildir_create=True)
        received = []

        def _record(batch):
            # Nothing has been archived yet at this point -- that is the
            # whole contract: the caller gets to veto the archiving.
            received.append((batch, len(conn.fetch_messages("INBOX"))))

        _, result = self._run(connection=conn, save_callback=_record)

        self.assertEqual(len(received), 1)
        batch, inbox_count_at_callback_time = received[0]
        self.assertEqual(len(batch["aggregate_reports"]), 1)
        self.assertEqual(len(batch["failure_reports"]), 1)
        self.assertEqual(len(batch["smtp_tls_reports"]), 1)
        self.assertEqual(inbox_count_at_callback_time, 3)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/SMTP-TLS")), 1)

    def test_failed_save_callback_with_delete_does_not_delete(self):
        """delete=True does not bypass the save_callback contract: a failed
        save leaves the message in place instead of deleting it, since the
        mailbox is the only remaining copy of the report."""
        self._deliver(self.FAILURE)

        conn, result = self._run(delete=True, save_callback=self._fail)

        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)

    def test_invalid_message_still_filed_when_save_fails(self):
        """An unparseable message carries no report data, so nothing about it
        can fail to save: it is filed to Archive/Invalid regardless of the
        callback's verdict, and only the successfully parsed report's message
        is held back."""
        self._deliver(self.JUNK)
        self._deliver(self.AGGREGATE)

        conn, result = self._run(save_callback=self._fail)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)

    def test_unsaved_folder_created_only_with_a_save_callback(self):
        """The Unsaved holding folder is only reachable when a callback can
        report a batch unsaved, so it is only created up front in that case
        -- it would otherwise sit empty in every user's mailbox. The
        without-callback half runs in a second, fresh Maildir: the first run
        already created the folder in the shared one, so its absence is only
        observable somewhere the callback never touched."""
        self._deliver(self.AGGREGATE)

        conn, _ = self._run(save_callback=lambda batch: None)
        self.assertTrue(conn.folder_exists("Archive/Unsaved"))

        other_maildir = os.path.join(self._tmp, "MaildirNoCallback")
        other_inbox = mailbox.Maildir(other_maildir, create=True)
        with open(self.FAILURE, "rb") as failure_file:
            other_inbox.add(mailbox.MaildirMessage(failure_file.read()))
        other_inbox.flush()
        other_conn = MaildirConnection(other_maildir, maildir_create=True)
        parsedmarc.get_dmarc_reports_from_mailbox(connection=other_conn, offline=True)
        self.assertTrue(other_conn.folder_exists("Archive/Failure"))
        self.assertFalse(other_conn.folder_exists("Archive/Unsaved"))

    def test_repeated_failures_move_the_message_to_unsaved(self):
        """With the default max_unsaved_retries of 2, a message stays in the
        reports folder through its first failed save and the retry after it,
        and moves to Archive/Unsaved on the third -- the initial attempt plus
        two retries, so a permanently broken output destination receives the
        same reports at most three times instead of forever."""
        self._deliver(self.AGGREGATE)

        for _ in range(2):
            conn, _ = self._run(save_callback=self._fail)
            self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
            self.assertEqual(conn.fetch_messages("Archive/Unsaved"), [])

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            conn, _ = self._run(save_callback=self._fail)

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)
        self.assertTrue(any("Archive/Unsaved" in line for line in cm.output), cm.output)

    def test_max_unsaved_retries_zero_moves_on_the_first_failure(self):
        """max_unsaved_retries=0 is valid and means "do not retry": the
        message moves to Archive/Unsaved the first time its batch fails to
        save."""
        self._deliver(self.AGGREGATE)

        conn, _ = self._run(save_callback=self._fail, max_unsaved_retries=0)

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)

    def test_unsaved_messages_are_moved_not_deleted(self):
        """A message that ran out of retries is moved to Unsaved even when
        every delete flag says delete: it holds the only copy of a report
        that was never saved anywhere, so deleting it is the one outcome
        this feature exists to prevent."""
        self._deliver(self.AGGREGATE)

        conn, _ = self._run(
            save_callback=self._fail, max_unsaved_retries=0, delete=True
        )

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)

    def test_successful_save_clears_the_retry_counters(self):
        """A successful save resets the batch's failure counts, so an
        unrelated failure later starts from zero rather than inheriting a
        near-cap count. The counters are asserted directly because the
        messages they were counting are archived on success, taking their
        own future behavior with them."""
        self._deliver(self.AGGREGATE)

        conn, _ = self._run(save_callback=self._fail)
        self.assertEqual(len(parsedmarc._FAILED_SAVE_ATTEMPTS), 1)

        conn, _ = self._run(save_callback=lambda batch: True)

        self.assertEqual(parsedmarc._FAILED_SAVE_ATTEMPTS, {})
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)

    def test_test_mode_invokes_the_callback_without_touching_anything(self):
        """test=True still runs the callback, so a test run exercises the
        whole output pipeline, but neither the mailbox nor the retry
        counters move regardless of the verdict -- even at
        max_unsaved_retries=0, which would otherwise file the message under
        Unsaved immediately."""
        self._deliver(self.AGGREGATE)

        received = []

        def _record_and_fail(batch):
            received.append(batch)
            return False

        conn = None
        for _ in range(2):
            conn, _ = self._run(
                save_callback=_record_and_fail, max_unsaved_retries=0, test=True
            )
        assert conn is not None

        self.assertEqual(len(received), 2)
        self.assertEqual(len(received[0]["aggregate_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertFalse(conn.folder_exists("Archive/Unsaved"))
        self.assertEqual(parsedmarc._FAILED_SAVE_ATTEMPTS, {})

    def test_unsaved_folder_is_created_when_folder_creation_was_skipped(self):
        """Watch mode calls in with create_folders=False, so the Unsaved
        folder may not exist by the time a message needs to go there. The
        defensive check before the move creates it."""
        self._deliver(self.AGGREGATE)
        conn = MaildirConnection(self._maildir, maildir_create=True)
        conn.create_folder("Archive")

        self._run(
            connection=conn,
            save_callback=self._fail,
            max_unsaved_retries=0,
            create_folders=False,
        )

        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)

    def test_unsaved_folder_check_failure_is_logged_not_raised(self):
        """A backend that cannot answer whether the Unsaved folder exists is
        warned about and skipped rather than crashing the run; the move
        itself is still attempted."""
        self._deliver(self.AGGREGATE)
        conn = _UncreatableFolderMaildirConnection(self._maildir, maildir_create=True)
        conn.create_folder("Archive")

        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            self._run(
                connection=conn,
                save_callback=self._fail,
                max_unsaved_retries=0,
                create_folders=False,
            )

        self.assertTrue(
            any(
                "Could not create folder Archive/Unsaved" in line for line in cm.output
            ),
            cm.output,
        )
        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)

    def test_failed_move_to_unsaved_is_logged_and_leaves_the_message(self):
        """A backend that rejects the move to Unsaved is logged like any
        other mailbox error, and the message simply stays in the reports
        folder -- it is never dropped."""
        self._deliver(self.AGGREGATE)
        conn = _FailingDisposalMaildirConnection(
            self._maildir, maildir_create=True, fail_move=True
        )

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            self._run(connection=conn, save_callback=self._fail, max_unsaved_retries=0)

        self.assertTrue(
            any(
                "Mailbox error: Error moving message UID" in line for line in cm.output
            ),
            cm.output,
        )
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Unsaved"), [])

    def test_failed_move_keeps_the_counter_so_the_move_is_retried(self):
        """A failed move to Unsaved must not reset the message's failure
        counter: the still-in-place message would otherwise get a fresh set
        of under-cap retries (and duplicate deliveries) each time the move
        failed. With the counter kept, the next failed save classifies the
        message over-cap again and re-attempts the move -- which succeeds
        here once the backend allows it. Cap 1 makes the distinction
        observable: were the counter reset by run 2's failed move, run 3
        would count the message back under the cap and leave it in the
        INBOX instead of moving it."""
        self._deliver(self.AGGREGATE)

        conn, _ = self._run(save_callback=self._fail, max_unsaved_retries=1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)

        failing_conn = _FailingDisposalMaildirConnection(
            self._maildir, maildir_create=True, fail_move=True
        )
        with self.assertLogs("parsedmarc.log", level="ERROR"):
            self._run(
                connection=failing_conn,
                save_callback=self._fail,
                max_unsaved_retries=1,
            )
        self.assertEqual(len(failing_conn.fetch_messages("INBOX")), 1)
        self.assertEqual(len(parsedmarc._FAILED_SAVE_ATTEMPTS), 1)

        conn, _ = self._run(save_callback=self._fail, max_unsaved_retries=1)

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)
        self.assertEqual(parsedmarc._FAILED_SAVE_ATTEMPTS, {})

    def test_failed_save_skips_the_batch_size_zero_re_check(self):
        """With batch_size=0 the function re-checks the folder and recurses
        on whatever is still there. After a failed save that would re-fetch
        the very messages just held back and burn the whole retry budget
        inside one call, so the re-check is skipped: one run costs a message
        exactly one retry."""
        self._deliver(self.AGGREGATE)

        conn, result = self._run(
            save_callback=self._fail, batch_size=0, max_unsaved_retries=1
        )

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Unsaved"), [])

    def test_save_callback_receives_each_batch_separately(self):
        """batch_size=0 recursion hands each fetched batch to the callback on
        its own, and each batch is archived before the next is fetched --
        the callback never sees an earlier batch's reports twice, while the
        returned results accumulate all of them."""
        self._deliver(self.AGGREGATE)
        conn = _MidRunArrivalMaildirConnection(
            self._maildir, maildir_create=True, extra_source=self.SMTP_TLS
        )
        received = []

        _, result = self._run(
            connection=conn, save_callback=received.append, batch_size=0
        )

        self.assertEqual(len(received), 2)
        self.assertEqual(len(received[0]["aggregate_reports"]), 1)
        self.assertEqual(received[0]["smtp_tls_reports"], [])
        self.assertEqual(received[1]["aggregate_reports"], [])
        self.assertEqual(len(received[1]["smtp_tls_reports"]), 1)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_failed_save_callback_parallel(self):
        """The n_procs>1 parsing branch stages its dedup keys and holds its
        messages back exactly like the sequential one; only parsing moves to
        the worker processes."""
        self._deliver(self.AGGREGATE)
        self._deliver(self.FAILURE)

        conn, result = self._run(save_callback=self._fail, n_procs=2)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 2)

        # The dedup keys were not committed, so a retry reparses.
        conn, result = self._run(save_callback=None, n_procs=2)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)


# Read by the worker job below, which runs in another process and so
# cannot be handed the test's temporary path any other way.
_WORKER_ATTEMPTS_FILE_VARIABLE = "TEST_ATTEMPTS_FILE_FOR_PARSE_WORKERS"


def _job_requiring_recorded_attempt(msg_content, *, config):
    """A parallel parse job that parses only a message whose attempt is
    already in the attempts file, and rejects any other as invalid.

    Module level so a process pool can pickle it under every start method.
    """
    with open(os.environ[_WORKER_ATTEMPTS_FILE_VARIABLE], encoding="utf-8") as f:
        attempts = json.load(f)["attempts"]
    digest = attempt_key("", "", msg_content).rsplit("\x1f", 1)[1]
    if not any(
        key.endswith("\x1f" + digest) and entry["count"] == 1
        for key, entry in attempts.items()
    ):
        return parsedmarc.InvalidDMARCReport("no attempt recorded before the job")
    return _parse_report_email_job(msg_content, config=config)


class _FailingInvalidMoveIMAPConnection(_InMemoryIMAPConnection):
    """The in-memory IMAP backend, refusing every move to the Invalid
    folder."""

    def move_message(self, message_id, folder_name):
        if folder_name.endswith("/Invalid"):
            raise RuntimeError("server said no")
        super().move_message(message_id, folder_name)


class _ArrivalIMAPConnection(_InMemoryIMAPConnection):
    """The in-memory IMAP backend, delivering one more message right after
    its first fetch_messages() call, so batch_size=0 recurses once."""

    def __init__(self, messages, extra_id, extra_content):
        super().__init__(messages)
        self._extra = (extra_id, extra_content)

    def fetch_messages(self, reports_folder, **kwargs):
        result = super().fetch_messages(reports_folder, **kwargs)
        if self._extra is not None:
            extra_id, extra_content = self._extra
            self._extra = None
            self.folders["INBOX"][extra_id] = extra_content
        return result


class _SingleCheckIMAPConnection(_InMemoryIMAPConnection):
    """The in-memory IMAP backend, whose watch() runs one check."""

    def watch(self, check_callback, check_timeout, config_reloading=None):
        del check_timeout, config_reloading
        check_callback(self)


class TestCrashedMessageAttempts(unittest.TestCase):
    """attempts_file: a message whose parse never finished (the process
    died) is counted in a JSON file, and once it has died
    MAX_PARSE_ATTEMPTS times it is set aside as invalid without being
    parsed again, so a one-shot run no longer dies on it forever
    (GHSA-qcc2-4x3v-v4g7, GHSA-q7gm-8cj9-94hr, GHSA-4272-4r8g-6c5h). The
    file is read and written for real; the process deaths are simulated by
    seeding the file with the count earlier runs would have left."""

    AGGREGATE = "samples/aggregate/twilight.eml"
    SMTP_TLS = "samples/smtp_tls/google.com_smtp_tls_report.eml"
    FAILURE = "samples/failure/dmarc_ruf_report_linkedin.eml"

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        parsedmarc._FAILED_SAVE_ATTEMPTS.clear()
        self.addCleanup(parsedmarc._FAILED_SAVE_ATTEMPTS.clear)
        self.path = os.path.join(self._tmp, "attempts.json")
        self.samples = {}
        for name in (self.AGGREGATE, self.SMTP_TLS, self.FAILURE):
            with open(name, encoding="utf-8") as sample:
                self.samples[name] = sample.read()

    def _seed(self, message_id, content, count):
        with open(self.path, "w", encoding="utf-8") as attempts_file:
            json.dump(
                {
                    "version": 1,
                    "attempts": {
                        attempt_key("INBOX", message_id, content): {
                            "count": count,
                            "last": datetime.now(timezone.utc).isoformat(),
                        }
                    },
                },
                attempts_file,
            )

    def _attempts(self):
        with open(self.path, encoding="utf-8") as attempts_file:
            return json.load(attempts_file)["attempts"]

    def _run(self, conn, **kwargs):
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        return parsedmarc.get_dmarc_reports_from_mailbox(
            connection=conn, offline=True, attempts_file=self.path, **kwargs
        )

    def test_attempt_is_recorded_before_the_parse_and_cleared_after(self):
        content = self.samples[self.AGGREGATE]
        key = attempt_key("INBOX", 1, content)
        seen_during_parse = []
        real_parse = parsedmarc.parse_report_email

        def parse_and_look(*args, **kwargs):
            seen_during_parse.append(self._attempts().get(key))
            return real_parse(*args, **kwargs)

        conn = _InMemoryIMAPConnection({1: content})
        with patch("parsedmarc.parse_report_email", parse_and_look):
            result = self._run(conn)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(seen_during_parse), 1)
        self.assertIsNotNone(seen_during_parse[0])
        self.assertEqual(seen_during_parse[0]["count"], 1)
        self.assertEqual(self._attempts(), {})
        self.assertEqual(list(conn.folders["Archive/Aggregate"]), [1])

    def test_unparseable_message_clears_its_attempt(self):
        """A ParserError is a finished parse: the message goes to Invalid
        as before and its attempt is not left behind to count as a crash."""
        junk = "From: noise@example.com\nSubject: not a report\n\nplain text\n"
        conn = _InMemoryIMAPConnection({1: junk})
        with self.assertLogs("parsedmarc.log", level="WARNING"):
            self._run(conn)
        self.assertEqual(list(conn.folders["Archive/Invalid"]), [1])
        self.assertEqual(self._attempts(), {})

    def test_message_at_the_cap_is_moved_to_invalid_without_parsing(self):
        crashed = self.samples[self.AGGREGATE]
        healthy = self.samples[self.SMTP_TLS]
        for n_procs in (1, 2):
            with self.subTest(n_procs=n_procs):
                self._seed(1, crashed, count=2)
                parsed = []
                real_parse = parsedmarc.parse_report_email

                def parse_and_note(content, *args, **kwargs):
                    parsed.append(content)
                    return real_parse(content, *args, **kwargs)

                conn = _InMemoryIMAPConnection({1: crashed, 2: healthy})
                with patch("parsedmarc.parse_report_email", parse_and_note):
                    with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
                        result = self._run(conn, n_procs=n_procs)

                self.assertEqual(result["aggregate_reports"], [])
                self.assertEqual(len(result["smtp_tls_reports"]), 1)
                self.assertEqual(conn.folders["INBOX"], {})
                self.assertEqual(list(conn.folders["Archive/Invalid"]), [1])
                self.assertEqual(list(conn.folders["Archive/SMTP-TLS"]), [2])
                self.assertIn(
                    "Message UID 1 in INBOX has crashed parsedmarc 2 time(s) "
                    "before it could be parsed; moving it to Archive/Invalid "
                    "without parsing it",
                    "\n".join(cm.output),
                )
                self.assertNotIn(crashed, parsed)
                if n_procs == 1:
                    self.assertEqual(parsed, [healthy])
                # Out of the folder, so the entry is gone.
                self.assertEqual(self._attempts(), {})

    def test_message_below_the_cap_is_parsed_again(self):
        """One unfinished attempt (a crash for any reason) is not enough:
        the message is parsed again, and a successful parse clears it."""
        content = self.samples[self.AGGREGATE]
        self._seed(1, content, count=1)
        conn = _InMemoryIMAPConnection({1: content})
        result = self._run(conn)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(list(conn.folders["Archive/Aggregate"]), [1])
        self.assertEqual(self._attempts(), {})

    def test_message_at_the_cap_is_deleted_with_delete_invalid(self):
        content = self.samples[self.AGGREGATE]
        for n_procs in (1, 2):
            with self.subTest(n_procs=n_procs):
                self._seed(1, content, count=2)
                conn = _InMemoryIMAPConnection(
                    {1: content, 2: self.samples[self.SMTP_TLS]}
                )
                with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
                    self._run(conn, n_procs=n_procs, delete_invalid=True)
                self.assertEqual(conn.folders["INBOX"], {})
                self.assertEqual(conn.folders["Archive/Invalid"], {})
                self.assertEqual(conn.folders["Archive/Aggregate"], {})
                self.assertIn(
                    "has crashed parsedmarc 2 time(s) before it could be "
                    "parsed; deleting it without parsing it",
                    "\n".join(cm.output),
                )
                self.assertEqual(self._attempts(), {})

    def test_failed_save_is_not_counted_as_a_crash(self):
        """The attempt is cleared when the parse returns, before the save,
        so a batch an output keeps rejecting stays in the folder for the
        Unsaved retry logic and is never set aside as a crashed message."""
        content = self.samples[self.AGGREGATE]
        conn = _InMemoryIMAPConnection({1: content})
        for _ in range(MAX_PARSE_ATTEMPTS + 2):
            with self.assertLogs("parsedmarc.log", level="ERROR"):
                self._run(
                    conn, save_callback=lambda batch: False, max_unsaved_retries=10
                )
            self.assertEqual(self._attempts(), {})
        self.assertEqual(list(conn.folders["INBOX"]), [1])
        self.assertEqual(conn.folders["Archive/Invalid"], {})

    def test_test_mode_records_and_clears_but_moves_nothing(self):
        crashed = self.samples[self.AGGREGATE]
        healthy = self.samples[self.SMTP_TLS]
        junk = "From: noise@example.com\nSubject: not a report\n\nplain text\n"
        self._seed(1, crashed, count=2)
        conn = _InMemoryIMAPConnection({1: crashed, 2: healthy, 3: junk})

        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            result = self._run(conn, test=True)

        self.assertEqual(result["aggregate_reports"], [])
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertEqual(sorted(conn.folders["INBOX"]), [1, 2, 3])
        self.assertNotIn("Archive/Invalid", conn.folders)
        self.assertIn(
            "leaving it in place without parsing it (test mode)",
            "\n".join(cm.output),
        )
        # The set-aside message is still in the folder, so its count stays;
        # the parsed and the unparseable ones were recorded and cleared.
        attempts = self._attempts()
        self.assertEqual(list(attempts), [attempt_key("INBOX", 1, crashed)])
        self.assertEqual(attempts[attempt_key("INBOX", 1, crashed)]["count"], 3)

    def test_parallel_path_records_each_attempt_before_submitting_it(self):
        conn = _InMemoryIMAPConnection(
            {1: self.samples[self.AGGREGATE], 2: self.samples[self.SMTP_TLS]}
        )
        with patch.dict(os.environ, {_WORKER_ATTEMPTS_FILE_VARIABLE: self.path}):
            with patch(
                "parsedmarc.parallel._parse_report_email_job",
                _job_requiring_recorded_attempt,
            ):
                result = self._run(conn, n_procs=2)

        # The job rejects a message whose attempt was not yet on disk, which
        # would have sent it to Invalid.
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertNotIn(1, conn.folders["Archive/Invalid"])
        self.assertNotIn(2, conn.folders["Archive/Invalid"])
        self.assertEqual(self._attempts(), {})

    def test_parallel_path_parses_a_suspect_alone_in_this_process(self):
        """With n_procs > 1 a run that died had several messages in flight,
        and only one of them killed it. A message with one unfinished
        attempt is therefore not submitted to the pool beside others: it is
        parsed in this process after them, its attempt recorded first, so a
        second death counts against it alone and the messages parsed beside
        it the first time are not set aside with it."""
        suspect = self.samples[self.AGGREGATE]
        others = {2: self.samples[self.SMTP_TLS], 3: self.samples[self.FAILURE]}
        self._seed(1, suspect, count=1)
        key = attempt_key("INBOX", 1, suspect)
        parsed_here = []
        real_parse = parsedmarc.parse_report_email
        parent = os.getpid()

        def parse_and_look(content, *args, **kwargs):
            if os.getpid() == parent:
                parsed_here.append((content, self._attempts().get(key)))
            return real_parse(content, *args, **kwargs)

        conn = _InMemoryIMAPConnection({1: suspect, **others})
        with patch("parsedmarc.parse_report_email", parse_and_look):
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                result = self._run(conn, n_procs=2)

        self.assertEqual(len(parsed_here), 1)
        self.assertEqual(parsed_here[0][0], suspect)
        self.assertEqual(parsed_here[0][1]["count"], 2)
        self.assertIn(
            "Message UID 1 in INBOX was being parsed when parsedmarc last "
            "stopped without finishing; parsing it on its own",
            "\n".join(cm.output),
        )
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(conn.folders["INBOX"], {})
        self.assertEqual(self._attempts(), {})

    def _recording_parallel_map(self, calls, jobs_seen):
        """``_parallel_map_timing_out`` that also notes each job it is
        given, per call, as the call consumes it."""
        fake = _parallel_map_timing_out(calls)

        def recording(func, jobs, n_procs, **kwargs):
            seen = []
            jobs_seen.append(seen)

            def noted():
                for job in jobs:
                    seen.append(job)
                    yield job

            return fake(func, noted(), n_procs, **kwargs)

        return recording

    def test_suspect_parse_is_bounded_by_parse_timeout(self):
        """With parse_timeout set, a suspect is parsed alone in a worker
        pool of its own rather than in this process, where the timeout
        could not stop it; one that times out goes to Invalid like any
        other timed-out message and its attempt is cleared."""
        others = {2: self.samples[self.AGGREGATE], 3: self.samples[self.SMTP_TLS]}
        for n_procs in (1, 2):
            with self.subTest(n_procs=n_procs):
                self._seed(1, _SLOW_MESSAGE, count=1)
                calls = []
                jobs_seen = []
                conn = _InMemoryIMAPConnection({1: _SLOW_MESSAGE, **others})
                with (
                    patch(
                        "parsedmarc.parallel.parallel_map",
                        self._recording_parallel_map(calls, jobs_seen),
                    ),
                    self.assertLogs("parsedmarc.log", level="WARNING") as cm,
                ):
                    result = self._run(conn, n_procs=n_procs, parse_timeout=1.0)

                self.assertEqual(len(calls), 2)
                self.assertNotIn(_SLOW_MESSAGE, jobs_seen[0])
                self.assertEqual(jobs_seen[1], [_SLOW_MESSAGE])
                self.assertEqual(calls[1]["n_procs"], 1)
                self.assertEqual(calls[1]["parse_timeout"], 1.0)
                self.assertEqual(calls[1]["heartbeat"], conn.keepalive)
                self.assertIn(
                    "longer than parse_timeout (1 seconds)", "\n".join(cm.output)
                )
                self.assertEqual(list(conn.folders["Archive/Invalid"]), [1])
                self.assertEqual(len(result["aggregate_reports"]), 1)
                self.assertEqual(len(result["smtp_tls_reports"]), 1)
                self.assertEqual(conn.folders["INBOX"], {})
                self.assertEqual(self._attempts(), {})

    def test_suspect_without_parse_timeout_is_parsed_in_this_process(self):
        """Without a timeout nothing would bound a worker any better than
        this process, so the suspect is not given to parallel_map."""
        suspect = self.samples[self.AGGREGATE]
        self._seed(1, suspect, count=1)
        calls = []
        jobs_seen = []
        conn = _InMemoryIMAPConnection({1: suspect, 2: self.samples[self.SMTP_TLS]})
        with (
            patch(
                "parsedmarc.parallel.parallel_map",
                self._recording_parallel_map(calls, jobs_seen),
            ),
            self.assertLogs("parsedmarc.log", level="WARNING"),
        ):
            result = self._run(conn, n_procs=2)

        self.assertEqual(len(calls), 1)
        self.assertNotIn(suspect, jobs_seen[0])
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertEqual(conn.folders["INBOX"], {})
        self.assertEqual(self._attempts(), {})

    def test_failed_disposal_keeps_the_entry(self):
        """The entry is cleared only once the message has left the folder:
        a move the server refuses leaves the count in place, so the next
        run sets the message aside again instead of parsing it."""
        content = self.samples[self.AGGREGATE]
        key = attempt_key("INBOX", 1, content)
        for n_procs in (1, 2):
            with self.subTest(n_procs=n_procs):
                self._seed(1, content, count=2)
                conn = _FailingInvalidMoveIMAPConnection(
                    {1: content, 2: self.samples[self.SMTP_TLS]}
                )
                with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
                    self._run(conn, n_procs=n_procs)
                self.assertEqual(list(conn.folders["INBOX"]), [1])
                self.assertEqual(self._attempts()[key]["count"], 3)
                self.assertIn(
                    "Error moving invalid message UID 1", "\n".join(cm.output)
                )

    def test_batch_size_zero_recursion_forwards_the_attempts_file(self):
        """A message that arrives during the run is processed by the
        recursive re-check call, which must use the same attempts file."""
        crashed = self.samples[self.SMTP_TLS]
        self._seed(2, crashed, count=2)
        conn = _ArrivalIMAPConnection(
            {1: self.samples[self.AGGREGATE]}, extra_id=2, extra_content=crashed
        )
        with self.assertLogs("parsedmarc.log", level="ERROR"):
            result = self._run(conn, batch_size=0)
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(result["smtp_tls_reports"], [])
        self.assertEqual(list(conn.folders["Archive/Invalid"]), [2])

    def test_watch_inbox_forwards_the_attempts_file(self):
        crashed = self.samples[self.AGGREGATE]
        self._seed(1, crashed, count=2)
        conn = _SingleCheckIMAPConnection({1: crashed})
        conn.create_folder("Archive/Invalid")
        with self.assertLogs("parsedmarc.log", level="ERROR"):
            parsedmarc.watch_inbox(
                conn,
                lambda batch: None,
                offline=True,
                attempts_file=self.path,
            )
        self.assertEqual(list(conn.folders["Archive/Invalid"]), [1])
        self.assertEqual(self._attempts(), {})

    def test_no_attempts_file_keeps_no_record(self):
        content = self.samples[self.AGGREGATE]
        self._seed(1, content, count=5)
        conn = _InMemoryIMAPConnection({1: content})
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        result = parsedmarc.get_dmarc_reports_from_mailbox(
            connection=conn, offline=True
        )
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(list(conn.folders["Archive/Aggregate"]), [1])
        # The file is neither consulted nor written.
        self.assertEqual(self._attempts()[attempt_key("INBOX", 1, content)]["count"], 5)


class _MidRunArrivalMaildirConnection(MaildirConnection):
    """A MaildirConnection that delivers one extra message into the INBOX
    right after its first fetch_messages() call returns, simulating mail
    arriving while the first batch is being processed.

    Used only to make get_dmarc_reports_from_mailbox's batch_size=0
    tail-recursion branch (`if not test and not batch_size:`) actually
    recurse once for real -- no parsedmarc internals are mocked, only this
    real mailsuite MaildirConnection subclass's timing -- so the n_procs
    pass-through in that recursive call is genuinely exercised rather than
    merely inspected. The recursive call's own re-check then finds nothing
    further (the extra message has already been archived), so recursion
    terminates after one extra level -- cheap and deterministic.
    """

    def __init__(self, *args, extra_source, **kwargs):
        super().__init__(*args, **kwargs)
        self._extra_source = extra_source
        self._delivered_extra = False

    def fetch_messages(self, reports_folder, **kwargs):
        result = super().fetch_messages(reports_folder, **kwargs)
        if not self._delivered_extra:
            self._delivered_extra = True
            with open(self._extra_source, "rb") as extra_file:
                raw = extra_file.read()
            box = mailbox.Maildir(self._maildir_path, create=False)
            box.add(mailbox.MaildirMessage(raw))
            box.flush()
        return result


class TestGetDmarcReportsFromMailboxMaildirBatchSizeZeroRecursion(unittest.TestCase):
    """batch_size=0 makes get_dmarc_reports_from_mailbox re-check the
    mailbox after its main pass and recurse if new messages showed up
    (__init__.py's `if not test and not batch_size:` block). This exercises
    that recursive call with n_procs=2 threaded through it for real."""

    AGGREGATE = "samples/aggregate/twilight.eml"
    FAILURE = "samples/failure/dmarc_ruf_report_linkedin.eml"
    SMTP_TLS = "samples/smtp_tls/google.com_smtp_tls_report.eml"

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        self._maildir = os.path.join(self._tmp, "Maildir")
        inbox = mailbox.Maildir(self._maildir, create=True)
        for source in (self.AGGREGATE, self.FAILURE):
            with open(source, "rb") as source_file:
                inbox.add(mailbox.MaildirMessage(source_file.read()))
        inbox.flush()

    def test_batch_size_zero_recursion_threads_n_procs(self):
        conn = _MidRunArrivalMaildirConnection(
            self._maildir, maildir_create=True, extra_source=self.SMTP_TLS
        )

        result = parsedmarc.get_dmarc_reports_from_mailbox(
            connection=conn, offline=True, n_procs=2, batch_size=0
        )

        # The main pass parses AGGREGATE + FAILURE; the message that "arrives"
        # after the main pass's fetch is only found and parsed via the
        # recursive re-check call, which would be missing from the results
        # entirely if the n_procs kwarg (or anything else) were dropped from
        # that recursive call.
        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(len(result["failure_reports"]), 1)
        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])

    def test_batch_size_zero_recursion_threads_per_type_delete(self):
        """The per-report-type delete flags must be threaded through the
        recursive re-check call too. The SMTP TLS report only "arrives" after
        the main pass's fetch, so it is disposed of by the recursive call: with
        delete_smtp_tls=True it must be deleted, not archived. Dropping the
        kwarg from the recursive call archives it instead and fails here."""
        conn = _MidRunArrivalMaildirConnection(
            self._maildir, maildir_create=True, extra_source=self.SMTP_TLS
        )

        result = parsedmarc.get_dmarc_reports_from_mailbox(
            connection=conn, offline=True, batch_size=0, delete_smtp_tls=True
        )

        self.assertEqual(len(result["smtp_tls_reports"]), 1)
        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(conn.fetch_messages("Archive/SMTP-TLS"), [])
        # The types that inherit the (False) delete default are unaffected.
        self.assertEqual(len(conn.fetch_messages("Archive/Aggregate")), 1)
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)


class _SingleCheckMaildirConnection(MaildirConnection):
    """A MaildirConnection whose watch() performs exactly one check.

    mailsuite's own MaildirConnection.watch() loops forever (sleeping
    check_timeout seconds between checks) and swallows every exception the
    callback raises, so it cannot be driven from a test as-is. This override
    keeps the same signature, invokes watch_inbox's check_callback once, lets
    exceptions propagate, and returns -- so the real closure inside
    watch_inbox runs against a real on-disk Maildir, with no parsedmarc
    internals mocked.
    """

    def watch(
        self,
        check_callback: Callable[[parsedmarc.MailboxConnection], None],
        check_timeout: int,
        config_reloading: Callable[[], bool] | None = None,
    ) -> None:
        del check_timeout, config_reloading
        check_callback(self)


class TestWatchInboxMaildir(unittest.TestCase):
    """watch_inbox builds a check_callback closure that calls
    get_dmarc_reports_from_mailbox on every mailbox check. Everything watch
    mode does to messages therefore flows through that closure, which is
    reached only via the backend's watch() -- so it needs a connection whose
    watch() actually runs one check (see _SingleCheckMaildirConnection)."""

    FAILURE = "samples/failure/dmarc_ruf_report_linkedin.eml"
    JUNK = b"From: noise@example.com\nSubject: not a report\n\nplain text\n"

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        self._maildir = os.path.join(self._tmp, "Maildir")
        inbox = mailbox.Maildir(self._maildir, create=True)
        with open(self.FAILURE, "rb") as failure_file:
            inbox.add(mailbox.MaildirMessage(failure_file.read()))
        inbox.add(mailbox.MaildirMessage(self.JUNK))
        inbox.flush()

    def test_watch_inbox_forwards_per_type_delete_flags(self):
        """Trip-wire for the per-report-type delete flags on watch_inbox's
        inner call: delete=True with delete_failure=False must archive the
        failure report message while the unparseable message, inheriting
        delete=True, is deleted. Dropping delete_failure from the closure
        would silently delete the failure report message instead -- watch
        mode ignoring what the caller asked for -- and fail here."""
        conn = _SingleCheckMaildirConnection(self._maildir, maildir_create=True)
        # watch_inbox passes create_folders=False (in real watch mode the
        # archive folders already exist, created by the run's first pass), so
        # the destination folder and its parent are seeded here.
        conn.create_folder("Archive")
        conn.create_folder("Archive/Failure")
        received = []

        parsedmarc.watch_inbox(
            mailbox_connection=conn,
            callback=received.append,
            offline=True,
            delete=True,
            delete_failure=False,
        )

        # The results reach the callback through the same closure.
        self.assertEqual(len(received), 1)
        self.assertEqual(len(received[0]["failure_reports"]), 1)

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Failure")), 1)
        # delete_invalid inherited delete=True, so the unparseable message was
        # deleted rather than filed in the Invalid subfolder.
        self.assertFalse(conn.folder_exists("Archive/Invalid"))

    def test_watch_inbox_callback_returning_false_defers_the_batch(self):
        """watch_inbox's callback is the batch's save_callback, not a
        notification that runs after archiving: returning False leaves the
        failure report message in the INBOX for the next check. Before this
        was wired through, watch mode archived every batch first and told the
        callback afterward, which is the data-loss path of #242."""
        parsedmarc._FAILED_SAVE_ATTEMPTS.clear()
        self.addCleanup(parsedmarc._FAILED_SAVE_ATTEMPTS.clear)
        conn = _SingleCheckMaildirConnection(self._maildir, maildir_create=True)
        conn.create_folder("Archive")
        conn.create_folder("Archive/Invalid")
        received = []

        def _record_and_fail(batch):
            received.append(batch)
            return False

        parsedmarc.watch_inbox(
            mailbox_connection=conn,
            callback=_record_and_fail,
            offline=True,
        )

        self.assertEqual(len(received), 1)
        self.assertEqual(len(received[0]["failure_reports"]), 1)
        self.assertEqual(len(conn.fetch_messages("INBOX")), 1)
        self.assertEqual(conn.fetch_messages("Archive/Failure"), [])
        # The unparseable message carries no report data and is filed either
        # way, so only the report message is held back.
        self.assertEqual(len(conn.fetch_messages("Archive/Invalid")), 1)

    def test_watch_inbox_forwards_max_unsaved_retries(self):
        """max_unsaved_retries reaches the per-check mailbox call: with 0,
        the first failed save in watch mode files the message under
        Archive/Unsaved instead of leaving it for the next check."""
        parsedmarc._FAILED_SAVE_ATTEMPTS.clear()
        self.addCleanup(parsedmarc._FAILED_SAVE_ATTEMPTS.clear)
        conn = _SingleCheckMaildirConnection(self._maildir, maildir_create=True)
        conn.create_folder("Archive")
        conn.create_folder("Archive/Invalid")

        parsedmarc.watch_inbox(
            mailbox_connection=conn,
            callback=lambda batch: False,
            offline=True,
            max_unsaved_retries=0,
        )

        self.assertEqual(conn.fetch_messages("INBOX"), [])
        self.assertEqual(len(conn.fetch_messages("Archive/Unsaved")), 1)


class TestEmailResultsErrorBranches(unittest.TestCase):
    """email_results requires mail_to to be a list — this is enforced
    by an assert. A regression that dropped the assert would mean the
    SMTP code further down would silently iterate over the characters
    of a string."""

    def test_mail_to_must_be_list(self):
        with self.assertRaises(AssertionError):
            parsedmarc.email_results(
                {
                    "aggregate_reports": [],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
                host="smtp.example.com",
                mail_from="from@example.com",
                # str, not list — triggers assert
                mail_to="admin@example.com",  # pyright: ignore[reportArgumentType]
            )


def _fake_smtp_class(kind: str, calls: list, *, advertise_starttls: bool) -> type:
    """Build a stand-in for ``smtplib.SMTP`` / ``smtplib.SMTP_SSL`` that
    appends every call it receives to ``calls``, in order, so a test can
    assert what happened on the wire and in which order (modeled on the fake
    in mailsuite's ``tests/test_smtp.py``). ``kind`` names the patched class
    in the constructor entry, and ``advertise_starttls`` decides whether the
    EHLO reply lists STARTTLS -- ``False`` plays a server, or an on-path
    attacker, that strips it (GHSA-3588-2mr7-vrcm)."""

    class _FakeSMTP:
        def __init__(self, host="", port=0, *args, **kwargs):
            calls.append((kind, host, port))

        def ehlo_or_helo_if_needed(self):
            calls.append(("ehlo",))

        def ehlo(self):
            calls.append(("ehlo",))

        def has_extn(self, name):
            return name.lower() == "starttls" and advertise_starttls

        def starttls(self, context=None):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user, password))

        def auth(self, mechanism, authobject, **kwargs):
            calls.append(("auth", mechanism))

        def sendmail(self, sender, to, msg):
            calls.append(("sendmail", sender, sorted(to), msg))

    return _FakeSMTP


class TestEmailResultsStartTLS(unittest.TestCase):
    """GHSA-3588-2mr7-vrcm: with ``require_encryption=False``,
    ``email_results()`` used to authenticate in plain text whenever the
    server's EHLO reply did not list STARTTLS, so an on-path attacker who
    stripped STARTTLS from that reply received the SMTP credentials and the
    report. With mailsuite >= 2.3.4 the default (``starttls=None``) refuses
    to send credentials over a connection that was not upgraded, and
    ``starttls=False`` is the explicit plain-text opt-out. These tests patch
    ``smtplib`` itself (the SDK boundary under mailsuite's ``send_email()``)
    and assert on the recorded calls and their payloads."""

    PASSWORD = "Sup3rSecret-placeholder"

    def _send(self, *, advertise_starttls: bool, **kwargs) -> list:
        calls: list = []
        with (
            patch(
                "smtplib.SMTP",
                _fake_smtp_class("SMTP", calls, advertise_starttls=advertise_starttls),
            ),
            patch(
                "smtplib.SMTP_SSL",
                _fake_smtp_class(
                    "SMTP_SSL", calls, advertise_starttls=advertise_starttls
                ),
            ),
        ):
            try:
                parsedmarc.email_results(
                    {
                        "aggregate_reports": [],
                        "failure_reports": [],
                        "smtp_tls_reports": [],
                    },
                    "smtp.example.com",
                    "dmarc@example.com",
                    ["admin@example.com"],
                    port=587,
                    **kwargs,
                )
            finally:
                self.calls = calls
        return calls

    def _names(self, calls: list) -> list:
        return [call[0] for call in calls]

    def testCredentialsWithoutStartTLSAreRefused(self):
        """GHSA-3588-2mr7-vrcm: by default, credentials are never sent when
        the server does not advertise STARTTLS. The send fails with
        mailsuite's SMTPError before LOGIN, nothing is sent, and the
        password appears nowhere in the error or its traceback."""
        from mailsuite.smtp import SMTPError

        with self.assertRaises(SMTPError) as ctx:
            self._send(
                advertise_starttls=False,
                username="dmarc@example.com",
                password=self.PASSWORD,
            )

        names = self._names(self.calls)
        self.assertEqual(names[0], "SMTP")
        self.assertNotIn("SMTP_SSL", names)
        self.assertNotIn("login", names)
        self.assertNotIn("auth", names)
        self.assertNotIn("sendmail", names)
        self.assertIn("STARTTLS", str(ctx.exception))
        formatted = "".join(
            traceback.format_exception(
                type(ctx.exception), ctx.exception, ctx.exception.__traceback__
            )
        )
        self.assertNotIn(self.PASSWORD, formatted)

    def testStartTLSPrecedesLoginAndSend(self):
        """When the server advertises STARTTLS, the connection is upgraded
        before LOGIN, LOGIN gets the configured credentials, and the report
        is sent last (GHSA-3588-2mr7-vrcm)."""
        calls = self._send(
            advertise_starttls=True,
            username="dmarc@example.com",
            password=self.PASSWORD,
        )

        names = self._names(calls)
        self.assertEqual(calls[0], ("SMTP", "smtp.example.com", 587))
        self.assertLess(names.index("starttls"), names.index("login"))
        self.assertLess(names.index("login"), names.index("sendmail"))
        login = calls[names.index("login")]
        self.assertEqual(login, ("login", "dmarc@example.com", self.PASSWORD))
        sendmail = calls[names.index("sendmail")]
        self.assertEqual(sendmail[1], "dmarc@example.com")
        self.assertEqual(sendmail[2], ["admin@example.com"])
        self.assertIn("Subject: DMARC results for ", sendmail[3])
        self.assertIn('filename="DMARC-', sendmail[3])

    def testRequireEncryptionUsesImplicitTLS(self):
        """``require_encryption=True`` connects with ``SMTP_SSL`` and never
        issues STARTTLS, whatever ``starttls`` says (GHSA-3588-2mr7-vrcm)."""
        for starttls in (None, True, False):
            with self.subTest(starttls=starttls):
                calls = self._send(
                    advertise_starttls=False,
                    require_encryption=True,
                    starttls=starttls,
                    username="dmarc@example.com",
                    password=self.PASSWORD,
                )
                names = self._names(calls)
                self.assertEqual(calls[0], ("SMTP_SSL", "smtp.example.com", 587))
                self.assertNotIn("SMTP", names)
                self.assertNotIn("starttls", names)
                self.assertLess(names.index("login"), names.index("sendmail"))

    def testNoCredentialsWithoutStartTLSSendsWithWarning(self):
        """Without credentials there is nothing to steal at login, so a
        server without STARTTLS still gets the message in plain text, with
        mailsuite's warning (GHSA-3588-2mr7-vrcm scope)."""
        with self.assertLogs("mailsuite.smtp", level="WARNING") as logs:
            calls = self._send(advertise_starttls=False)

        names = self._names(calls)
        self.assertNotIn("starttls", names)
        self.assertNotIn("login", names)
        self.assertEqual(names[-1], "sendmail")
        self.assertTrue(
            any("does not support STARTTLS" in line for line in logs.output),
            logs.output,
        )

    def testStartTLSFalseAuthenticatesInPlainText(self):
        """``starttls=False`` is the explicit opt-out from
        GHSA-3588-2mr7-vrcm's fix: credentials are sent without STARTTLS,
        with a warning."""
        with self.assertLogs("mailsuite.smtp", level="WARNING") as logs:
            calls = self._send(
                advertise_starttls=False,
                starttls=False,
                username="dmarc@example.com",
                password=self.PASSWORD,
            )

        names = self._names(calls)
        self.assertNotIn("starttls", names)
        self.assertEqual(
            calls[names.index("login")],
            ("login", "dmarc@example.com", self.PASSWORD),
        )
        self.assertLess(names.index("login"), names.index("sendmail"))
        self.assertTrue(any("unencrypted" in line for line in logs.output), logs.output)

    def testStartTLSFalseNeverUpgradesEvenWhenAdvertised(self):
        """``starttls=False`` never upgrades, even when the server
        advertises STARTTLS (GHSA-3588-2mr7-vrcm opt-out semantics)."""
        calls = self._send(
            advertise_starttls=True,
            starttls=False,
            username="dmarc@example.com",
            password=self.PASSWORD,
        )

        names = self._names(calls)
        self.assertNotIn("starttls", names)
        self.assertLess(names.index("login"), names.index("sendmail"))

    def testStartTLSTrueRefusesWithoutAdvertisement(self):
        """``starttls=True`` requires the upgrade: no STARTTLS in the EHLO
        reply raises before anything is sent, even without credentials
        (GHSA-3588-2mr7-vrcm)."""
        from mailsuite.smtp import SMTPError

        with self.assertRaises(SMTPError):
            self._send(advertise_starttls=False, starttls=True)

        names = self._names(self.calls)
        self.assertNotIn("sendmail", names)
        self.assertNotIn("login", names)


class TestEmailResultsViaMsGraph(unittest.TestCase):
    """email_results_via_msgraph() shares its
    subject/message/attachment-building logic with email_results() via the
    extracted _build_report_email_content() helper, so both transports stay
    in lockstep instead of drifting into two different sets of defaults."""

    @staticmethod
    def _results() -> ParsingResults:
        return {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

    def testEmailResultsViaMsGraphBuildsSameContentAsEmailResults(self):
        connection = MagicMock(spec=MSGraphConnection, mailbox_name="mb@example.com")
        results = self._results()

        parsedmarc.email_results_via_msgraph(results, connection, ["admin@example.com"])

        connection.send_message.assert_called_once()
        graph_kwargs = connection.send_message.call_args.kwargs

        with patch("parsedmarc.send_email") as mock_send_email:
            parsedmarc.email_results(
                results,
                host="smtp.example.com",
                mail_from="from@example.com",
                mail_to=["admin@example.com"],
            )
        mock_send_email.assert_called_once()
        smtp_kwargs = mock_send_email.call_args.kwargs

        self.assertEqual(graph_kwargs["subject"], smtp_kwargs["subject"])
        self.assertEqual(graph_kwargs["plain_message"], smtp_kwargs["plain_message"])
        self.assertEqual(
            graph_kwargs["attachments"][0][0],
            smtp_kwargs["attachments"][0][0],
        )
        self.assertEqual(graph_kwargs["message_to"], ["admin@example.com"])
        self.assertEqual(graph_kwargs["message_from"], "mb@example.com")

    def testEmailResultsViaMsGraphAppendsZipExtension(self):
        connection = MagicMock(spec=MSGraphConnection, mailbox_name="mb@example.com")

        parsedmarc.email_results_via_msgraph(
            self._results(),
            connection,
            ["admin@example.com"],
            attachment_filename="report",
        )

        graph_kwargs = connection.send_message.call_args.kwargs
        self.assertEqual(graph_kwargs["attachments"][0][0], "report.zip")


class TestAppendJson(unittest.TestCase):
    """append_json writes new files cleanly and merges into existing
    JSON arrays without breaking valid JSON."""

    def test_writes_new_file(self):
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        os.remove(path)  # ensure file is fresh
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"a": 1}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"a": 1}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_appends_to_existing_file(self):
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"a": 1}]))
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"b": 2}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"a": 1}, {"b": 2}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_empty_list_on_existing_file_is_noop(self):
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"a": 1}]))
            parsedmarc.append_json(path, [])
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"a": 1}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_corrupt_existing_file_is_overwritten_cleanly(self):
        """If the existing JSON file is corrupt (e.g. truncated by a
        prior crash, or hit the pre-fix `append_json` bug), the
        read-merge-write path falls back to overwriting with the new
        content rather than silently failing to record.

        Recording at the cost of losing prior corrupt data is the
        lesser evil — those bytes are already unparseable, so no
        downstream consumer can read them anyway."""
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write("{ this is not valid json at all")
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"new": "data"}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"new": "data"}])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_existing_file_with_non_list_root_is_overwritten(self):
        """If the existing file parses cleanly but the root isn't a
        list (e.g. someone wrote {"foo": 1} by hand), the
        isinstance(loaded, list) guard kicks in and we overwrite
        rather than concatenating a dict and a list."""
        with NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            tf.write('{"not": "a list"}')
            path = tf.name
        try:
            parsedmarc.append_json(path, cast(list[AggregateReport], [{"new": "data"}]))
            with open(path) as f:
                data = json.loads(f.read())
            self.assertEqual(data, [{"new": "data"}])
        finally:
            if os.path.exists(path):
                os.remove(path)


class TestAppendCsv(unittest.TestCase):
    def test_writes_new_file_with_header(self):
        with NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
            path = tf.name
        os.remove(path)
        try:
            parsedmarc.append_csv(path, "h1,h2\nv1,v2\n")
            with open(path) as f:
                content = f.read()
            self.assertEqual(content, "h1,h2\nv1,v2\n")
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_appends_strips_header_on_existing_file(self):
        """Second append must not re-emit the header line."""
        with NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_csv(path, "h1,h2\nv1,v2\n")
            parsedmarc.append_csv(path, "h1,h2\nv3,v4\n")
            with open(path) as f:
                content = f.read()
            # Only one header line in the merged output.
            self.assertEqual(content.count("h1,h2"), 1)
            self.assertIn("v3,v4", content)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_append_empty_csv_on_existing_file_is_noop(self):
        """append_csv with just a header row (no data) should not
        rewrite the file when one already exists."""
        with NamedTemporaryFile("w", suffix=".csv", delete=False) as tf:
            path = tf.name
        try:
            parsedmarc.append_csv(path, "h1,h2\nv1,v2\n")
            parsedmarc.append_csv(path, "h1,h2\n")
            with open(path) as f:
                content = f.read()
            # File unchanged.
            self.assertEqual(content, "h1,h2\nv1,v2\n")
        finally:
            if os.path.exists(path):
                os.remove(path)


def _minimal_aggregate_xml(
    policy_published: str = (
        "<policy_published><domain>example.com</domain><p>none</p></policy_published>"
    ),
    org_name: str = "TestOrg",
    email: str = "test@example.com",
    reason: str = "",
) -> str:
    """A minimal, valid aggregate report with substitutable sections."""
    return f"""<?xml version="1.0"?>
    <feedback>
        <report_metadata>
            <org_name>{org_name}</org_name>
            <email>{email}</email>
            <report_id>edge-case</report_id>
            <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
        </report_metadata>
        {policy_published}
        <record>
            <row>
                <source_ip>192.0.2.1</source_ip>
                <count>1</count>
                <policy_evaluated>
                    <disposition>none</disposition>
                    <dkim>pass</dkim>
                    <spf>pass</spf>
                    {reason}
                </policy_evaluated>
            </row>
            <identifiers><header_from>example.com</header_from></identifiers>
            <auth_results>
                <spf><domain>example.com</domain><result>pass</result></spf>
            </auth_results>
        </record>
    </feedback>"""


class TestAggregateReportEdgeCases(unittest.TestCase):
    """Parsing edge cases for aggregate report XML documents."""

    def testBytesInputIsDecoded(self):
        """parse_aggregate_report_xml accepts bytes input"""
        xml = _minimal_aggregate_xml().encode("utf-8")
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["report_id"], "edge-case")

    def testPolicyPublishedListUsesFirstEntry(self):
        """When a reporter emits multiple policy_published elements, the
        first one is used"""
        policies = (
            "<policy_published><domain>example.com</domain><p>reject</p>"
            "</policy_published>"
            "<policy_published><domain>other.example</domain><p>none</p>"
            "</policy_published>"
        )
        report = parsedmarc.parse_aggregate_report_xml(
            _minimal_aggregate_xml(policy_published=policies), offline=True
        )
        self.assertEqual(report["policy_published"]["domain"], "example.com")
        self.assertEqual(report["policy_published"]["p"], "reject")

    def testUnknownPolicyOverrideTypeWarnsUnderRFC9990(self):
        """An override reason type that RFC 9990 does not define (and RFC
        7489 never defined) logs an 'Unknown policy override reason type'
        warning; it is stored as-is. RFC 9990's PolicyOverrideType
        enumeration is {local_policy, mailing_list, other,
        policy_test_mode, trusted_forwarder}."""
        policies = (
            "<policy_published><domain>example.com</domain><p>none</p>"
            "<np>none</np></policy_published>"
        )
        reason = "<reason><type>banana</type></reason>"
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            report = parsedmarc.parse_aggregate_report_xml(
                _minimal_aggregate_xml(policy_published=policies, reason=reason),
                offline=True,
            )
        self.assertTrue(
            any(
                "Unknown policy override reason type" in message
                for message in cm.output
            )
        )
        reasons = report["records"][0]["policy_evaluated"]["policy_override_reasons"]
        self.assertEqual(reasons[0]["type"], "banana")

    def testMissingOrgNameAndEmailIsInvalid(self):
        """A report with empty org_name and email raises
        InvalidAggregateReport, since org_name has no fallback source"""
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(
                _minimal_aggregate_xml(org_name="", email=""), offline=True
            )
        self.assertIn("Organization name is missing", str(ctx.exception))

    def testMalformedEmailAttributeOnlyIsDiscarded(self):
        """An <email> element that xmltodict turns into an attributes-only
        dict (no text) is discarded rather than crashing"""
        xml = _minimal_aggregate_xml().replace(
            "<email>test@example.com</email>", '<email xml:lang="en"></email>'
        )
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIsNone(report["report_metadata"]["org_email"])


class _NonSeekableStream:
    """A minimal non-seekable stream, like sys.stdin / a socket file."""

    def __init__(self, data):
        self._data = data
        self._pos = 0

    def seekable(self):
        return False

    def read(self, size=-1):
        if size < 0:
            result = self._data[self._pos :]
            self._pos = len(self._data)
        else:
            result = self._data[self._pos : self._pos + size]
            self._pos += size
        return result


class _BrokenSeekableStream(_NonSeekableStream):
    """A stream whose seekable() itself raises, as some wrapped streams do."""

    def seekable(self):
        raise OSError("stream does not support seekable()")


class TestExtractReportStreams(unittest.TestCase):
    """extract_report accepts file objects that cannot seek (stdin, pipes,
    sockets) and must reject text-mode streams with a clear error."""

    def testNonSeekableTextStreamRaisesParserError(self):
        """A non-seekable text-mode stream raises ParserError instead of
        failing later on a bytes/str mismatch"""
        with open("samples/extract_report/nice-input.xml") as f:
            text = f.read()
        with self.assertRaises(parsedmarc.ParserError) as ctx:
            parsedmarc.extract_report(cast(BinaryIO, _NonSeekableStream(text)))
        self.assertIn("binary", str(ctx.exception))

    def testNonSeekableBytesStreamIsExtracted(self):
        """A non-seekable binary stream is buffered and extracted"""
        with open("samples/extract_report/nice-input.xml", "rb") as f:
            data = f.read()
        result = parsedmarc.extract_report(cast(BinaryIO, _NonSeekableStream(data)))
        self.assertIn("<feedback>", result)

    def testStreamWithBrokenSeekableIsExtracted(self):
        """A stream whose seekable() raises is treated as non-seekable"""
        with open("samples/extract_report/nice-input.xml", "rb") as f:
            data = f.read()
        result = parsedmarc.extract_report(cast(BinaryIO, _BrokenSeekableStream(data)))
        self.assertIn("<feedback>", result)


class TestSaveOutput(unittest.TestCase):
    """save_output() writes each failure report's message sample to a file
    named after the sample's Subject header.

    That header comes from the message that failed authentication, i.e.
    from an untrusted sender, so every test here asserts on the on-disk
    layout of the whole temporary root -- not just of the samples
    directory -- because the defect being guarded against
    (GHSA-c284-w5m6-jhjm) wrote files above it."""

    def setUp(self):
        self.temp_root = mkdtemp()
        self.addCleanup(rmtree, self.temp_root, True)
        # Nested, so a traversal out of samples/ has somewhere to land
        # inside the tree the assertions walk.
        self.output_directory = os.path.join(self.temp_root, "parsedmarc", "output")

    def _failure_report(self, subject, **parsed_sample_extra) -> FailureReport:
        """A failure report carrying only the keys save_output() reads"""
        parsed_sample = {"subject": subject}
        parsed_sample.update(parsed_sample_extra)
        return cast(
            FailureReport,
            {
                "sample": f"Subject: {subject!r}\r\n\r\nThe message body.\r\n",
                "parsed_sample": parsed_sample,
                # Read only by the CSV renderer save_output() also calls.
                "auth_failure": ["dmarc"],
                "authentication_mechanisms": [],
                "source": {
                    "ip_address": "192.0.2.1",
                    "reverse_dns": None,
                    "base_domain": None,
                    "name": None,
                    "type": None,
                    "asn": None,
                    "as_name": None,
                    "as_domain": None,
                    "country": None,
                },
            },
        )

    def _save(self, *failure_reports: FailureReport) -> None:
        results = cast(
            ParsingResults,
            {
                "aggregate_reports": [],
                "failure_reports": list(failure_reports),
                "smtp_tls_reports": [],
            },
        )
        parsedmarc.save_output(results, output_directory=self.output_directory)

    def _written_files(self) -> list[str]:
        """Every file under the temp root, as a path relative to it"""
        written = []
        for root, _dirs, files in os.walk(self.temp_root):
            for name in files:
                written.append(
                    os.path.relpath(os.path.join(root, name), self.temp_root)
                )
        return sorted(written)

    def testTraversalSubjectsAreConfinedToTheSamplesDirectory(self):
        """Subjects made only of path separators and dots all collapse to
        the "sample" fallback inside samples/, instead of escaping it.

        Regression test for GHSA-c284-w5m6-jhjm: save_output() fell back to
        the raw subject whenever sanitizing it produced an empty string, so
        os.path.join(samples_directory, "../../../.eml") escaped three
        levels up and os.path.join(samples_directory, "/.eml") became the
        absolute path /.eml."""
        self._save(
            self._failure_report("../../../"),
            self._failure_report("/"),
            self._failure_report(".."),
        )

        samples = os.path.join("parsedmarc", "output", "samples")
        eml_files = [f for f in self._written_files() if f.endswith(".eml")]
        self.assertEqual(
            eml_files,
            [
                os.path.join(samples, "sample (1).eml"),
                os.path.join(samples, "sample (2).eml"),
                os.path.join(samples, "sample.eml"),
            ],
        )
        # Nothing at all was written above the output directory.
        self.assertTrue(
            all(
                f.startswith(os.path.join("parsedmarc", "output") + os.sep)
                for f in self._written_files()
            ),
            self._written_files(),
        )

    def testCraftedFilenameSafeSubjectIsIgnored(self):
        """The filename is derived from the subject at write time, so a
        caller-supplied filename_safe_subject cannot name the file.

        parse_email() derives that key with the same sanitizer, but
        save_output() is public API: a library caller assembling its own
        ParsingResults can put anything there, and the value used to win
        over the subject."""
        self._save(
            self._failure_report("monthly digest", filename_safe_subject="../evil")
        )

        written = self._written_files()
        samples = os.path.join("parsedmarc", "output", "samples")
        self.assertIn(os.path.join(samples, "monthly digest.eml"), written)
        self.assertFalse([f for f in written if "evil" in f], written)

    def testNullByteSubjectIsStrippedAndWritten(self):
        """A NUL in the subject is stripped rather than reaching open(),
        which would raise ValueError: embedded null byte and, in the CLI,
        hold back the whole mailbox batch"""
        self._save(self._failure_report("re\x00port"))

        samples = os.path.join("parsedmarc", "output", "samples")
        self.assertEqual(
            [f for f in self._written_files() if f.endswith(".eml")],
            [os.path.join(samples, "report.eml")],
        )

    def testMultiByteSubjectWithinFilesystemNameLimit(self):
        """A subject of 84 CJK characters is truncated to fit the
        filesystem's 255-byte name limit, and the sample is written.

        Regression test for GHSA-j53g-34vj-g25q: the name was truncated to
        100 characters, so 84 three-byte characters plus ``.eml`` made a
        256-byte name and save_output() failed with ENAMETOOLONG after the
        batch's JSON and CSV rows had already been appended."""
        subject = "\u4e2d" * 84
        self._save(self._failure_report(subject))

        samples = os.path.join("parsedmarc", "output", "samples")
        self.assertEqual(
            [f for f in self._written_files() if f.endswith(".eml")],
            [os.path.join(samples, "\u4e2d" * 33 + ".eml")],
        )

    def testOrdinarySubjectNamesTheFileAndSampleIsWrittenVerbatim(self):
        """An ordinary subject is unchanged by sanitizing, and the file
        holds the message sample"""
        report = self._failure_report("DMARC failure report")
        self._save(report)

        path = os.path.join(
            self.output_directory, "samples", "DMARC failure report.eml"
        )
        # newline="" so the sample's CRLFs are not translated on the way in.
        with open(path, newline="", encoding="utf-8") as sample_file:
            self.assertEqual(sample_file.read(), report["sample"])

    def testParsedSampleReportIsNamedFromItsSubject(self):
        """End to end: a real failure report parsed from the sample corpus
        is written under its own subject line"""
        report = cast(
            FailureReport,
            parsedmarc.parse_report_file(
                "samples/failure/dmarc_ruf_report_linkedin.eml", offline=True
            )["report"],
        )
        self._save(report)

        samples = os.path.join("parsedmarc", "output", "samples")
        self.assertEqual(
            [f for f in self._written_files() if f.endswith(".eml")],
            [os.path.join(samples, "Subject line, could be UTF8 encoded.eml")],
        )


DOMAIN_SCOPE_REPORTER = "reporter.example"
DOMAIN_SCOPE_REPORT_ID = "1721054318-shared.example@reporter.example"


def _domain_scope_aggregate_xml(
    policy_domain: str | None,
    record_count: int,
    *,
    reporter: str = DOMAIN_SCOPE_REPORTER,
    report_id: str = DOMAIN_SCOPE_REPORT_ID,
) -> bytes:
    """Builds one well-formed aggregate report document.

    ``policy_domain`` fills ``policy_published/domain`` -- the field RFC 9990
    scopes Report-ID uniqueness to -- and ``record_count`` fills the single
    ``record``'s ``count``, so a caller can tell which document a batch kept.
    ``reporter`` and ``report_id`` default to one fixed reporter/ID so that a
    caller varying only the domain is varying only the identity component
    under test. ``None`` emits an empty policy-domain element, which the
    existing parser accepts as ``None``; record domains remain populated.
    All domain names use the reserved ``.example`` TLD.
    """
    record_domain = policy_domain or "a.example"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<feedback>\n"
        "  <report_metadata>\n"
        f"    <org_name>{reporter}</org_name>\n"
        "    <email>dmarc@reporter.example</email>\n"
        f"    <report_id>{report_id}</report_id>\n"
        "    <date_range>\n"
        "      <begin>1680000000</begin>\n"
        "      <end>1680086400</end>\n"
        "    </date_range>\n"
        "  </report_metadata>\n"
        "  <policy_published>\n"
        f"    <domain>{policy_domain or ''}</domain>\n"
        "    <p>none</p>\n"
        "  </policy_published>\n"
        "  <record>\n"
        "    <row>\n"
        "      <source_ip>192.0.2.1</source_ip>\n"
        f"      <count>{record_count}</count>\n"
        "      <policy_evaluated>\n"
        "        <disposition>none</disposition>\n"
        "        <dkim>pass</dkim>\n"
        "        <spf>pass</spf>\n"
        "      </policy_evaluated>\n"
        "    </row>\n"
        f"    <identifiers><header_from>{record_domain}</header_from></identifiers>\n"
        "    <auth_results>\n"
        f"      <spf><domain>{record_domain}</domain><result>pass</result></spf>\n"
        "    </auth_results>\n"
        "  </record>\n"
        "</feedback>"
    ).encode()


def _domain_scope_email(
    policy_domain: str | None,
    record_count: int,
    *,
    reporter: str = DOMAIN_SCOPE_REPORTER,
    report_id: str = DOMAIN_SCOPE_REPORT_ID,
) -> bytes:
    """Wraps that report in a minimal, well-formed MIME aggregate-report email."""
    message = MIMEMultipart()
    message["From"] = "dmarc@reporter.example"
    message["To"] = "postmaster@example.net"
    message["Subject"] = f"Report domain: {policy_domain}"
    message["Date"] = "Mon, 1 Jan 2024 00:00:00 +0000"
    attachment = MIMEApplication(
        gzip.compress(
            _domain_scope_aggregate_xml(
                policy_domain,
                record_count,
                reporter=reporter,
                report_id=report_id,
            )
        ),
        "gzip",
    )
    attachment.add_header("Content-Disposition", "attachment", filename="report.xml.gz")
    message.attach(attachment)
    return message.as_bytes()


class TestAggregateReportIdentityIsDomainScoped(unittest.TestCase):
    """Aggregate-report dedup must follow RFC 9990 §3.5.1's identity scope.

    RFC 9990 §3.5.1 ("Definition of Report-ID") says: "This identifier MUST
    be unique among reports to the same domain to aid receivers in
    identifying duplicate reports should they happen." Uniqueness is
    therefore per (reporting domain), not global: one reporter legitimately
    reusing the same Report-ID for ``a.example`` and ``b.example`` is
    sending two distinct, non-duplicate reports.

    These tests drive the public consumer -- ``get_dmarc_reports_from_mbox``
    (real temporary mbox, ``n_procs=1`` and ``n_procs=2``) and the companion
    class's ``get_dmarc_reports_from_mailbox`` (real on-disk Maildir) -- and assert on
    the returned reports' own ``policy_published.domain`` and record
    ``count`` values, never on internal helpers or mock call counts. Configs
    are isolated except where a test explicitly shares one across calls.
    """

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)

    def _mbox(self, messages: list[bytes]) -> str:
        with NamedTemporaryFile(dir=self._tmp, suffix=".mbox", delete=False) as tmp:
            path = tmp.name
        box = mailbox.mbox(path)
        try:
            box.lock()
            try:
                for message in messages:
                    box.add(mailbox.mboxMessage(message))
                box.flush()
            finally:
                box.unlock()
        finally:
            box.close()
        return path

    def _parse_mbox(self, path: str, *, n_procs: int = 1):
        return parsedmarc.get_dmarc_reports_from_mbox(
            path,
            n_procs=n_procs,
            config=parsedmarc.ParserConfig(offline=True, always_use_local_files=True),
        )

    @staticmethod
    def _domains(result) -> list[str | None]:
        return [
            report["policy_published"]["domain"]
            for report in result["aggregate_reports"]
        ]

    @staticmethod
    def _counts(result) -> list[int]:
        return [
            sum(record["count"] for record in report["records"])
            for report in result["aggregate_reports"]
        ]

    def test_same_report_id_for_different_domains_keeps_both_reports(self):
        """One reporter, one Report-ID, two policy domains in one batch:
        both reports survive, with their own content intact.

        Fails on a dedup key that is only ``org_name + report_id``: the
        second report is then classified as a duplicate of the first and
        silently dropped, even though RFC 9990 §3.5.1 only forbids reusing
        an ID *within* one domain.
        """
        path = self._mbox(
            [
                _domain_scope_email("a.example", 3),
                _domain_scope_email("b.example", 5),
            ]
        )

        result = self._parse_mbox(path)

        self.assertEqual(self._domains(result), ["a.example", "b.example"])
        self.assertEqual(self._counts(result), [3, 5])

    def test_different_domains_are_kept_in_either_delivery_order(self):
        """Delivery order must not decide which of the two domains survives:
        with the same batch reversed, the roles swap and both are still
        returned, in message order."""
        path = self._mbox(
            [
                _domain_scope_email("b.example", 5),
                _domain_scope_email("a.example", 3),
            ]
        )

        result = self._parse_mbox(path)

        self.assertEqual(self._domains(result), ["b.example", "a.example"])
        self.assertEqual(self._counts(result), [5, 3])

    def test_same_domain_duplicate_report_is_still_suppressed(self):
        """The negative half of the contract: the same reporter re-sending
        the same Report-ID for the *same* domain is a genuine duplicate and
        is still dropped, leaving one report."""
        path = self._mbox(
            [
                _domain_scope_email("a.example", 3),
                _domain_scope_email("a.example", 3),
            ]
        )

        result = self._parse_mbox(path)

        self.assertEqual(self._domains(result), ["a.example"])
        self.assertEqual(self._counts(result), [3])

    def test_dedup_is_per_domain_within_one_batch(self):
        """Three messages, one Report-ID: a.example, a.example, b.example.

        Exactly one report per domain is kept (the first of each, so the
        content assertion pins *which* document survived rather than just
        how many), which is what per-domain identity means: duplicates are
        suppressed inside a domain and never across domains.
        """
        path = self._mbox(
            [
                _domain_scope_email("a.example", 1),
                _domain_scope_email("a.example", 2),
                _domain_scope_email("b.example", 3),
            ]
        )

        result = self._parse_mbox(path)

        self.assertEqual(self._domains(result), ["a.example", "b.example"])
        self.assertEqual(self._counts(result), [1, 3])

    def test_domain_ascii_case_does_not_disable_duplicate_suppression(self):
        """RFC 4343 §3: ASCII domain letters compare without case.

        Keep the original spelling in the returned report while suppressing
        a repeated report for the same domain with a different spelling.
        """
        path = self._mbox(
            [
                _domain_scope_email("A.Example", 3),
                _domain_scope_email("a.example", 5),
                _domain_scope_email("b.example", 7),
            ]
        )
        result = self._parse_mbox(path)
        self.assertEqual(self._domains(result), ["A.Example", "b.example"])
        self.assertEqual(self._counts(result), [3, 7])

    def test_empty_policy_domain_keeps_existing_parser_behavior(self):
        """The XML parser accepts an empty policy domain as None.

        Adding the domain to report identity must not make classification
        crash on this previously accepted input, or merge it with a named
        domain. Repeated empty-domain reports still count as duplicates.
        """
        path = self._mbox(
            [
                _domain_scope_email(None, 3),
                _domain_scope_email(None, 5),
                _domain_scope_email("b.example", 7),
            ]
        )
        result = self._parse_mbox(path)
        self.assertEqual(self._domains(result), [None, "b.example"])
        self.assertEqual(self._counts(result), [3, 7])

    def test_parallel_mbox_keeps_both_domains_and_suppresses_duplicates(self):
        """Parallel parsing leaves domain-scoped dedup in the parent process."""
        path = self._mbox(
            [
                _domain_scope_email("a.example", 3),
                _domain_scope_email("a.example", 5),
                _domain_scope_email("b.example", 7),
            ]
        )
        result = self._parse_mbox(path, n_procs=2)
        self.assertEqual(self._domains(result), ["a.example", "b.example"])
        self.assertEqual(self._counts(result), [3, 7])

    def test_one_config_keeps_each_domain_and_still_suppresses_repeats(self):
        """Across two calls sharing one ``ParserConfig`` -- i.e. one live dedup
        cache, the way a long-running watch loop uses it -- the domain is
        still part of the identity.

        Run one parses ``a.example``; run two carries a *different domain*
        with the same reporter and Report-ID and must be retained, then a
        repeat of that same domain must be suppressed. A key without the
        domain fails the middle assertion: run two's report is dropped as a
        duplicate of run one's.
        """
        config = parsedmarc.ParserConfig(offline=True, always_use_local_files=True)

        def parse(messages):
            return parsedmarc.get_dmarc_reports_from_mbox(
                self._mbox(messages), n_procs=1, config=config
            )

        first = parse([_domain_scope_email("a.example", 3)])
        second = parse([_domain_scope_email("b.example", 5)])
        third = parse([_domain_scope_email("b.example", 5)])

        self.assertEqual(self._domains(first), ["a.example"])
        self.assertEqual(self._domains(second), ["b.example"])
        self.assertEqual(self._counts(second), [5])
        self.assertEqual(self._domains(third), [])

    def test_key_encoding_does_not_collide_on_field_boundaries(self):
        """Two different reports must not share one dedup key just because a
        reporter's name and a Report-ID contain the same characters.

        ``("a_b", "c")`` and ``("a", "b_c")`` both flatten to ``a_b_c`` under
        a key built by joining the fields with underscores; a JSON
        array of the fields cannot be ambiguous. Both messages below report
        the same policy domain, so the only thing telling them apart is the
        reporter/ID split: a colliding key drops the second one.
        """
        messages = [
            _domain_scope_email("a.example", 1, reporter="a_b", report_id="c"),
            _domain_scope_email("a.example", 2, reporter="a", report_id="b_c"),
        ]

        result = self._parse_mbox(self._mbox(messages))

        self.assertEqual(len(result["aggregate_reports"]), 2)
        self.assertEqual(self._counts(result), [1, 2])
        self.assertEqual(
            [
                report["report_metadata"]["org_name"]
                for report in result["aggregate_reports"]
            ],
            ["a_b", "a"],
        )


class TestAggregateReportIdentityDomainScopePendingSave(unittest.TestCase):
    """The same domain-scoped identity contract on the mailbox path that
    defers its dedup-cache writes until the batch is known to be saved.

    ``get_dmarc_reports_from_mailbox`` stages new aggregate keys in a
    per-batch pending set and folds them into the config's cache only after
    the caller's ``save_callback`` reports success (see
    ``_classify_parsed_email``'s ``pending_aggregate_keys`` and
    ``get_dmarc_reports_from_mailbox``). The pending set has to make exactly
    the same domain-scoped decision as the immediate-write path; otherwise a
    fix to one path leaves the other silently dropping reports.

    Real on-disk Maildir through mailsuite's ``MaildirConnection``, using
    the public ``save_callback`` and dry-run ``test=True`` options. These
    tests cover classification and cache commit/retry decisions, not
    message marking, archive/delete, or failed-save retry counters.
    """

    def setUp(self):
        self._tmp = mkdtemp()
        self.addCleanup(rmtree, self._tmp, ignore_errors=True)
        self._maildir = os.path.join(self._tmp, "Maildir")
        self._inbox = mailbox.Maildir(self._maildir, create=True)
        self.addCleanup(self._inbox.close)
        self._config = parsedmarc.ParserConfig(
            offline=True, always_use_local_files=True
        )

    def _deliver(self, policy_domain: str, record_count: int) -> None:
        self._inbox.add(
            mailbox.MaildirMessage(_domain_scope_email(policy_domain, record_count))
        )
        self._inbox.flush()

    def _run(self, save_callback=None):
        connection = MaildirConnection(self._maildir, maildir_create=True)
        # Dry-run leaves messages in place for the next call, while still
        # classifying reports, invoking save_callback, and folding pending
        # keys into the cache only after a successful save.
        return parsedmarc.get_dmarc_reports_from_mailbox(
            connection=connection,
            config=self._config,
            save_callback=save_callback,
            test=True,
        )

    @staticmethod
    def _domains(result) -> list[str]:
        return [
            report["policy_published"]["domain"]
            for report in result["aggregate_reports"]
        ]

    def _count_by_domain(self, result) -> dict[str, int]:
        """Maps each returned report's policy domain to its total record count.

        Order-free on purpose: a Maildir's message iteration order is not
        part of any contract, so these tests pin *which* domains came back
        and what they contain, not the sequence they arrived in.
        """
        reports = result["aggregate_reports"]
        counts = {
            report["policy_published"]["domain"]: sum(
                record["count"] for record in report["records"]
            )
            for report in reports
        }
        self.assertEqual(len(reports), len(counts), "duplicate domain report retained")
        return counts

    @staticmethod
    def _saved(batch) -> bool:
        del batch
        return True

    @staticmethod
    def _not_saved(batch) -> bool:
        del batch
        return False

    def test_committed_batch_keeps_reports_for_both_domains(self):
        """Two domains, one Report-ID, batch saved: both reports are returned."""
        self._deliver("a.example", 3)
        self._deliver("b.example", 5)

        result = self._run(save_callback=self._saved)

        self.assertEqual(
            self._count_by_domain(result), {"a.example": 3, "b.example": 5}
        )

    def test_committed_batch_still_suppresses_same_domain_duplicate(self):
        """Same domain twice, batch saved: still a duplicate, so one report
        is returned -- the pending path must not weaken same-domain dedup
        either."""
        self._deliver("a.example", 3)
        self._deliver("a.example", 3)

        result = self._run(save_callback=self._saved)

        self.assertEqual(len(result["aggregate_reports"]), 1)
        self.assertEqual(self._count_by_domain(result), {"a.example": 3})

    def test_failed_save_drops_pending_keys_so_the_retry_reparses(self):
        """A failed save must not commit the pending keys: the retry has to
        reparse the same message rather than skip it as a duplicate."""
        self._deliver("a.example", 3)

        first = self._run(save_callback=self._not_saved)
        retry = self._run(save_callback=self._saved)

        self.assertEqual(self._count_by_domain(first), {"a.example": 3})
        self.assertEqual(self._count_by_domain(retry), {"a.example": 3})

    def test_successful_save_then_rerun_returns_nothing(self):
        """After a batch is saved, the same two messages are deduplicated on
        the next run: the pending keys were folded into the cache, so the
        committed batch is not reprocessed. Both domains are recorded, so
        neither one is left out of the commit."""
        self._deliver("a.example", 3)
        self._deliver("b.example", 5)

        committed = self._run(save_callback=self._saved)
        rerun = self._run(save_callback=self._saved)

        self.assertEqual(
            self._count_by_domain(committed), {"a.example": 3, "b.example": 5}
        )
        self.assertEqual(self._domains(rerun), [])

    def test_false_callback_retry_still_returns_both_domains(self):
        """A callback returning ``False`` must not leave the two domains
        poisoned against each other: the retry reparses both messages and
        returns both reports, rather than suppressing one as a duplicate of
        the other."""
        self._deliver("a.example", 3)
        self._deliver("b.example", 5)

        unsaved = self._run(save_callback=self._not_saved)
        retry = self._run(save_callback=self._saved)

        expected = {"a.example": 3, "b.example": 5}
        self.assertEqual(self._count_by_domain(unsaved), expected)
        self.assertEqual(self._count_by_domain(retry), expected)

    def test_raising_callback_retry_still_returns_both_domains(self):
        """A callback that *raises* fails the save the same way: the
        exception propagates to the caller, and the retry must still return
        both domains."""
        self._deliver("a.example", 3)
        self._deliver("b.example", 5)

        def boom(batch):
            del batch
            raise RuntimeError("output destination down")

        with self.assertRaises(RuntimeError):
            self._run(save_callback=boom)

        retry = self._run(save_callback=self._saved)

        self.assertEqual(self._count_by_domain(retry), {"a.example": 3, "b.example": 5})


class TestMessageStructureLimits(unittest.TestCase):
    """Messages whose structure makes parsing slow are rejected up front
    (GHSA-qcc2-4x3v-v4g7).

    Each input is a shape from the advisory. The time limits are generous:
    the guard is one linear pass, and the timings cited are those measured
    on 11.2.1 under Python 3.12 before the guard existed."""

    HEAD = (
        "From: sender@example.net\r\nTo: dmarc@example.com\r\nSubject: x\r\n"
        "Date: Thu, 1 Jan 2026 00:00:00 +0000\r\nMIME-Version: 1.0\r\n"
    )

    def setUp(self):
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        self.addCleanup(resource.setrlimit, resource.RLIMIT_AS, (soft, hard))
        limit = 3 * 1024**3
        if hard != resource.RLIM_INFINITY:
            limit = min(limit, hard)
        resource.setrlimit(resource.RLIMIT_AS, (limit, hard))

    def _assert_rejected_quickly(self, data):
        limit = budget(2.0)
        start = time.monotonic()
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as caught:
            parsedmarc.parse_report_email(data.encode(), offline=True)
        elapsed = time.monotonic() - start
        self.assertIn("Message rejected", str(caught.exception))
        self.assertLess(elapsed, limit)

    def test_blank_lines_after_delivery_status_part(self):
        """512 KiB of blank lines after a message/delivery-status part took
        6.1 s to parse on 11.2.1"""
        data = (
            self.HEAD
            + "Content-Type: message/delivery-status\r\n\r\n"
            + "\n" * (512 * 1024)
        )
        self._assert_rejected_quickly(data)

    def test_address_group_with_many_members(self):
        """A To: group of 250,000 members took 1.9 s to parse on 11.2.1"""
        group = "g:" + ",".join("a@x" for _ in range(250_000)) + ";"
        data = f"From: a@b\r\nTo: {group}\r\nSubject: s\r\n\r\nbody\r\n"
        self._assert_rejected_quickly(data)

    def test_nested_multiparts(self):
        """900 nested multiparts around 30,000 parts took 10.9 s to parse on
        11.2.1"""
        depth, parts = 900, 30000
        nested = "".join(
            f"Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n"
            for i in range(depth)
        )
        inner = (
            "Content-Type: multipart/mixed; boundary=L\n\n"
            + "--L\n\nx\n" * parts
            + "--L--\n"
        )
        close = "".join(f"--b{i}--\n" for i in range(depth - 1, -1, -1))
        self._assert_rejected_quickly(self.HEAD + nested + inner + close)

    def test_header_flood(self):
        """A 4 MiB flood of ``X-A: b`` header lines took 1.4 s to parse on
        11.2.1"""
        data = self.HEAD + "X-A: b\r\n" * (4 * 1024 * 1024 // 8) + "\r\nbody\r\n"
        self._assert_rejected_quickly(data)

    def test_failure_report_sample_over_a_limit(self):
        """A failure report whose message/rfc822 sample exceeds a limit is an
        InvalidFailureReport, not a bare ValueError or an unexpected error"""
        feedback_report = "\n".join(
            [
                "Feedback-Type: auth-failure",
                "Version: 1",
                "Source-IP: 203.0.113.1",
                "Reported-Domain: example.com",
                "Auth-Failure: dmarc",
            ]
        )
        # Each blank-line-separated block of a message/delivery-status body
        # is a part, so 200,000 blank lines pass the part limit.
        sample = (
            "From: a@example.com\nSubject: s\n"
            "Content-Type: message/delivery-status\n\n" + "\n" * 200_000
        )
        with self.assertRaises(parsedmarc.InvalidFailureReport) as caught:
            parsedmarc.parse_failure_report(
                feedback_report,
                sample,
                datetime(2024, 1, 1, tzinfo=timezone.utc),
                offline=True,
            )
        self.assertIn(
            "Sample message rejected: Message exceeds max_parts (10000)",
            str(caught.exception),
        )
        self.assertNotIn("Unexpected error", str(caught.exception))

    def test_normal_message_is_not_rejected(self):
        """A message within the limits reaches the report parsers"""
        with self.assertRaises(parsedmarc.InvalidDMARCReport) as caught:
            parsedmarc.parse_report_email(
                (self.HEAD + "\r\nhello\r\n").encode(), offline=True
            )
        self.assertNotIn("Message rejected", str(caught.exception))


class TestAggregateReportXMLLimits(unittest.TestCase):
    """The nesting depth and node limits of ``parse_aggregate_report_xml()``
    (GHSA-q7gm-8cj9-94hr)."""

    SAMPLE = "samples/aggregate/!example.com!1538204542!1538463818.xml"
    MALFORMED_DECLARATION = '<?xml version="1.0" foo?>'

    def _sample(self, inner="", declaration=None):
        """The sample report with ``inner`` inserted at the start of its
        ``<report_metadata>`` element (depth 2), and its XML declaration
        replaced by ``declaration`` when given"""
        with open(self.SAMPLE, encoding="utf-8") as f:
            original = f.read()
        header, body = original.split("?>", 1)
        self.assertIn("<report_metadata>", body)
        body = body.replace("<report_metadata>", "<report_metadata>" + inner, 1)
        return (declaration or header + "?>") + body

    @staticmethod
    def _nested(levels):
        return "<a>" * levels + "x" + "</a>" * levels

    def testUnclosedElementsAreRejectedQuickly(self):
        """The advisory's document of unclosed ``<a>`` tags is rejected as
        soon as it is nested too deep, before xmltodict builds the tree.

        Regression test for GHSA-q7gm-8cj9-94hr: xmltodict keeps one stack
        entry per open element and expat reports the missing end tags only
        at the end of the input, so the reporter measured 1.35 GB of RSS for
        10 MiB. Measured locally with 11.2.1 (Python 3.14), this 2 MiB input
        took 1.2 s, +255 MiB of RSS and a 236 MiB tracemalloc peak; the
        triage measured +117 MiB and 1.3 s. The fixed code rejects it in
        milliseconds. Memory is measured with tracemalloc rather than
        ``ru_maxrss``, which only grows past the process's earlier peak and
        so could not show an increase after other tests in the suite."""
        head = '<?xml version="1.0"?><feedback><report_metadata><org_name>x</org_name>'
        xml = head + "<a>" * ((2 * 2**20 - len(head)) // 3)
        limit = budget(1)
        start = time.perf_counter()
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertLess(time.perf_counter() - start, limit)
        self.assertIn(
            f"nested more than {constants.MAX_XML_DEPTH} levels", str(ctx.exception)
        )

        tracemalloc.start()
        try:
            with self.assertRaises(parsedmarc.InvalidAggregateReport):
                parsedmarc.parse_aggregate_report_xml(xml, offline=True)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 100 * 2**20)

    def testDepthLimitBoundary(self):
        """A document nested exactly ``MAX_XML_DEPTH`` levels deep parses;
        one level more is rejected."""
        # <feedback> and <report_metadata> are the first two levels.
        within = constants.MAX_XML_DEPTH - 2
        report = parsedmarc.parse_aggregate_report_xml(
            self._sample(self._nested(within)), offline=OFFLINE_MODE
        )
        self.assertGreater(len(report["records"]), 0)
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(
                self._sample(self._nested(within + 1)), offline=OFFLINE_MODE
            )
        self.assertIn("levels deep", str(ctx.exception))

    def testSixtyLevelsDeepReportStillParses(self):
        """A valid report with a 60-level-deep extension element parses like
        the sample it was made from."""
        expected = parsedmarc.parse_aggregate_report_xml(
            self._sample(), offline=OFFLINE_MODE
        )
        report = parsedmarc.parse_aggregate_report_xml(
            self._sample(self._nested(60)), offline=OFFLINE_MODE
        )
        self.assertEqual(report["records"], expected["records"])
        self.assertEqual(report["report_metadata"]["errors"], [])

    def testWideDocumentIsRejectedOnTheNodeLimit(self):
        """A well-formed document with more than ``MAX_XML_NODES`` sibling
        elements is rejected on the node limit.

        Regression test for GHSA-q7gm-8cj9-94hr: the reporter measured
        1.75 GB of RSS for 40 MiB of ``<a b=""/>`` siblings. Empty ``<a/>``
        siblings are the cheapest way to reach the shipped limit (about
        4 MiB here); ``testAttributesCountAsNodes`` covers attributes."""
        siblings = constants.MAX_XML_NODES  # plus <feedback>: one node over
        xml = "<feedback>" + "<a/>" * siblings + "</feedback>"
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIn(
            f"more than {constants.MAX_XML_NODES:,} elements and attributes",
            str(ctx.exception),
        )

    def testAttributesCountAsNodes(self):
        """Elements and attributes both count toward the node limit, which
        is checked exactly: at the limit the document parses, one node over
        it is rejected. The limit is lowered so the inputs stay small."""
        instances = []
        original_init = parsedmarc._LimitedExpatParser.__init__

        def record(proxy, parser):
            original_init(proxy, parser)
            instances.append(proxy)

        with patch.object(parsedmarc._LimitedExpatParser, "__init__", record):
            parsedmarc.parse_aggregate_report_xml(self._sample(), offline=OFFLINE_MODE)
        sample_nodes = instances[-1]._counts.nodes
        self.assertGreater(sample_nodes, 0)
        # Three <a b=""/> siblings add three elements and three attributes.
        widened = self._sample('<a b=""/>' * 3)
        with patch.object(parsedmarc, "MAX_XML_NODES", sample_nodes + 6):
            parsedmarc.parse_aggregate_report_xml(widened, offline=OFFLINE_MODE)
        with patch.object(parsedmarc, "MAX_XML_NODES", sample_nodes + 5):
            with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
                parsedmarc.parse_aggregate_report_xml(widened, offline=OFFLINE_MODE)
        self.assertIn("elements and attributes", str(ctx.exception))

    def testLimitsApplyOnTheRecoveryPath(self):
        """A deep body behind a malformed XML declaration is rejected too.

        The malformed declaration makes the first parse fail before expat
        reads any element, so the document goes through the lxml recovery
        path and the second ``xmltodict.parse()``, which must apply the same
        limits (GHSA-q7gm-8cj9-94hr)."""
        # Without the deep body, the recovery path parses the report.
        report = parsedmarc.parse_aggregate_report_xml(
            self._sample(declaration=self.MALFORMED_DECLARATION),
            offline=OFFLINE_MODE,
        )
        self.assertTrue(
            any(
                e.startswith("Invalid XML") for e in report["report_metadata"]["errors"]
            )
        )
        deep_bodies = {
            "closed": self._nested(150),
            # libxml2 stops at its own depth limit of 256 and recovers the
            # elements read so far, which are still over this one.
            "unclosed": "<a>" * (2 * 2**20 // 3),
        }
        for name, inner in deep_bodies.items():
            with self.subTest(body=name):
                xml = self._sample(inner, declaration=self.MALFORMED_DECLARATION)
                limit = budget(1)
                start = time.perf_counter()
                with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
                    parsedmarc.parse_aggregate_report_xml(xml, offline=True)
                self.assertLess(time.perf_counter() - start, limit)
                self.assertIn("levels deep", str(ctx.exception))

    def testWideDocumentIsRejectedBeforeTheRecoveryTree(self):
        """A wide document behind a malformed XML declaration is rejected by
        the counting pass, before lxml builds the recovery tree.

        Regression test for GHSA-q7gm-8cj9-94hr: the malformed declaration
        sends the document to the lxml recovery parse, which has no node
        limit. Measured locally before the counting pass, 2,600,000
        ``<a b=""/>`` siblings (22 MiB) behind this declaration peaked at
        +1532 MiB of RSS, 890 MiB of it the lxml tree. The counting pass
        builds no tree. ``testLimitsApplyOnTheRecoveryPath`` shows the
        declaration alone still lets the report parse."""
        xml = (
            self.MALFORMED_DECLARATION
            + "<feedback>"
            + "<a/>" * constants.MAX_XML_NODES
            + "</feedback>"
        )
        limit = budget(10)
        tracemalloc.start()
        try:
            start = time.perf_counter()
            with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
                parsedmarc.parse_aggregate_report_xml(xml, offline=True)
            elapsed = time.perf_counter() - start
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(elapsed, limit)
        self.assertLess(peak, 100 * 2**20)
        self.assertIn(
            f"more than {constants.MAX_XML_NODES:,} elements and attributes",
            str(ctx.exception),
        )

    def _assert_rejected_on_tag_length(self, xml: str) -> None:
        limit = budget(1.0)
        tracemalloc.start()
        try:
            start = time.perf_counter()
            with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
                parsedmarc.parse_aggregate_report_xml(xml, offline=True)
            elapsed = time.perf_counter() - start
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(
            str(ctx.exception),
            f"Invalid XML: a tag is longer than {constants.MAX_XML_TAG_LENGTH:,} "
            "characters",
        )
        self.assertLess(elapsed, limit)
        self.assertLess(peak, 200 * 2**20)

    def test_element_with_many_attributes_is_rejected_before_parsing(self):
        """expat builds a start tag's whole attribute list before the
        counting handler sees it: one element with 900,000 attributes
        (9.3 MiB), within the node limit and the ``=`` count, took 1.1 s and
        +200 MiB. The tag scan now rejects it."""
        attributes = " ".join(f"a{i}=''" for i in range(900_000))
        xml = self._sample(f"<x {attributes}/>")
        self._assert_rejected_on_tag_length(xml)
        self._assert_rejected_on_tag_length(
            self._sample(f"<x {attributes}/>", self.MALFORMED_DECLARATION)
        )

    def test_tag_length_limit_is_exact(self):
        """A tag of exactly MAX_XML_TAG_LENGTH characters, from its "<" to
        the character before its ">", passes the scan; one more is
        rejected, as is an unterminated tag after the last ">"."""
        limit = constants.MAX_XML_TAG_LENGTH
        head = '<a b="'
        at_limit = head + "x" * (limit - len(head) - 2) + '"/'
        self.assertEqual(len(at_limit), limit)
        parsedmarc._check_tag_lengths(f"<feedback>{at_limit}></feedback>")
        over = head + "x" * (limit - len(head) - 1) + '"/'
        for xml in (f"<feedback>{over}></feedback>", f"<feedback>{over}"):
            with self.assertRaises(parsedmarc.InvalidAggregateReport, msg=xml[-20:]):
                parsedmarc._check_tag_lengths(xml)
        report = parsedmarc.parse_aggregate_report_xml(
            self._sample(at_limit + ">"), offline=True
        )
        self.assertTrue(report["records"])

    def test_tag_scan_spans_chunks_and_stays_small(self):
        """The scan reads the text one chunk at a time: a tag across a chunk
        boundary is measured whole, and a document of millions of short
        tags is scanned in little memory (one split of 100 MiB of "<a/>"
        peaked at +1,318 MiB)."""
        limit = constants.MAX_XML_TAG_LENGTH
        chunk = parsedmarc._TAG_SCAN_CHUNK
        filler = "x" * (chunk - 100)
        # From "<" to the "/" before ">": exactly the limit, then one more.
        at_limit = "<a" + "b" * (limit - 3) + "/>"
        over = "<a" + "b" * (limit - 2) + "/>"
        parsedmarc._check_tag_lengths(filler + at_limit)
        with self.assertRaises(parsedmarc.InvalidAggregateReport):
            parsedmarc._check_tag_lengths(filler + over)
        dense = "<feedback>" + "<a/>" * (4 * 2**20) + "</feedback>"
        tracemalloc.start()
        try:
            parsedmarc._check_tag_lengths(dense)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 8 * 2**20)

    def test_attributes_hidden_by_a_raw_gt_are_counted_by_their_equals(self):
        """XML allows a raw ">" in a quoted attribute value, so
        ``x=">"`` attributes cut a tag into short pieces that pass the tag
        scan: 2,000,000 of them (23.7 MiB) took 1.4 s and +310 MiB before
        the node limit rejected them."""
        attributes = " ".join(f'x{i}=">"' for i in range(2_000_000))
        xml = f"<feedback><report_metadata {attributes}/></feedback>"
        limit = budget(0.2)
        tracemalloc.start()
        try:
            start = time.perf_counter()
            with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
                parsedmarc.parse_aggregate_report_xml(xml, offline=True)
            elapsed = time.perf_counter() - start
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertIn("`=` characters", str(ctx.exception))
        self.assertLess(elapsed, limit)
        self.assertLess(peak, 50 * 2**20)

    def test_equals_count_limit_is_exact(self):
        limit = constants.MAX_XML_NODES
        parsedmarc._check_attribute_count("=" * limit)
        with self.assertRaises(parsedmarc.InvalidAggregateReport):
            parsedmarc._check_attribute_count("=" * (limit + 1))
        # The '=' characters may sit in text, where they count all the same.
        xml = _minimal_aggregate_xml().replace(
            "<org_name>TestOrg</org_name>",
            "<org_name>TestOrg</org_name><extra_contact_info>"
            + "=" * (limit - 10)
            + "</extra_contact_info>",
        )
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertTrue(report["records"])

    def test_report_over_32_mib_of_utf8_is_rejected_before_parsing(self):
        """An uncompressed report is held to the cap a compressed one is, in
        bytes of UTF-8: counting characters let 999,000 elements of 14 emoji
        (31.2 Mi characters, 71 MiB of UTF-8) through, at +649 MiB."""
        cap = parsedmarc.MAX_DECOMPRESSED_REPORT_SIZE
        frame = len("<feedback></feedback>")
        parsedmarc._check_xml_text("<feedback>" + "x" * (cap - frame) + "</feedback>")
        expected = "Invalid XML: the report is larger than 32 MiB of UTF-8"
        for label, xml in (
            ("ASCII", "<feedback>" + "x" * (cap - frame + 1) + "</feedback>"),
            ("emoji", "<feedback>" + "\U0001f600" * (cap // 4) + "</feedback>"),
        ):
            with self.assertRaises(parsedmarc.InvalidAggregateReport, msg=label) as ctx:
                parsedmarc.parse_aggregate_report_xml(xml, offline=True)
            self.assertEqual(str(ctx.exception), expected, msg=label)
        # Under the cap in bytes, non-ASCII text passes the measure.
        self.assertFalse(parsedmarc._exceeds_size_cap("\u00e9" * (cap // 2)))
        self.assertTrue(parsedmarc._exceeds_size_cap(b"x" * (cap + 1)))
        self.assertFalse(parsedmarc._exceeds_size_cap(b"x" * cap))
        # Bytes over the cap are rejected before they are decoded, and are
        # measured as bytes.
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(b"<a>" + b"x" * cap, offline=True)
        self.assertEqual(
            str(ctx.exception), "Invalid XML: the report is larger than 32 MiB"
        )

    def test_smtp_tls_report_over_the_size_cap_is_rejected_before_parsing(self):
        """parse_smtp_tls_report_json() decoded and parsed JSON of any size:
        60 MiB of ``[],`` cost +1,505 MiB."""
        cap = parsedmarc.MAX_DECOMPRESSED_REPORT_SIZE
        content = b"[" + b"[]," * (cap // 3 + 1) + b"[]]"
        limit = budget(0.1)
        start = time.perf_counter()
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(content)
        self.assertLess(time.perf_counter() - start, limit)
        self.assertEqual(str(ctx.exception), "the report is larger than 32 MiB")
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(content.decode())
        self.assertEqual(
            str(ctx.exception), "the report is larger than 32 MiB of UTF-8"
        )
        with open("samples/smtp_tls/rfc8460.json", "rb") as sample_file:
            self.assertTrue(
                parsedmarc.parse_smtp_tls_report_json(sample_file.read())["policies"]
            )

    def test_a_parse_leaves_no_reference_cycle(self):
        """The counting wrappers referred to the parser proxy, closing a
        cycle through the parser that kept xmltodict's tree alive until the
        cyclic collector ran: 2,000,000 distinct siblings peaked at
        +1,020 MiB, against +391 MiB without the cycle."""
        xml = "<feedback>" + "".join(f"<x{i}/>" for i in range(1000)) + "</feedback>"
        gc.collect()
        gc.disable()
        try:
            parsedmarc._parse_limited_xml(xml)
            self.assertEqual(gc.collect(), 0)
        finally:
            gc.enable()

    def test_the_first_parse_is_released_before_recovery(self):
        """The recovery parse runs after the first parse's except block: a
        handler keeps the handled exception's traceback, and with it the
        failed parse's frames and partial tree, alive while it runs (on
        Python 3.10 even after ``e.__traceback__ = None``). The first
        parse's counter, held by those frames, must be gone when the
        recovery starts."""
        counters: list[weakref.ref] = []
        alive_at_recovery: list[bool] = []
        original_init = parsedmarc._XMLCounts.__init__
        original_recovery = parsedmarc._parse_xml_with_recovery

        def record(counts):
            original_init(counts)
            counters.append(weakref.ref(counts))

        def check(xml):
            gc.collect()
            alive_at_recovery.append(counters[0]() is not None)
            return original_recovery(xml)

        with (
            patch.object(parsedmarc._XMLCounts, "__init__", record),
            patch.object(parsedmarc, "_parse_xml_with_recovery", check),
        ):
            parsedmarc.parse_aggregate_report_xml(
                self._sample("", self.MALFORMED_DECLARATION), offline=True
            )
        self.assertEqual(alive_at_recovery, [False])

    def test_the_recovery_path_leaves_no_tree_behind(self):
        """After the lxml recovery path, gc.collect() finds a constant set
        of lxml helper objects (18 here), the same for a document ten
        times larger, so no tree of the document survives a parse."""

        def garbage_after_recovery(elements: int) -> int:
            xml = (
                self.MALFORMED_DECLARATION
                + "<feedback>"
                + "".join(f"<x{i}>t</x{i}>" for i in range(elements))
                + "</feedback>"
            )
            gc.collect()
            gc.disable()
            try:
                with self.assertRaises(parsedmarc.InvalidAggregateReport):
                    parsedmarc.parse_aggregate_report_xml(xml, offline=True)
                return gc.collect()
            finally:
                gc.enable()

        small = garbage_after_recovery(1000)
        self.assertEqual(garbage_after_recovery(10_000), small)
        self.assertLess(small, 100)

    def test_attributes_still_count_toward_the_node_limit(self):
        """xmltodict keeps no attributes (xml_attribs=False), but expat still
        passes them to the counting start handler: one element with 1,000
        attributes is 1,001 nodes."""
        attributes = " ".join(f'a{i}=""' for i in range(1000))
        xml = f"<a {attributes}/>"
        with patch("parsedmarc.MAX_XML_NODES", 1001):
            self.assertIsNone(parsedmarc._parse_limited_xml(xml)["a"])
        with patch("parsedmarc.MAX_XML_NODES", 1000):
            with self.assertRaises(parsedmarc.InvalidAggregateReport):
                parsedmarc._parse_limited_xml(xml)


class TestAggregateReportSpanLimit(unittest.TestCase):
    """The <date_range> of an aggregate report is bounded before it is
    normalized into one record per day."""

    BEGIN = 1704067200  # 2024-01-01 00:00:00 UTC

    def _xml(self, begin: int, end: int, count: int) -> str:
        return (
            _minimal_aggregate_xml()
            .replace(
                "<begin>1704067200</begin><end>1704153599</end>",
                f"<begin>{begin}</begin><end>{end}</end>",
            )
            .replace("<count>1</count>", f"<count>{count}</count>")
        )

    def test_span_over_limit_is_rejected(self):
        xml = self._xml(self.BEGIN, self.BEGIN + 400 * 86400, 400)
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(
            str(ctx.exception),
            f"Report date range spans more than {constants.MAX_REPORT_SPAN_DAYS} days",
        )

    def test_span_of_a_year_parses_to_at_most_one_record_per_day(self):
        """Before the limit, 200,000 days with a count of 200,000 produced
        200,000 records in about 0.8 s; a year must stay far below 1 s."""
        xml = self._xml(self.BEGIN, self.BEGIN + 365 * 86400, 365)
        limit = budget(1.0)
        started = time.monotonic()
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        elapsed = time.monotonic() - started
        self.assertLessEqual(len(report["records"]), 365)
        self.assertGreater(len(report["records"]), 1)
        self.assertLess(elapsed, limit)

    def test_span_too_large_for_a_float_is_rejected_with_its_message(self):
        """An <end> of 4,001 digits (below Python's 4,300-digit limit for
        int()) made the message's float division raise OverflowError, which
        reached the caller as "Unexpected error: integer division result too
        large for a float"."""
        xml = self._xml(self.BEGIN, 10**4000, 1)
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        # No sender-derived number reaches the message or the log.
        self.assertEqual(
            str(ctx.exception),
            f"Report date range spans more than {constants.MAX_REPORT_SPAN_DAYS} days",
        )
        self.assertLess(len(str(ctx.exception)), 200)

    def test_many_records_over_many_days_are_kept_whole(self):
        """10,000 records over 366 days, each with a count of 1,000,000,
        normalized into 3,670,000 records in 13.5 s and 1.7 GB before the
        limit; the report now keeps its 10,000 records whole."""
        record_count = 10_000
        xml = self._xml(self.BEGIN, self.BEGIN + 366 * 86400, 1_000_000)
        start = xml.index("<record>")
        end = xml.index("</record>") + len("</record>")
        xml = xml[:start] + xml[start:end] * record_count + xml[end:]
        limit = budget(3.0)
        started = time.monotonic()
        with self.assertLogs("parsedmarc.log", level="WARNING") as logs:
            report = cast(
                dict, parsedmarc.parse_aggregate_report_xml(xml, offline=True)
            )
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, limit)
        self.assertEqual(len(report["records"]), record_count)
        self.assertFalse(
            any(record["normalized_timespan"] for record in report["records"])
        )
        self.assertFalse(report["report_metadata"]["timespan_requires_normalization"])
        # Each record covers the report's own range, in UTC.
        self.assertEqual(report["records"][0]["interval_begin"], "2024-01-01 00:00:00")
        self.assertEqual(report["records"][0]["interval_end"], "2025-01-01 00:00:00")
        warnings = [line for line in logs.output if "not normalized" in line]
        self.assertEqual(len(warnings), 1)
        self.assertIn(str(constants.MAX_NORMALIZED_RECORDS), warnings[0])
        self.assertIn(f"{record_count} records over 366 days", warnings[0])

    def test_keep_alive_is_called_every_20_records(self):
        xml = self._xml(self.BEGIN, self.BEGIN + 86399, 1)
        start = xml.index("<record>")
        end = xml.index("</record>") + len("</record>")
        xml = xml[:start] + xml[start:end] * 45 + xml[end:]
        keep_alive = MagicMock()
        report = parsedmarc.parse_aggregate_report_xml(
            xml, offline=True, keep_alive=keep_alive
        )
        self.assertEqual(len(report["records"]), 45)
        self.assertEqual(keep_alive.call_count, 2)

    def _records_times_days(self, record_count, days, begin_offset=0):
        begin = self.BEGIN + begin_offset
        xml = self._xml(begin, begin + days * 86400, days)
        start = xml.index("<record>")
        end = xml.index("</record>") + len("</record>")
        xml = xml[:start] + xml[start:end] * record_count + xml[end:]
        return cast(dict, parsedmarc.parse_aggregate_report_xml(xml, offline=True))

    def test_normalization_at_exactly_the_limit_is_split(self):
        """1,000 records over 250 days make exactly MAX_NORMALIZED_RECORDS."""
        self.assertEqual(1000 * 250, constants.MAX_NORMALIZED_RECORDS)
        report = self._records_times_days(1000, 250)
        self.assertTrue(report["report_metadata"]["timespan_requires_normalization"])
        self.assertEqual(len(report["records"]), 250_000)

    def test_normalization_just_under_and_over_the_limit(self):
        """683 records over 366 days make 249,978 records; 684 make
        250,344, which keeps the records whole."""
        under = self._records_times_days(683, 366)
        self.assertTrue(under["report_metadata"]["timespan_requires_normalization"])
        self.assertEqual(len(under["records"]), 683 * 366)
        with self.assertLogs("parsedmarc.log", level="WARNING"):
            over = self._records_times_days(684, 366)
        self.assertFalse(over["report_metadata"]["timespan_requires_normalization"])
        self.assertEqual(len(over["records"]), 684)

    def test_a_range_starting_after_midnight_counts_the_extra_day(self):
        """A range of 366 days starting 1 s after midnight touches 367
        calendar days, so 682 records would make 250,294."""
        with self.assertLogs("parsedmarc.log", level="WARNING") as logs:
            report = self._records_times_days(682, 366, begin_offset=1)
        self.assertFalse(report["report_metadata"]["timespan_requires_normalization"])
        self.assertEqual(len(report["records"]), 682)
        self.assertTrue(
            any("682 records over 367 days" in line for line in logs.output)
        )

    def test_small_multi_day_report_is_still_normalized(self):
        xml = self._xml(self.BEGIN, self.BEGIN + 3 * 86400, 30)
        start = xml.index("<record>")
        end = xml.index("</record>") + len("</record>")
        xml = xml[:start] + xml[start:end] * 2 + xml[end:]
        report = cast(dict, parsedmarc.parse_aggregate_report_xml(xml, offline=True))
        self.assertTrue(report["report_metadata"]["timespan_requires_normalization"])
        self.assertEqual(len(report["records"]), 6)
        self.assertTrue(
            all(record["normalized_timespan"] for record in report["records"])
        )
        self.assertEqual(sum(record["count"] for record in report["records"]), 60)

    def test_negative_span_is_rejected(self):
        xml = self._xml(self.BEGIN, self.BEGIN - 86400, 1)
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(str(ctx.exception), "Report date range is negative")


def _smtp_tls_report_dict() -> dict:
    """A minimal valid RFC 8460 §4.4 report, as a dict to mutate per test."""
    return {
        "organization-name": "Reporter Example",
        "date-range": {
            "start-datetime": "2024-01-01T00:00:00Z",
            "end-datetime": "2024-01-01T23:59:59Z",
        },
        "contact-info": "tls@reporter.example",
        "report-id": "report-1",
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-string": ["version: STSv1", "mode: enforce"],
                    "policy-domain": "example.com",
                },
                "summary": {
                    "total-successful-session-count": 10,
                    "total-failure-session-count": 1,
                },
                "failure-details": [
                    {
                        "result-type": "certificate-expired",
                        "sending-mta-ip": "192.0.2.1",
                        "receiving-mx-hostname": "mx.example.com",
                        "failed-session-count": 1,
                    }
                ],
            }
        ],
    }


def _smtp_tls_field_container(report: dict, field: str) -> dict:
    """Return the object of ``report`` that holds ``field``."""
    policy = report["policies"][0]
    if field in ("policy-domain", "policy-type", "policy-string", "mx-host"):
        return policy["policy"]
    if field.startswith("total-"):
        return policy["summary"]
    if field in ("organization-name", "report-id", "contact-info"):
        return report
    return policy["failure-details"][0]


class TestSmtpTlsReportTypeValidation(unittest.TestCase):
    """GHSA-4272-4r8g-6c5h: parse_smtp_tls_report_json() copied every field
    without a type check, so a sender could make an output raise later:
    ``"policy-string": [1]`` gave a TypeError in the CSV writer, and
    ``"start-datetime": 5`` an AttributeError in the Elasticsearch,
    OpenSearch and Splunk saves and a TypeError in the PostgreSQL save. The
    exception escaped the CLI and stopped the mailbox run on every attempt.
    Each field now has the type RFC 8460 §4.4 gives it, or the report is
    rejected as InvalidSMTPTLSReport."""

    def _assert_rejected(self, report: dict, label: str) -> None:
        with self.subTest(label):
            with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
                parsedmarc.parse_smtp_tls_report_json(json.dumps(report))

    def testValidReportStillParses(self):
        parsed = parsedmarc.parse_smtp_tls_report_json(
            json.dumps(_smtp_tls_report_dict())
        )
        self.assertEqual(parsed["begin_date"], "2024-01-01T00:00:00Z")
        policy = parsed["policies"][0]
        self.assertEqual(
            policy.get("policy_strings"), ["version: STSv1", "mode: enforce"]
        )
        self.assertEqual(
            policy.get("failure_details", [{}])[0].get("failed_session_count"), 1
        )

    def testPolicyStringOfIntegersIsRejectedBeforeTheCsvWriter(self):
        """The advisory's file-output case: before the fix the report
        parsed and parsed_smtp_tls_reports_to_csv() raised TypeError."""
        report = _smtp_tls_report_dict()
        report["policies"][0]["policy"]["policy-string"] = [1]
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
        self.assertIn("policy-string", str(ctx.exception))

    def testPolicyStringMustBeAListOfStrings(self):
        for value in ("version: STSv1", {"version": "STSv1"}, [["nested"]]):
            report = _smtp_tls_report_dict()
            report["policies"][0]["policy"]["policy-string"] = value
            self._assert_rejected(report, f"policy-string={value!r}")

    def testNullPolicyStringIsTreatedAsAbsent(self):
        report = _smtp_tls_report_dict()
        report["policies"][0]["policy"]["policy-string"] = None
        parsed = parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
        self.assertNotIn("policy_strings", parsed["policies"][0])

    def testMxHostPatternListOfIntegersIsRejected(self):
        report = _smtp_tls_report_dict()
        report["policies"][0]["policy"]["mx-host-pattern"] = [1]
        self._assert_rejected(report, "mx-host-pattern=[1]")

    def testStringFieldsMustBeStrings(self):
        for field in (
            "organization-name",
            "report-id",
            "policy-domain",
            "policy-type",
            "result-type",
            "receiving-mx-hostname",
            "additional-information",
        ):
            for value in (5, ["sts"], {"#text": "sts"}):
                report = _smtp_tls_report_dict()
                _smtp_tls_field_container(report, field)[field] = value
                self._assert_rejected(report, f"{field}={value!r}")

    def testContactInfoIsAStringOrAListOfStrings(self):
        for value in ("tls@reporter.example", ["a@reporter.example", "b@x.example"]):
            report = _smtp_tls_report_dict()
            report["contact-info"] = value
            parsed = parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
            self.assertEqual(parsed["contact_info"], value)
        for value in (5, [1], {"email": "a@reporter.example"}):
            report = _smtp_tls_report_dict()
            report["contact-info"] = value
            self._assert_rejected(report, f"contact-info={value!r}")

    def testDatesMustBeParseableStrings(self):
        for field in ("start-datetime", "end-datetime"):
            for value in (5, None, ["2024-01-01T00:00:00Z"], "not a date", ""):
                report = _smtp_tls_report_dict()
                report["date-range"][field] = value
                self._assert_rejected(report, f"{field}={value!r}")

    def testStartDatetimeIntegerIsRejected(self):
        """The advisory's Elasticsearch/OpenSearch/Splunk/PostgreSQL case."""
        report = _smtp_tls_report_dict()
        report["date-range"]["start-datetime"] = 5
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
        self.assertIn("start-datetime", str(ctx.exception))

    def testUnparseableDateIsSanitizedInTheErrorMessage(self):
        report = _smtp_tls_report_dict()
        report["date-range"]["start-datetime"] = "bad\r\nforged log line"
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
        self.assertNotIn("\r\n", str(ctx.exception))
        self.assertIn("bad\\r\\nforged log line", str(ctx.exception))

    def testOverlongDateIsRejectedQuickly(self):
        """dateutil took 12.4 s (Python 3.14) to fail on a 1,000,000-digit
        date string; a date over 64 characters is now rejected unparsed."""
        report = _smtp_tls_report_dict()
        report["date-range"]["start-datetime"] = "1" * 1_000_000
        limit = budget(2.0)
        start = time.perf_counter()
        with self.assertRaises(parsedmarc.InvalidSMTPTLSReport) as ctx:
            parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
        self.assertLess(time.perf_counter() - start, limit)
        self.assertIn("longer than", str(ctx.exception))

    def testOtherDateFormatsStillParse(self):
        for value in ("2024-01-01", "2024-01-01T00:00:00.123456789+00:00"):
            report = _smtp_tls_report_dict()
            report["date-range"]["start-datetime"] = value
            parsed = parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
            self.assertEqual(parsed["begin_date"], value)

    def testCountersAreIntegersOrNull(self):
        for field in (
            "total-successful-session-count",
            "total-failure-session-count",
            "failed-session-count",
        ):
            report = _smtp_tls_report_dict()
            _smtp_tls_field_container(report, field)[field] = None
            parsed = parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
            self.assertEqual(parsed["report_id"], "report-1")
            for value in ("5", 1.5, True, [1], {"count": 1}):
                report = _smtp_tls_report_dict()
                _smtp_tls_field_container(report, field)[field] = value
                self._assert_rejected(report, f"{field}={value!r}")

    def testFailureDetailsMustBeAListOfObjects(self):
        for value in ("certificate-expired", {"result-type": "x"}, [1], ["x"]):
            report = _smtp_tls_report_dict()
            report["policies"][0]["failure-details"] = value
            self._assert_rejected(report, f"failure-details={value!r}")

    def test_lone_surrogate_is_rejected(self):
        """A JSON "\\ud800" passed every type check and later made
        print() in process_reports() raise UnicodeEncodeError, which exited
        the CLI with status 1."""
        cases = (
            ("organization-name", "Comp\ud800any"),
            ("policy-string", ["version: STSv1", "mode: \ud800"]),
            ("contact-info", ["tls@example.com", "\udfff"]),
            ("contact-info", "tls\ud800@example.com"),
            ("mx-host", "\ud800.example.com"),
            ("mx-host", ["mx.example.com", "\ud800.example.com"]),
        )
        for field, value in cases:
            report = _smtp_tls_report_dict()
            _smtp_tls_field_container(report, field)[field] = value
            with self.assertRaises(parsedmarc.InvalidSMTPTLSReport, msg=field) as ctx:
                parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
            self.assertIn(f"{field} is not valid UTF-8 text", str(ctx.exception))


class TestPolicyOverrideReasonTypeNormalization(unittest.TestCase):
    """GHSA-4272-4r8g-6c5h: _parse_report_record() normalized only a
    reason's ``comment``, so a ``<reason>`` without ``<type>`` gave
    parsed_aggregate_reports_to_csv_rows() a KeyError, and a ``<type>``
    that xmltodict parsed to a dict or a list a TypeError in its join. The
    exception escaped the CLI's file output and stopped the mailbox run.
    A reason's ``type`` and ``comment`` are now each a string or None."""

    @staticmethod
    def _report_xml(reason: str) -> str:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata><org_name>reporter.example</org_name>
    <email>dmarc@reporter.example</email><report_id>reason-test</report_id>
    <date_range><begin>1704067200</begin><end>1704153599</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf>
    <p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record><row><source_ip>192.0.2.1</source_ip><count>1</count>
    <policy_evaluated><disposition>none</disposition><dkim>fail</dkim>
      <spf>fail</spf>{reason}</policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>fail</result></spf>
    </auth_results></record>
</feedback>
"""

    def _csv_row(self, reason: str) -> tuple[dict, dict]:
        """Parse a report holding ``reason`` and return its parsed
        override reason and its one CSV row."""
        parsedmarc.SEEN_AGGREGATE_REPORT_IDS.clear()
        report = parsedmarc.parse_aggregate_report_xml(
            self._report_xml(reason), offline=True
        )
        csv_text = parsedmarc.parsed_aggregate_reports_to_csv(report)
        rows = list(csv.DictReader(StringIO(csv_text)))
        self.assertEqual(len(rows), 1)
        record = report["records"][0]
        override = dict(record["policy_evaluated"]["policy_override_reasons"][0])
        return override, rows[0]

    def testReasonWithoutTypeWritesNone(self):
        override, row = self._csv_row("<reason><comment>x</comment></reason>")
        self.assertIsNone(override["type"])
        self.assertEqual(row["policy_override_reasons"], "none")
        self.assertEqual(row["policy_override_comments"], "x")

    def testTypeWithChildElementsWritesNone(self):
        """An element with child elements has no text of its own."""
        override, row = self._csv_row(
            "<reason><type><x>local_policy</x></type><comment>x</comment></reason>"
        )
        self.assertIsNone(override["type"])
        self.assertEqual(row["policy_override_reasons"], "none")

    def testTypeWithTextBesideChildElementsWritesTheText(self):
        override, row = self._csv_row(
            "<reason><type>forwarded<x/></type><comment>x</comment></reason>"
        )
        self.assertEqual(override["type"], "forwarded")
        self.assertEqual(row["policy_override_reasons"], "forwarded")

    def testTypeWithLangAttributeWritesItsText(self):
        override, row = self._csv_row(
            '<reason><type lang="en">local_policy</type><comment>x</comment></reason>'
        )
        self.assertEqual(override["type"], "local_policy")
        self.assertEqual(row["policy_override_reasons"], "local_policy")

    def testRepeatedTypeAndCommentAreNull(self):
        """A repeated element follows the rule of every other string field
        (_scalar()): it is None, written as "none" in CSV."""
        override, row = self._csv_row(
            "<reason><type>local_policy</type><type>other</type>"
            "<comment>a</comment><comment>b</comment></reason>"
        )
        self.assertIsNone(override["type"])
        self.assertIsNone(override["comment"])
        self.assertEqual(row["policy_override_reasons"], "none")
        self.assertEqual(row["policy_override_comments"], "none")

    def testPlainTypeIsUnchanged(self):
        override, row = self._csv_row(
            "<reason><type>mailing_list</type><comment>list</comment></reason>"
        )
        self.assertEqual(override["type"], "mailing_list")
        self.assertEqual(override["comment"], "list")
        self.assertEqual(row["policy_override_reasons"], "mailing_list")


class TestSmtpTlsMxHostKey(unittest.TestCase):
    """Issue #942: RFC 8460 §4.4 keys a policy's MX host patterns
    ``"mx-host"`` (its schema line reads ``"mx-host": mx-host-pattern``,
    and §4.4 describes the value as "a JSON array of strings"), and the
    RFC's Appendix B example gives it as a plain string. The parser read
    only ``"mx-host-pattern"``, the value type's name, so every
    RFC-conformant report lost the field. ``mx-host`` is now read as a list
    or a string, ``mx-host-pattern`` stays a fallback, and the output key
    is still ``mx_host_patterns``."""

    def _parse_policy(self, **policy_keys) -> dict:
        report = _smtp_tls_report_dict()
        report["policies"][0]["policy"].update(policy_keys)
        parsed = parsedmarc.parse_smtp_tls_report_json(json.dumps(report))
        return dict(parsed["policies"][0])

    def testMxHostList(self):
        policy = self._parse_policy(
            **{"mx-host": ["*.mail.example.com", "mx.example.com"]}
        )
        self.assertEqual(
            policy["mx_host_patterns"], ["*.mail.example.com", "mx.example.com"]
        )

    def testMxHostStringBecomesAOneElementList(self):
        policy = self._parse_policy(**{"mx-host": "*.mail.company-y.example"})
        self.assertEqual(policy["mx_host_patterns"], ["*.mail.company-y.example"])

    def testMxHostPatternIsAFallback(self):
        policy = self._parse_policy(**{"mx-host-pattern": ["*.legacy.example"]})
        self.assertEqual(policy["mx_host_patterns"], ["*.legacy.example"])
        policy = self._parse_policy(**{"mx-host-pattern": "*.legacy.example"})
        self.assertEqual(policy["mx_host_patterns"], ["*.legacy.example"])

    def testMxHostWinsOverMxHostPattern(self):
        policy = self._parse_policy(
            **{"mx-host": ["*.rfc.example"], "mx-host-pattern": ["*.legacy.example"]}
        )
        self.assertEqual(policy["mx_host_patterns"], ["*.rfc.example"])

    def testEmptyMxHostFallsBackThenOmits(self):
        for value in (None, "", []):
            with self.subTest(value=value):
                policy = self._parse_policy(
                    **{"mx-host": value, "mx-host-pattern": ["*.legacy.example"]}
                )
                self.assertEqual(policy["mx_host_patterns"], ["*.legacy.example"])
                policy = self._parse_policy(**{"mx-host": value})
                self.assertNotIn("mx_host_patterns", policy)

    def testWrongTypedMxHostIsRejected(self):
        for key in ("mx-host", "mx-host-pattern"):
            for value in (5, [1], {"pattern": "*.example.com"}):
                report = _smtp_tls_report_dict()
                report["policies"][0]["policy"][key] = value
                with self.subTest(key=key, value=value):
                    with self.assertRaises(parsedmarc.InvalidSMTPTLSReport):
                        parsedmarc.parse_smtp_tls_report_json(json.dumps(report))

    def testRfc8460AppendixBSampleKeepsItsMxHost(self):
        """samples/smtp_tls/rfc8460.json is the RFC's Appendix B example."""
        parsed = parsedmarc.parse_report_file(
            "samples/smtp_tls/rfc8460.json", offline=True
        )
        self.assertEqual(parsed["report_type"], "smtp_tls")
        report = cast(SMTPTLSReport, parsed["report"])
        self.assertEqual(
            report["policies"][0].get("mx_host_patterns"),
            ["*.mail.company-y.example"],
        )
        csv_text = parsedmarc.parsed_smtp_tls_reports_to_csv(report)
        rows = list(csv.DictReader(StringIO(csv_text)))
        self.assertTrue(rows)
        self.assertEqual(
            {row["mx_host_patterns"] for row in rows}, {"*.mail.company-y.example"}
        )


class TestAggregateReportXMLAttributesDropped(unittest.TestCase):
    """An XML attribute on a scalar element made xmltodict return an object
    (``{"@a": "1", "#text": "none"}``) that reached Elasticsearch and
    OpenSearch and mapped the field as an object (GHSA-qpcg-29vr-jwm3)."""

    ATTRIBUTE = ' a="1"'

    @classmethod
    def poisoned_xml(cls, attribute=ATTRIBUTE):
        return (
            _minimal_aggregate_xml(
                policy_published=(
                    "<policy_published><domain>example.com</domain>"
                    f"<p{attribute}>none</p><fo{attribute}>1</fo></policy_published>"
                ),
                reason='<reason><type>other</type><comment lang="en">x</comment></reason>',
            )
            .replace("<feedback>", f"<feedback><version{attribute}>1.0</version>", 1)
            .replace("<disposition>", f"<disposition{attribute}>", 1)
            .replace(
                "<header_from>example.com</header_from>",
                "<header_from>example.com</header_from>"
                f"<envelope_to{attribute}>example.org</envelope_to>",
                1,
            )
        )

    def test_attributes_on_scalar_elements_are_dropped(self):
        report = cast(
            dict,
            parsedmarc.parse_aggregate_report_xml(self.poisoned_xml(), offline=True),
        )
        record = report["records"][0]
        self.assertEqual(report["xml_schema"], "1.0")
        self.assertEqual(report["policy_published"]["p"], "none")
        self.assertEqual(report["policy_published"]["fo"], "1")
        self.assertEqual(record["policy_evaluated"]["disposition"], "none")
        self.assertEqual(record["identifiers"]["envelope_to"], "example.org")
        self.assertEqual(
            record["policy_evaluated"]["policy_override_reasons"],
            [{"type": "other", "comment": "x"}],
        )

    def test_element_with_many_attributes_parses_to_its_text(self):
        attributes = "".join(f' a{i}="v"' for i in range(500))
        report = cast(
            dict,
            parsedmarc.parse_aggregate_report_xml(
                self.poisoned_xml(attributes), offline=True
            ),
        )
        self.assertEqual(report["policy_published"]["p"], "none")
        self.assertEqual(report["xml_schema"], "1.0")

    def test_rfc_9990_is_still_detected_through_a_field_with_an_attribute(self):
        """With no namespace, an RFC 9990-only field (``np``) still marks the
        report as RFC 9990 after its attribute is dropped, so a DKIM result
        without a selector gets the RFC 9990 warning."""
        xml = _minimal_aggregate_xml(
            policy_published=(
                "<policy_published><domain>example.com</domain><p>none</p>"
                f"<np{self.ATTRIBUTE}>reject</np></policy_published>"
            )
        ).replace(
            "<auth_results>",
            "<auth_results><dkim><domain>example.com</domain>"
            "<result>pass</result></dkim>",
            1,
        )
        with self.assertLogs("parsedmarc.log", level="WARNING") as logs:
            report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertIsNone(report["xml_namespace"])
        self.assertEqual(report["policy_published"]["np"], "reject")
        self.assertTrue(any("REQUIRED by RFC 9990" in line for line in logs.output))


# Every element of an aggregate report that the schema types as a string,
# with its plain value; {name} placeholders take a variant.
_SCALAR_FIELD_VALUES = {
    "version": "1.0",
    "org_name": "reporter.example",
    "email": "dmarc@reporter.example",
    "extra_contact_info": "https://reporter.example/dmarc",
    "report_id": "scalar-test",
    "generator": "reporter/1.0",
    "domain": "example.com",
    "adkim": "r",
    "aspf": "s",
    "p": "none",
    "sp": "quarantine",
    "pct": "100",
    "fo": "1",
    "np": "reject",
    "testing": "n",
    "discovery_method": "psl",
    "source_ip": "192.0.2.1",
    "count": "3",
    "disposition": "none",
    "dkim": "pass",
    "spf": "fail",
    "header_from": "example.com",
    "envelope_from": "bounce.example.com",
    "envelope_to": "example.org",
    "dkim_domain": "example.com",
    "selector": "s1",
    "dkim_result": "pass",
    "dkim_human_result": "good signature",
    "spf_domain": "bounce.example.com",
    "scope": "mfrom",
    "spf_result": "fail",
    "spf_human_result": "not listed",
}
_SCALAR_FIELD_TEMPLATE = (
    "<feedback><version>{version}</version><report_metadata>"
    "<org_name>{org_name}</org_name><email>{email}</email>"
    "<extra_contact_info>{extra_contact_info}</extra_contact_info>"
    "<report_id>{report_id}</report_id><generator>{generator}</generator>"
    "<date_range><begin>1704067200</begin><end>1704153599</end></date_range>"
    "</report_metadata><policy_published><domain>{domain}</domain>"
    "<adkim>{adkim}</adkim><aspf>{aspf}</aspf><p>{p}</p><sp>{sp}</sp>"
    "<pct>{pct}</pct><fo>{fo}</fo><np>{np}</np><testing>{testing}</testing>"
    "<discovery_method>{discovery_method}</discovery_method></policy_published>"
    "<record><row><source_ip>{source_ip}</source_ip><count>{count}</count>"
    "<policy_evaluated><disposition>{disposition}</disposition>"
    "<dkim>{dkim}</dkim><spf>{spf}</spf>"
    "<reason><type>other</type><comment>c</comment></reason>"
    "</policy_evaluated></row><identifiers><header_from>{header_from}</header_from>"
    "<envelope_from>{envelope_from}</envelope_from>"
    "<envelope_to>{envelope_to}</envelope_to></identifiers><auth_results>"
    "<dkim><domain>{dkim_domain}</domain><selector>{selector}</selector>"
    "<result>{dkim_result}</result><human_result>{dkim_human_result}</human_result>"
    "</dkim><spf><domain>{spf_domain}</domain><scope>{scope}</scope>"
    "<result>{spf_result}</result><human_result>{spf_human_result}</human_result>"
    "</spf></auth_results></record></feedback>"
)


def _scalar_field_xml(**variants: str) -> str:
    """The report with each named field's value replaced by its variant."""
    return _SCALAR_FIELD_TEMPLATE.format(**{**_SCALAR_FIELD_VALUES, **variants})


_POLICY_FIELDS = (
    "domain",
    "adkim",
    "aspf",
    "p",
    "sp",
    "pct",
    "fo",
    "np",
    "testing",
    "discovery_method",
)


def _record(report: dict) -> dict:
    return report["records"][0]


def _auth_result(report: dict, kind: str) -> dict:
    return (_record(report)["auth_results"][kind] or [{}])[0]


class TestAggregateReportScalarFields(unittest.TestCase):
    """GHSA-qpcg-29vr-jwm3: a child element under a field the schema types
    as a string (``<p><x>1</x></p>``, ``<p>none<x/></p>``) reached the
    parsed report, and the Elasticsearch and OpenSearch documents, as a dict
    that mapped the field as an object."""

    GETTERS: dict[str, Callable[[dict], Any]] = {
        "version": lambda r: r["xml_schema"],
        "org_name": lambda r: r["report_metadata"]["org_name"],
        "email": lambda r: r["report_metadata"]["org_email"],
        "extra_contact_info": lambda r: r["report_metadata"]["org_extra_contact_info"],
        "report_id": lambda r: r["report_metadata"]["report_id"],
        "generator": lambda r: r["report_metadata"]["generator"],
        **{
            name: (lambda name: lambda r: r["policy_published"][name])(name)
            for name in _POLICY_FIELDS
        },
        "source_ip": lambda r: _record(r)["source"]["ip_address"],
        "count": lambda r: _record(r)["count"],
        "disposition": lambda r: _record(r)["policy_evaluated"]["disposition"],
        "dkim": lambda r: _record(r)["policy_evaluated"]["dkim"],
        "spf": lambda r: _record(r)["policy_evaluated"]["spf"],
        "header_from": lambda r: _record(r)["identifiers"]["header_from"],
        "envelope_from": lambda r: _record(r)["identifiers"]["envelope_from"],
        "envelope_to": lambda r: _record(r)["identifiers"]["envelope_to"],
        "dkim_domain": lambda r: _auth_result(r, "dkim").get("domain"),
        "selector": lambda r: _auth_result(r, "dkim").get("selector"),
        "dkim_result": lambda r: _auth_result(r, "dkim").get("result"),
        "dkim_human_result": lambda r: _auth_result(r, "dkim").get("human_result"),
        "spf_domain": lambda r: _auth_result(r, "spf").get("domain"),
        "scope": lambda r: _auth_result(r, "spf").get("scope"),
        "spf_result": lambda r: _auth_result(r, "spf").get("result"),
        "spf_human_result": lambda r: _auth_result(r, "spf").get("human_result"),
    }

    def _parse(self, **variants: str) -> dict:
        return cast(
            dict,
            parsedmarc.parse_aggregate_report_xml(
                _scalar_field_xml(**variants), offline=True
            ),
        )

    def test_every_scalar_field_has_a_getter(self):
        self.assertEqual(set(self.GETTERS), set(_SCALAR_FIELD_VALUES))

    def test_mixed_content_keeps_the_text(self):
        plain = self._parse()
        for name, getter in self.GETTERS.items():
            value = _SCALAR_FIELD_VALUES[name]
            report = self._parse(**{name: f"{value}<x/>"})
            self.assertEqual(getter(report), getter(plain), msg=name)

    def test_child_element_gives_a_string_none_or_a_rejection(self):
        for name, getter in self.GETTERS.items():
            try:
                report = self._parse(**{name: "<x>1</x>"})
            except parsedmarc.InvalidAggregateReport:
                continue
            value = getter(report)
            self.assertNotIsInstance(value, (dict, list), msg=name)
            self.assertTrue(value is None or isinstance(value, str), msg=name)

    def test_repeated_policy_published_is_coerced_too(self):
        """A second <policy_published> makes the field a list; the parser
        reads the first, whose <p> holds a child element."""
        report = self._parse(
            p="<x>1</x>",
            discovery_method=(
                "psl</discovery_method></policy_published><policy_published>"
                "<domain>example.com</domain><p>none</p><discovery_method>psl"
            ),
        )
        self.assertIsNone(report["policy_published"]["p"])
        self.assertEqual(report["policy_published"]["discovery_method"], "psl")

    def test_error_with_a_child_element_keeps_its_text(self):
        """<error> may repeat, so it goes through _text(), which gives the
        text beside a child element or drops an error with none."""
        xml = _scalar_field_xml().replace(
            "<generator>",
            "<error>disk full<x/></error><error><x>1</x></error><generator>",
            1,
        )
        report = parsedmarc.parse_aggregate_report_xml(xml, offline=True)
        self.assertEqual(report["report_metadata"]["errors"], ["disk full"])

    def test_repeated_scalar_element_gives_none(self):
        report = self._parse(fo="1</fo><fo>0")
        self.assertIsNone(report["policy_published"]["fo"])

    def test_count_with_child_elements_takes_the_non_numeric_count_path(self):
        with self.assertRaises(parsedmarc.InvalidAggregateReport) as ctx:
            self._parse(count="<x>1</x>")
        self.assertIn("invalid literal for int()", str(ctx.exception))


class TestReportEmailSerializesEachPartOnce(unittest.TestCase):
    """parse_report_email() serialized every part walk() visited, and str()
    of a composite part renders its whole subtree, so a deep nesting within
    mailsuite's limits re-rendered its leaf once per level
    (GHSA-qcc2-4x3v-v4g7)."""

    HEAD = (
        "From: a@example.com\nTo: b@example.com\n"
        "Subject: Report Domain: example.com\n"
        "Date: Mon, 9 Nov 2026 00:00:00 +0000\nMIME-Version: 1.0\n"
    )

    def _assert_quick(self, message: str) -> None:
        limit = budget(2.0)
        start = time.monotonic()
        with self.assertRaises(parsedmarc.InvalidDMARCReport):
            parsedmarc.parse_report_email(message, offline=True)
        self.assertLess(time.monotonic() - start, limit)

    def test_nested_multiparts_around_a_large_leaf(self):
        """98 nested multiparts around a 20 MiB one-line leaf took 26.6 s."""
        message = self.HEAD + 'Content-Type: multipart/mixed; boundary="b0"\n\n'
        for i in range(1, 98):
            message += f'--b{i - 1}\nContent-Type: multipart/mixed; boundary="b{i}"\n\n'
        message += "--b97\nContent-Type: text/plain\n\n" + "x" * 20 * 2**20
        self._assert_quick(message + "\n--b97--\n")

    def test_chain_of_rfc822_messages_around_a_large_leaf(self):
        """A chain of 99 message/rfc822 parts around a 10 MiB leaf took
        11.3 s."""
        message = (
            self.HEAD
            + "Content-Type: message/rfc822\n\n"
            + "Subject: s\nContent-Type: message/rfc822\n\n" * 97
            + "Subject: s\nContent-Type: text/plain\n\n"
            + "x" * 10 * 2**20
            + "\n"
        )
        self._assert_quick(message)

    def test_chain_of_feedback_report_parts_around_a_large_leaf(self):
        """A chain of 99 message/feedback-report parts around a 10 MiB leaf
        rendered every level and took 11.6 s."""
        message = (
            self.HEAD
            + "Content-Type: message/feedback-report\n\n"
            + "Subject: s\nContent-Type: message/feedback-report\n\n" * 97
            + "Subject: s\nContent-Type: text/plain\n\n"
            + "x" * 10 * 2**20
            + "\n"
        )
        self._assert_quick(message)

    def test_a_message_inside_the_sample_does_not_replace_it(self):
        """A feedback report has one sample (RFC 6591 §3.1); a message/rfc822
        attached inside the sample replaced it before."""
        message = (
            self.HEAD
            + 'Content-Type: multipart/report; report-type=feedback-report; boundary="r"\n\n'
            "--r\nContent-Type: message/feedback-report\n\n"
            "Feedback-Type: auth-failure\nUser-Agent: test/1.0\nVersion: 1\n"
            "Original-Mail-From: user@example.com\n"
            "Arrival-Date: Mon, 01 Jan 2024 00:00:00 +0000\n"
            "Source-IP: 192.0.2.1\nReported-Domain: example.com\n"
            "Authentication-Results: mx; dmarc=fail\n\n"
            "--r\nContent-Type: message/rfc822\n\n"
            "From: spoofer@example.com\nTo: victim@example.org\nSubject: outer\n"
            'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="s"\n\n'
            "--s\nContent-Type: text/plain\n\nhello\n"
            "--s\nContent-Type: message/rfc822\n\n"
            "From: other@example.net\nSubject: inner\n\nforwarded\n"
            "--s--\n--r--\n"
        )
        parsed = parsedmarc.parse_report_email(message, offline=True)
        self.assertEqual(parsed["report_type"], "failure")
        report = cast(dict, parsed["report"])
        self.assertEqual(report["parsed_sample"]["subject"], "outer")


class TestFailureReportPartPrecedence(unittest.TestCase):
    """An RFC 6591 message/feedback-report part and its sample win over a
    legacy "A message claiming to be from you has failed" text part, in
    either order, and a legacy text part inside the sample (the spoofer's
    own text) cannot replace the report's Source-IP or sample
    (GHSA-qcc2-4x3v-v4g7)."""

    HEAD = (
        "From: a@example.net\nTo: b@example.com\nSubject: fail\n"
        "Date: Mon, 9 Nov 2026 00:00:00 +0000\nMIME-Version: 1.0\n"
        'Content-Type: multipart/report; report-type=feedback-report; boundary="r"\n\n'
    )
    LEGACY = (
        "--r\nContent-Type: text/plain\n\n"
        "A message claiming to be from you has failed the published DMARC "
        "policy for your domain.\n\n  Sender Domain: example.com\n"
        "  Sender IP Address: 192.0.2.9\n"
        "  Received Date: Mon, 9 Nov 2026 00:00:00 +0000\n"
        "  SPF Alignment: no\n  DKIM Alignment: no\n"
        "  DMARC Results: None, Accept\n\ndetected.\n\n"
        "From: x@example.com\nSubject: legacy\n\n"
    )
    FEEDBACK = (
        "--r\nContent-Type: message/feedback-report\n\n"
        "Feedback-Type: auth-failure\nVersion: 1\nAuth-Failure: dmarc\n"
        "Source-IP: 192.0.2.1\nReported-Domain: example.com\n"
        "Arrival-Date: Mon, 9 Nov 2026 00:00:00 +0000\n\n"
    )
    SAMPLE = (
        "--r\nContent-Type: message/rfc822\n\nFrom: x@example.com\n"
        "To: y@example.org\nSubject: arfsample\n"
        "Date: Mon, 9 Nov 2026 00:00:00 +0000\n\nbody\n\n"
    )

    def _parse(self, body: str) -> dict:
        parsed = parsedmarc.parse_report_email(
            self.HEAD + body + "--r--\n", offline=True
        )
        self.assertEqual(parsed["report_type"], "failure")
        return cast(dict, parsed["report"])

    def _assert_arf(self, report: dict) -> None:
        self.assertEqual(report["source"]["ip_address"], "192.0.2.1")
        self.assertEqual(report["parsed_sample"]["subject"], "arfsample")

    def test_arf_after_a_legacy_text_part_wins(self):
        self._assert_arf(self._parse(self.LEGACY + self.FEEDBACK + self.SAMPLE))

    def test_arf_before_a_legacy_text_part_wins(self):
        self._assert_arf(self._parse(self.FEEDBACK + self.SAMPLE + self.LEGACY))

    def test_attachments_inside_the_sample_are_not_reports(self):
        """The sample is the reported message, the spoofer's attachments
        included: an SVG or zipped HTML attachment made the email rejected,
        a gzipped aggregate report or SMTP TLS JSON inside it was returned
        as that report instead of the failure report."""
        with open(
            "samples/aggregate/example.net!example.com!1529366400!1529452799.xml",
            "rb",
        ) as sample_file:
            aggregate = sample_file.read()
        with open("samples/smtp_tls/smtp_tls.json", "rb") as sample_file:
            smtp_tls = sample_file.read()
        zipped = BytesIO()
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr("invoice.html", "<html><body>pay</body></html>")
        cases = (
            ("image/svg+xml", b'<svg xmlns="http://www.w3.org/2000/svg"/>'),
            ("application/zip", zipped.getvalue()),
            ("application/json", b'{"a": 1}'),
            ("application/gzip", gzip.compress(aggregate)),
            ("application/tlsrpt+json", smtp_tls),
            ("application/pdf", b"%PDF-1.4 x"),
        )
        for content_type, data in cases:
            attachment = base64.encodebytes(data).decode()
            sample = (
                "--r\nContent-Type: message/rfc822\n\nFrom: x@example.com\n"
                "To: y@example.org\nSubject: arfsample\n"
                "Date: Mon, 9 Nov 2026 00:00:00 +0000\nMIME-Version: 1.0\n"
                'Content-Type: multipart/mixed; boundary="s"\n\n'
                "--s\nContent-Type: text/plain\n\nhello\n\n"
                f"--s\nContent-Type: {content_type}\n"
                "Content-Transfer-Encoding: base64\n"
                "Content-Disposition: attachment; filename=a\n\n"
                f"{attachment}\n--s--\n\n"
            )
            with self.subTest(content_type=content_type):
                report = self._parse(self.FEEDBACK + sample)
                self._assert_arf(report)
                self.assertIn(content_type, report["sample"])

    def test_legacy_text_then_a_feedback_part_without_its_sample_is_invalid(self):
        """RFC 6591 §3.1 puts the sample after the feedback report part, so a
        sample before it, or none, leaves the RFC 6591 report without one;
        the legacy part read earlier is not mixed in."""
        for body in (
            self.LEGACY + self.FEEDBACK,
            self.LEGACY + self.SAMPLE + self.FEEDBACK,
        ):
            with self.assertRaises(parsedmarc.InvalidDMARCReport):
                parsedmarc.parse_report_email(
                    self.HEAD + body + "--r--\n", offline=True
                )

    @staticmethod
    def _gzipped_aggregate_attachment() -> str:
        with open(
            "samples/aggregate/example.net!example.com!1529366400!1529452799.xml",
            "rb",
        ) as sample_file:
            data = base64.encodebytes(gzip.compress(sample_file.read())).decode()
        return (
            "Content-Type: application/gzip\nContent-Transfer-Encoding: base64\n"
            f"Content-Disposition: attachment; filename=a.gz\n\n{data}\n"
        )

    def _sample_with(self, boundary: str, extra: str) -> str:
        return (
            "--r\nContent-Type: message/rfc822\n\nFrom: x@example.com\n"
            "To: y@example.org\nSubject: arfsample\n"
            "Date: Mon, 9 Nov 2026 00:00:00 +0000\nMIME-Version: 1.0\n"
            f'Content-Type: multipart/mixed; boundary="{boundary}"\n\n'
            f"--{boundary}\nContent-Type: text/plain\n\nhello\n\n"
            f"{extra}--{boundary}--\n\n"
        )

    def test_parts_inside_a_later_sample_candidate_are_not_reports(self):
        """Only the first sample candidate is kept, but every candidate is
        part of the reported message: a gzipped aggregate report inside a
        second candidate was returned in place of the failure report."""
        attachment = "--s\n" + self._gzipped_aggregate_attachment()
        headers = (
            "--r\nContent-Type: text/rfc822-headers\n\nFrom: x@example.com\n"
            "To: y@example.org\nSubject: arfsample\n\n"
        )
        for label, body in (
            ("headers, then rfc822", headers + self._sample_with("s", attachment)),
            (
                "rfc822, then rfc822",
                self._sample_with("q", "") + self._sample_with("s", attachment),
            ),
        ):
            with self.subTest(label):
                report = self._parse(self.FEEDBACK + body)
                self.assertEqual(report["source"]["ip_address"], "192.0.2.1")

    def test_a_report_beside_the_sample_is_still_read(self):
        """Only parts inside the sample are skipped: a gzipped aggregate
        report after the sample, as a sibling, is returned as before."""
        body = (
            self.FEEDBACK
            + self._sample_with("q", "")
            + "--r\n"
            + self._gzipped_aggregate_attachment()
        )
        parsed = parsedmarc.parse_report_email(
            self.HEAD + body + "--r--\n", offline=True
        )
        self.assertEqual(parsed["report_type"], "aggregate")

    def test_legacy_text_inside_the_sample_is_ignored(self):
        sample = (
            "--r\nContent-Type: message/rfc822\n\nFrom: x@example.com\n"
            "To: y@example.org\nSubject: arfsample\n"
            "Date: Mon, 9 Nov 2026 00:00:00 +0000\nMIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="s"\n\n'
            "--s\nContent-Type: text/plain\n\n"
            "A message claiming to be from you has failed\n"
            "  Sender IP Address: 203.0.113.66\n"
            "  Received Date: Mon, 9 Nov 2026 00:00:00 +0000\ndetected.\n"
            "From: forged@example.com\nSubject: injected\n\n--s--\n\n"
        )
        self._assert_arf(self._parse(self.FEEDBACK + sample))


if __name__ == "__main__":
    unittest.main(verbosity=2)
