# -*- coding: utf-8 -*-

"""Mailbox connections for parsedmarc.

The implementations live in :mod:`mailsuite.mailbox` (extracted from
parsedmarc in mailsuite 2.0.0). This module re-exports them so
``parsedmarc.mail`` remains a stable import path for downstream consumers.
"""

from mailsuite.mailbox import (
    GmailConnection,
    IMAPConnection,
    MailboxConnection,
    MaildirConnection,
    MSGraphConnection,
)
from mailsuite.mailbox.graph import AuthMethod

__all__ = [
    "AuthMethod",
    "GmailConnection",
    "IMAPConnection",
    "MailboxConnection",
    "MaildirConnection",
    "MSGraphConnection",
]
