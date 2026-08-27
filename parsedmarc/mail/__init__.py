# -*- coding: utf-8 -*-

"""Mailbox connections for parsedmarc.

The implementations live in :mod:`mailsuite.mailbox` (extracted from
parsedmarc in mailsuite 2.0.0). This module re-exports them so
``parsedmarc.mail`` remains a stable import path for downstream consumers.

The Gmail and Microsoft Graph connections require optional extras. Importing
this module must not: when an extra is missing, its connection class is
replaced by a placeholder that raises the same ImportError at construction
time, so ``import parsedmarc`` works for consumers that only parse reports.
"""

from typing import TYPE_CHECKING

from mailsuite.mailbox import (
    IMAPConnection,
    MailboxConnection,
    MaildirConnection,
)

if TYPE_CHECKING:
    from mailsuite.mailbox import GmailConnection, MSGraphConnection
    from mailsuite.mailbox.graph import AuthMethod
else:
    try:
        from mailsuite.mailbox import GmailConnection
    except ImportError as error:
        _gmail_import_error = error

        class GmailConnection:
            """Placeholder raising the gmail extra's ImportError when used."""

            def __init__(self, *args, **kwargs):
                raise _gmail_import_error

    try:
        from mailsuite.mailbox import MSGraphConnection
        from mailsuite.mailbox.graph import AuthMethod
    except ImportError as error:
        _msgraph_import_error = error

        class MSGraphConnection:
            """Placeholder raising the msgraph extra's ImportError when used."""

            def __init__(self, *args, **kwargs):
                raise _msgraph_import_error

        AuthMethod = None

__all__ = [
    "AuthMethod",
    "GmailConnection",
    "IMAPConnection",
    "MailboxConnection",
    "MaildirConnection",
    "MSGraphConnection",
]
