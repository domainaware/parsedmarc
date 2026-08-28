# -*- coding: utf-8 -*-

"""Mailbox connections for parsedmarc.

The implementations live in :mod:`mailsuite.mailbox` (extracted from
parsedmarc in mailsuite 2.0.0). This module re-exports them so
``parsedmarc.mail`` remains a stable import path for downstream consumers.

The Gmail and Microsoft Graph connections require optional extras. Importing
this module must not fail: when an extra is missing, its connection class is
replaced by a placeholder that raises an equivalent ImportError — chained to
the original — at construction time, so ``import parsedmarc`` works for
consumers that only parse reports. When the msgraph extra is missing,
``AuthMethod`` is likewise a placeholder that raises that ImportError when a
non-dunder attribute is accessed, or when it is iterated, called, or
subscripted.
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
                raise ImportError(*_gmail_import_error.args) from _gmail_import_error

    try:
        from mailsuite.mailbox import MSGraphConnection
        from mailsuite.mailbox.graph import AuthMethod
    except ImportError as error:
        _msgraph_import_error = error

        class MSGraphConnection:
            """Placeholder raising the msgraph extra's ImportError when used."""

            def __init__(self, *args, **kwargs):
                raise ImportError(
                    *_msgraph_import_error.args
                ) from _msgraph_import_error

        class _MissingAuthMethod:
            """Placeholder raising the msgraph extra's ImportError when used."""

            def __getattr__(self, name: str):
                if name.startswith("__") and name.endswith("__"):
                    raise AttributeError(name)
                raise ImportError(
                    *_msgraph_import_error.args
                ) from _msgraph_import_error

            def __iter__(self):
                raise ImportError(
                    *_msgraph_import_error.args
                ) from _msgraph_import_error

            def __call__(self, *args, **kwargs):
                raise ImportError(
                    *_msgraph_import_error.args
                ) from _msgraph_import_error

            def __getitem__(self, name: str):
                raise ImportError(
                    *_msgraph_import_error.args
                ) from _msgraph_import_error

        AuthMethod = _MissingAuthMethod()

__all__ = [
    "AuthMethod",
    "GmailConnection",
    "IMAPConnection",
    "MailboxConnection",
    "MaildirConnection",
    "MSGraphConnection",
]
