# Package
from parsedmarc.mail.gmail import GmailConnection
from parsedmarc.mail.graph import MSGraphConnection
from parsedmarc.mail.imap import IMAPConnection
from parsedmarc.mail.mailbox_connection import MailboxConnection

__all__ = [
    "MailboxConnection",
    "MSGraphConnection",
    "GmailConnection",
    "IMAPConnection",
]
