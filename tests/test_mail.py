"""Tests for parsedmarc.mail"""

import importlib
import importlib.abc
import importlib.machinery
import sys
import unittest
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from types import ModuleType

from parsedmarc import mail

# Top-level module roots pulled in by mailsuite's optional mailbox extras.
# Blocking these makes the corresponding extra look uninstalled.
GMAIL_ROOTS = ("google", "google_auth_oauthlib", "googleapiclient")
MSGRAPH_ROOTS = (
    "azure",
    "msgraph",
    "msgraph_core",
    "kiota_authentication_azure",
    "kiota_abstractions",
)


class _ImportBlocker(importlib.abc.MetaPathFinder):
    """A meta path finder that makes chosen module roots unimportable.

    Installed at the head of ``sys.meta_path``, it raises ``ImportError``
    for any module whose top-level root is blocked, which is what an
    install without the optional extra looks like to the import system.
    """

    def __init__(self, roots: frozenset[str]) -> None:
        self.roots = roots

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname.split(".")[0] in self.roots:
            raise ImportError(f"blocked for test: {fullname}")
        return None


def _is_affected(name: str, roots: frozenset[str]) -> bool:
    """Is *name* a module the blocked roots or mailsuite own?

    The whole ``mailsuite`` tree counts: ``mailsuite.mailbox`` caches its
    ``gmail``/``graph`` submodules as attributes once loaded, and a stale
    ``mailsuite.mailbox.graph`` in ``sys.modules`` would satisfy
    ``from mailsuite.mailbox.graph import AuthMethod`` without ever
    reaching the blocked roots.
    """
    root = name.split(".")[0]
    return root in roots or root == "mailsuite"


@contextmanager
def blocked_stacks(*roots: str) -> Iterator[ModuleType]:
    """Reload :mod:`parsedmarc.mail` with *roots* unimportable.

    Yields the reloaded module. On exit — including when the body raises,
    so a failed assertion cannot leak state into other tests — the finder
    is removed, anything imported under the blocked roots or the mailsuite
    tree while blocked is discarded, the snapshotted modules are put back,
    and :mod:`parsedmarc.mail` is reloaded once more so its attributes are
    the real mailsuite objects again.
    """
    blocked = frozenset(roots)
    blocker = _ImportBlocker(blocked)
    removed: dict[str, ModuleType] = {}
    for name in list(sys.modules):
        if _is_affected(name, blocked):
            removed[name] = sys.modules.pop(name)
    sys.meta_path.insert(0, blocker)
    try:
        importlib.invalidate_caches()
        importlib.reload(mail)
        yield mail
    finally:
        sys.meta_path.remove(blocker)
        for name in list(sys.modules):
            if _is_affected(name, blocked):
                del sys.modules[name]
        sys.modules.update(removed)
        importlib.invalidate_caches()
        importlib.reload(mail)


class Test(unittest.TestCase):
    """Guards the lazy optional-import contract of parsedmarc.mail (#884).

    ``parsedmarc.mail`` re-exports mailsuite's Gmail and Microsoft Graph
    connections, which live behind optional extras. Importing the module
    must succeed without those extras; the failure must surface only when
    the missing connection is actually used.
    """

    def test_import_succeeds_without_either_optional_stack(self):
        """parsedmarc.mail imports with both optional stacks absent.

        This is the ``import parsedmarc`` guarantee for installs that only
        parse reports: no Gmail or Microsoft Graph dependency is needed.
        """
        with blocked_stacks(*GMAIL_ROOTS, *MSGRAPH_ROOTS) as blocked_mail:
            self.assertIs(blocked_mail, sys.modules["parsedmarc.mail"])
            self.assertIsNotNone(blocked_mail.IMAPConnection)
            self.assertIsNotNone(blocked_mail.GmailConnection)
            self.assertIsNotNone(blocked_mail.MSGraphConnection)

    def test_placeholder_connections_raise_the_extras_import_error(self):
        """Constructing a placeholder raises the missing extra's ImportError.

        The message must keep mailsuite's actionable
        ``pip install mailsuite[<extra>]`` text, and each construction must
        raise a *fresh* exception chained to the one stored original, so
        repeated constructions do not keep appending frames to one shared
        exception's traceback. Constructing twice and comparing identities
        discriminates that from re-raising the stored exception object,
        which would also carry an ``ImportError`` cause (mailsuite raises
        its guard error ``from`` the underlying one).
        """
        with blocked_stacks(*GMAIL_ROOTS, *MSGRAPH_ROOTS) as blocked_mail:
            with self.assertRaises(ImportError) as gmail_ctx:
                blocked_mail.GmailConnection()
            self.assertIn("gmail", str(gmail_ctx.exception))
            self.assertIn("mailsuite[gmail]", str(gmail_ctx.exception))
            self.assertIsInstance(gmail_ctx.exception.__cause__, ImportError)
            with self.assertRaises(ImportError) as gmail_ctx_2:
                blocked_mail.GmailConnection()
            self.assertIsNot(gmail_ctx.exception, gmail_ctx_2.exception)
            self.assertIs(
                gmail_ctx.exception.__cause__, gmail_ctx_2.exception.__cause__
            )

            with self.assertRaises(ImportError) as graph_ctx:
                blocked_mail.MSGraphConnection()
            self.assertIn("msgraph", str(graph_ctx.exception))
            self.assertIn("mailsuite[msgraph]", str(graph_ctx.exception))
            self.assertIsInstance(graph_ctx.exception.__cause__, ImportError)
            with self.assertRaises(ImportError) as graph_ctx_2:
                blocked_mail.MSGraphConnection()
            self.assertIsNot(graph_ctx.exception, graph_ctx_2.exception)
            self.assertIs(
                graph_ctx.exception.__cause__, graph_ctx_2.exception.__cause__
            )

    def test_placeholders_do_not_disturb_isinstance_checks(self):
        """Placeholders stay out of the MailboxConnection type hierarchy.

        The mailbox-processing code in ``parsedmarc/__init__.py`` branches
        on connection type with ``isinstance``, so a placeholder must never
        answer ``True`` for a real connection instance, nor pass as a
        ``MailboxConnection`` subclass. ``object.__new__`` builds an
        ``IMAPConnection`` without opening a network connection.
        """
        with blocked_stacks(*GMAIL_ROOTS, *MSGRAPH_ROOTS) as blocked_mail:
            imap = object.__new__(blocked_mail.IMAPConnection)
            self.assertIsInstance(imap, blocked_mail.MailboxConnection)
            self.assertNotIsInstance(imap, blocked_mail.GmailConnection)
            self.assertNotIsInstance(imap, blocked_mail.MSGraphConnection)
            self.assertFalse(
                issubclass(blocked_mail.GmailConnection, blocked_mail.MailboxConnection)
            )
            self.assertFalse(
                issubclass(
                    blocked_mail.MSGraphConnection, blocked_mail.MailboxConnection
                )
            )

    def test_auth_method_placeholder_raises_on_every_real_use(self):
        """AuthMethod raises the msgraph ImportError when accessed, iterated,
        called, or subscripted.

        ``parsedmarc.cli`` accesses ``AuthMethod`` members by attribute
        (``AuthMethod.UsernamePassword.name``) and iterates the enum
        (``for method in AuthMethod``); Enum's value lookup
        (``AuthMethod(value)``) is a call and its name lookup
        (``AuthMethod["UsernamePassword"]``) is a subscript, so binding
        ``None`` would surface any of these as an unhelpful
        ``AttributeError``/``TypeError`` instead of the missing extra.
        Dunder lookups are deliberately exempt so ordinary introspection —
        the ``copy`` module probing ``__deepcopy__``, for instance — still
        gets a plain ``AttributeError``.
        """
        with blocked_stacks(*GMAIL_ROOTS, *MSGRAPH_ROOTS) as blocked_mail:
            with self.assertRaises(ImportError) as attr_ctx:
                blocked_mail.AuthMethod.UsernamePassword
            self.assertIn("msgraph", str(attr_ctx.exception))

            with self.assertRaises(ImportError) as iter_ctx:
                iter(blocked_mail.AuthMethod)
            self.assertIn("msgraph", str(iter_ctx.exception))

            with self.assertRaises(ImportError) as call_ctx:
                blocked_mail.AuthMethod(1)
            self.assertIn("msgraph", str(call_ctx.exception))

            with self.assertRaises(ImportError) as item_ctx:
                blocked_mail.AuthMethod["UsernamePassword"]
            self.assertIn("msgraph", str(item_ctx.exception))

            self.assertIsNone(getattr(blocked_mail.AuthMethod, "__deepcopy__", None))

    def test_the_two_extras_are_guarded_independently(self):
        """A missing extra disables only its own connection, in either
        direction.

        Each optional import has its own ``try``/``except``, so with only
        the gmail stack absent the Graph connection and ``AuthMethod`` must
        still be the real mailsuite objects rather than placeholders, and
        with only the msgraph stack absent the Gmail connection must be.
        """
        with blocked_stacks(*GMAIL_ROOTS) as blocked_mail:
            with self.assertRaises(ImportError) as gmail_ctx:
                blocked_mail.GmailConnection()
            self.assertIn("mailsuite[gmail]", str(gmail_ctx.exception))

            graph = importlib.import_module("mailsuite.mailbox.graph")
            self.assertIs(blocked_mail.MSGraphConnection, graph.MSGraphConnection)
            self.assertIs(blocked_mail.AuthMethod, graph.AuthMethod)

        with blocked_stacks(*MSGRAPH_ROOTS) as blocked_mail:
            with self.assertRaises(ImportError) as graph_ctx:
                blocked_mail.MSGraphConnection()
            self.assertIn("mailsuite[msgraph]", str(graph_ctx.exception))

            gmail = importlib.import_module("mailsuite.mailbox.gmail")
            self.assertIs(blocked_mail.GmailConnection, gmail.GmailConnection)

    def test_full_dependencies_re_export_the_real_objects(self):
        """With every extra installed, the re-exports are mailsuite's own.

        Guards against the ``try``/``except`` shadowing the real classes
        with placeholders when the imports actually succeed.
        """
        gmail = importlib.import_module("mailsuite.mailbox.gmail")
        graph = importlib.import_module("mailsuite.mailbox.graph")
        self.assertIs(mail.GmailConnection, gmail.GmailConnection)
        self.assertIs(mail.MSGraphConnection, graph.MSGraphConnection)
        self.assertIs(mail.AuthMethod, graph.AuthMethod)


if __name__ == "__main__":
    unittest.main(verbosity=2)
