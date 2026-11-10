"""Tests for parsedmarc.postgres — the PostgreSQL output backend.

The pure timestamp/contact-info helpers are tested directly. The
``PostgreSQLClient`` save methods are tested with psycopg mocked at the SDK
boundary (``parsedmarc.postgres.psycopg``); the assertions check the SQL and
the bound parameters that a real PostgreSQL server would receive, plus the
real-sample round trip, so the tests fail if the dict-key mapping regresses.
"""

import contextlib
import importlib.util
import os
import shlex
import socket
import struct
import sys
import tempfile
import threading
import traceback
import unittest
import urllib.parse
from glob import glob
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import parsedmarc
from parsedmarc.postgres import (
    AlreadySaved,
    PostgreSQLClient,
    PostgreSQLError,
    PostgreSQLRejectedReport,
    _contact_info_to_text,
    _ensure_utc_suffix,
    _has_unencoded_at,
    _naive_local_to_timestamptz,
    _normalize_arrival_date,
    _nul_safe_dumper_classes,
    _register_nul_safe_dumpers,
    _strip_nul,
)

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

PSYCOPG_INSTALLED = importlib.util.find_spec("psycopg") is not None


class _FakeStrDumper:
    """Stands in for a psycopg ``str`` dumper: encodes with no NUL check."""

    def __init__(self, cls, context=None):
        pass

    def dump(self, obj):
        return obj.encode("utf-8")


class _FakeStrBinaryDumper(_FakeStrDumper):
    pass


class _FakeConninfoError(Exception):
    """Stands in for the ProgrammingError of a malformed connection string."""


def _fake_conninfo_to_dict(conninfo: str = "") -> dict:
    """Stands in for ``psycopg.conninfo.conninfo_to_dict`` when psycopg is
    absent: parses ``key=value`` pairs (a value may be single-quoted, as
    in libpq) and the host and query of a URI,
    and, like libpq, raises on a word without ``=`` (quoting with that
    word in the message). Like libpq, a URI's userinfo ends at the
    *first* ``@``, and the authority at the first ``/`` (so
    ``postgresql://u:x/y@db/d`` has host ``u``, port ``x`` and dbname
    ``y@db/d``), so the rest of a password containing ``@`` is part of
    the host, the port or the database name, as with
    ``psycopg.conninfo.conninfo_to_dict`` 3.3 on libpq:
    ``postgresql://u:s3c@pw@db.example/d`` has host ``pw@db.example``,
    ``postgresql://u:s3c@pw:x@db.example/d`` host ``pw`` and port
    ``x@db.example``, and ``postgresql://u:s3c@pw/x@db.example/d`` host
    ``pw`` and dbname ``x@db.example/d``. Components are percent-decoded
    (``u:s3c%40pw@db.example`` has password ``s3c@pw``)."""
    unquote = urllib.parse.unquote
    if conninfo.startswith(("postgresql://", "postgres://")):
        try:
            parts = urllib.parse.urlsplit(conninfo)
        except ValueError:
            raise _FakeConninfoError(f'invalid URI: "{conninfo}"') from None
        params = {}
        authority = parts.netloc
        if "@" in authority:
            userinfo, _, authority = authority.partition("@")
            user, sep, password = userinfo.partition(":")
            if user:
                params["user"] = unquote(user)
            if sep:
                params["password"] = unquote(password)
        if parts.path[1:]:
            params["dbname"] = unquote(parts.path[1:])
        if authority.startswith("["):
            host, _, rest = authority[1:].partition("]")
            port = rest[1:] if rest.startswith(":") else ""
        else:
            host, _, port = authority.partition(":")
        if host:
            params["host"] = unquote(host)
        if port:
            params["port"] = unquote(port)
        params.update(urllib.parse.parse_qsl(parts.query))
        return params
    params = {}
    for word in shlex.split(conninfo):
        key, sep, value = word.partition("=")
        if not sep:
            raise _FakeConninfoError(f'missing "=" after "{word}"')
        params[key] = value
    return params


# psycopg is an optional dependency and is not installed in CI (whose
# unit-test job installs the [build,all] extras, deliberately without
# postgresql). The save methods mock the connection, but the
# failure path also references ``psycopg_json.Jsonb`` at module scope, and
# connecting subclasses the dumpers of ``psycopg_string`` and parses a
# connection string with ``psycopg_conninfo``, so mock those SDK boundaries
# for the whole module when psycopg is absent.
_types_patchers = []


def setUpModule():
    import parsedmarc.postgres as pg

    if pg.psycopg_json is None:
        _types_patchers.append(patch("parsedmarc.postgres.psycopg_json", MagicMock()))
    if pg.psycopg_conninfo is None:
        _types_patchers.append(
            patch(
                "parsedmarc.postgres.psycopg_conninfo",
                SimpleNamespace(conninfo_to_dict=_fake_conninfo_to_dict),
            )
        )
    if pg.psycopg_string is None:
        _types_patchers.append(
            patch(
                "parsedmarc.postgres.psycopg_string",
                SimpleNamespace(
                    StrDumperUnknown=_FakeStrDumper,
                    StrBinaryDumper=_FakeStrBinaryDumper,
                ),
            )
        )
    for patcher in _types_patchers:
        patcher.start()


def tearDownModule():
    for patcher in _types_patchers:
        patcher.stop()


class TestPsycopgImportFallback(unittest.TestCase):
    """The module-level psycopg import has two arms — psycopg installed
    and psycopg missing — and a normal test run only ever executes the
    arm that matches the environment. Re-execute the module's source
    with sys.modules manipulated to force each arm, so both are
    exercised (and covered) whether or not psycopg is installed."""

    def _exec_fresh_module_with(self, modules):
        """Execute parsedmarc.postgres's source into a fresh, throwaway
        module object under a patched sys.modules, and return the
        (psycopg, psycopg_json, psycopg_string, psycopg_conninfo) it bound.
        The canonical module in sys.modules is untouched, so the identity of its classes
        (PostgreSQLError, AlreadySaved, ...) that other tests hold
        references to is preserved."""
        spec = importlib.util.find_spec("parsedmarc.postgres")
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(mod)
        return mod.psycopg, mod.psycopg_json, mod.psycopg_string, mod.psycopg_conninfo

    def test_missing_psycopg_falls_back_to_none(self):
        """A None entry in sys.modules makes ``import psycopg`` raise
        ImportError, exercising the fallback arm."""
        psycopg_mod, json_mod, string_mod, conninfo_mod = self._exec_fresh_module_with(
            {
                "psycopg": None,
                "psycopg.conninfo": None,
                "psycopg.types": None,
                "psycopg.types.json": None,
                "psycopg.types.string": None,
            }
        )
        self.assertIsNone(psycopg_mod)
        self.assertIsNone(json_mod)
        self.assertIsNone(string_mod)
        self.assertIsNone(conninfo_mod)

    def test_installed_psycopg_binds_module_and_type_submodules(self):
        fake_json = MagicMock()
        fake_string = MagicMock()
        fake_types = MagicMock(json=fake_json, string=fake_string)
        fake_conninfo = MagicMock()
        fake_psycopg = MagicMock(types=fake_types, conninfo=fake_conninfo)
        psycopg_mod, json_mod, string_mod, conninfo_mod = self._exec_fresh_module_with(
            {
                "psycopg": fake_psycopg,
                "psycopg.conninfo": fake_conninfo,
                "psycopg.types": fake_types,
                "psycopg.types.json": fake_json,
                "psycopg.types.string": fake_string,
            }
        )
        self.assertIs(psycopg_mod, fake_psycopg)
        self.assertIs(json_mod, fake_json)
        self.assertIs(string_mod, fake_string)
        self.assertIs(conninfo_mod, fake_conninfo)


class TestPostgreSQLHelpers(unittest.TestCase):
    """Unit tests for the pure helper functions in parsedmarc.postgres."""

    # -- _ensure_utc_suffix --------------------------------------------------

    def test_ensure_utc_suffix_none(self):
        """None passes through unchanged."""
        self.assertIsNone(_ensure_utc_suffix(None))

    def test_ensure_utc_suffix_empty_string(self):
        """Empty string passes through unchanged (falsy)."""
        self.assertEqual(_ensure_utc_suffix(""), "")

    def test_ensure_utc_suffix_naive_utc(self):
        """A naive UTC timestamp gets '+00' appended."""
        self.assertEqual(
            _ensure_utc_suffix("2024-01-15 10:30:00"),
            "2024-01-15 10:30:00+00",
        )

    def test_ensure_utc_suffix_already_has_plus(self):
        """A timestamp already containing '+' is left unchanged."""
        val = "2024-01-15 10:30:00+05:30"
        self.assertEqual(_ensure_utc_suffix(val), val)

    def test_ensure_utc_suffix_already_has_z(self):
        """A timestamp ending with 'Z' is left unchanged."""
        val = "2024-01-15T10:30:00Z"
        self.assertEqual(_ensure_utc_suffix(val), val)

    def test_ensure_utc_suffix_negative_offset(self):
        """A timestamp with a negative offset after position 10 is unchanged."""
        val = "2024-01-15 10:30:00-05:00"
        self.assertEqual(_ensure_utc_suffix(val), val)

    def test_ensure_utc_suffix_iso_t_naive(self):
        """Naive ISO 8601 with T separator gets '+00'."""
        self.assertEqual(
            _ensure_utc_suffix("2024-01-15T10:30:00"),
            "2024-01-15T10:30:00+00",
        )

    # -- _naive_local_to_timestamptz -----------------------------------------

    def test_naive_local_to_timestamptz_none(self):
        self.assertIsNone(_naive_local_to_timestamptz(None))

    def test_naive_local_to_timestamptz_empty(self):
        self.assertEqual(_naive_local_to_timestamptz(""), "")

    def test_naive_local_to_timestamptz_valid(self):
        """A valid naive string is returned with a timezone offset."""
        result = _naive_local_to_timestamptz("2024-01-15 10:30:00")
        assert result is not None
        self.assertIsInstance(result, str)
        self.assertTrue(
            "+" in result or "-" in result[10:],
            f"Expected timezone offset in result: {result}",
        )
        from datetime import datetime as _dt

        parsed = _dt.fromisoformat(result)
        self.assertIsNotNone(parsed.tzinfo)

    def test_naive_local_to_timestamptz_bad_format_raises(self):
        """An unparseable string raises ValueError (from strptime)."""
        with self.assertRaises(ValueError):
            _naive_local_to_timestamptz("not-a-date")

    # -- _normalize_arrival_date ---------------------------------------------

    def test_normalize_arrival_date_none(self):
        self.assertIsNone(_normalize_arrival_date(None))

    def test_normalize_arrival_date_empty(self):
        self.assertEqual(_normalize_arrival_date(""), "")

    def test_normalize_arrival_date_iso_naive_utc(self):
        """A naive ISO string (known UTC) is returned with +00 suffix."""
        result = _normalize_arrival_date("2024-01-15 10:30:00")
        assert result is not None
        self.assertTrue(result.endswith("+00"), f"Expected +00 suffix: {result}")

    def test_normalize_arrival_date_rfc2822(self):
        """An RFC 2822 date is converted to UTC with +00 suffix."""
        result = _normalize_arrival_date("Fri, 28 Oct 2022 00:34:24 +0800")
        assert result is not None
        self.assertTrue(result.endswith("+00"), f"Expected +00 suffix: {result}")
        # 00:34:24 +0800 is 16:34:24 UTC on 27 Oct 2022.
        self.assertIn("2022-10-27", result)
        self.assertIn("16:34:24", result)

    def test_normalize_arrival_date_already_utc(self):
        """A string already ending with +00 still works."""
        result = _normalize_arrival_date("2024-01-15 10:30:00+00")
        assert result is not None
        self.assertTrue(result.endswith("+00"), f"Expected +00 suffix: {result}")

    def test_normalize_arrival_date_unparseable(self):
        """An unparseable string is returned as-is (fallback)."""
        garbage = "not a date at all"
        self.assertEqual(_normalize_arrival_date(garbage), garbage)

    # -- _contact_info_to_text -----------------------------------------------

    def test_contact_info_to_text_none(self):
        self.assertIsNone(_contact_info_to_text(None))

    def test_contact_info_to_text_string(self):
        self.assertEqual(
            _contact_info_to_text("admin@example.com"),
            "admin@example.com",
        )

    def test_contact_info_to_text_list(self):
        self.assertEqual(
            _contact_info_to_text(["admin@example.com", "abuse@example.com"]),
            "admin@example.com, abuse@example.com",
        )

    def test_contact_info_to_text_empty_list(self):
        self.assertEqual(_contact_info_to_text([]), "")

    def test_contact_info_to_text_numeric(self):
        """Non-string scalars are converted via str()."""
        # Deliberately outside the annotated parameter types
        self.assertEqual(_contact_info_to_text(123), "123")  # pyright: ignore[reportArgumentType]


def _without_libpq_env():
    """Patch os.environ for the duration of a ``with`` block so that none of
    libpq's ``PG*`` variables (PGSSLMODE, PGHOST, ...) from the developer's
    shell reaches the code under test."""
    return patch.dict(
        os.environ,
        {k: v for k, v in os.environ.items() if not k.startswith("PG")},
        clear=True,
    )


def _without_early_refusal():
    """Patch out the shape check that refuses a URI connection string
    before anything is logged (``_has_unencoded_at``), so a test exercises
    what keeps the password out of the logs whatever shape gets past it:
    withholding every value parsed from the string."""
    return patch("parsedmarc.postgres._has_unencoded_at", MagicMock(return_value=False))


@contextlib.contextmanager
def _captured_log_text():
    """Capture every parsedmarc log record, DEBUG and up, into a list of
    formatted strings (unlike assertLogs, an empty capture is allowed)."""
    import logging

    from parsedmarc.log import logger

    records: list[str] = []

    class _ListHandler(logging.Handler):
        def emit(self, record):
            records.append(self.format(record))

    handler = _ListHandler(level=logging.DEBUG)
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


def _make_client():
    """Create a PostgreSQLClient with a fully-mocked psycopg connection."""
    with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
        mock_conn = MagicMock()
        mock_psycopg.connect.return_value = mock_conn
        mock_psycopg.Error = Exception

        client = PostgreSQLClient(
            host="localhost", database="test", user="test", password="test"
        )
    mock_conn.closed = False
    client._conn = mock_conn
    return client, mock_conn


def _mock_cursor(mock_conn, fetchone_results):
    """Wire up a mock cursor whose fetchone() yields *fetchone_results*."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.side_effect = list(fetchone_results)
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.transaction.return_value.__enter__ = MagicMock()
    mock_conn.transaction.return_value.__exit__ = MagicMock(return_value=False)
    return mock_cursor


def _executed_sql(mock_cursor):
    """Return the list of SQL strings passed to cursor.execute()."""
    return [c.args[0] for c in mock_cursor.execute.call_args_list]


def _named_params(call):
    """Map an INSERT's column names to the bound parameter values.

    Lets tests assert by column name instead of fragile positional indices.
    """
    import re

    sql = call.args[0]
    m = re.search(r"\(([^)]*?)\)\s*VALUES", sql, re.S)
    assert m is not None
    cols = [c.strip() for c in m.group(1).split(",") if c.strip()]
    return dict(zip(cols, call.args[1]))


class TestPostgreSQLConstruction(unittest.TestCase):
    """Construction-time behaviour, including the optional-dependency guard."""

    def test_missing_psycopg_raises_install_hint(self):
        """Without psycopg installed, construction fails with an install hint."""
        with patch("parsedmarc.postgres.psycopg", None):
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(host="localhost")
        self.assertIn("pip install parsedmarc[postgresql]", str(ctx.exception))

    def test_close_closes_open_connection(self):
        """close() closes a live connection and is a no-op once closed."""
        client, mock_conn = _make_client()
        mock_conn.closed = False
        client.close()
        mock_conn.close.assert_called_once()

        mock_conn.close.reset_mock()
        mock_conn.closed = True
        client.close()
        mock_conn.close.assert_not_called()

    def test_ensure_connected_reconnects_on_closed(self):
        """_ensure_connected reconnects when the connection is closed."""
        client, mock_conn = _make_client()
        mock_conn.closed = True
        with patch.object(client, "_connect") as mock_reconnect:
            client._ensure_connected()
            mock_reconnect.assert_called_once()

    def test_connect_uses_connection_string_when_provided(self):
        """A DSN/URI is passed straight to psycopg.connect, with the default
        sslmode as a keyword argument because the string sets none."""
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
        ):
            mock_psycopg.Error = Exception
            PostgreSQLClient(connection_string="postgresql://u:p@h/db")
        mock_psycopg.connect.assert_called_once_with(
            "postgresql://u:p@h/db", sslmode="require"
        )

    def test_connect_failure_raises_postgresql_error(self):
        """A driver-level connection error is wrapped in PostgreSQLError."""
        with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
            mock_psycopg.Error = Exception
            mock_psycopg.ProgrammingError = type("ProgrammingError", (Exception,), {})
            mock_psycopg.connect.side_effect = mock_psycopg.Error("refused")
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(host="localhost")
        self.assertIn("refused", str(ctx.exception))

    def test_connect_failure_detail_is_url_redacted(self):
        """With the separate arguments, a driver error keeps its detail,
        with URL credentials masked."""
        programming_error = type("ProgrammingError", (Exception,), {})
        with patch("parsedmarc.postgres.psycopg") as mock_psycopg:
            mock_psycopg.Error = Exception
            mock_psycopg.ProgrammingError = programming_error
            mock_psycopg.connect.side_effect = mock_psycopg.Error(
                'connection to "postgresql://u:PGSECRET@db.example/x" failed'
            )
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(host="h", user="u", password="PGSECRET")
        message = str(ctx.exception)
        self.assertNotIn("PGSECRET", message)
        self.assertIn('connection to "postgresql://u:***@db.example/x" failed', message)

    def test_connect_failure_is_not_chained_to_the_driver_error(self):
        """The driver names the host when it cannot connect, and a host
        with an "@" can hold part of a password (a URI connection string
        with one is refused before connecting; the *host* argument is
        passed on). The replacement message is credential-masked, and it is
        raised from None: chaining printed the driver's own text, unmasked,
        wherever the error was logged with its traceback (the SIGHUP reload
        path's logger.exception)."""
        operational_error = type("OperationalError", (Exception,), {})
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
        ):
            mock_psycopg.Error = Exception
            mock_psycopg.ProgrammingError = type("ProgrammingError", (Exception,), {})
            mock_psycopg.connect.side_effect = operational_error(
                "failed to resolve host 'pw@db.example': [Errno -2] Name or "
                "service not known"
            )
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(
                    host="pw@db.example", password="s3c", sslmode="verify-full"
                )
        exc = ctx.exception
        rendered = "".join(traceback.format_exception(exc))
        for secret in ("s3c", "pw@"):
            self.assertNotIn(secret, str(exc))
            self.assertNotIn(secret, rendered)
        self.assertIn("***@db.example", str(exc))
        self.assertIsNone(exc.__cause__)
        self.assertTrue(exc.__suppress_context__)
        # The real host and password still reach the driver.
        self.assertEqual(mock_psycopg.connect.call_args.kwargs["host"], "pw@db.example")
        self.assertEqual(mock_psycopg.connect.call_args.kwargs["password"], "s3c")

    def test_malformed_connection_string_detail_withheld(self):
        """A ProgrammingError from parsing the connection string (which libpq
        words with the whole string or a password fragment) is replaced with
        a fixed message that still identifies the problem. The string is
        parsed before connecting too; that parse is stubbed to succeed here
        so the error surfaces from psycopg.connect, the guard under test
        (the pre-parse is tested in TestPostgreSQLTLS)."""
        programming_error = type("ProgrammingError", (Exception,), {})
        for dsn, driver_message in (
            (
                "postgresql://u:PGSECRET@[::1/db",
                'end of string reached when looking for matching "]" in IPv6 '
                'host address in URI: "postgresql://u:PGSECRET@[::1/db"',
            ),
            (
                "postgresql://u:PG%ZZSECRET@h/db",
                'invalid percent-encoded token: "PG%ZZSECRET"',
            ),
        ):
            with self.subTest(dsn=dsn):
                with (
                    patch("parsedmarc.postgres.psycopg") as mock_psycopg,
                    patch(
                        "parsedmarc.postgres.psycopg_conninfo",
                        SimpleNamespace(conninfo_to_dict=lambda conninfo: {}),
                    ),
                ):
                    mock_psycopg.Error = Exception
                    mock_psycopg.ProgrammingError = programming_error
                    mock_psycopg.connect.side_effect = programming_error(driver_message)
                    with self.assertRaises(PostgreSQLError) as ctx:
                        PostgreSQLClient(connection_string=dsn)
                message = str(ctx.exception)
                self.assertNotIn("PGSECRET", message)
                self.assertNotIn("SECRET", message)
                self.assertIn("Invalid PostgreSQL connection_string", message)

    @unittest.skipIf(
        importlib.util.find_spec("psycopg") is None, "psycopg is not installed"
    )
    def test_real_psycopg_malformed_connection_string_withheld(self):
        """With the real driver, both malformed strings fail in parsing (no
        network I/O) and the raised message carries no part of the password."""
        for dsn in (
            "postgresql://u:PGSECRET@[::1/db",
            "postgresql://u:PG%ZZSECRET@h/db",
        ):
            with self.subTest(dsn=dsn):
                with self.assertRaises(PostgreSQLError) as ctx:
                    PostgreSQLClient(connection_string=dsn)
                self.assertNotIn("SECRET", str(ctx.exception))
                self.assertIn(
                    "Invalid PostgreSQL connection_string", str(ctx.exception)
                )

    def test_create_tables_executes_all_ddl(self):
        """create_tables issues CREATE TABLE for every table and the indexes."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        client.create_tables()
        executed = " ".join(_executed_sql(cur))
        for table in (
            "dmarc_aggregate_report",
            "dmarc_aggregate_record",
            "dmarc_aggregate_record_dkim",
            "dmarc_aggregate_record_spf",
            "dmarc_aggregate_record_policy_override",
            "dmarc_failure_report",
            "dmarc_failure_sample_address",
            "smtp_tls_report",
            "smtp_tls_policy",
            "smtp_tls_failure_detail",
        ):
            self.assertIn(f"CREATE TABLE IF NOT EXISTS {table}", executed)
        self.assertIn("CREATE INDEX IF NOT EXISTS", executed)

    def test_create_tables_indexes_every_foreign_key(self):
        """Every REFERENCES column gets an index.

        PostgreSQL indexes the referenced primary key but not the referencing
        column ("the declaration of a foreign key constraint does not
        automatically create an index on the referencing columns", PostgreSQL
        docs, "Foreign Keys"), so without one a per-record lookup such as the
        PostgreSQL Grafana dashboard's DKIM/SPF result subqueries scans the
        whole child table.
        """
        import re

        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        client.create_tables()
        statements = _executed_sql(cur)

        foreign_keys = set()
        for stmt in statements:
            table = re.search(r"CREATE TABLE IF NOT EXISTS (\w+)", stmt)
            if table:
                for column in re.findall(
                    r"^\s*(\w+)[^\n]*\n?\s*REFERENCES", stmt, re.M | re.I
                ):
                    foreign_keys.add((table.group(1), column))
        indexed = {
            (m.group(1), m.group(2))
            for stmt in statements
            if (m := re.search(r"ON (\w+) \((\w+)\)", stmt))
        }

        # Every REFERENCES in the DDL must have been attributed to a column,
        # so a layout the column regex misses fails here instead of passing.
        references = sum(
            len(re.findall(r"\bREFERENCES\b", s, re.I)) for s in statements
        )
        self.assertEqual(len(foreign_keys), references)
        self.assertEqual(foreign_keys - indexed, set())

    def test_create_tables_wraps_db_error(self):
        """A driver error during DDL is wrapped in PostgreSQLError."""

        class FakeDriverError(Exception):
            pass

        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        cur.execute.side_effect = FakeDriverError("ddl boom")
        with patch("parsedmarc.postgres.psycopg") as mp:
            mp.Error = FakeDriverError
            with self.assertRaises(PostgreSQLError) as ctx:
                client.create_tables()
        self.assertIn("ddl boom", str(ctx.exception))


class TestPostgreSQLClientSave(unittest.TestCase):
    """Save methods with a mocked DB: assert on SQL and bound parameters."""

    # -- aggregate -----------------------------------------------------------

    def test_save_aggregate_report_calls_insert(self):
        """Aggregate save executes INSERTs for report, record, dkim and spf."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,), (10,)])

        report = {
            "xml_schema": "1.0",
            "xml_namespace": "urn:ietf:params:xml:ns:dmarc-2.0",
            "report_metadata": {
                "org_name": "Example Inc.",
                "org_email": "dmarc@example.com",
                "org_extra_contact_info": None,
                "report_id": "rpt-123",
                "begin_date": "2024-01-15 00:00:00",
                "end_date": "2024-01-15 23:59:59",
                "errors": [],
                "generator": "ExampleReporter/2.0",
            },
            "policy_published": {
                "domain": "example.com",
                "adkim": "r",
                "aspf": "r",
                "p": "none",
                "sp": "none",
                "pct": "100",
                "fo": "0",
                "np": "reject",
                "testing": "y",
                "discovery_method": "treewalk",
            },
            "records": [
                {
                    "source": {
                        "ip_address": "203.0.113.1",
                        "country": "US",
                        "reverse_dns": "mail.example.com",
                        "base_domain": "example.com",
                        "name": None,
                        "type": None,
                    },
                    "count": 5,
                    "alignment": {"spf": True, "dkim": True, "dmarc": True},
                    "policy_evaluated": {
                        "disposition": "none",
                        "dkim": "pass",
                        "spf": "pass",
                        "policy_override_reasons": [],
                    },
                    "identifiers": {
                        "header_from": "example.com",
                        "envelope_from": "example.com",
                        "envelope_to": None,
                    },
                    "interval_begin": "2024-01-15 00:00:00",
                    "interval_end": "2024-01-15 23:59:59",
                    "auth_results": {
                        "dkim": [
                            {
                                "domain": "example.com",
                                "selector": "s1",
                                "result": "pass",
                                "human_result": "valid signature",
                            }
                        ],
                        "spf": [
                            {
                                "domain": "example.com",
                                "scope": "mfrom",
                                "result": "pass",
                                "human_result": None,
                            }
                        ],
                    },
                }
            ],
        }

        client.save_aggregate_report_to_postgresql(report)

        sqls = _executed_sql(cur)
        self.assertIn("dmarc_aggregate_report", sqls[0])
        self.assertIn("dmarc_aggregate_record", sqls[1])
        self.assertTrue(any("dmarc_aggregate_record_dkim" in s for s in sqls))
        self.assertTrue(any("dmarc_aggregate_record_spf" in s for s in sqls))

        # The RFC 9990 / DMARCbis fields must reach the report INSERT.
        report_params = _named_params(cur.execute.call_args_list[0])
        self.assertEqual(
            report_params["xml_namespace"], "urn:ietf:params:xml:ns:dmarc-2.0"
        )
        self.assertEqual(report_params["generator"], "ExampleReporter/2.0")
        self.assertEqual(report_params["np"], "reject")
        self.assertEqual(report_params["testing"], "y")
        self.assertEqual(report_params["discovery_method"], "treewalk")

        # DKIM auth-result values, including human_result, reach the INSERT.
        dkim_sql_idx = next(
            i for i, s in enumerate(sqls) if "dmarc_aggregate_record_dkim" in s
        )
        dkim_params = _named_params(cur.execute.call_args_list[dkim_sql_idx])
        self.assertEqual(dkim_params["domain"], "example.com")
        self.assertEqual(dkim_params["selector"], "s1")
        self.assertEqual(dkim_params["result"], "pass")
        self.assertEqual(dkim_params["human_result"], "valid signature")

    def test_save_aggregate_report_already_saved(self):
        """AlreadySaved is raised when ON CONFLICT returns no row."""
        client, mock_conn = _make_client()
        _mock_cursor(mock_conn, [None])

        report = {
            "report_metadata": {
                "org_name": "Dup Inc.",
                "report_id": "dup-001",
                "begin_date": "2024-01-01 00:00:00",
                "end_date": "2024-01-01 23:59:59",
            },
            "policy_published": {"domain": "example.com"},
            "records": [],
        }

        with self.assertRaises(AlreadySaved):
            client.save_aggregate_report_to_postgresql(report)

    def test_aggregate_report_normalizes_timestamps(self):
        """Report dates get a tz offset; record intervals get a +00 suffix."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,), (10,)])

        report = {
            "report_metadata": {
                "org_name": "TZ Test",
                "report_id": "tz-001",
                "begin_date": "2024-01-15 00:00:00",
                "end_date": "2024-01-15 23:59:59",
            },
            "policy_published": {"domain": "example.com"},
            "records": [
                {
                    "source": {},
                    "count": 1,
                    "alignment": {},
                    "policy_evaluated": {},
                    "identifiers": {"header_from": "example.com"},
                    "interval_begin": "2024-01-15 00:00:00",
                    "interval_end": "2024-01-15 23:59:59",
                    "auth_results": {"dkim": [], "spf": []},
                }
            ],
        }

        client.save_aggregate_report_to_postgresql(report)

        report_params = _named_params(cur.execute.call_args_list[0])
        for label in ("begin_date", "end_date"):
            val = report_params[label]
            self.assertIsNotNone(val, f"{label} should not be None")
            self.assertTrue(
                "+" in val or "-" in val[10:],
                f"Report {label} should carry a tz offset: {val}",
            )

        record_params = _named_params(cur.execute.call_args_list[1])
        for label in ("interval_begin", "interval_end"):
            val = record_params[label]
            self.assertIsNotNone(val, f"{label} should not be None")
            self.assertTrue(
                val.endswith("+00"),
                f"Record {label} should end with +00: {val}",
            )

    # -- failure -------------------------------------------------------------

    def test_save_failure_report_calls_insert(self):
        """Failure save dedups, then INSERTs the report and sample addresses."""
        client, mock_conn = _make_client()
        # 1st fetchone = dedup SELECT (None → not a duplicate); 2nd = INSERT id.
        cur = _mock_cursor(mock_conn, [None, (1,)])

        report = {
            "feedback_type": "auth-failure",
            "user_agent": "test/1.0",
            "version": "1",
            "original_envelope_id": None,
            "original_mail_from": "sender@example.com",
            "original_rcpt_to": "receiver@example.com",
            "arrival_date": "Mon, 15 Jan 2024 10:30:00 +0000",
            "arrival_date_utc": "2024-01-15 10:30:00",
            "authentication_results": "spf=pass",
            "delivery_result": None,
            "auth_failure": ["dkim"],
            "authentication_mechanisms": [],
            "dkim_domain": "example.com",
            "reported_domain": "example.com",
            "sample_headers_only": False,
            "source": {
                "ip_address": "203.0.113.1",
                "country": "US",
                "reverse_dns": "mail.example.com",
                "base_domain": "example.com",
                "name": None,
                "type": None,
            },
            "sample": "raw email content",
            "parsed_sample": {
                "date": "2024-01-15",
                "subject": "Test",
                "body": "Hello",
                "has_defects": False,
                "headers": {"From": "sender@example.com"},
                "from": {"display_name": "Sender", "address": "sender@example.com"},
                "to": [{"display_name": "Receiver", "address": "receiver@example.com"}],
                "cc": [],
                "bcc": [],
                "reply_to": [],
            },
        }

        client.save_failure_report_to_postgresql(report)

        sqls = _executed_sql(cur)
        # First statement is the dedup SELECT, then the report INSERT.
        self.assertIn("SELECT", sqls[0])
        self.assertIn("dmarc_failure_report", sqls[0])
        self.assertTrue(
            any("INSERT INTO dmarc_failure_report" in s for s in sqls),
            "expected a failure-report INSERT",
        )
        self.assertTrue(
            any("dmarc_failure_sample_address" in s for s in sqls),
            "expected a sample-address INSERT for the 'to' recipient",
        )

    def test_save_failure_report_already_saved(self):
        """A matching existing failure report raises AlreadySaved."""
        client, mock_conn = _make_client()
        # Dedup SELECT returns a row → duplicate.
        _mock_cursor(mock_conn, [(1,)])

        report = {
            "arrival_date_utc": "2024-01-15 10:30:00",
            "reported_domain": "example.com",
            "source": {"ip_address": "203.0.113.1"},
            "parsed_sample": {"subject": "Test"},
        }

        with self.assertRaises(AlreadySaved):
            client.save_failure_report_to_postgresql(report)

    # -- SMTP TLS ------------------------------------------------------------

    def test_save_smtp_tls_report_calls_insert(self):
        """SMTP TLS save INSERTs report, policy, and failure detail rows."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,), (10,)])

        report = {
            "organization_name": "Example Inc.",
            "begin_date": "2024-01-15T00:00:00Z",
            "end_date": "2024-01-16T00:00:00Z",
            "contact_info": "admin@example.com",
            "report_id": "tls-001",
            "policies": [
                {
                    "policy_domain": "example.com",
                    "policy_type": "sts",
                    "policy_strings": ["version: STSv1"],
                    "mx_host_patterns": ["*.example.com"],
                    "successful_session_count": 100,
                    "failed_session_count": 2,
                    "failure_details": [
                        {
                            "result_type": "certificate-expired",
                            "failed_session_count": 2,
                            "sending_mta_ip": "203.0.113.1",
                            "receiving_ip": "198.51.100.1",
                            "receiving_mx_hostname": "mx.example.com",
                            "receiving_mx_helo": "mx.example.com",
                            "additional_info_uri": None,
                            "failure_reason_code": None,
                        }
                    ],
                }
            ],
        }

        client.save_smtp_tls_report_to_postgresql(report)

        sqls = _executed_sql(cur)
        self.assertIn("smtp_tls_report", sqls[0])
        self.assertIn("smtp_tls_policy", sqls[1])
        self.assertIn("smtp_tls_failure_detail", sqls[2])

        # Policy field mapping must reach the INSERT (regression guard).
        policy_params = cur.execute.call_args_list[1].args[1]
        self.assertIn("example.com", policy_params)
        self.assertIn("sts", policy_params)
        self.assertIn(100, policy_params)
        self.assertIn(2, policy_params)

    def test_save_smtp_tls_report_blank_failure_detail_fields_become_null(self):
        """Blank optional failure-detail fields reach PostgreSQL as None,
        not "" (issue #915).

        samples/smtp_tls/empty_failure_detail_fields.json reproduces a
        real reporter's shape: sending-mta-ip/receiving-ip/
        receiving-mx-hostname/additional-information sent as "" on an
        sts-policy-fetch-error. "" is not a valid PostgreSQL INET value, so
        before the parser fix in parsedmarc/__init__.py this reached
        cur.execute() as an empty string and crashed the save with
        "invalid input syntax for type inet: \"\"" against a real server.
        This test goes through the real parser (parsedmarc.parse_report_file)
        rather than a hand-built dict, so it fails on unfixed
        parsedmarc/__init__.py even though this test file only mocks
        psycopg.
        """
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,), (10,)])

        result = parsedmarc.parse_report_file(
            "samples/smtp_tls/empty_failure_detail_fields.json", offline=True
        )
        report = result["report"]

        client.save_smtp_tls_report_to_postgresql(cast(dict, report))

        sqls = _executed_sql(cur)
        self.assertIn("smtp_tls_failure_detail", sqls[2])

        detail_params = _named_params(cur.execute.call_args_list[2])
        self.assertIsNone(detail_params["sending_mta_ip"])
        self.assertIsNone(detail_params["receiving_ip"])
        self.assertIsNone(detail_params["receiving_mx_hostname"])
        self.assertIsNone(detail_params["additional_info_uri"])
        # A non-blank optional field is preserved.
        self.assertEqual(detail_params["failure_reason_code"], "no-policy-served")
        # Required fields are preserved.
        self.assertEqual(detail_params["result_type"], "sts-policy-fetch-error")
        self.assertEqual(detail_params["failed_session_count"], 1)

    def test_save_smtp_tls_report_already_saved(self):
        """AlreadySaved is raised when ON CONFLICT returns no row."""
        client, mock_conn = _make_client()
        _mock_cursor(mock_conn, [None])

        report = {
            "organization_name": "Dup Inc.",
            "begin_date": "2024-01-01T00:00:00Z",
            "end_date": "2024-01-02T00:00:00Z",
            "contact_info": "admin@dup.com",
            "report_id": "dup-tls-001",
            "policies": [],
        }

        with self.assertRaises(AlreadySaved):
            client.save_smtp_tls_report_to_postgresql(report)

    def test_save_smtp_tls_report_contact_info_list(self):
        """A contact_info list is joined to a string before insert."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [(1,)])

        report = {
            "organization_name": "Multi Inc.",
            "begin_date": "2024-01-15T00:00:00Z",
            "end_date": "2024-01-16T00:00:00Z",
            "contact_info": ["admin@multi.com", "abuse@multi.com"],
            "report_id": "multi-001",
            "policies": [],
        }

        client.save_smtp_tls_report_to_postgresql(report)

        insert_params = cur.execute.call_args_list[0].args[1]
        self.assertEqual(insert_params[3], "admin@multi.com, abuse@multi.com")

    def test_save_failure_report_single_address_dict(self):
        """A recipient header parsed as a single dict (not a list) is wrapped."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [None, (1,)])

        report = {
            "arrival_date_utc": "2024-01-15 10:30:00",
            "reported_domain": "example.com",
            "source": {"ip_address": "203.0.113.1"},
            "parsed_sample": {
                "subject": "Single",
                # 'to' as a lone dict rather than a list of dicts.
                "to": {"display_name": "Solo", "address": "solo@example.com"},
            },
        }

        client.save_failure_report_to_postgresql(report)

        addr_sqls = [
            (c.args[0], c.args[1])
            for c in cur.execute.call_args_list
            if "dmarc_failure_sample_address" in c.args[0]
        ]
        self.assertEqual(len(addr_sqls), 1)
        self.assertIn("solo@example.com", addr_sqls[0][1])

    def test_save_failure_report_indexes_reply_to_address(self):
        """A parsed Reply-To address is written to
        dmarc_failure_sample_address with address_type 'reply_to' — the
        rows the Grafana PostgreSQL failure panel aggregates for its
        'Reply To' column. Guards the path that parse_email now
        populates (reply_to was always [] before the hyphen-key fix)."""
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [None, (1,)])

        report = {
            "arrival_date_utc": "2024-01-15 10:30:00",
            "reported_domain": "example.com",
            "source": {"ip_address": "203.0.113.1"},
            "parsed_sample": {
                "subject": "Test",
                "reply_to": [
                    {"display_name": "Real One", "address": "real@phish.example"}
                ],
            },
        }

        client.save_failure_report_to_postgresql(report)

        reply_to_inserts = [
            _named_params(c)
            for c in cur.execute.call_args_list
            if "dmarc_failure_sample_address" in c.args[0]
            and c.args[1][1] == "reply_to"
        ]
        self.assertEqual(len(reply_to_inserts), 1)
        self.assertEqual(reply_to_inserts[0]["address"], "real@phish.example")
        self.assertEqual(reply_to_inserts[0]["display_name"], "Real One")


class TestPostgreSQLSaveErrors(unittest.TestCase):
    """Driver errors raised mid-save are wrapped in PostgreSQLError."""

    class _FakeDriverError(Exception):
        pass

    def _run(self, method, report):
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        cur.execute.side_effect = self._FakeDriverError("db boom")
        with patch("parsedmarc.postgres.psycopg") as mp:
            mp.Error = self._FakeDriverError
            mp.DataError = type("DataError", (self._FakeDriverError,), {})
            with self.assertRaises(PostgreSQLError) as ctx:
                getattr(client, method)(report)
        self.assertIn("db boom", str(ctx.exception))

    def test_save_aggregate_wraps_db_error(self):
        self._run(
            "save_aggregate_report_to_postgresql",
            {"report_metadata": {}, "policy_published": {}, "records": []},
        )

    def test_save_failure_wraps_db_error(self):
        self._run(
            "save_failure_report_to_postgresql",
            {"parsed_sample": {}, "source": {}},
        )

    def test_save_smtp_tls_wraps_db_error(self):
        self._run(
            "save_smtp_tls_report_to_postgresql",
            {"policies": []},
        )


class TestPostgreSQLWithSamples(unittest.TestCase):
    """Feed real parsed sample reports through the save methods (DB mocked)."""

    def test_aggregate_samples(self):
        client, mock_conn = _make_client()
        saved = 0
        for sample_path in glob("samples/aggregate/*"):
            if os.path.isdir(sample_path):
                continue
            try:
                parsed = parsedmarc.parse_report_file(
                    sample_path,
                    always_use_local_files=True,
                    offline=OFFLINE_MODE,
                )
            except parsedmarc.ParserError:
                continue
            if parsed.get("report_type") != "aggregate":
                continue

            report = parsed["report"]
            num_records = len(report.get("records", []))
            _mock_cursor(mock_conn, [(rid,) for rid in range(1, 2 + num_records)])
            try:
                client.save_aggregate_report_to_postgresql(cast(dict, report))
                saved += 1
            except Exception as exc:
                self.fail(f"aggregate save failed for {sample_path}: {exc}")

        self.assertGreater(saved, 0, "Expected at least one aggregate sample")

    def test_failure_samples(self):
        client, mock_conn = _make_client()
        saved = 0
        for sample_path in glob("samples/failure/*.eml"):
            try:
                parsed = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
            except parsedmarc.ParserError:
                continue
            if parsed.get("report_type") != "failure":
                continue

            reports = parsed["report"]
            if not isinstance(reports, list):
                reports = [reports]
            for report in reports:
                # Dedup SELECT returns None (not a dup), then the INSERT id.
                _mock_cursor(mock_conn, [None, (1,)])
                try:
                    client.save_failure_report_to_postgresql(cast(dict, report))
                    saved += 1
                except Exception as exc:
                    self.fail(f"failure save failed for {sample_path}: {exc}")

        self.assertGreater(saved, 0, "Expected at least one failure sample")

    def test_smtp_tls_samples(self):
        client, mock_conn = _make_client()
        saved = 0
        for sample_path in glob("samples/smtp_tls/*"):
            if os.path.isdir(sample_path):
                continue
            try:
                parsed = parsedmarc.parse_report_file(sample_path, offline=OFFLINE_MODE)
            except parsedmarc.ParserError:
                continue
            if parsed.get("report_type") != "smtp_tls":
                continue

            report = parsed["report"]
            num_policies = len(report.get("policies", []))
            _mock_cursor(mock_conn, [(rid,) for rid in range(1, 2 + num_policies)])
            try:
                client.save_smtp_tls_report_to_postgresql(cast(dict, report))
                saved += 1
            except Exception as exc:
                self.fail(f"smtp_tls save failed for {sample_path}: {exc}")

        self.assertGreater(saved, 0, "Expected at least one SMTP TLS sample")


class TestEnsureUtcSuffixNonString(unittest.TestCase):
    """GHSA-4272-4r8g-6c5h: ``_ensure_utc_suffix(5)`` raised ``TypeError``
    (``"+" in 5``) outside the save's ``psycopg.Error`` handler, so an SMTP
    TLS report with ``"start-datetime": 5`` escaped the CLI. A non-string
    is now returned unchanged, for PostgreSQL to accept or reject."""

    def test_non_string_is_returned_unchanged(self):
        for value in (5, 1.5, ["2024-01-01"]):
            with self.subTest(value=value):
                self.assertEqual(
                    _ensure_utc_suffix(value),  # pyright: ignore[reportArgumentType]
                    value,
                )


class TestNulReplacement(unittest.TestCase):
    """GHSA-fxr7-7h9q-v949: PostgreSQL cannot store NUL in ``text`` or
    ``jsonb``. psycopg's text-format ``str`` dumper raises ``DataError``
    ("PostgreSQL text fields cannot contain NUL (0x00) bytes") and the server
    rejects ``\\u0000`` in ``jsonb``, so a failure report whose sample
    Subject was ``=?utf-8?q?a=00b?=`` failed the save and held the batch.
    NUL is now replaced with U+FFFD."""

    def test_strip_nul_replaces_nested_strings_and_keys(self):
        value = {
            "Sub\x00ject": ["a\x00b", {"x": "\x00\x00"}],
            "count": 3,
            "none": None,
            "flag": True,
        }
        self.assertEqual(
            _strip_nul(value),
            {
                "Sub\ufffdject": ["a\ufffdb", {"x": "\ufffd\ufffd"}],
                "count": 3,
                "none": None,
                "flag": True,
            },
        )

    def test_connect_registers_binary_then_text_nul_safe_dumper(self):
        """psycopg uses the dumper registered last for a type as its
        default, so the text dumper must be registered after the binary one.
        Each registered class must replace NUL before its parent dumps."""
        _make_client_conn = MagicMock()
        fake_string = SimpleNamespace(
            StrDumperUnknown=_FakeStrDumper, StrBinaryDumper=_FakeStrBinaryDumper
        )
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            patch("parsedmarc.postgres.psycopg_string", fake_string),
        ):
            mock_psycopg.Error = Exception
            mock_psycopg.connect.return_value = _make_client_conn
            client = PostgreSQLClient(host="localhost")
        self.assertIs(client._conn, _make_client_conn)
        calls = _make_client_conn.adapters.register_dumper.call_args_list
        self.assertEqual([c.args[0] for c in calls], [str, str])
        binary_cls, text_cls = (c.args[1] for c in calls)
        self.assertTrue(issubclass(binary_cls, _FakeStrBinaryDumper))
        self.assertTrue(issubclass(text_cls, _FakeStrDumper))
        self.assertFalse(issubclass(text_cls, _FakeStrBinaryDumper))
        for cls in (binary_cls, text_cls):
            self.assertEqual(cls(str, None).dump("a\x00b"), "a\ufffdb".encode())

    @unittest.skipUnless(PSYCOPG_INSTALLED, "psycopg is not installed")
    def test_real_psycopg_parent_dumpers_reject_or_keep_nul(self):
        """The behavior being worked around: the text dumper raises
        DataError and the binary one passes the NUL on to the server."""
        import psycopg
        from psycopg.types.string import StrBinaryDumper, StrDumperUnknown

        with self.assertRaises(psycopg.DataError):
            StrDumperUnknown(str, None).dump("a\x00b")
        self.assertEqual(StrBinaryDumper(str, None).dump("a\x00b"), b"a\x00b")

        text_cls, binary_cls = _nul_safe_dumper_classes()
        self.assertEqual(text_cls(str, None).dump("a\x00b"), "a\ufffdb".encode())
        self.assertEqual(binary_cls(str, None).dump("a\x00b"), "a\ufffdb".encode())

    @unittest.skipUnless(PSYCOPG_INSTALLED, "psycopg is not installed")
    def test_real_psycopg_dumps_str_and_str_list_without_nul(self):
        """With the real adapters map, every format psycopg may pick for a
        ``str`` parameter, and for a ``list[str]`` (``TEXT[]`` columns),
        resolves to a NUL-safe dumper."""
        import psycopg
        from psycopg.abc import AdaptContext
        from psycopg.adapt import AdaptersMap, PyFormat, Transformer

        context = SimpleNamespace(
            adapters=AdaptersMap(psycopg.adapters), connection=None
        )
        _register_nul_safe_dumpers(cast(psycopg.Connection, context))
        transformer = Transformer(cast(AdaptContext, context))
        for fmt in (PyFormat.AUTO, PyFormat.TEXT, PyFormat.BINARY):
            with self.subTest(fmt=fmt):
                dumped = transformer.get_dumper("a\x00b", fmt).dump("a\x00b")
                self.assertEqual(bytes(cast(bytes, dumped)), "a\ufffdb".encode())
                list_dumped = bytes(
                    cast(
                        bytes,
                        transformer.get_dumper(["a\x00b"], fmt).dump(["a\x00b"]),
                    )
                )
                self.assertNotIn(b"\x00b", list_dumped)
                self.assertIn("a\ufffdb".encode(), list_dumped)

    def test_failure_report_jsonb_values_have_nul_replaced(self):
        """The sample headers, From and To reach Jsonb with NUL replaced."""

        class FakeJsonb:
            def __init__(self, obj):
                self.obj = obj

        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [None, (1,)])
        report = {
            "arrival_date_utc": "2024-01-15 10:30:00",
            "reported_domain": "example.com",
            "source": {"ip_address": "203.0.113.1"},
            "parsed_sample": {
                "subject": "a\x00b",
                "headers": {"Subject": "a\x00b"},
                "from": {"display_name": "N\x00", "address": "x@example.com"},
                "to": [{"display_name": None, "address": "y\x00@example.com"}],
            },
        }
        with patch(
            "parsedmarc.postgres.psycopg_json", SimpleNamespace(Jsonb=FakeJsonb)
        ):
            client.save_failure_report_to_postgresql(report)
        insert = next(
            c
            for c in cur.execute.call_args_list
            if "INSERT INTO dmarc_failure_report" in c.args[0]
        )
        params = _named_params(insert)
        self.assertEqual(params["sample_headers"].obj, {"Subject": "a\ufffdb"})
        self.assertEqual(
            params["sample_from"].obj,
            {"display_name": "N\ufffd", "address": "x@example.com"},
        )
        self.assertEqual(
            params["sample_to"].obj,
            [{"display_name": None, "address": "y\ufffd@example.com"}],
        )
        # The input report is not modified.
        self.assertEqual(report["parsed_sample"]["headers"], {"Subject": "a\x00b"})


class TestPostgreSQLRejectedReport(unittest.TestCase):
    """GHSA-fxr7-7h9q-v949: a value PostgreSQL rejects (``psycopg.DataError``)
    raises PostgreSQLRejectedReport naming the report, so the CLI can skip
    that one report instead of holding the batch; any other driver error
    stays a plain PostgreSQLError."""

    class _FakeError(Exception):
        pass

    class _FakeDataError(_FakeError):
        pass

    class _FakeOperationalError(_FakeError):
        pass

    REPORTS = {
        "save_aggregate_report_to_postgresql": (
            {
                "report_metadata": {"org_name": "Example Inc.", "report_id": "agg-1"},
                "policy_published": {},
                "records": [],
            },
            ("aggregate report from Example Inc.", "agg-1"),
        ),
        "save_failure_report_to_postgresql": (
            {
                "reported_domain": "example.com",
                "arrival_date_utc": "2024-01-15 10:30:00",
                "parsed_sample": {},
                "source": {},
            },
            ("failure report for example.com", "2024-01-15 10:30:00+00"),
        ),
        "save_smtp_tls_report_to_postgresql": (
            {"organization_name": "TLS Org", "report_id": "tls-1", "policies": []},
            ("SMTP TLS report from TLS Org", "tls-1"),
        ),
    }

    def _save(self, method, report, error):
        client, mock_conn = _make_client()
        cur = _mock_cursor(mock_conn, [])
        cur.execute.side_effect = error
        with patch("parsedmarc.postgres.psycopg") as mp:
            mp.Error = self._FakeError
            mp.DataError = self._FakeDataError
            with self.assertRaises(PostgreSQLError) as ctx:
                getattr(client, method)(report)
        return ctx.exception

    def test_data_error_raises_rejected_report_naming_the_report(self):
        for method, (report, expected) in self.REPORTS.items():
            with self.subTest(method=method):
                exc = self._save(
                    method,
                    report,
                    self._FakeDataError('invalid input syntax for type inet: "x"'),
                )
                self.assertIsInstance(exc, PostgreSQLRejectedReport)
                message = str(exc)
                self.assertTrue(message.startswith("PostgreSQL rejected a value"))
                for part in expected:
                    self.assertIn(part, message)
                self.assertIn("invalid input syntax for type inet", message)

    def test_rejected_report_message_escapes_line_breaks(self):
        """The org name and the driver text come from the sender, so a
        CR/LF in them cannot forge a log line."""
        exc = self._save(
            "save_aggregate_report_to_postgresql",
            {
                "report_metadata": {"org_name": "Evil\r\nFAKE", "report_id": "1"},
                "policy_published": {},
                "records": [],
            },
            self._FakeDataError("bad value\nFAKE"),
        )
        self.assertNotIn("\n", str(exc))
        self.assertNotIn("\r", str(exc))
        self.assertIn("Evil\\r\\nFAKE", str(exc))

    def test_rejected_report_message_truncates_long_driver_text(self):
        """A DataError can quote the rejected value, which the sender chose
        and can make any length; the driver text in the message is cut to
        200 characters with an ellipsis, for every report type."""
        driver_text = 'invalid input syntax for type inet: "' + "A" * 5000 + '"'
        for method, (report, expected) in self.REPORTS.items():
            with self.subTest(method=method):
                exc = self._save(method, report, self._FakeDataError(driver_text))
                self.assertIsInstance(exc, PostgreSQLRejectedReport)
                message = str(exc)
                for part in expected:
                    self.assertIn(part, message)
                self.assertTrue(message.endswith(": " + driver_text[:200] + "..."))
                self.assertNotIn("A" * 201, message)

    def test_rejected_report_message_truncates_before_escaping(self):
        """The driver text is cut before it is escaped, so the cut cannot
        split an escape sequence: a line break at character 200 is kept
        whole as ``\\n``, and one after it is cut off."""
        exc = self._save(
            "save_aggregate_report_to_postgresql",
            self.REPORTS["save_aggregate_report_to_postgresql"][0],
            self._FakeDataError("x" * 199 + "\n" + "\r" * 50),
        )
        self.assertTrue(str(exc).endswith(": " + "x" * 199 + "\\n..."))
        self.assertNotIn("\\r", str(exc))

    def test_rejected_report_message_keeps_short_driver_text_whole(self):
        exc = self._save(
            "save_aggregate_report_to_postgresql",
            self.REPORTS["save_aggregate_report_to_postgresql"][0],
            self._FakeDataError("x" * 200),
        )
        self.assertTrue(str(exc).endswith(": " + "x" * 200))

    def test_other_driver_error_stays_plain_postgresql_error(self):
        for method, (report, _expected) in self.REPORTS.items():
            with self.subTest(method=method):
                exc = self._save(
                    method, report, self._FakeOperationalError("server closed")
                )
                self.assertNotIsInstance(exc, PostgreSQLRejectedReport)
                self.assertEqual(str(exc), "server closed")


if __name__ == "__main__":
    unittest.main()


# A password with the characters that end a URL's authority early, so a
# leak through a URL-shaped value would not be masked by accident.
_TLS_TEST_PASSWORD = "s3c/r?t#pw"


# (text after "postgresql://", refused by _has_unencoded_at(), the part of
# the password libpq parses into another component, or None for a string
# libpq parses as written).
_AT_RULE_CASES = (
    ("u:SECRETX/x@db.invalid/d", True, "SECRETX"),
    ("127.0.0.1:SECRETX/x@db.invalid/d", True, "SECRETX"),
    ("u:pa?sslmode=SECRETX/x@db.invalid/d", True, "SECRETX"),
    ("u:SECRETX/x?sslrootcert=a@b", True, "SECRETX"),
    ("u:pa@ss-SECRETX,@db.invalid/d", True, "SECRETX"),
    ("u:s3c@pw@db.example/d", True, "pw@"),
    ("u:s3c@pw:x@db.example/d", True, "x@db"),
    ("u:s3c@pw/x@db.example/d", True, "x@db"),
    ("u:s3c@p,w@db.example/d", True, "p,w"),
    ("u:a@b?sslmode=require@db/d", True, "require@"),
    ("u:a@b?sslrootcert=SECRET@db", True, "SECRET"),
    ("u/x:SECRETX@db.invalid/d", True, "SECRETX"),
    ("u:/SECRETX@db.invalid/d", True, "SECRETX"),
    ("u:12345/x@db.invalid/d", True, "12345"),
    # Not recognized, because each reads like a legitimate string: an
    # all-digit password before a "/", with the "@" only in a query value
    # (host "u", port 12345), and an "@", "?" and "/" in a password (host
    # "pw" and an sslmode after a "?", like a certificate path after one).
    ("u:12345/x?sslrootcert=a@b", False, "12345"),
    ("u:s3c@pw?sslmode=SECRET/x@db", False, "SECRET"),
    ("u:p%40w@db/d", False, None),
    ("u@db/d", False, None),
    ("db.invalid/d?sslrootcert=/home/a@b/ca.pem", False, None),
    ("db.invalid:5432/d?sslrootcert=/home/a@b/ca.pem", False, None),
    ("u:p@db.invalid/d?sslrootcert=/home/a@b/ca.pem", False, None),
    ("u:p@db.invalid?sslrootcert=/home/a@b/ca.pem", False, None),
    ("/d?host=/tmp", False, None),
    ("?host=/tmp&sslrootcert=/a@b/c", False, None),
    ("u:pw@%40sock/d", False, None),
    ("u:p@db.invalid/d%40x", False, None),
    ("[::1]:5432/d", False, None),
    ("[::1]:5432/d?sslrootcert=/a@b/c", False, None),
    ("u:p@[::1]:5432/d", False, None),
    ("u:pa?x@db/d", False, None),
    ("u:p@h1:5432,h2:5433/d", False, None),
    ("db.invalid", False, None),
)


# Connection strings whose password a shape check once let through, or
# that the early refusal catches, each with the secret (and fragments of it)
# that must never be logged or raised. The driver error each test raises
# quotes the first one.
_SECRET_CONNECTION_STRINGS = (
    ("postgresql://u:SECRETX/x@db.invalid/d", ("SECRETX",)),
    ("postgresql://127.0.0.1:SECRETX/x@db.invalid/d", ("SECRETX",)),
    ("postgresql://u:pa?sslmode=SECRETX/x@db.invalid/d", ("SECRETX",)),
    ("postgresql://u:pa@ss-SECRETX,@db.invalid/d", ("SECRETX", "ss-")),
    ("postgresql://u:s3c@pw@db.example/d", ("s3c", "pw@")),
    (
        "host=db.invalid password='SEC RETX' port=notanumber",
        ("SEC RETX", "SEC", "RETX"),
    ),
)


class TestConnectionStringDetailsWithheld(unittest.TestCase):
    """Fourth review of GHSA-xvp7-7762-gx9g: libpq ends a URI's userinfo
    at the first "@" *or* "/", so ``postgresql://u:SECRETX/x@db.invalid/d``
    parses (real psycopg 3.3 ``conninfo_to_dict``) to host ``u``, port
    ``SECRETX`` and dbname ``x@db.invalid/d``, and connecting raised
    ``connection is bad: invalid integer value "SECRETX" for connection
    option "port"``, which the client passed on. Three rounds of shape
    checks each missed a shape, so with a connection string nothing
    derived from it is logged or raised any more: a connection failure
    carries a fixed message (plus a well-formed SQLSTATE) and the startup
    warning names no host or value from the string."""

    def _construct(self, dsn, driver_error, refuse_early=True):
        """Construct a client from *dsn* with psycopg.connect raising
        *driver_error*; return (exception, log lines, connect mock)."""
        operational_error = type(driver_error)
        with contextlib.ExitStack() as stack:
            mock_psycopg = stack.enter_context(patch("parsedmarc.postgres.psycopg"))
            stack.enter_context(_without_libpq_env())
            if not refuse_early:
                stack.enter_context(_without_early_refusal())
            logs = stack.enter_context(_captured_log_text())
            mock_psycopg.Error = operational_error.__mro__[1]
            mock_psycopg.ProgrammingError = type(
                "ProgrammingError", (mock_psycopg.Error,), {}
            )
            mock_psycopg.connect.side_effect = driver_error
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(connection_string=dsn)
        return ctx.exception, logs, mock_psycopg.connect

    @staticmethod
    def _driver_error(text, sqlstate=None):
        """Return a stand-in psycopg OperationalError (a subclass of a
        fresh Error class) with *text* and a ``sqlstate`` attribute."""
        error = type("Error", (Exception,), {})
        operational_error = type("OperationalError", (error,), {"sqlstate": sqlstate})
        return operational_error(text)

    def _assert_nothing_leaks(self, dsn, secrets, exc, logs):
        rendered = "".join(traceback.format_exception(exc))
        log_text = "\n".join(logs)
        for secret in (dsn, *secrets):
            self.assertNotIn(secret, str(exc))
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, log_text)
        self.assertIsNone(exc.__cause__)
        self.assertTrue(exc.__suppress_context__)

    def test_secret_never_logged_or_raised_with_the_early_refusal(self):
        """Each string is refused before anything is logged, or (the
        keyword/value one, whose password is its own keyword) connects
        and fails with the driver's text withheld."""
        for dsn, secrets in _SECRET_CONNECTION_STRINGS:
            with self.subTest(dsn=dsn):
                driver_error = self._driver_error(
                    f'invalid integer value "{secrets[0]}" for connection option "port"'
                )
                exc, logs, _ = self._construct(dsn, driver_error)
                self._assert_nothing_leaks(dsn, secrets, exc, logs)

    def test_secret_never_logged_or_raised_without_the_early_refusal(self):
        """With the shape checks patched out, every string reaches the
        driver, whose error quotes the secret, and still nothing derived
        from the string is logged or raised: the message is the fixed
        withheld one, with no chain. This is what holds whatever shape
        gets past the early refusal."""
        for dsn, secrets in _SECRET_CONNECTION_STRINGS:
            with self.subTest(dsn=dsn):
                driver_error = self._driver_error(
                    f'connection is bad: invalid integer value "{secrets[0]}" '
                    'for connection option "port"'
                )
                exc, logs, connect = self._construct(
                    dsn, driver_error, refuse_early=False
                )
                connect.assert_called_once()
                self.assertEqual(connect.call_args.args, (dsn,))
                self.assertEqual(
                    str(exc),
                    "PostgreSQL connection failed (details withheld because "
                    "the connection string may include the password; use the "
                    "separate host, port, user, password and database "
                    "settings to see the driver's message)",
                )
                self._assert_nothing_leaks(dsn, secrets, exc, logs)

    def test_sqlstate_is_appended_only_when_well_formed(self):
        """A server's SQLSTATE (five digits or upper-case letters) is a
        fixed code, not text from the string, so it is kept; a missing,
        empty or malformed one is not shown."""
        dsn = "host=db.example password=SECRETX"
        for sqlstate, suffix in (
            ("28P01", " [SQLSTATE 28P01]"),
            (None, ""),
            ("", ""),
            ("28P01; DROP", ""),
            ("28p01", ""),
        ):
            with self.subTest(sqlstate=sqlstate):
                driver_error = self._driver_error(
                    'password authentication failed for user "SECRETX"', sqlstate
                )
                exc, _, _ = self._construct(dsn, driver_error)
                self.assertTrue(str(exc).endswith("driver's message)" + suffix))
                self.assertNotIn("SECRETX", str(exc))
                self.assertNotIn("DROP", str(exc))

    def test_separate_arguments_keep_the_driver_message(self):
        """Without a connection string the driver's message is passed on
        (with URL credentials masked), since no value in it is derived
        from a string a password fragment could land in."""
        driver_error = self._driver_error(
            'connection to "postgresql://u:PGSECRET@db.example/x" failed: '
            "Connection refused",
            "08001",
        )
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
        ):
            mock_psycopg.Error = type(driver_error).__mro__[1]
            mock_psycopg.ProgrammingError = type("ProgrammingError", (Exception,), {})
            mock_psycopg.connect.side_effect = driver_error
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(host="db.example", sslmode="verify-full")
        exc = ctx.exception
        self.assertEqual(
            str(exc),
            'connection to "postgresql://u:***@db.example/x" failed: '
            "Connection refused",
        )
        self.assertIsNone(exc.__cause__)
        self.assertTrue(exc.__suppress_context__)

    def _assert_no_secret_anywhere(self, exc, logs, secret="SECRETX"):
        """Assert *secret* is in no rendering of *exc* (str, repr, args,
        formatted traceback) nor in the captured log, and that nothing is
        chained."""
        rendered = "".join(traceback.format_exception(exc))
        for text in (str(exc), repr(exc), repr(exc.args), rendered, *logs):
            self.assertNotIn(secret, text)
        self.assertIsNone(exc.__cause__)
        self.assertTrue(exc.__suppress_context__)

    def _non_driver_failure(self, failure, client_kwargs, stage="connect"):
        """Construct a client whose *stage* (``connect``, ``autocommit`` or
        ``dumpers``) raises *failure*, an error that is not the driver's
        own (psycopg.Error is a fresh class it does not derive from);
        return (exception, log lines)."""
        with contextlib.ExitStack() as stack:
            mock_psycopg = stack.enter_context(patch("parsedmarc.postgres.psycopg"))
            stack.enter_context(_without_libpq_env())
            logs = stack.enter_context(_captured_log_text())
            mock_psycopg.Error = type("Error", (Exception,), {})
            mock_psycopg.ProgrammingError = type(
                "ProgrammingError", (mock_psycopg.Error,), {}
            )
            conn = MagicMock()
            if stage == "connect":
                mock_psycopg.connect.side_effect = failure
            elif stage == "autocommit":
                type(conn).autocommit = property(
                    lambda self: False,
                    lambda self, value: (_ for _ in ()).throw(failure),
                )
                mock_psycopg.connect.return_value = conn
            else:
                conn.adapters.register_dumper.side_effect = failure
                mock_psycopg.connect.return_value = conn
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(**client_kwargs)
        return ctx.exception, logs

    def test_non_driver_connect_errors_are_withheld(self):
        """Fifth review of GHSA-xvp7-7762-gx9g: _connect caught only
        psycopg.Error, so any other exception escaped unwrapped. psycopg
        encodes the connection string it builds from the separate
        arguments, so a password holding a lone surrogate (an environment
        variable with invalid UTF-8) raised UnicodeEncodeError with the
        whole string, password included, in ``.object``, ``.args`` and
        ``repr()``. Any such error is now a PostgreSQLError with a fixed
        message and no chain, from the connect call, setting autocommit,
        or registering the dumpers."""
        failures = (
            lambda: UnicodeEncodeError("utf-8", "password=SECRETX", 0, 1, "x"),
            lambda: ValueError("SECRETX"),
        )
        cases = (
            (
                {"connection_string": "host=db.invalid password=SECRETX"},
                "PostgreSQL connection failed (details withheld because the "
                "connection string may include the password; use the "
                "separate host, port, user, password and database settings "
                "to see the driver's message)",
            ),
            (
                {"host": "db.invalid", "user": "u", "password": "SECRETX"},
                "PostgreSQL connection failed: a connection setting could not "
                "be passed to the driver (details withheld because they may "
                "include the password)",
            ),
        )
        for make_failure in failures:
            for client_kwargs, message in cases:
                for stage in ("connect", "autocommit", "dumpers"):
                    failure = make_failure()
                    with self.subTest(
                        failure=type(failure).__name__,
                        kwargs=sorted(client_kwargs),
                        stage=stage,
                    ):
                        exc, logs = self._non_driver_failure(
                            failure, client_kwargs | {"sslmode": "verify-full"}, stage
                        )
                        self.assertEqual(str(exc), message)
                        self._assert_no_secret_anywhere(exc, logs)

    def test_keyboard_interrupt_is_not_swallowed(self):
        """The catch-all is ``except Exception``: a Ctrl-C during the
        connect attempt still propagates as KeyboardInterrupt."""
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
        ):
            mock_psycopg.Error = type("Error", (Exception,), {})
            mock_psycopg.connect.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                PostgreSQLClient(host="db.invalid", sslmode="verify-full")

    @unittest.skipUnless(PSYCOPG_INSTALLED, "psycopg is not installed")
    def test_real_psycopg_surrogate_password_is_withheld(self):
        """With the real driver, a password holding a lone surrogate makes
        psycopg raise UnicodeEncodeError('utf-8', 'host=127.0.0.1 port=1
        user=u password=\\udcffSECRETX ...') while it encodes the
        connection string, before any network I/O (Python 3.12 and 3.15).
        The client raises a PostgreSQLError with none of it."""
        with _without_libpq_env(), _captured_log_text() as logs:
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(
                    host="127.0.0.1",
                    port=1,
                    user="u",
                    password="\udcffSECRETX",
                    database="d",
                    sslmode="disable",
                )
        exc = ctx.exception
        self.assertIsInstance(exc, PostgreSQLError)
        self.assertTrue(str(exc).startswith("PostgreSQL connection failed: a "))
        self._assert_no_secret_anywhere(exc, logs)

    @unittest.skipUnless(PSYCOPG_INSTALLED, "psycopg is not installed")
    def test_real_psycopg_overlong_host_label_is_withheld(self):
        """A host label over 63 characters fails in psycopg's name
        resolution before any network I/O: on Python 3.15 with
        UnicodeEncodeError('idna', '<the host>', ...), which psycopg's
        getaddrinfo wrapper (it catches only OSError) does not wrap, and
        on 3.12 with a bare UnicodeError. Here the host holds the rest of
        a password (``password=se host=a`` + ``SECRETX`` * 10 +
        ``.invalid``); the client raises the withheld message instead."""
        dsn = "password=se host=a" + "SECRETX" * 10 + ".invalid"
        with _without_libpq_env(), _captured_log_text() as logs:
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(connection_string=dsn, sslmode="disable")
        exc = ctx.exception
        self.assertIsInstance(exc, PostgreSQLError)
        self.assertTrue(str(exc).startswith("PostgreSQL connection failed ("))
        self._assert_no_secret_anywhere(exc, logs)

    @unittest.skipUnless(PSYCOPG_INSTALLED, "psycopg is not installed")
    def test_real_psycopg_withholds_a_password_parsed_as_the_port(self):
        """With the real driver and the early refusal patched out,
        ``postgresql://127.0.0.1:SECRETX/x@db.invalid/d`` reaches libpq,
        which fails locally on the port ``SECRETX`` (no server is
        contacted) with ``invalid integer value "SECRETX" for connection
        option "port"``; the raised error, its traceback and the log carry
        no part of it."""
        dsn = "postgresql://127.0.0.1:SECRETX/x@db.invalid/d"
        with (
            _without_libpq_env(),
            _without_early_refusal(),
            _captured_log_text() as logs,
        ):
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(connection_string=dsn)
        exc = ctx.exception
        self.assertTrue(str(exc).startswith("PostgreSQL connection failed"))
        self._assert_nothing_leaks(dsn, ("SECRETX",), exc, logs)


class TestPostgreSQLTLS(unittest.TestCase):
    """GHSA-xvp7-7762-gx9g: the client connects with ``sslmode=require``
    unless the caller, the connection string, or ``PGSSLMODE`` chooses a
    mode, and warns at startup when a remote server's certificate is not
    verified. Before the fix no sslmode was passed, so libpq used
    ``prefer`` and continued over plain TCP when an on-path attacker
    declined TLS, then answered its clear-text password request.

    psycopg is mocked at ``parsedmarc.postgres.psycopg``; the libpq
    environment is cleared so the developer's shell does not leak in."""

    def _connect_call(self, env=None, **client_kwargs):
        """Construct a client with psycopg.connect mocked and return the
        call psycopg.connect received."""
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
            patch.dict(os.environ, env or {}),
        ):
            mock_psycopg.Error = Exception
            PostgreSQLClient(**client_kwargs)
        mock_psycopg.connect.assert_called_once()
        return mock_psycopg.connect.call_args

    def _warnings(self, env=None, **client_kwargs) -> list[str]:
        """Construct a client and return the warnings it logged."""
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            self._connect_call(env=env, **client_kwargs)
        return cm.output

    def _assert_no_warning(self, env=None, **client_kwargs):
        with self.assertNoLogs("parsedmarc.log", level="WARNING"):
            self._connect_call(env=env, **client_kwargs)

    # -- the sslmode passed to psycopg.connect -------------------------------

    def test_default_sslmode_is_require_with_host(self):
        call = self._connect_call(
            host="db.example", user="u", password="pw", database="d"
        )
        self.assertEqual(call.args, ())
        self.assertEqual(call.kwargs["sslmode"], "require")
        self.assertNotIn("sslrootcert", call.kwargs)
        self.assertEqual(call.kwargs["host"], "db.example")
        self.assertEqual(call.kwargs["password"], "pw")

    def test_default_sslmode_is_require_with_connection_string(self):
        call = self._connect_call(connection_string="host=db.example user=u")
        self.assertEqual(call.args, ("host=db.example user=u",))
        self.assertEqual(call.kwargs, {"sslmode": "require"})

    def test_explicit_sslmode_and_sslrootcert_pass_through(self):
        call = self._connect_call(
            host="db.example", sslmode="verify-full", sslrootcert="/etc/ca.pem"
        )
        self.assertEqual(call.kwargs["sslmode"], "verify-full")
        self.assertEqual(call.kwargs["sslrootcert"], "/etc/ca.pem")

    def test_explicit_sslmode_overrides_connection_string_and_environment(self):
        call = self._connect_call(
            env={"PGSSLMODE": "disable"},
            connection_string="host=db.example sslmode=prefer",
            sslmode="verify-ca",
        )
        self.assertEqual(call.kwargs, {"sslmode": "verify-ca"})

    def test_connection_string_sslmode_is_left_to_libpq(self):
        """A string that sets sslmode gets no sslmode keyword, which psycopg
        would merge over the string's own value."""
        call = self._connect_call(
            connection_string="host=db.example sslmode=verify-full user=u",
            sslrootcert="/etc/ca.pem",
        )
        self.assertEqual(call.args, ("host=db.example sslmode=verify-full user=u",))
        self.assertEqual(call.kwargs, {"sslrootcert": "/etc/ca.pem"})

    def test_pgsslmode_environment_is_left_to_libpq(self):
        call = self._connect_call(env={"PGSSLMODE": "verify-ca"}, host="db.example")
        self.assertNotIn("sslmode", call.kwargs)

    def test_malformed_connection_string_withheld_before_connecting(self):
        """The string is parsed before connecting; a parse failure, whose
        libpq message quotes the offending word, raises the withheld-details
        error from None, so neither the message nor the traceback carries
        the string or the password, and no connection is attempted."""
        dsn = f"host=db.example {_TLS_TEST_PASSWORD}"
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
        ):
            mock_psycopg.Error = Exception
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(connection_string=dsn)
        mock_psycopg.connect.assert_not_called()
        exc = ctx.exception
        self.assertIn("Invalid PostgreSQL connection_string", str(exc))
        rendered = "".join(traceback.format_exception(exc))
        for secret in (dsn, _TLS_TEST_PASSWORD, "s3c"):
            self.assertNotIn(secret, str(exc))
            self.assertNotIn(secret, rendered)
        self.assertIsNone(exc.__cause__)
        self.assertTrue(exc.__suppress_context__)

    # -- the startup warning -------------------------------------------------

    def test_warning_for_remote_host_without_verification(self):
        cases = (
            ({"host": "db.example"}, "require"),
            ({"host": "db.example", "sslmode": "require"}, "require"),
            ({"host": "db.example", "sslmode": "prefer"}, "prefer"),
            ({"connection_string": "host=db.example"}, "require"),
            ({"connection_string": "hostaddr=192.0.2.10"}, "require"),
            ({"host": "localhost,db.example"}, "require"),
            ({"host": "192.0.2.10"}, "require"),
            # libpq connects to hostaddr, not host, when both are set.
            ({"connection_string": "host=localhost hostaddr=203.0.113.5"}, "require"),
        )
        for kwargs, mode in cases:
            with self.subTest(kwargs=kwargs):
                output = self._warnings(**kwargs)
                self.assertEqual(len(output), 1)
                if "connection_string" in kwargs:
                    self.assertIn(
                        "The PostgreSQL connection_string does not verify the "
                        f"server certificate (sslmode is {mode});",
                        output[0],
                    )
                else:
                    self.assertIn(
                        f"uses sslmode={mode}, which does not verify", output[0]
                    )
                self.assertIn("set [postgresql] sslmode = verify-full", output[0])

    def test_warning_names_the_host_but_no_credential(self):
        """With the separate arguments the warning names the host only:
        not the password (one with "/", "?" and "#") or the user."""
        output = "\n".join(
            self._warnings(
                host="db.example", user="dmarcuser", password=_TLS_TEST_PASSWORD
            )
        )
        self.assertIn("PostgreSQL connection to db.example uses", output)
        for secret in (_TLS_TEST_PASSWORD, "s3c", "dmarcuser"):
            self.assertNotIn(secret, output)

    def test_connection_string_warning_names_no_value_from_the_string(self):
        """With a connection string the warning names no host, user,
        password or other value from the string: when the user name or
        password holds an unencoded "@" or "/", libpq parses part of the
        password as the host or a query parameter. PGHOST from the
        environment is not named either."""
        dsn = f"host=db.example user=dmarcuser password={_TLS_TEST_PASSWORD}"
        for env in ({}, {"PGHOST": "pghost.example"}):
            with self.subTest(env=env):
                output = "\n".join(self._warnings(env=env, connection_string=dsn))
                self.assertIn(
                    "The PostgreSQL connection_string does not verify the server "
                    "certificate (sslmode is require)",
                    output,
                )
                for value in (
                    "db.example",
                    "pghost.example",
                    _TLS_TEST_PASSWORD,
                    "s3c",
                    "dmarcuser",
                    dsn,
                ):
                    self.assertNotIn(value, output)

    def test_connection_string_warning_prints_only_a_recognized_mode(self):
        """The mode is printed only when it is one of SSL_MODES: a typo
        (``verfy-full``) and an sslmode that holds a password fragment
        (``postgresql://u:pa?sslmode=SECRETX/x@db.invalid/d`` parses with
        host ``u``, port ``pa`` and sslmode ``SECRETX/x@db.invalid/d``) are
        both shown as "not a recognized value". The early refusal is
        patched out so the warning itself is what is tested."""
        for dsn, secrets in (
            ("host=db.example sslmode=verfy-full", ("db.example", "verfy")),
            (
                "postgresql://u:pa?sslmode=SECRETX/x@db.invalid/d",
                ("SECRETX", "db.invalid", "x@"),
            ),
        ):
            with self.subTest(dsn=dsn), _without_early_refusal():
                output = "\n".join(self._warnings(connection_string=dsn))
                self.assertIn("(sslmode is not a recognized value)", output)
                for secret in secrets:
                    self.assertNotIn(secret, output)

    def test_warning_masks_a_host_with_an_at_sign(self):
        """A URI connection string whose host holds an "@" is refused (see
        test_unencoded_at_in_connection_string_is_refused), but the *host*
        argument, ``PGHOST`` and ``PGHOSTADDR`` are passed on, so the
        warning still credential-masks the host it names, in a host list
        too."""
        cases = (
            ({"host": "pw@db.example"}, {}),
            ({"host": "pw@db.example,h2.example"}, {}),
            ({}, {"PGHOST": "pw@db.example"}),
            ({}, {"PGHOSTADDR": "pw@db.example"}),
        )
        for kwargs, env in cases:
            with self.subTest(kwargs=kwargs, env=env):
                output = "\n".join(self._warnings(env=env, **kwargs))
                self.assertIn("PostgreSQL connection to ***@db.example", output)
                self.assertNotIn("pw@", output)

    def test_unencoded_at_in_connection_string_is_refused(self):
        """libpq ends a URI's userinfo at the first "@", so the rest of a
        password containing an unencoded "@" lands in the host, the port or
        the database name (with psycopg 3.3's conninfo_to_dict:
        ``u:s3c@pw:x@db.example`` gives host ``pw`` and port
        ``x@db.example``; ``u:s3c@pw/x@db.example/d`` host ``pw`` and
        dbname ``x@db.example/d``; ``u:s3c@p,w@db.example`` host
        ``p,w@db.example``; ``u:s3c@pw@db.example`` host
        ``pw@db.example``). The startup warning then named host ``pw`` and
        the driver failed to resolve it, a password fragment in the log
        both times. Such a string is now refused before anything is logged
        or any connection is attempted, with every sslmode, and neither
        the message nor the traceback holds the password or a fragment."""
        cases = (
            ("postgresql://u:s3c@pw:x@db.example/d", ("s3c", "pw", "x@db")),
            ("postgresql://u:s3c@pw/x@db.example/d", ("s3c", "pw", "x@db")),
            ("postgresql://u:s3c@p,w@db.example/d", ("s3c", "p,w")),
            ("postgresql://u:s3c@pw@db.example/d", ("s3c", "pw")),
            # An "@" at the start of a host-list entry names an abstract
            # socket, which a check on the parsed host exempted.
            ("postgresql://u:pa@ss-SECRETX,@db.invalid/d", ("SECRETX", "ss-", "pa@ss")),
            # The fragment lands in a query parameter: sslmode (which the
            # warning names) or sslrootcert (which libpq's errors quote).
            ("postgresql://u:a@b?sslmode=require@db/d", ("a@b", "sslmode=require")),
            ("postgresql://u:a@b?sslrootcert=SECRET@db", ("SECRET", "a@b")),
            # libpq's scan for the userinfo stops at the first "/" as well as
            # the first "@", so an unencoded "/" in the password ends the
            # authority: host "u", port "SECRETX", dbname "x@db.invalid/d".
            ("postgresql://u:SECRETX/x@db.invalid/d", ("SECRETX",)),
            ("postgresql://127.0.0.1:SECRETX/x@db.invalid/d", ("SECRETX",)),
            ("postgresql://u:pa?sslmode=SECRETX/x@db.invalid/d", ("SECRETX",)),
            # Port "SECRETX", and the "@" only in a query value.
            ("postgresql://u:SECRETX/x?sslrootcert=a@b", ("SECRETX",)),
            # A "/" in the user name, or a password that starts with "/" or
            # is all digits: the "@" lands in the database name.
            ("postgresql://u/x:SECRETX@db.invalid/d", ("SECRETX",)),
            ("postgresql://u:/SECRETX@db.invalid/d", ("SECRETX",)),
            ("postgresql://u:12345/x@db.invalid/d", ("12345",)),
            # Case and leading whitespace do not hide the URI form.
            (" PostgreSQL://u:s3c@pw@db.example/d", ("s3c", "pw")),
        )
        for dsn, secrets in cases:
            for sslmode in (None, "verify-full"):
                with self.subTest(dsn=dsn, sslmode=sslmode):
                    with (
                        patch("parsedmarc.postgres.psycopg") as mock_psycopg,
                        _without_libpq_env(),
                        self.assertNoLogs("parsedmarc.log", level="DEBUG"),
                    ):
                        mock_psycopg.Error = Exception
                        with self.assertRaises(PostgreSQLError) as ctx:
                            PostgreSQLClient(connection_string=dsn, sslmode=sslmode)
                    mock_psycopg.connect.assert_not_called()
                    exc = ctx.exception
                    self.assertIn(
                        'appears to have an unencoded "@" or "/" in its user '
                        "name, password or database name",
                        str(exc),
                    )
                    self.assertIn("percent-encode", str(exc))
                    rendered = "".join(traceback.format_exception(exc))
                    for secret in (dsn, *secrets):
                        self.assertNotIn(secret, str(exc))
                        self.assertNotIn(secret, rendered)
                    self.assertIsNone(exc.__cause__)

    def test_unencoded_at_rule_table(self):
        """_has_unencoded_at() mirrors libpq's URI scan (userinfo up to the
        first "@" or "/") and refuses each string in which a part of the
        password lands in another component, except two shapes it does not
        recognize because each reads like a legitimate string (see the
        table), which the withheld messages keep out of the logs
        regardless. Strings libpq parses as written are accepted."""
        for rest, refused, fragment in _AT_RULE_CASES:
            with self.subTest(rest=rest):
                self.assertIs(_has_unencoded_at("postgresql://" + rest), refused)
                if refused:
                    self.assertIsNotNone(fragment)

    @unittest.skipUnless(PSYCOPG_INSTALLED, "psycopg is not installed")
    def test_real_parser_agrees_with_the_rule_table(self):
        """With the real conninfo_to_dict, the password fragment of each
        misparsed string in the table is in a component other than the
        user name and password, and each string listed as parsed as
        written has its "@" only where it was written: in the userinfo
        separator, a %40, or a query value."""
        from psycopg.conninfo import conninfo_to_dict

        for rest, _refused, fragment in _AT_RULE_CASES:
            with self.subTest(rest=rest):
                params = conninfo_to_dict("postgresql://" + rest)
                others = [
                    str(value)
                    for key, value in params.items()
                    if key not in ("user", "password")
                ]
                if fragment is not None:
                    self.assertTrue(any(fragment in v for v in others), params)
                    continue
                for key in ("host", "port", "dbname"):
                    value = str(params.get(key) or "")
                    self.assertTrue("@" not in value or "%40" in rest, (key, params))
                port = str(params.get("port") or "")
                self.assertTrue(all(p.isdigit() for p in port.split(",") if p))

    def test_unencoded_at_is_refused_on_reconnect(self):
        """_connect parses the string itself as well, so a reconnect (whose
        sslmode lookup skips the string when sslmode is set) never hands a
        refused string to the driver either."""
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
        ):
            mock_psycopg.Error = Exception
            client = PostgreSQLClient(
                connection_string="postgresql://u:p@db.example/d",
                sslmode="verify-full",
            )
            client._connection_string = "postgresql://u:s3c@pw@db.example/d"
            with self.assertRaises(PostgreSQLError) as ctx:
                client._connect()
        self.assertEqual(mock_psycopg.connect.call_count, 1)
        self.assertIn('unencoded "@"', str(ctx.exception))

    def test_percent_encoded_at_in_password_connects(self):
        """A password whose "@" is percent-encoded parses with the right
        host, and the string reaches the driver unchanged."""
        dsn = "postgresql://u:s3c%40pw@db.example/d"
        call = self._connect_call(connection_string=dsn, sslmode="verify-full")
        self.assertEqual(call.args, (dsn,))

    def test_percent_encoded_at_elsewhere_in_uri_connects(self):
        """A URI never needs a second literal "@": one in an abstract
        socket host or a query value is written %40, which libpq decodes
        (psycopg 3.3: ``postgresql://u@%40sock/d`` has host ``@sock``,
        ``?sslrootcert=a%40b`` sslrootcert ``a@b``), so such a URI is
        accepted and passed on unchanged."""
        for dsn in (
            "postgresql://u@%40pgsock/d",
            "postgresql://u:pw@/d?host=%40pgsock",
            "postgresql://u:pw@db.example/d?sslrootcert=a%40b",
            "postgresql://u:p%2Fw@db.example/d",
        ):
            with self.subTest(dsn=dsn):
                call = self._connect_call(connection_string=dsn, sslmode="verify-full")
                self.assertEqual(call.args, (dsn,))

    def test_legitimate_connection_strings_are_not_refused(self):
        """Strings libpq parses as written are passed on unchanged: an "@"
        that is percent-encoded (a database name ``d%40x`` cannot be fixed
        by encoding, so refusing it would leave no way to name it), one in
        a query value after a "/" (a certificate path), IPv6 hosts with a
        port, host lists, a "?" in a password, and keyword/value strings,
        whose password is a keyword of its own: an "@" in their host,
        hostaddr or dbname is not a password fragment, and libpq does not
        percent-decode them, so encoding advice would be wrong."""
        for dsn in (
            "postgresql://u:p%40w@db.invalid/d",
            "postgresql://u@db.invalid/d",
            "postgresql://db.invalid/d?sslrootcert=/home/a@b/ca.pem",
            "postgresql://db.invalid:5432/d?sslrootcert=/home/a@b/ca.pem",
            "postgresql://u:p@db.invalid/d?sslrootcert=/home/a@b/ca.pem",
            "postgresql://u:p@db.invalid?sslrootcert=/home/a@b/ca.pem",
            "postgresql:///d?host=/tmp",
            "postgresql://u:pw@%40sock/d",
            "postgresql://u:p@db.invalid/d%40x",
            "postgresql://[::1]:5432/d",
            "postgresql://u:p@[::1]:5432/d",
            "postgresql://u:pa?x@db.invalid/d",
            "postgresql://u:p@h1.invalid:5432,h2.invalid:5433/d",
            "dbname=a@b host=db.invalid",
            "host=pw@db.invalid,h2.invalid",
            "hostaddr=pw@db.invalid",
        ):
            with self.subTest(dsn=dsn):
                call = self._connect_call(connection_string=dsn, sslmode="verify-full")
                self.assertEqual(call.args, (dsn,))

    def test_abstract_socket_host_in_connection_string_is_allowed(self):
        """An "@" at the start of a host entry names a Linux abstract
        socket, not a password fragment, in a keyword/value string (whose
        password is its own keyword, so no fragment of it can land in the
        host)."""
        for dsn in ("host=@pgsock dbname=d", "host=db.example,@pgsock dbname=d"):
            with self.subTest(dsn=dsn):
                call = self._connect_call(connection_string=dsn)
                self.assertEqual(call.args, (dsn,))

    def test_warning_host_and_mode_come_from_the_environment(self):
        """With no host argument libpq connects to PGHOST (or PGHOSTADDR),
        and with no sslmode set elsewhere it uses PGSSLMODE."""
        output = self._warnings(env={"PGHOST": "db.example", "PGSSLMODE": "allow"})
        self.assertIn("connection to db.example uses sslmode=allow", output[0])
        output = self._warnings(env={"PGHOSTADDR": "192.0.2.10"})
        self.assertIn("connection to 192.0.2.10 uses sslmode=require", output[0])
        output = self._warnings(
            env={"PGSSLMODE": "prefer"},
            connection_string="host=db.example sslmode=disable",
        )
        self.assertIn("(sslmode is disable)", output[0])
        # PGHOST decides that a connection string without a host is remote,
        # but is not named.
        output = self._warnings(
            env={"PGHOST": "pghost.example"}, connection_string="dbname=d"
        )
        self.assertIn("(sslmode is require)", output[0])
        self.assertNotIn("pghost.example", output[0])

    def test_warning_host_is_escaped(self):
        """A line break in the host is escaped, so it cannot forge a log
        line."""
        output = self._warnings(host="db.example\nforged")
        self.assertIn("db.example\\nforged", output[0])
        self.assertNotIn("\nforged", output[0])

    def test_no_warning_for_local_or_verified_connections(self):
        cases = (
            {"host": "127.0.0.1"},
            {"host": "127.0.0.53"},
            {"host": "::1"},
            {"host": "localhost"},
            {"host": "LocalHost"},
            {"host": "/var/run/postgresql"},
            {"host": "@abstract"},
            {"host": "localhost,::1,/tmp"},
            {"host": None},
            {"connection_string": "dbname=dmarc"},
            {"connection_string": "postgresql:///dmarc"},
            {"host": "db.example", "sslmode": "verify-full"},
            {"host": "db.example", "sslmode": "verify-ca"},
            {"connection_string": "host=db.example sslmode=verify-full"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                self._assert_no_warning(**kwargs)
        with self.subTest(env="PGSSLMODE=verify-full"):
            self._assert_no_warning(env={"PGSSLMODE": "verify-full"}, host="db.example")

    def test_no_warning_for_require_with_an_existing_root_certificate(self):
        """libpq: "if a root CA file exists, the behavior of sslmode=require
        will be the same as that of verify-ca" (PostgreSQL docs, libpq SSL
        support), so the default mode with an sslrootcert that exists is
        not warned about, from the argument, the string or PGSSLROOTCERT.
        A root certificate that does not exist leaves require unverified."""
        with tempfile.TemporaryDirectory() as tmp:
            ca = os.path.join(tmp, "ca.pem")
            with open(ca, "w") as f:
                f.write("not parsed")
            for env, kwargs in (
                ({}, {"host": "db.example", "sslrootcert": ca}),
                ({}, {"host": "db.example", "sslmode": "require", "sslrootcert": ca}),
                ({}, {"connection_string": f"host=db.example sslrootcert={ca}"}),
                ({"PGSSLROOTCERT": ca}, {"host": "db.example"}),
            ):
                with self.subTest(env=env, kwargs=kwargs):
                    self._assert_no_warning(env=env, **kwargs)
            missing = os.path.join(tmp, "missing.pem")
            output = self._warnings(host="db.example", sslrootcert=missing)
            self.assertIn("uses sslmode=require", output[0])
            output = self._warnings(host="db.example", sslmode="prefer", sslrootcert=ca)
            self.assertIn("uses sslmode=prefer", output[0])

    def test_warning_is_logged_once_not_on_reconnect(self):
        with (
            patch("parsedmarc.postgres.psycopg") as mock_psycopg,
            _without_libpq_env(),
        ):
            mock_psycopg.Error = Exception
            with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
                client = PostgreSQLClient(host="db.example")
                mock_psycopg.connect.return_value.closed = True
                client._ensure_connected()
        self.assertEqual(mock_psycopg.connect.call_count, 2)
        self.assertEqual(
            mock_psycopg.connect.call_args_list[1].kwargs["sslmode"], "require"
        )
        tls = [m for m in cm.output if "does not verify the server" in m]
        self.assertEqual(len(tls), 1)

    # -- the real driver against a server that declines TLS ------------------

    @unittest.skipUnless(PSYCOPG_INSTALLED, "psycopg is not installed")
    def test_real_psycopg_sends_nothing_after_tls_is_declined(self):
        """With the default sslmode, libpq gives up when the server answers
        the SSLRequest with "N": no startup packet (which names the user),
        let alone a password, follows. The same server with
        ``sslmode="disable"`` receives the startup packet, so the server
        does observe what it claims to. Before the fix, libpq's ``prefer``
        sent the startup packet over plain TCP after the "N" and then
        answered a clear-text password request."""
        with _without_libpq_env():
            server = _TLSDecliningServer()
            with self.assertRaises(PostgreSQLError) as ctx:
                PostgreSQLClient(
                    host="127.0.0.1",
                    port=server.port,
                    user="u",
                    password=_TLS_TEST_PASSWORD,
                    database="d",
                )
            server.join()
        message = str(ctx.exception)
        self.assertIn("SSL", message)
        self.assertNotIn(_TLS_TEST_PASSWORD, message)
        self.assertNotIn("s3c", message)
        self.assertTrue(server.ssl_requested)
        self.assertEqual(server.after_refusal, b"")

        with _without_libpq_env():
            server = _TLSDecliningServer()
            with self.assertRaises(PostgreSQLError):
                PostgreSQLClient(
                    host="127.0.0.1",
                    port=server.port,
                    user="u",
                    password=_TLS_TEST_PASSWORD,
                    database="d",
                    sslmode="disable",
                )
            server.join()
        self.assertFalse(server.ssl_requested)
        self.assertIn(b"user\x00u\x00", server.startup)


# PostgreSQL protocol request codes (protocol docs, "Message Formats"):
# SSLRequest and GSSENCRequest are an Int32 length of 8 and one of these.
_SSL_REQUEST_CODE = 80877103
_GSSENC_REQUEST_CODE = 80877104


class _TLSDecliningServer:
    """A one-connection loopback server that declines encryption.

    It answers an SSLRequest (and a GSSENCRequest, which libpq built with
    GSSAPI may send first) with "N", then records every byte the client
    sends afterwards until the client closes or 1 s passes. A first
    message that is not such a request is a startup packet, recorded the
    same way. No authentication request is ever sent, so the client fails.
    """

    def __init__(self):
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self.ssl_requested = False
        self.after_refusal = b""
        self.startup = b""
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def join(self):
        self._thread.join(timeout=10)
        self._sock.close()

    @staticmethod
    def _read_until_idle(conn) -> bytes:
        data = b""
        conn.settimeout(1.0)
        try:
            while chunk := conn.recv(4096):
                data += chunk
        except (TimeoutError, OSError):
            pass
        return data

    def _serve(self):
        self._sock.settimeout(10)
        conn, _ = self._sock.accept()
        with conn:
            conn.settimeout(5)
            while True:
                first = b""
                while len(first) < 8:
                    chunk = conn.recv(8 - len(first))
                    if not chunk:
                        return
                    first += chunk
                length, code = struct.unpack("!ii", first)
                if length == 8 and code == _GSSENC_REQUEST_CODE:
                    conn.sendall(b"N")
                    continue
                if length == 8 and code == _SSL_REQUEST_CODE:
                    self.ssl_requested = True
                    conn.sendall(b"N")
                    self.after_refusal = self._read_until_idle(conn)
                else:
                    self.startup = first + self._read_until_idle(conn)
                return
