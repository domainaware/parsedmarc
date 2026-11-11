# -*- coding: utf-8 -*-

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # LiteralString requires Python >= 3.11, so only import it for type checking
    from typing import LiteralString

    import psycopg
    from psycopg import conninfo as psycopg_conninfo
    from psycopg.abc import Buffer
    from psycopg.types import json as psycopg_json
    from psycopg.types import string as psycopg_string
else:
    try:
        import psycopg
        from psycopg import conninfo as psycopg_conninfo
        from psycopg.types import json as psycopg_json
        from psycopg.types import string as psycopg_string
    except ImportError:
        psycopg = None
        psycopg_conninfo = None
        psycopg_json = None
        psycopg_string = None

from parsedmarc.log import logger
from parsedmarc.utils import (
    human_timestamp_to_datetime,
    redact_url_credentials,
    sanitize_for_log,
)

# psycopg is an optional dependency (the PostgreSQL backend is opt-in). The
# pure helper functions below work without it; only PostgreSQLClient needs a
# live driver, so the import error surfaces at client construction with a
# pip-install hint rather than breaking ``import parsedmarc`` for everyone.
_PSYCOPG_INSTALL_HINT = (
    "The PostgreSQL backend requires the 'psycopg' package. "
    "Install it with: pip install parsedmarc[postgresql]"
)

# libpq's sslmode values, weakest first. libpq's own default is "prefer",
# which falls back to plain TCP when the server (or an on-path attacker)
# declines TLS, so parsedmarc defaults to "require" (GHSA-xvp7-7762-gx9g).
SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")
DEFAULT_SSL_MODE = "require"
_VERIFYING_SSL_MODES = ("verify-ca", "verify-full")

_WITHHELD_CONNECTION_STRING_ERROR = (
    "Invalid PostgreSQL connection_string (details withheld "
    "because they may include the password)"
)

_UNENCODED_AT_CONNECTION_STRING_ERROR = (
    'PostgreSQL connection_string appears to have an unencoded "@" or "/" '
    "in its user name, password or database name (details withheld because "
    'they may include the password); percent-encode "@" as %40 and "/" as '
    "%2F, or use the separate host, port, user, password and database "
    "settings"
)

# With a connection string, a connection failure is reported with this fixed
# text and not libpq's: libpq's message can quote any value parsed from the
# string (a port, a host, an sslmode), and when the string's user name or
# password holds an unencoded "@" or "/", such a value is a fragment of the
# password. See PostgreSQLClient._connect().
_WITHHELD_CONNECTION_FAILURE_ERROR = (
    "PostgreSQL connection failed (details withheld because the "
    "connection string may include the password; use the separate host, "
    "port, user, password and database settings to see the driver's "
    "message)"
)

# With a connection string, a table creation failure is reported with this
# fixed text and not the server's: the server's message can quote a session
# setting taken from the string's options (for "-c default_tablespace=X",
# 'tablespace "X" does not exist'). See PostgreSQLClient.create_tables().
_WITHHELD_TABLE_CREATION_ERROR = (
    "PostgreSQL table creation failed (details withheld because the "
    "connection string may include the password; use the separate host, "
    "port, user, password and database settings to see the server's "
    "message)"
)

# With the separate settings, an error that is not the driver's own (a
# password the driver cannot encode, say) is reported with this fixed text:
# such an error quotes the value it could not handle, or the whole
# connection string psycopg built from the settings, password included.
_WITHHELD_CONNECTION_SETTING_ERROR = (
    "PostgreSQL connection failed: a connection setting could not be passed "
    "to the driver (details withheld because they may include the password)"
)

# A SQLSTATE is five digits or upper-case letters (PostgreSQL docs, Appendix
# A, "PostgreSQL Error Codes"); anything else is not included.
_SQLSTATE_PATTERN = re.compile(r"[0-9A-Z]{5}")


def _sqlstate_suffix(exc: BaseException) -> str:
    """Return `` [SQLSTATE xxxxx]`` for a driver error that carries a
    well-formed SQLSTATE, else an empty string.

    psycopg sets ``sqlstate`` when the server answered with an error (for
    example ``28P01``, a failed password). It is a fixed code chosen by the
    server, not text taken from the connection string, so it is safe to
    show even when the driver's message is withheld.
    """
    sqlstate = getattr(exc, "sqlstate", None)
    if isinstance(sqlstate, str) and _SQLSTATE_PATTERN.fullmatch(sqlstate):
        return f" [SQLSTATE {sqlstate}]"
    return ""


def _is_local_host(host: str) -> bool:
    """Return whether one libpq ``host`` entry is a Unix socket or loopback.

    An empty entry means libpq's default Unix socket, and a value starting
    with ``/`` (a socket directory) or ``@`` (a Linux abstract socket) is a
    socket as well.
    """
    if not host or host.startswith(("/", "@")) or host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _log_safe_host(host: str) -> str:
    """Return a libpq ``host`` (or ``hostaddr``) value safe to log.

    Each entry of a comma-separated list is credential-masked with
    ``redact_url_credentials()`` (``pw@db.example`` becomes
    ``***@db.example``), and the result is escaped for the log.
    """
    entries = [str(redact_url_credentials(entry)) for entry in host.split(",")]
    return sanitize_for_log(",".join(entries))


_URI_PREFIXES = ("postgresql://", "postgres://")


def _is_uri(connection_string: str) -> bool:
    """Return whether a connection string is in libpq's URI form.

    libpq itself recognizes only the exact lowercase prefixes
    ``postgresql://`` and ``postgres://`` at the very start of the string,
    and parses anything else as keyword/value pairs. The check here also
    ignores case and leading whitespace: such a string fails libpq's
    keyword/value parse anyway, so treating it as a URI only refuses it
    with a different fixed message.
    """
    return connection_string.lstrip().lower().startswith(_URI_PREFIXES)


def _port_is_numeric(entry: str) -> bool:
    """Return whether one ``host[:port]`` entry of a URI authority has no
    port, an empty one (``db:``, which libpq parses as no port) or an
    all-digit one. A bracketed IPv6 address is skipped first, so its colons
    are not taken for a port separator."""
    entry = entry.strip()
    if entry.startswith("["):
        entry = entry.partition("]")[2]
    if ":" not in entry:
        return True
    port = entry.rpartition(":")[2]
    return not port or (port.isascii() and port.isdigit())


def _has_unencoded_at(connection_string: str) -> bool:
    """Return whether a URI connection string looks like its user name or
    password holds an unencoded ``@`` or ``/``.

    The scan mirrors libpq's URI parser. libpq looks for the userinfo by
    scanning the text after ``://`` up to the first ``@`` or ``/``; when it
    meets ``@`` first, everything before it is the user name and password,
    the host list runs to the next ``/`` or ``?``, and the database name
    from that ``/`` to the next ``?``. So the rest of a password containing
    an unencoded ``@`` lands in the host
    (``postgresql://u:s3c@pw@db.example/d`` has host ``pw@db.example``),
    the port, the database name or a query parameter, and a password
    containing an unencoded ``/`` ends the authority early
    (``postgresql://u:SECRET/x@db.example/d`` has no userinfo, host ``u``,
    port ``SECRET`` and dbname ``x@db.example/d``).

    The string is refused when, with userinfo, the text from it to the next
    ``/`` holds another ``@`` (the host list, or a query parameter written
    before any ``/``), or the database name holds an ``@``; and, without
    userinfo, when the database name holds an ``@``, or an ``@`` follows an
    authority whose port is not a number (``u:pa?sslmode=SECRET/x@db/d``
    has port ``pa`` and sslmode ``SECRET/x@db/d``). A URI never needs an
    unencoded ``@`` in those places: libpq decodes ``%40`` and ``%2F`` in
    every component. An ``@`` in a query value after a ``/``
    (``?sslrootcert=/home/a@b/ca.pem``) is not refused, because nothing
    tells it apart from a legitimate one. For the same reason two shapes
    are not recognized: an empty or all-digit password before a ``/``,
    followed by an ``@`` only in a query value
    (``u:12345/x?sslrootcert=a@b``, ``u:/x?sslrootcert=a@b``), and a
    password with an ``@``, then a ``?``, then a ``/``
    (``u:s3c@pw?sslmode=SECRET/x@db``).

    This refusal is a convenience that names the common mistake; it does
    not keep the password out of the logs. That is done by withholding
    every value parsed from a connection string from the startup warning
    and the connection error (``PostgreSQLClient._connect()``), whatever
    shape the string has.
    """
    rest = connection_string.partition("://")[2]
    first = next((i for i, char in enumerate(rest) if char in "@/"), -1)
    if first == -1:
        return False
    if rest[first] == "@":
        segment, slash, tail = rest[first + 1 :].partition("/")
        if "@" in segment:
            return True
        # A "?" before the "/" puts that "/" in a query value.
        return bool(slash) and "?" not in segment and "@" in tail.partition("?")[0]
    authority, question, _ = rest[:first].partition("?")
    tail = rest[first + 1 :]
    if not question and "@" in tail.partition("?")[0]:
        return True
    return "@" in tail and not all(
        _port_is_numeric(entry) for entry in authority.split(",")
    )


# Two timestamp conventions coexist in parsed reports, so two helpers are
# needed — do not collapse them into one. Aggregate *report* begin/end dates
# come from ``timestamp_to_human()`` → ``datetime.fromtimestamp()``, which is
# **local** naive time, so they go through ``_naive_local_to_timestamptz``.
# Aggregate *record* interval_begin/end and SMTP-TLS begin/end are already
# **UTC** naive strings, so they only need a ``+00`` suffix via
# ``_ensure_utc_suffix``. Using the wrong helper silently shifts timestamps.
def _ensure_utc_suffix(value: str | None) -> str | None:
    """Append ``+00`` to a timestamp string if it lacks timezone info.

    Several parsers produce ``YYYY-MM-DD HH:MM:SS`` format strings that
    are known to be UTC but lack an explicit offset.  PostgreSQL
    ``TIMESTAMPTZ`` columns need the offset to avoid interpreting the
    value in the session timezone. A value that is not a string is
    returned unchanged, for PostgreSQL to accept or reject.
    """
    if (
        isinstance(value, str)
        and value
        and "+" not in value
        and "-" not in value[10:]
        and "Z" not in value
    ):
        return value + "+00"
    return value


def _naive_local_to_timestamptz(value: str | None) -> str | None:
    """Convert a naive local-time string to an ISO 8601 string with offset.

    ``timestamp_to_human()`` produces ``YYYY-MM-DD HH:MM:SS`` in
    **local** time (via ``datetime.fromtimestamp()``).  Inserting such
    a string into a ``TIMESTAMPTZ`` column would cause PostgreSQL to
    interpret it using the *session* timezone, which may differ from
    the machine's local timezone.

    This helper re-parses the string, attaches the local timezone
    offset, and returns an ISO 8601 representation that PostgreSQL
    will interpret unambiguously.
    """
    if not value:
        return value
    naive = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    aware = naive.astimezone()  # attaches the local system timezone
    return aware.isoformat()


def _normalize_arrival_date(value: str | None) -> str | None:
    """Normalize a failure-report ``arrival_date`` for safe TIMESTAMPTZ insert.

    The arrival date may be an RFC 2822 string (e.g.
    ``Fri, 28 Oct 2022 00:34:24 +0800``) or an ISO 8601 string.
    ``human_timestamp_to_datetime`` (backed by *dateutil*) can parse
    both.  We convert to UTC and return an ISO 8601 string with offset
    so PostgreSQL interprets it unambiguously.
    """
    if not value:
        return value
    try:
        dt = human_timestamp_to_datetime(value, to_utc=True)
        return dt.strftime("%Y-%m-%d %H:%M:%S") + "+00"
    except Exception:
        # If parsing fails, return as-is and let PostgreSQL try.
        return value


def _contact_info_to_text(
    value: str | list | None,
) -> str | None:
    """Ensure ``contact_info`` is a plain string.

    The TLS-RPT ``contact-info`` field is normally a single string, but
    the TypedDict allows ``str | list[str]``.  If a list is
    encountered, join the entries so they fit into a ``TEXT`` column.
    """
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


# PostgreSQL cannot store a NUL character in text or jsonb, and a sender can
# plant one in a failure report's sample through an RFC 2047 encoded-word
# (=?utf-8?q?a=00b?=). It is replaced with U+FFFD, the replacement character,
# which keeps the text searchable and marks the spot (GHSA-fxr7-7h9q-v949).
_NUL_REPLACEMENT = "\ufffd"


def _strip_nul(value: Any) -> Any:
    """Return ``value`` with every NUL in its strings replaced by U+FFFD.

    Dict keys and values and list items are replaced recursively; any
    other value is returned unchanged. Used for the values wrapped in
    ``Jsonb``, which the server rejects when they contain ``\\u0000``.
    """
    if isinstance(value, str):
        return value.replace("\x00", _NUL_REPLACEMENT)
    if isinstance(value, dict):
        return {_strip_nul(k): _strip_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_nul(item) for item in value]
    return value


def _nul_safe_dumper_classes() -> tuple[type, type]:
    """Return the text and binary ``str`` dumpers that replace NUL.

    psycopg dumps a ``str`` parameter with ``StrDumperUnknown`` (text
    format) or ``StrBinaryDumper`` (binary format); the first raises
    ``DataError`` on a NUL and the server rejects the second. ``list[str]``
    parameters (``TEXT[]`` columns) dump each item with the same dumpers.
    The subclasses replace NUL with U+FFFD first.
    """

    class _NulSafeStrDumper(psycopg_string.StrDumperUnknown):
        def dump(self, obj: str) -> Buffer | None:
            return super().dump(obj.replace("\x00", _NUL_REPLACEMENT))

    class _NulSafeStrBinaryDumper(psycopg_string.StrBinaryDumper):
        def dump(self, obj: str) -> Buffer | None:
            return super().dump(obj.replace("\x00", _NUL_REPLACEMENT))

    return _NulSafeStrDumper, _NulSafeStrBinaryDumper


def _register_nul_safe_dumpers(conn: psycopg.Connection) -> None:
    """Make ``conn`` dump every ``str`` parameter with NUL replaced.

    psycopg uses the dumper registered last for a type as its default, so
    the binary dumper is registered first and the text one last, the order
    psycopg's own ``register_default_adapters`` uses.
    """
    text_dumper, binary_dumper = _nul_safe_dumper_classes()
    conn.adapters.register_dumper(str, binary_dumper)
    conn.adapters.register_dumper(str, text_dumper)


# Most characters of a driver message that a PostgreSQLRejectedReport quotes:
# a DataError can quote the rejected value, which the sender chose.
_MAX_REJECTION_DETAIL_CHARS = 200


def _rejection_detail(exc: BaseException) -> str:
    """Return the driver's message for a rejected value, cut to
    ``_MAX_REJECTION_DETAIL_CHARS`` characters with an ellipsis and then
    escaped for the log (cutting first means the cut cannot split an
    escape sequence)."""
    detail = str(exc)
    suffix = ""
    if len(detail) > _MAX_REJECTION_DETAIL_CHARS:
        detail = detail[:_MAX_REJECTION_DETAIL_CHARS]
        suffix = "..."
    return sanitize_for_log(detail) + suffix


class PostgreSQLError(RuntimeError):
    """Raised when a PostgreSQL-level error occurs"""


class PostgreSQLRejectedReport(PostgreSQLError):
    """Raised when PostgreSQL rejected a value of one report.

    psycopg raised ``DataError`` (a value the column type cannot hold) and
    that report's transaction was rolled back. The connection and the
    schema are fine, so the next report will save.
    """


class AlreadySaved(ValueError):
    """Raised when an identical report already exists in the database"""


class PostgreSQLClient:
    """A client for saving DMARC reports to a PostgreSQL database.

    Accepts either a full libpq connection string/DSN via
    *connection_string* or individual connection parameters.  When both
    are supplied *connection_string* takes precedence.
    """

    def __init__(
        self,
        connection_string: str | None = None,
        host: str | None = None,
        port: int = 5432,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
        sslmode: str | None = None,
        sslrootcert: str | None = None,
    ) -> None:
        """
        Initializes the PostgreSQLClient and opens a database connection.

        Args:
            connection_string: A libpq connection string or URI
                (e.g. ``postgresql://user:pass@host/dbname``).  When
                present, *host*, *port*, *user*, *password* and *database*
                are ignored; *sslmode* and *sslrootcert* still apply and
                override the string's own values.
            host: Database server hostname or IP address.
            port: Database server port (default: 5432).
            user: Database user name.
            password: Database user password.
            database: Database name to connect to.
            sslmode (str | None): A libpq sslmode, one of ``SSL_MODES``.
                ``None`` keeps an ``sslmode`` set in *connection_string* or
                the ``PGSSLMODE`` environment variable, and otherwise uses
                ``require``.
            sslrootcert: Path to the CA certificate file that
                ``verify-ca`` and ``verify-full`` check the server's
                certificate against.

        Raises:
            PostgreSQLError: If psycopg is not installed, the connection
                string is malformed, or the connection attempt fails.
        """
        if psycopg is None:
            raise PostgreSQLError(_PSYCOPG_INSTALL_HINT)

        # Store parameters so we can reconnect later if needed.
        self._connection_string = connection_string
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._database = database
        self._sslmode = sslmode
        self._sslrootcert = sslrootcert

        self._conn: psycopg.Connection | None = None
        self._warn_if_server_unverified()
        self._connect()

    def _connection_string_params(self) -> dict[str, Any]:
        """Return the parameters set in the connection string, if any.

        Raises:
            PostgreSQLError: If the connection string is malformed. libpq
                words its parse errors with the string or a fragment of it,
                which can contain the password, so the detail is withheld
                (any error from the parse is replaced). Also, as a
                convenience that names the common mistake, if a URI looks
                like its user name or password holds an unencoded ``@`` or
                ``/`` (``_has_unencoded_at()``). That check runs before
                anything is logged, but it recognizes shapes and is not
                what keeps the password out of the logs; the startup
                warning and the connection error withhold every value
                parsed from the string instead. A keyword/value string is
                not checked: its password is a keyword of its own, which
                an ``@`` or ``/`` does not end.
        """
        if not self._connection_string:
            return {}
        if _is_uri(self._connection_string) and _has_unencoded_at(
            self._connection_string
        ):
            raise PostgreSQLError(_UNENCODED_AT_CONNECTION_STRING_ERROR) from None
        try:
            params = psycopg_conninfo.conninfo_to_dict(self._connection_string)
        except Exception:
            raise PostgreSQLError(_WITHHELD_CONNECTION_STRING_ERROR) from None
        return params

    def _ssl_connect_kwargs(self) -> dict[str, Any]:
        """Return the TLS keyword arguments for ``psycopg.connect()``.

        An explicit *sslmode* wins. Without one, an ``sslmode`` in the
        connection string or the ``PGSSLMODE`` environment variable, both
        of which libpq reads itself, is left in effect, and otherwise
        ``require`` replaces libpq's ``prefer`` default.
        """
        kwargs: dict[str, Any] = {}
        if self._sslmode:
            kwargs["sslmode"] = self._sslmode
        elif not (
            self._connection_string_params().get("sslmode")
            or os.environ.get("PGSSLMODE")
        ):
            kwargs["sslmode"] = DEFAULT_SSL_MODE
        if self._sslrootcert:
            kwargs["sslrootcert"] = self._sslrootcert
        return kwargs

    def _warn_if_server_unverified(self) -> None:
        """Log a warning when a remote server's certificate is not checked.

        Below ``verify-ca``, anyone who can impersonate a TCP host can
        receive the password. A Unix socket, ``localhost`` or a loopback
        address is not warned about, and neither is an unset host (libpq's
        default socket).
        The host is the one libpq connects to: the connection string's
        ``hostaddr`` (else the ``PGHOSTADDR`` environment variable) when
        set, since libpq connects to it and uses ``host`` only to name the
        server, and otherwise the *host* argument or the connection
        string's ``host``, else the ``PGHOST`` environment variable. Every
        entry of a comma-separated host list is considered.

        With a connection string, the warning names no host and no other
        value from the string, whatever its shape: when the string's user
        name or password holds an unencoded ``@`` or ``/``, libpq parses a
        fragment of the password as the host, the port or a query
        parameter such as ``sslmode``. The mode is printed only when it is
        one of ``SSL_MODES``. With the separate *host* argument (or
        ``PGHOST``/``PGHOSTADDR``, which the operator sets), the warning
        names the host, credential-masked and escaped, which covers a host
        with an ``@``.

        With ``sslmode=require`` and a root certificate file that exists,
        libpq verifies the server as ``verify-ca`` does ("if a root CA file
        exists, the behavior of sslmode=require will be the same as that of
        verify-ca", PostgreSQL docs, libpq SSL support), so that is not
        warned about either.
        """
        params = self._connection_string_params()
        if self._connection_string:
            host = params.get("host")
            hostaddr = params.get("hostaddr")
        else:
            host = self._host
            hostaddr = None
        host = (
            hostaddr or os.environ.get("PGHOSTADDR") or host or os.environ.get("PGHOST")
        )
        if not host or all(_is_local_host(h.strip()) for h in host.split(",")):
            return
        mode = (
            self._ssl_connect_kwargs().get("sslmode")
            or params.get("sslmode")
            or os.environ.get("PGSSLMODE")
        )
        if mode in _VERIFYING_SSL_MODES:
            return
        rootcert = (
            self._sslrootcert
            or params.get("sslrootcert")
            or os.environ.get("PGSSLROOTCERT")
        )
        if mode == "require" and rootcert and os.path.isfile(rootcert):
            return
        if self._connection_string:
            shown_mode = mode if mode in SSL_MODES else "not a recognized value"
            logger.warning(
                "The PostgreSQL connection_string does not verify the server "
                f"certificate (sslmode is {shown_mode}); set [postgresql] "
                "sslmode = verify-full and sslrootcert to protect the password "
                "from an impersonated server"
            )
            return
        logger.warning(
            f"PostgreSQL connection to {_log_safe_host(host)} uses "
            f"sslmode={sanitize_for_log(str(mode))}, which does not verify the "
            "server certificate; set [postgresql] sslmode = verify-full and "
            "sslrootcert to protect the password from an impersonated server"
        )

    def _connect(self) -> psycopg.Connection:
        """Open a new database connection using stored parameters.

        Raises:
            PostgreSQLError: If the connection string is malformed or the
                connection attempt fails. With a connection string, the
                driver's message is withheld (only a well-formed SQLSTATE
                is kept); with the separate arguments, it is passed on with
                URL credentials masked. Any other error raised between
                reading the settings and holding a configured connection
                (a password the driver cannot encode, a host name the
                resolver rejects) is replaced with a fixed message, since
                its text can quote the password or the whole connection
                string. Either way the original error is not chained. A
                connection opened before its setup failed is closed.
        """
        logger.debug("Connecting to PostgreSQL")
        # A connection that fails its setup (autocommit, the dumpers) is
        # closed before the error propagates; nothing else holds it.
        opened: psycopg.Connection | None = None
        configured = False
        try:
            # Parse the connection string first, on every path (the sslmode
            # lookup below skips it when sslmode is set), so a malformed
            # string or one the early refusal recognizes never reaches the
            # driver.
            self._connection_string_params()
            ssl_kwargs = self._ssl_connect_kwargs()
            if self._connection_string:
                conn = psycopg.connect(self._connection_string, **ssl_kwargs)
            else:
                conn = psycopg.connect(
                    host=self._host,
                    port=self._port,
                    user=self._user,
                    password=self._password,
                    dbname=self._database,
                    **ssl_kwargs,
                )
            opened = conn
            conn.autocommit = False
            _register_nul_safe_dumpers(conn)
            configured = True
        except PostgreSQLError:
            # Already a fixed, secret-free message (_connection_string_params).
            raise
        except psycopg.Error as exc:
            # Chaining would print the driver's own text, unredacted,
            # wherever the error is logged with its traceback (the SIGHUP
            # reload path does that), so every branch raises from None.
            if self._connection_string:
                # libpq reports a malformed connection string by echoing the
                # whole string, or the fragment it could not parse. psycopg
                # raises ProgrammingError for those parse failures. The
                # string was already parsed once (_connection_string_params),
                # so this guards the same failure if it surfaces here.
                if isinstance(exc, psycopg.ProgrammingError):
                    raise PostgreSQLError(_WITHHELD_CONNECTION_STRING_ERROR) from None
                # Any other failure can quote a value parsed from the string
                # (libpq: 'invalid integer value "..." for connection option
                # "port"'), and with an unencoded "@" or "/" in the user
                # name or password, that value is part of the password. No
                # check of the string's shape can rule that out, so the text
                # is withheld whatever the string looks like.
                raise PostgreSQLError(
                    _WITHHELD_CONNECTION_FAILURE_ERROR + _sqlstate_suffix(exc)
                ) from None
            # With the separate arguments, the text names the host, and a
            # host from the argument or PGHOST can hold anything, so it is
            # credential-masked.
            raise PostgreSQLError(redact_url_credentials(str(exc))) from None
        except Exception:
            # Not the driver's own error: psycopg encodes the connection
            # string it builds from the separate arguments, so a password
            # holding a lone surrogate (an environment variable with invalid
            # UTF-8) raises UnicodeEncodeError carrying that whole string,
            # and on Python 3.15 a host label over 63 characters raises
            # UnicodeEncodeError('idna', '<host>', ...) from name resolution,
            # which psycopg does not wrap. Such text is never passed on.
            # KeyboardInterrupt and SystemExit are not Exceptions and pass.
            if self._connection_string:
                raise PostgreSQLError(_WITHHELD_CONNECTION_FAILURE_ERROR) from None
            raise PostgreSQLError(_WITHHELD_CONNECTION_SETTING_ERROR) from None
        finally:
            # Also on KeyboardInterrupt and SystemExit. An error from
            # close() is dropped so the original failure is the one raised.
            if opened is not None and not configured:
                with contextlib.suppress(Exception):
                    opened.close()
        self._conn = conn
        return conn

    def close(self) -> None:
        """Close the database connection if it is open.

        Called by the CLI's output-client cleanup on shutdown / config
        reload. Safe to call multiple times.
        """
        if self._conn is not None and not self._conn.closed:
            self._conn.close()

    def _ensure_connected(self) -> psycopg.Connection:
        """Check the connection health and reconnect if necessary.

        When *parsedmarc* runs in watch mode the process can stay alive
        for days or weeks.  PostgreSQL may drop idle connections (e.g.
        server restart, ``idle_in_transaction_session_timeout``, TCP
        keep-alive expiry).  This method detects a closed connection
        and transparently re-establishes it so that subsequent
        ``save_*`` calls succeed without manual intervention.
        """
        conn = self._conn
        if conn is None or conn.closed:
            logger.warning("PostgreSQL connection lost — attempting to reconnect")
            conn = self._connect()
        return conn

    def create_tables(self) -> None:
        """Creates all required tables if they do not already exist.

        This method is idempotent and safe to call on every startup.

        Raises:
            PostgreSQLError: If table creation fails. With a connection
                string, the server's message is withheld (only a
                well-formed SQLSTATE is kept): it can quote a session
                setting from the string's ``options``, such as a
                ``default_tablespace``. With the separate arguments, it is
                passed on with URL credentials masked. Either way the
                original error is not chained.
        """
        conn = self._ensure_connected()
        ddl_statements: list[LiteralString] = [
            # ----------------------------------------------------------------
            # Aggregate reports
            # ----------------------------------------------------------------
            """
            CREATE TABLE IF NOT EXISTS dmarc_aggregate_report (
                id                      BIGSERIAL PRIMARY KEY,
                xml_schema              TEXT,
                xml_namespace           TEXT,
                org_name                TEXT NOT NULL,
                org_email               TEXT,
                org_extra_contact_info  TEXT,
                generator               TEXT,
                report_id               TEXT NOT NULL,
                begin_date              TIMESTAMPTZ NOT NULL,
                end_date                TIMESTAMPTZ NOT NULL,
                errors                  TEXT[],
                domain                  TEXT NOT NULL,
                adkim                   TEXT,
                aspf                    TEXT,
                policy                  TEXT,
                subdomain_policy        TEXT,
                pct                     TEXT,
                fo                      TEXT,
                np                      TEXT,
                testing                 TEXT,
                discovery_method        TEXT,
                UNIQUE (org_name, report_id, domain, begin_date, end_date)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dmarc_aggregate_record (
                id                  BIGSERIAL PRIMARY KEY,
                report_id           BIGINT NOT NULL
                                        REFERENCES dmarc_aggregate_report(id)
                                        ON DELETE CASCADE,
                interval_begin      TIMESTAMPTZ,
                interval_end        TIMESTAMPTZ,
                source_ip_address   INET,
                source_country      TEXT,
                source_reverse_dns  TEXT,
                source_base_domain  TEXT,
                source_name         TEXT,
                source_type         TEXT,
                message_count       INTEGER NOT NULL,
                spf_aligned         BOOLEAN,
                dkim_aligned        BOOLEAN,
                dmarc_passed        BOOLEAN,
                disposition         TEXT,
                policy_dkim         TEXT,
                policy_spf          TEXT,
                header_from         TEXT,
                envelope_from       TEXT,
                envelope_to         TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dmarc_aggregate_record_dkim (
                id           BIGSERIAL PRIMARY KEY,
                record_id    BIGINT NOT NULL
                                 REFERENCES dmarc_aggregate_record(id)
                                 ON DELETE CASCADE,
                domain       TEXT,
                selector     TEXT,
                result       TEXT,
                human_result TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dmarc_aggregate_record_spf (
                id           BIGSERIAL PRIMARY KEY,
                record_id    BIGINT NOT NULL
                                 REFERENCES dmarc_aggregate_record(id)
                                 ON DELETE CASCADE,
                domain       TEXT,
                scope        TEXT,
                result       TEXT,
                human_result TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dmarc_aggregate_record_policy_override (
                id            BIGSERIAL PRIMARY KEY,
                record_id     BIGINT NOT NULL
                                  REFERENCES dmarc_aggregate_record(id)
                                  ON DELETE CASCADE,
                override_type TEXT,
                comment       TEXT
            )
            """,
            # ----------------------------------------------------------------
            # Failure reports
            # ----------------------------------------------------------------
            """
            CREATE TABLE IF NOT EXISTS dmarc_failure_report (
                id                          BIGSERIAL PRIMARY KEY,
                feedback_type               TEXT,
                user_agent                  TEXT,
                version                     TEXT,
                original_envelope_id        TEXT,
                original_mail_from          TEXT,
                original_rcpt_to            TEXT,
                arrival_date                TIMESTAMPTZ,
                arrival_date_utc            TIMESTAMPTZ,
                authentication_results      TEXT,
                delivery_result             TEXT,
                auth_failure                TEXT[],
                authentication_mechanisms   TEXT[],
                dkim_domain                 TEXT,
                reported_domain             TEXT,
                sample_headers_only         BOOLEAN,
                source_ip_address           INET,
                source_country              TEXT,
                source_reverse_dns          TEXT,
                source_base_domain          TEXT,
                source_name                 TEXT,
                source_type                 TEXT,
                sample                      TEXT,
                sample_date                 TEXT,
                sample_subject              TEXT,
                sample_body                 TEXT,
                sample_has_defects          BOOLEAN,
                sample_headers              JSONB,
                sample_from                 JSONB,
                sample_to                   JSONB
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dmarc_failure_sample_address (
                id           BIGSERIAL PRIMARY KEY,
                report_id    BIGINT NOT NULL
                                 REFERENCES dmarc_failure_report(id)
                                 ON DELETE CASCADE,
                address_type TEXT,
                display_name TEXT,
                address      TEXT
            )
            """,
            # ----------------------------------------------------------------
            # SMTP TLS reports
            # ----------------------------------------------------------------
            """
            CREATE TABLE IF NOT EXISTS smtp_tls_report (
                id                BIGSERIAL PRIMARY KEY,
                organization_name TEXT NOT NULL,
                begin_date        TIMESTAMPTZ NOT NULL,
                end_date          TIMESTAMPTZ NOT NULL,
                contact_info      TEXT,
                report_id         TEXT NOT NULL,
                UNIQUE (organization_name, report_id, begin_date, end_date)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS smtp_tls_policy (
                id                      BIGSERIAL PRIMARY KEY,
                report_id               BIGINT NOT NULL
                                            REFERENCES smtp_tls_report(id)
                                            ON DELETE CASCADE,
                policy_domain           TEXT,
                policy_type             TEXT,
                policy_strings          TEXT[],
                mx_host_patterns        TEXT[],
                successful_session_count INTEGER,
                failed_session_count    INTEGER
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS smtp_tls_failure_detail (
                id                      BIGSERIAL PRIMARY KEY,
                policy_id               BIGINT NOT NULL
                                            REFERENCES smtp_tls_policy(id)
                                            ON DELETE CASCADE,
                result_type             TEXT,
                failed_session_count    INTEGER,
                sending_mta_ip          INET,
                receiving_ip            INET,
                receiving_mx_hostname   TEXT,
                receiving_mx_helo       TEXT,
                additional_info_uri     TEXT,
                failure_reason_code     TEXT
            )
            """,
            # ----- indexes for Grafana dashboard query performance -----
            """
            CREATE INDEX IF NOT EXISTS idx_agg_report_begin_date
                ON dmarc_aggregate_report (begin_date)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_agg_record_report_id
                ON dmarc_aggregate_record (report_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_agg_record_header_from
                ON dmarc_aggregate_record (header_from)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_failure_report_arrival_date
                ON dmarc_failure_report (arrival_date_utc)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_smtp_tls_report_begin_date
                ON smtp_tls_report (begin_date)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_smtp_tls_policy_report_id
                ON smtp_tls_policy (report_id)
            """,
            # ----- remaining foreign-key columns (PostgreSQL does not index
            # the referencing side) -----
            """
            CREATE INDEX IF NOT EXISTS idx_agg_record_dkim_record_id
                ON dmarc_aggregate_record_dkim (record_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_agg_record_spf_record_id
                ON dmarc_aggregate_record_spf (record_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_agg_record_override_record_id
                ON dmarc_aggregate_record_policy_override (record_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_failure_sample_address_report_id
                ON dmarc_failure_sample_address (report_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_smtp_tls_failure_detail_policy_id
                ON smtp_tls_failure_detail (policy_id)
            """,
        ]

        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    for stmt in ddl_statements:
                        cur.execute(stmt)
            logger.debug("PostgreSQL tables verified / created")
        except psycopg.Error as exc:
            # Raised from None, as in _connect(): a chain would print the
            # server's own text wherever the error is logged with its
            # traceback.
            if self._connection_string:
                raise PostgreSQLError(
                    _WITHHELD_TABLE_CREATION_ERROR + _sqlstate_suffix(exc)
                ) from None
            raise PostgreSQLError(redact_url_credentials(str(exc))) from None

    def save_aggregate_report_to_postgresql(self, report: dict) -> None:
        """Saves a parsed aggregate DMARC report to PostgreSQL.

        Args:
            report: A parsed aggregate report dictionary (the ``report``
                value of a :func:`parsedmarc.parse_report_file` result).

        Raises:
            AlreadySaved: If an identical report is already present.
            PostgreSQLRejectedReport: If PostgreSQL rejected a value of the
                report.
            PostgreSQLError: If another database error occurs.
        """
        conn = self._ensure_connected()
        meta = report.get("report_metadata", {})
        pub = report.get("policy_published", {})

        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO dmarc_aggregate_report (
                            xml_schema, xml_namespace, org_name, org_email,
                            org_extra_contact_info, generator, report_id,
                            begin_date, end_date, errors,
                            domain, adkim, aspf, policy,
                            subdomain_policy, pct, fo,
                            np, testing, discovery_method
                        ) VALUES (
                            %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s
                        )
                        ON CONFLICT (org_name, report_id, domain,
                                     begin_date, end_date)
                        DO NOTHING
                        RETURNING id
                        """,
                        (
                            report.get("xml_schema"),
                            report.get("xml_namespace"),
                            meta.get("org_name"),
                            meta.get("org_email"),
                            meta.get("org_extra_contact_info"),
                            meta.get("generator"),
                            meta.get("report_id"),
                            _naive_local_to_timestamptz(meta.get("begin_date")),
                            _naive_local_to_timestamptz(meta.get("end_date")),
                            meta.get("errors") or [],
                            pub.get("domain"),
                            pub.get("adkim"),
                            pub.get("aspf"),
                            pub.get("p"),
                            pub.get("sp"),
                            pub.get("pct"),
                            pub.get("fo"),
                            pub.get("np"),
                            pub.get("testing"),
                            pub.get("discovery_method"),
                        ),
                    )
                    row = cur.fetchone()
                    if row is None:
                        raise AlreadySaved(
                            "Aggregate report {report_id} from {org} "
                            "has already been saved".format(
                                report_id=meta.get("report_id"),
                                org=meta.get("org_name"),
                            )
                        )
                    report_db_id: int = row[0]

                    for record in report.get("records", []):
                        src = record.get("source", {})
                        pol = record.get("policy_evaluated", {})
                        idens = record.get("identifiers", {})
                        cur.execute(
                            """
                            INSERT INTO dmarc_aggregate_record (
                                report_id, interval_begin, interval_end,
                                source_ip_address, source_country,
                                source_reverse_dns, source_base_domain,
                                source_name, source_type,
                                message_count,
                                spf_aligned, dkim_aligned, dmarc_passed,
                                disposition, policy_dkim, policy_spf,
                                header_from, envelope_from, envelope_to
                            ) VALUES (
                                %s, %s, %s,
                                %s, %s, %s, %s, %s, %s,
                                %s,
                                %s, %s, %s,
                                %s, %s, %s,
                                %s, %s, %s
                            )
                            RETURNING id
                            """,
                            (
                                report_db_id,
                                _ensure_utc_suffix(record.get("interval_begin")),
                                _ensure_utc_suffix(record.get("interval_end")),
                                src.get("ip_address"),
                                src.get("country"),
                                src.get("reverse_dns"),
                                src.get("base_domain"),
                                src.get("name"),
                                src.get("type"),
                                record.get("count"),
                                record.get("alignment", {}).get("spf"),
                                record.get("alignment", {}).get("dkim"),
                                record.get("alignment", {}).get("dmarc"),
                                pol.get("disposition"),
                                pol.get("dkim"),
                                pol.get("spf"),
                                idens.get("header_from"),
                                idens.get("envelope_from"),
                                idens.get("envelope_to"),
                            ),
                        )
                        # INSERT ... RETURNING always yields one row
                        record_db_id: int = cur.fetchone()[0]  # pyright: ignore[reportOptionalSubscript]

                        for dkim in record.get("auth_results", {}).get("dkim", []):
                            cur.execute(
                                """
                                INSERT INTO dmarc_aggregate_record_dkim
                                    (record_id, domain, selector, result,
                                     human_result)
                                VALUES (%s, %s, %s, %s, %s)
                                """,
                                (
                                    record_db_id,
                                    dkim.get("domain"),
                                    dkim.get("selector"),
                                    dkim.get("result"),
                                    dkim.get("human_result"),
                                ),
                            )

                        for spf in record.get("auth_results", {}).get("spf", []):
                            cur.execute(
                                """
                                INSERT INTO dmarc_aggregate_record_spf
                                    (record_id, domain, scope, result,
                                     human_result)
                                VALUES (%s, %s, %s, %s, %s)
                                """,
                                (
                                    record_db_id,
                                    spf.get("domain"),
                                    spf.get("scope"),
                                    spf.get("result"),
                                    spf.get("human_result"),
                                ),
                            )

                        for override in pol.get("policy_override_reasons", []):
                            cur.execute(
                                """
                                INSERT INTO dmarc_aggregate_record_policy_override
                                    (record_id, override_type, comment)
                                VALUES (%s, %s, %s)
                                """,
                                (
                                    record_db_id,
                                    override.get("type"),
                                    override.get("comment"),
                                ),
                            )

        except AlreadySaved:
            raise
        except psycopg.DataError as exc:
            raise PostgreSQLRejectedReport(
                "PostgreSQL rejected a value of the aggregate report from "
                f"{sanitize_for_log(str(meta.get('org_name')))} with ID "
                f"{sanitize_for_log(str(meta.get('report_id')))}: "
                f"{_rejection_detail(exc)}"
            ) from exc
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc

    def save_failure_report_to_postgresql(self, report: dict) -> None:
        """Saves a parsed failure (RUF) DMARC report to PostgreSQL.

        Args:
            report: A parsed failure report dictionary (the ``report``
                value of a :func:`parsedmarc.parse_report_file` result).

        Raises:
            AlreadySaved: If a matching failure report is already present.
            PostgreSQLRejectedReport: If PostgreSQL rejected a value of the
                report.
            PostgreSQLError: If another database error occurs.
        """
        conn = self._ensure_connected()
        sample = report.get("parsed_sample", {}) or {}
        src = report.get("source", {}) or {}
        arrival_date_utc = _ensure_utc_suffix(report.get("arrival_date_utc"))
        sample_subject = sample.get("subject")
        # JSONB values are reused by both the dedup check and the INSERT.
        # jsonb cannot hold \u0000, so NUL is replaced before wrapping. The
        # str dumpers registered in _connect() cover the text columns.
        sample_headers = (
            psycopg_json.Jsonb(_strip_nul(sample["headers"]))
            if sample.get("headers")
            else None
        )
        sample_from = (
            psycopg_json.Jsonb(_strip_nul(sample["from"]))
            if sample.get("from")
            else None
        )
        sample_to = (
            psycopg_json.Jsonb(_strip_nul(sample["to"])) if sample.get("to") else None
        )

        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    # Failure reports have no natural primary key, so mirror the
                    # Elasticsearch backend's query-then-insert dedup on the same
                    # dimensions it uses: arrival date + From + To + Subject.
                    # IS NOT DISTINCT FROM is NULL-safe (no PG15 NULLS NOT
                    # DISTINCT dependency); JSONB equality is semantic, so key
                    # order within the From/To objects doesn't matter.
                    cur.execute(
                        """
                        SELECT 1 FROM dmarc_failure_report
                        WHERE arrival_date_utc IS NOT DISTINCT FROM %s
                          AND sample_subject   IS NOT DISTINCT FROM %s
                          AND sample_from      IS NOT DISTINCT FROM %s
                          AND sample_to        IS NOT DISTINCT FROM %s
                        LIMIT 1
                        """,
                        (arrival_date_utc, sample_subject, sample_from, sample_to),
                    )
                    if cur.fetchone() is not None:
                        raise AlreadySaved(
                            f"A failure report with subject {sample_subject!r} arriving "
                            f"at {arrival_date_utc} has already been saved"
                        )
                    cur.execute(
                        """
                        INSERT INTO dmarc_failure_report (
                            feedback_type, user_agent, version,
                            original_envelope_id, original_mail_from,
                            original_rcpt_to, arrival_date, arrival_date_utc,
                            authentication_results, delivery_result,
                            auth_failure, authentication_mechanisms,
                            dkim_domain, reported_domain, sample_headers_only,
                            source_ip_address, source_country,
                            source_reverse_dns, source_base_domain,
                            source_name, source_type,
                            sample, sample_date, sample_subject,
                            sample_body, sample_has_defects,
                            sample_headers, sample_from, sample_to
                        ) VALUES (
                            %s, %s, %s,
                            %s, %s,
                            %s, %s, %s,
                            %s, %s,
                            %s, %s,
                            %s, %s, %s,
                            %s, %s,
                            %s, %s,
                            %s, %s,
                            %s, %s, %s,
                            %s, %s,
                            %s, %s, %s
                        )
                        RETURNING id
                        """,
                        (
                            report.get("feedback_type"),
                            report.get("user_agent"),
                            report.get("version"),
                            report.get("original_envelope_id"),
                            report.get("original_mail_from"),
                            report.get("original_rcpt_to"),
                            _normalize_arrival_date(report.get("arrival_date")),
                            arrival_date_utc,
                            report.get("authentication_results"),
                            report.get("delivery_result"),
                            report.get("auth_failure") or [],
                            report.get("authentication_mechanisms") or [],
                            report.get("dkim_domain"),
                            report.get("reported_domain"),
                            report.get("sample_headers_only"),
                            src.get("ip_address"),
                            src.get("country"),
                            src.get("reverse_dns"),
                            src.get("base_domain"),
                            src.get("name"),
                            src.get("type"),
                            report.get("sample"),
                            sample.get("date"),
                            sample_subject,
                            sample.get("body"),
                            sample.get("has_defects"),
                            sample_headers,
                            sample_from,
                            sample_to,
                        ),
                    )
                    # INSERT ... RETURNING always yields one row
                    report_db_id: int = cur.fetchone()[0]  # pyright: ignore[reportOptionalSubscript]

                    for addr_type in ("to", "cc", "bcc", "reply_to"):
                        entries = sample.get(addr_type) or []
                        if isinstance(entries, dict):
                            entries = [entries]
                        for entry in entries:
                            cur.execute(
                                """
                                INSERT INTO dmarc_failure_sample_address
                                    (report_id, address_type,
                                     display_name, address)
                                VALUES (%s, %s, %s, %s)
                                """,
                                (
                                    report_db_id,
                                    addr_type,
                                    entry.get("display_name"),
                                    entry.get("address"),
                                ),
                            )

        except AlreadySaved:
            raise
        except psycopg.DataError as exc:
            raise PostgreSQLRejectedReport(
                "PostgreSQL rejected a value of the failure report for "
                f"{sanitize_for_log(str(report.get('reported_domain')))} "
                f"arriving at {sanitize_for_log(str(arrival_date_utc))}: "
                f"{_rejection_detail(exc)}"
            ) from exc
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc

    def save_smtp_tls_report_to_postgresql(self, report: dict) -> None:
        """Saves a parsed SMTP TLS report to PostgreSQL.

        Args:
            report: A parsed SMTP TLS report dictionary (the ``report``
                value of a :func:`parsedmarc.parse_report_file` result).

        Raises:
            AlreadySaved: If an identical report is already present.
            PostgreSQLRejectedReport: If PostgreSQL rejected a value of the
                report.
            PostgreSQLError: If another database error occurs.
        """
        conn = self._ensure_connected()
        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO smtp_tls_report (
                            organization_name, begin_date, end_date,
                            contact_info, report_id
                        ) VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (organization_name, report_id,
                                     begin_date, end_date)
                        DO NOTHING
                        RETURNING id
                        """,
                        (
                            report.get("organization_name"),
                            _ensure_utc_suffix(report.get("begin_date")),
                            _ensure_utc_suffix(report.get("end_date")),
                            _contact_info_to_text(report.get("contact_info")),
                            report.get("report_id"),
                        ),
                    )
                    row = cur.fetchone()
                    if row is None:
                        raise AlreadySaved(
                            "SMTP TLS report {report_id} from {org} "
                            "has already been saved".format(
                                report_id=report.get("report_id"),
                                org=report.get("organization_name"),
                            )
                        )
                    report_db_id: int = row[0]

                    for policy in report.get("policies", []):
                        cur.execute(
                            """
                            INSERT INTO smtp_tls_policy (
                                report_id, policy_domain, policy_type,
                                policy_strings, mx_host_patterns,
                                successful_session_count, failed_session_count
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            RETURNING id
                            """,
                            (
                                report_db_id,
                                policy.get("policy_domain"),
                                policy.get("policy_type"),
                                policy.get("policy_strings") or [],
                                policy.get("mx_host_patterns") or [],
                                policy.get("successful_session_count"),
                                policy.get("failed_session_count"),
                            ),
                        )
                        # INSERT ... RETURNING always yields one row
                        policy_db_id: int = cur.fetchone()[0]  # pyright: ignore[reportOptionalSubscript]

                        for detail in policy.get("failure_details", []):
                            cur.execute(
                                """
                                INSERT INTO smtp_tls_failure_detail (
                                    policy_id, result_type,
                                    failed_session_count,
                                    sending_mta_ip, receiving_ip,
                                    receiving_mx_hostname, receiving_mx_helo,
                                    additional_info_uri, failure_reason_code
                                ) VALUES (
                                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                                )
                                """,
                                (
                                    policy_db_id,
                                    detail.get("result_type"),
                                    detail.get("failed_session_count"),
                                    detail.get("sending_mta_ip"),
                                    detail.get("receiving_ip"),
                                    detail.get("receiving_mx_hostname"),
                                    detail.get("receiving_mx_helo"),
                                    detail.get("additional_info_uri"),
                                    detail.get("failure_reason_code"),
                                ),
                            )

        except AlreadySaved:
            raise
        except psycopg.DataError as exc:
            raise PostgreSQLRejectedReport(
                "PostgreSQL rejected a value of the SMTP TLS report from "
                f"{sanitize_for_log(str(report.get('organization_name')))} with ID "
                f"{sanitize_for_log(str(report.get('report_id')))}: "
                f"{_rejection_detail(exc)}"
            ) from exc
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc
