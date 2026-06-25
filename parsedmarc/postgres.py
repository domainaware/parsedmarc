# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # LiteralString requires Python >= 3.11, so only import it for type checking
    from typing import LiteralString

    import psycopg
    from psycopg.types import json as psycopg_json
else:
    try:
        import psycopg
        from psycopg.types import json as psycopg_json
    except ImportError:
        psycopg = None
        psycopg_json = None

from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime

# psycopg is an optional dependency (the PostgreSQL backend is opt-in). The
# pure helper functions below work without it; only PostgreSQLClient needs a
# live driver, so the import error surfaces at client construction with a
# pip-install hint rather than breaking ``import parsedmarc`` for everyone.
_PSYCOPG_INSTALL_HINT = (
    "The PostgreSQL backend requires the 'psycopg' package. "
    "Install it with: pip install parsedmarc[postgresql]"
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
    value in the session timezone.
    """
    if value and "+" not in value and "-" not in value[10:] and "Z" not in value:
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


class PostgreSQLError(RuntimeError):
    """Raised when a PostgreSQL-level error occurs"""


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
    ) -> None:
        """
        Initializes the PostgreSQLClient and opens a database connection.

        Args:
            connection_string: A libpq connection string or URI
                (e.g. ``postgresql://user:pass@host/dbname``).  When
                present, individual keyword arguments are ignored.
            host: Database server hostname or IP address.
            port: Database server port (default: 5432).
            user: Database user name.
            password: Database user password.
            database: Database name to connect to.

        Raises:
            PostgreSQLError: If psycopg is not installed or the connection
                attempt fails.
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

        self._conn: psycopg.Connection | None = None
        self._connect()

    def _connect(self) -> psycopg.Connection:
        """Open a new database connection using stored parameters.

        Raises:
            PostgreSQLError: If the connection attempt fails.
        """
        logger.debug("Connecting to PostgreSQL")
        try:
            if self._connection_string:
                conn = psycopg.connect(self._connection_string)
            else:
                conn = psycopg.connect(
                    host=self._host,
                    port=self._port,
                    user=self._user,
                    password=self._password,
                    dbname=self._database,
                )
            conn.autocommit = False
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc
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
            PostgreSQLError: If table creation fails.
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
        ]

        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    for stmt in ddl_statements:
                        cur.execute(stmt)
            logger.debug("PostgreSQL tables verified / created")
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc

    def save_aggregate_report_to_postgresql(self, report: dict) -> None:
        """Saves a parsed aggregate DMARC report to PostgreSQL.

        Args:
            report: A parsed aggregate report dictionary as returned by
                :func:`parsedmarc.parse_report_file`.

        Raises:
            AlreadySaved: If an identical report is already present.
            PostgreSQLError: If a database error occurs.
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
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc

    def save_failure_report_to_postgresql(self, report: dict) -> None:
        """Saves a parsed failure (RUF) DMARC report to PostgreSQL.

        Args:
            report: A parsed failure report dictionary as returned by
                :func:`parsedmarc.parse_report_file`.

        Raises:
            AlreadySaved: If a matching failure report is already present.
            PostgreSQLError: If a database error occurs.
        """
        conn = self._ensure_connected()
        sample = report.get("parsed_sample", {}) or {}
        src = report.get("source", {}) or {}
        arrival_date_utc = _ensure_utc_suffix(report.get("arrival_date_utc"))
        sample_subject = sample.get("subject")
        # JSONB values are reused by both the dedup check and the INSERT.
        sample_headers = (
            psycopg_json.Jsonb(sample["headers"]) if sample.get("headers") else None
        )
        sample_from = psycopg_json.Jsonb(sample["from"]) if sample.get("from") else None
        sample_to = psycopg_json.Jsonb(sample["to"]) if sample.get("to") else None

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
                            "A failure report with subject {subj!r} arriving "
                            "at {date} has already been saved".format(
                                subj=sample_subject, date=arrival_date_utc
                            )
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
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc

    def save_smtp_tls_report_to_postgresql(self, report: dict) -> None:
        """Saves a parsed SMTP TLS report to PostgreSQL.

        Args:
            report: A parsed SMTP TLS report dictionary as returned by
                :func:`parsedmarc.parse_report_file`.

        Raises:
            AlreadySaved: If an identical report is already present.
            PostgreSQLError: If a database error occurs.
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
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc
