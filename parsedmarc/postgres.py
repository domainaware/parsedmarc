# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Optional

import psycopg
from psycopg import types as psycopg_types

from parsedmarc.log import logger


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
        connection_string: Optional[str] = None,
        host: Optional[str] = None,
        port: int = 5432,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
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
            PostgreSQLError: If the connection attempt fails.
        """
        if connection_string:
            conninfo = connection_string
        else:
            parts: list[str] = []
            if host:
                parts.append(f"host={host}")
            if port:
                parts.append(f"port={port}")
            if user:
                parts.append(f"user={user}")
            if password:
                parts.append(f"password={password}")
            if database:
                parts.append(f"dbname={database}")
            conninfo = " ".join(parts)

        logger.debug("Connecting to PostgreSQL")
        try:
            self._conn: psycopg.Connection = psycopg.connect(conninfo)
            self._conn.autocommit = False
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc

    def create_tables(self) -> None:
        """Creates all required tables if they do not already exist.

        This method is idempotent and safe to call on every startup.

        Raises:
            PostgreSQLError: If table creation fails.
        """
        ddl_statements = [
            # ----------------------------------------------------------------
            # Aggregate reports
            # ----------------------------------------------------------------
            """
            CREATE TABLE IF NOT EXISTS dmarc_aggregate_report (
                id                      BIGSERIAL PRIMARY KEY,
                xml_schema              TEXT,
                org_name                TEXT NOT NULL,
                org_email               TEXT,
                org_extra_contact_info  TEXT,
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
                id        BIGSERIAL PRIMARY KEY,
                record_id BIGINT NOT NULL
                              REFERENCES dmarc_aggregate_record(id)
                              ON DELETE CASCADE,
                domain    TEXT,
                selector  TEXT,
                result    TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS dmarc_aggregate_record_spf (
                id        BIGSERIAL PRIMARY KEY,
                record_id BIGINT NOT NULL
                              REFERENCES dmarc_aggregate_record(id)
                              ON DELETE CASCADE,
                domain    TEXT,
                scope     TEXT,
                result    TEXT
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
            # Forensic reports
            # ----------------------------------------------------------------
            """
            CREATE TABLE IF NOT EXISTS dmarc_forensic_report (
                id                          BIGSERIAL PRIMARY KEY,
                feedback_type               TEXT,
                user_agent                  TEXT,
                version                     TEXT,
                original_envelope_id        TEXT,
                original_mail_from          TEXT,
                original_rcpt_to            TEXT,
                arrival_date                TEXT,
                arrival_date_utc            TEXT,
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
            CREATE TABLE IF NOT EXISTS dmarc_forensic_sample_address (
                id           BIGSERIAL PRIMARY KEY,
                report_id    BIGINT NOT NULL
                                 REFERENCES dmarc_forensic_report(id)
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
                failure_reason_code     TEXT,
                ip_address              INET
            )
            """,
        ]

        try:
            with self._conn.transaction():
                with self._conn.cursor() as cur:
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
        meta = report.get("report_metadata", {})
        pub = report.get("policy_published", {})

        try:
            with self._conn.transaction():
                with self._conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO dmarc_aggregate_report (
                            xml_schema, org_name, org_email,
                            org_extra_contact_info, report_id,
                            begin_date, end_date, errors,
                            domain, adkim, aspf, policy,
                            subdomain_policy, pct, fo
                        ) VALUES (
                            %s, %s, %s, %s, %s,
                            %s, %s, %s,
                            %s, %s, %s, %s,
                            %s, %s, %s
                        )
                        ON CONFLICT (org_name, report_id, domain,
                                     begin_date, end_date)
                        DO NOTHING
                        RETURNING id
                        """,
                        (
                            report.get("xml_schema"),
                            meta.get("org_name"),
                            meta.get("org_email"),
                            meta.get("org_extra_contact_info"),
                            meta.get("report_id"),
                            meta.get("begin_date"),
                            meta.get("end_date"),
                            meta.get("errors") or [],
                            pub.get("domain"),
                            pub.get("adkim"),
                            pub.get("aspf"),
                            pub.get("p"),
                            pub.get("sp"),
                            pub.get("pct"),
                            pub.get("fo"),
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
                                record.get("begin_date"),
                                record.get("end_date"),
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
                        record_db_id: int = cur.fetchone()[0]

                        for dkim in record.get("auth_results", {}).get("dkim", []):
                            cur.execute(
                                """
                                INSERT INTO dmarc_aggregate_record_dkim
                                    (record_id, domain, selector, result)
                                VALUES (%s, %s, %s, %s)
                                """,
                                (
                                    record_db_id,
                                    dkim.get("domain"),
                                    dkim.get("selector"),
                                    dkim.get("result"),
                                ),
                            )

                        for spf in record.get("auth_results", {}).get("spf", []):
                            cur.execute(
                                """
                                INSERT INTO dmarc_aggregate_record_spf
                                    (record_id, domain, scope, result)
                                VALUES (%s, %s, %s, %s)
                                """,
                                (
                                    record_db_id,
                                    spf.get("domain"),
                                    spf.get("scope"),
                                    spf.get("result"),
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

    def save_forensic_report_to_postgresql(self, report: dict) -> None:
        """Saves a parsed forensic (RUF) DMARC report to PostgreSQL.

        Args:
            report: A parsed forensic report dictionary as returned by
                :func:`parsedmarc.parse_report_file`.

        Raises:
            PostgreSQLError: If a database error occurs.
        """
        sample = report.get("sample", {}) or {}
        src = report.get("source", {}) or {}

        try:
            with self._conn.transaction():
                with self._conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO dmarc_forensic_report (
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
                            report.get("arrival_date"),
                            report.get("arrival_date_utc"),
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
                            sample.get("subject"),
                            sample.get("body"),
                            sample.get("has_defects"),
                            psycopg_types.json.Jsonb(sample.get("headers"))
                            if sample.get("headers")
                            else None,
                            psycopg_types.json.Jsonb(sample.get("from"))
                            if sample.get("from")
                            else None,
                            psycopg_types.json.Jsonb(sample.get("to"))
                            if sample.get("to")
                            else None,
                        ),
                    )
                    report_db_id: int = cur.fetchone()[0]

                    for addr_type in ("to", "cc", "bcc", "reply_to"):
                        entries = sample.get(addr_type) or []
                        if isinstance(entries, dict):
                            entries = [entries]
                        for entry in entries:
                            cur.execute(
                                """
                                INSERT INTO dmarc_forensic_sample_address
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
        try:
            with self._conn.transaction():
                with self._conn.cursor() as cur:
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
                            report.get("begin_date"),
                            report.get("end_date"),
                            report.get("contact_info"),
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
                        policy_db_id: int = cur.fetchone()[0]

                        for detail in policy.get("failure_details", []):
                            cur.execute(
                                """
                                INSERT INTO smtp_tls_failure_detail (
                                    policy_id, result_type,
                                    failed_session_count,
                                    sending_mta_ip, receiving_ip,
                                    receiving_mx_hostname, receiving_mx_helo,
                                    additional_info_uri, failure_reason_code,
                                    ip_address
                                ) VALUES (
                                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
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
                                    detail.get("ip_address"),
                                ),
                            )

        except AlreadySaved:
            raise
        except psycopg.Error as exc:
            raise PostgreSQLError(str(exc)) from exc
