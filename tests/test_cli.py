"""Tests for parsedmarc.cli — CLI entry point, config parsing,
env-var overrides, mailbox watch wiring, and SIGHUP reload."""

import io
import json
import logging
import os
import signal
import sys
import tempfile
import unittest
import zipfile
from configparser import ConfigParser
from tempfile import NamedTemporaryFile
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import httpx
from azure.core.exceptions import ClientAuthenticationError
from msgraph.generated.models.o_data_errors.inner_error import InnerError
from msgraph.generated.models.o_data_errors.main_error import MainError
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

import parsedmarc
import parsedmarc.cli
import parsedmarc.elastic
import parsedmarc.opensearch as opensearch_module


class _BreakLoop(BaseException):
    pass


class _DummyMailboxConnection(parsedmarc.MailboxConnection):
    def __init__(self):
        self.fetch_calls: list[dict[str, object]] = []

    def create_folder(self, folder_name: str):
        return None

    def fetch_messages(self, reports_folder: str, **kwargs):
        self.fetch_calls.append({"reports_folder": reports_folder, **kwargs})
        return []

    def fetch_message(self, message_id, **kwargs) -> str:
        return ""

    def delete_message(self, message_id):
        return None

    def move_message(self, message_id, folder_name: str):
        return None

    def keepalive(self):
        return None

    def watch(self, check_callback, check_timeout, config_reloading=None):
        return None


class Test(unittest.TestCase):
    """Kitchen-sink tests redistributed from the original
    tests.py monolith. Future PRs should split these further
    into purpose-specific TestCase subclasses as natural
    groupings emerge."""

    def testOpenSearchSigV4RequiresRegion(self):
        with self.assertRaises(opensearch_module.OpenSearchError):
            opensearch_module.set_hosts(
                "https://example.org:9200",
                auth_type="awssigv4",
            )

    def testOpenSearchSigV4ConfiguresConnectionClass(self):
        fake_credentials = object()
        with patch.object(opensearch_module.boto3, "Session") as session_cls:
            session_cls.return_value.get_credentials.return_value = fake_credentials
            with patch.object(
                opensearch_module, "AWSV4SignerAuth", return_value="auth"
            ) as signer:
                with patch.object(
                    opensearch_module.connections, "create_connection"
                ) as create_connection:
                    opensearch_module.set_hosts(
                        "https://example.org:9200",
                        use_ssl=True,
                        auth_type="awssigv4",
                        aws_region="eu-west-1",
                    )
        signer.assert_called_once_with(fake_credentials, "eu-west-1", "es")
        create_connection.assert_called_once()
        self.assertEqual(
            create_connection.call_args.kwargs.get("connection_class"),
            opensearch_module.RequestsHttpConnection,
        )
        self.assertEqual(create_connection.call_args.kwargs.get("http_auth"), "auth")

    def testOpenSearchSigV4RejectsUnknownAuthType(self):
        with self.assertRaises(opensearch_module.OpenSearchError):
            opensearch_module.set_hosts(
                "https://example.org:9200",
                auth_type="kerberos",
            )

    def testOpenSearchSigV4RequiresAwsCredentials(self):
        with patch.object(opensearch_module.boto3, "Session") as session_cls:
            session_cls.return_value.get_credentials.return_value = None
            with self.assertRaises(opensearch_module.OpenSearchError):
                opensearch_module.set_hosts(
                    "https://example.org:9200",
                    auth_type="awssigv4",
                    aws_region="eu-west-1",
                )

    @patch("parsedmarc.cli.opensearch.migrate_indexes")
    @patch("parsedmarc.cli.opensearch.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testCliPassesOpenSearchSigV4Settings(
        self,
        mock_imap_connection,
        mock_get_reports,
        mock_set_hosts,
        _mock_migrate_indexes,
    ):
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        config = """[general]
save_aggregate = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[opensearch]
hosts = localhost
authentication_type = awssigv4
aws_region = eu-west-1
aws_service = aoss
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(mock_set_hosts.call_args.kwargs.get("auth_type"), "awssigv4")
        self.assertEqual(mock_set_hosts.call_args.kwargs.get("aws_region"), "eu-west-1")
        self.assertEqual(mock_set_hosts.call_args.kwargs.get("aws_service"), "aoss")

    @patch("parsedmarc.cli.elastic.save_aggregate_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.migrate_indexes")
    @patch("parsedmarc.cli.elastic.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testFailOnOutputErrorExits(
        self,
        mock_imap_connection,
        mock_get_reports,
        _mock_set_hosts,
        _mock_migrate_indexes,
        mock_save_aggregate,
    ):
        """CLI should exit with code 1 when fail_on_output_error is enabled"""
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [{"policy_published": {"domain": "example.com"}}],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        mock_save_aggregate.side_effect = parsedmarc.elastic.ElasticsearchError(
            "simulated output failure"
        )

        config = """[general]
save_aggregate = true
fail_on_output_error = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[elasticsearch]
hosts = localhost
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            with self.assertRaises(SystemExit) as ctx:
                parsedmarc.cli._main()

        self.assertEqual(ctx.exception.code, 1)
        mock_save_aggregate.assert_called_once()

    @patch("parsedmarc.cli.elastic.save_aggregate_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.migrate_indexes")
    @patch("parsedmarc.cli.elastic.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testOutputErrorDoesNotExitWhenDisabled(
        self,
        mock_imap_connection,
        mock_get_reports,
        _mock_set_hosts,
        _mock_migrate_indexes,
        mock_save_aggregate,
    ):
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [{"policy_published": {"domain": "example.com"}}],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        mock_save_aggregate.side_effect = parsedmarc.elastic.ElasticsearchError(
            "simulated output failure"
        )

        config = """[general]
save_aggregate = true
fail_on_output_error = false
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[elasticsearch]
hosts = localhost
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        mock_save_aggregate.assert_called_once()

    @patch("parsedmarc.cli.opensearch.save_failure_report_to_opensearch")
    @patch("parsedmarc.cli.opensearch.migrate_indexes")
    @patch("parsedmarc.cli.opensearch.set_hosts")
    @patch("parsedmarc.cli.elastic.save_failure_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.save_aggregate_report_to_elasticsearch")
    @patch("parsedmarc.cli.elastic.migrate_indexes")
    @patch("parsedmarc.cli.elastic.set_hosts")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testFailOnOutputErrorExitsWithMultipleSinkErrors(
        self,
        mock_imap_connection,
        mock_get_reports,
        _mock_es_set_hosts,
        _mock_es_migrate,
        mock_save_aggregate,
        _mock_save_failure_elastic,
        _mock_os_set_hosts,
        _mock_os_migrate,
        mock_save_failure_opensearch,
    ):
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [{"policy_published": {"domain": "example.com"}}],
            "failure_reports": [{"reported_domain": "example.com"}],
            "smtp_tls_reports": [],
        }
        mock_save_aggregate.side_effect = parsedmarc.elastic.ElasticsearchError(
            "aggregate sink failed"
        )
        mock_save_failure_opensearch.side_effect = (
            parsedmarc.cli.opensearch.OpenSearchError("failure sink failed")
        )

        config = """[general]
save_aggregate = true
save_failure = true
fail_on_output_error = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[elasticsearch]
hosts = localhost

[opensearch]
hosts = localhost
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            with self.assertRaises(SystemExit) as ctx:
                parsedmarc.cli._main()

        self.assertEqual(ctx.exception.code, 1)
        mock_save_aggregate.assert_called_once()
        mock_save_failure_opensearch.assert_called_once()

    def test_resolve_section_key_simple(self):
        """Simple section names resolve correctly."""
        from parsedmarc.cli import _resolve_section_key

        self.assertEqual(_resolve_section_key("IMAP_PASSWORD"), ("imap", "password"))
        self.assertEqual(_resolve_section_key("GENERAL_DEBUG"), ("general", "debug"))
        self.assertEqual(_resolve_section_key("S3_BUCKET"), ("s3", "bucket"))
        self.assertEqual(_resolve_section_key("GELF_HOST"), ("gelf", "host"))

    def test_resolve_section_key_underscore_sections(self):
        """Multi-word section names (splunk_hec, gmail_api, etc.) resolve correctly."""
        from parsedmarc.cli import _resolve_section_key

        self.assertEqual(
            _resolve_section_key("SPLUNK_HEC_TOKEN"), ("splunk_hec", "token")
        )
        self.assertEqual(
            _resolve_section_key("GMAIL_API_CREDENTIALS_FILE"),
            ("gmail_api", "credentials_file"),
        )
        self.assertEqual(
            _resolve_section_key("LOG_ANALYTICS_CLIENT_ID"),
            ("log_analytics", "client_id"),
        )

    def test_resolve_section_key_unknown(self):
        """Unknown prefixes return (None, None)."""
        from parsedmarc.cli import _resolve_section_key

        self.assertEqual(_resolve_section_key("UNKNOWN_FOO"), (None, None))
        # Just a section name with no key should not match
        self.assertEqual(_resolve_section_key("IMAP"), (None, None))

    def test_expand_file_path_args_keeps_bracketed_filenames(self):
        """Literal report filenames containing glob metacharacters must not
        be dropped.

        Regression test: ``_main`` expanded every file argument with
        ``glob()``, which treats ``[...]`` as a character class. A real
        file named ``[Provider DMARC Failure Report] Subject.eml`` (the
        shape Netease and others use) matched nothing and was silently
        skipped, so the report never reached the parser.
        See https://docs.python.org/3/library/glob.html.
        """
        from glob import glob
        from parsedmarc.cli import _expand_file_path_args

        with tempfile.TemporaryDirectory() as d:
            bracket = os.path.join(d, "[Netease DMARC Failure Report] Rent.eml")
            plain = os.path.join(d, "report.eml")
            for p in (bracket, plain):
                with open(p, "w") as f:
                    f.write("x")

            # Sanity: raw glob drops the bracketed path (documents the bug).
            self.assertEqual(glob(bracket), [])

            # The literal bracketed path is preserved as-is.
            self.assertEqual(_expand_file_path_args([bracket]), [bracket])

            # Wildcards (non-existent as literal paths) still expand.
            wildcard = os.path.join(d, "*.eml")
            self.assertEqual(
                sorted(_expand_file_path_args([wildcard])),
                sorted([bracket, plain]),
            )

    def test_apply_env_overrides_injects_values(self):
        """Env vars are injected into an existing ConfigParser."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()
        config.add_section("imap")
        config.set("imap", "host", "original.example.com")

        env = {
            "PARSEDMARC_IMAP_HOST": "new.example.com",
            "PARSEDMARC_IMAP_PASSWORD": "secret123",
        }
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        self.assertEqual(config.get("imap", "host"), "new.example.com")
        self.assertEqual(config.get("imap", "password"), "secret123")

    def test_apply_env_overrides_creates_sections(self):
        """Env vars create new sections when they don't exist."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()

        env = {"PARSEDMARC_ELASTICSEARCH_HOSTS": "http://localhost:9200"}
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        self.assertTrue(config.has_section("elasticsearch"))
        self.assertEqual(config.get("elasticsearch", "hosts"), "http://localhost:9200")

    def test_apply_env_overrides_postgresql_section(self):
        """PARSEDMARC_POSTGRESQL_* env vars must resolve to the [postgresql]
        section.

        Regression test: ``postgresql`` was missing from ``_KNOWN_SECTIONS``,
        so ``_resolve_section_key`` returned ``(None, None)`` for every
        ``PARSEDMARC_POSTGRESQL_*`` var and the override was silently dropped.
        The PostgreSQL backend is only initialized when ``"postgresql" in
        config.sections()`` (cli.py), so the section must exist for env-var /
        Docker-secret configuration of the backend to work at all.
        """
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()

        env = {
            "PARSEDMARC_POSTGRESQL_HOST": "db.example.com",
            "PARSEDMARC_POSTGRESQL_PORT": "5432",
            "PARSEDMARC_POSTGRESQL_USER": "parsedmarc",
            "PARSEDMARC_POSTGRESQL_DATABASE": "parsedmarc",
        }
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        self.assertIn("postgresql", config.sections())
        self.assertEqual(config.get("postgresql", "host"), "db.example.com")
        self.assertEqual(config.get("postgresql", "port"), "5432")
        self.assertEqual(config.get("postgresql", "database"), "parsedmarc")

    def test_apply_env_overrides_ignores_config_file_var(self):
        """PARSEDMARC_CONFIG_FILE is not injected as a config key."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()

        env = {"PARSEDMARC_CONFIG_FILE": "/some/path.ini"}
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)

        self.assertEqual(config.sections(), [])

    def test_load_config_with_file_and_env_override(self):
        """Env vars override values from an INI file."""
        from parsedmarc.cli import _load_config

        with NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write(
                "[imap]\nhost = file.example.com\nuser = alice\npassword = fromfile\n"
            )
            f.flush()
            config_path = f.name

        try:
            env = {"PARSEDMARC_IMAP_PASSWORD": "fromenv"}
            with patch.dict(os.environ, env, clear=False):
                config = _load_config(config_path)

            self.assertEqual(config.get("imap", "host"), "file.example.com")
            self.assertEqual(config.get("imap", "user"), "alice")
            self.assertEqual(config.get("imap", "password"), "fromenv")
        finally:
            os.unlink(config_path)

    def test_load_config_env_only(self):
        """Config can be loaded purely from env vars with no file."""
        from parsedmarc.cli import _load_config

        env = {
            "PARSEDMARC_GENERAL_DEBUG": "true",
            "PARSEDMARC_ELASTICSEARCH_HOSTS": "http://localhost:9200",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)

        self.assertEqual(config.get("general", "debug"), "true")
        self.assertEqual(config.get("elasticsearch", "hosts"), "http://localhost:9200")

    def test_parse_config_from_env(self):
        """Full round-trip: env vars -> ConfigParser -> opts."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        env = {
            "PARSEDMARC_GENERAL_DEBUG": "true",
            "PARSEDMARC_GENERAL_SAVE_AGGREGATE": "true",
            "PARSEDMARC_GENERAL_OFFLINE": "true",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)

        opts = Namespace()
        _parse_config(config, opts)

        self.assertTrue(opts.debug)
        self.assertTrue(opts.save_aggregate)
        self.assertTrue(opts.offline)

    def test_config_file_env_var(self):
        """PARSEDMARC_CONFIG_FILE env var specifies the config file path."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        with NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[general]\ndebug = true\noffline = true\n")
            f.flush()
            config_path = f.name

        try:
            env = {"PARSEDMARC_CONFIG_FILE": config_path}
            with patch.dict(os.environ, env, clear=False):
                config = _load_config(os.environ.get("PARSEDMARC_CONFIG_FILE"))

            opts = Namespace()
            _parse_config(config, opts)
            self.assertTrue(opts.debug)
            self.assertTrue(opts.offline)
        finally:
            os.unlink(config_path)

    def test_boolean_values_from_env(self):
        """Various boolean string representations work through ConfigParser."""
        from configparser import ConfigParser
        from parsedmarc.cli import _apply_env_overrides

        for true_val in ("true", "yes", "1", "on", "True", "YES"):
            config = ConfigParser()
            env = {"PARSEDMARC_GENERAL_DEBUG": true_val}
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertTrue(
                config.getboolean("general", "debug"),
                f"Expected truthy for {true_val!r}",
            )

        for false_val in ("false", "no", "0", "off", "False", "NO"):
            config = ConfigParser()
            env = {"PARSEDMARC_GENERAL_DEBUG": false_val}
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertFalse(
                config.getboolean("general", "debug"),
                f"Expected falsy for {false_val!r}",
            )

    def test_short_alias_debug(self):
        """The bare DEBUG alias maps to [general] debug."""
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()
        with patch.dict(os.environ, {"DEBUG": "true"}, clear=False):
            _apply_env_overrides(config)
        self.assertEqual(config.get("general", "debug"), "true")

    def test_short_alias_parsedmarc_debug(self):
        """The PARSEDMARC_DEBUG alias maps to [general] debug."""
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()
        with patch.dict(os.environ, {"PARSEDMARC_DEBUG": "true"}, clear=False):
            _apply_env_overrides(config)
        self.assertEqual(config.get("general", "debug"), "true")

    def test_file_env_var_reads_secret(self):
        """*_FILE env vars are loaded from a file (Docker secret style)."""
        from parsedmarc.cli import _apply_env_overrides

        with NamedTemporaryFile(
            mode="w", suffix=".secret", delete=False, encoding="utf-8"
        ) as f:
            f.write("sekret-123\n")
            secret_path = f.name

        try:
            config = ConfigParser()
            env = {"PARSEDMARC_IMAP_PASSWORD_FILE": secret_path}
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertEqual(config.get("imap", "password"), "sekret-123")
        finally:
            os.unlink(secret_path)

    def test_file_env_var_strips_trailing_crlf(self):
        """Leading and internal whitespace is preserved; trailing CR/LF is stripped."""
        from parsedmarc.cli import _apply_env_overrides

        with NamedTemporaryFile(
            mode="w", suffix=".secret", delete=False, encoding="utf-8"
        ) as f:
            f.write(" pre  inside\r\n")
            secret_path = f.name

        try:
            config = ConfigParser()
            env = {"PARSEDMARC_IMAP_PASSWORD_FILE": secret_path}
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertEqual(config.get("imap", "password"), " pre  inside")
        finally:
            os.unlink(secret_path)

    def test_file_env_var_supersedes_direct_env(self):
        """*_FILE wins when both the direct env var and _FILE are set."""
        from parsedmarc.cli import _apply_env_overrides

        with NamedTemporaryFile(
            mode="w", suffix=".secret", delete=False, encoding="utf-8"
        ) as f:
            f.write("from-file")
            secret_path = f.name

        try:
            config = ConfigParser()
            env = {
                "PARSEDMARC_IMAP_PASSWORD": "from-env",
                "PARSEDMARC_IMAP_PASSWORD_FILE": secret_path,
            }
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertEqual(config.get("imap", "password"), "from-file")
        finally:
            os.unlink(secret_path)

    def test_file_env_var_missing_file_raises(self):
        """A missing secret file aborts with ConfigurationError."""
        from parsedmarc.cli import ConfigurationError, _apply_env_overrides

        config = ConfigParser()
        env = {"PARSEDMARC_IMAP_PASSWORD_FILE": "/tmp/parsedmarc-nonexistent-secret"}
        with patch.dict(os.environ, env, clear=False):
            with self.assertRaises(ConfigurationError) as ctx:
                _apply_env_overrides(config)
        self.assertIn("PARSEDMARC_IMAP_PASSWORD_FILE", str(ctx.exception))

    def test_file_env_var_unreadable_file_raises(self):
        """A secret file we can't read aborts with ConfigurationError."""
        import platform

        # ``os.geteuid`` is POSIX-only; the ``platform.system() == "Windows"``
        # check short-circuits on Windows so the second clause never runs.
        if platform.system() == "Windows" or os.geteuid() == 0:
            self.skipTest("chmod 000 doesn't restrict the running user")

        from parsedmarc.cli import ConfigurationError, _apply_env_overrides

        with NamedTemporaryFile(
            mode="w", suffix=".secret", delete=False, encoding="utf-8"
        ) as f:
            f.write("data")
            secret_path = f.name

        try:
            os.chmod(secret_path, 0o000)
            config = ConfigParser()
            env = {"PARSEDMARC_IMAP_PASSWORD_FILE": secret_path}
            with patch.dict(os.environ, env, clear=False):
                with self.assertRaises(ConfigurationError):
                    _apply_env_overrides(config)
        finally:
            os.chmod(secret_path, 0o600)
            os.unlink(secret_path)

    def test_file_env_var_path_expansion(self):
        """~ and $VAR references in the path are expanded."""
        from parsedmarc.cli import _apply_env_overrides

        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = os.path.join(tmpdir, "secret")
            with open(secret_path, "w", encoding="utf-8") as f:
                f.write("expanded-value")

            config = ConfigParser()
            env = {
                "PARSEDMARC_TEST_SECRET_DIR": tmpdir,
                "PARSEDMARC_IMAP_PASSWORD_FILE": "$PARSEDMARC_TEST_SECRET_DIR/secret",
            }
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertEqual(config.get("imap", "password"), "expanded-value")

    def test_file_env_var_unknown_section_ignored(self):
        """_FILE vars whose base name doesn't resolve to a section are ignored.

        Uses ``clear=True`` so the assertion isn't perturbed by ambient
        ``PARSEDMARC_*`` vars set in the dev shell or CI runner.
        """
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()
        env = {"PARSEDMARC_UNKNOWN_FOO_FILE": "/tmp/should-not-be-read"}
        with patch.dict(os.environ, env, clear=True):
            _apply_env_overrides(config)
        self.assertEqual(config.sections(), [])

    def test_file_env_var_direct_file_keys_keep_direct_semantics(self):
        """Config keys ending in _file (log_file, token_file, ...) stay direct."""
        from parsedmarc.cli import _apply_env_overrides

        config = ConfigParser()
        env = {
            "PARSEDMARC_GENERAL_LOG_FILE": "/var/log/parsedmarc.log",
            "PARSEDMARC_GMAIL_API_CREDENTIALS_FILE": "/etc/parsedmarc/gmail.json",
            "PARSEDMARC_GMAIL_API_TOKEN_FILE": "/etc/parsedmarc/gmail.token",
            "PARSEDMARC_MSGRAPH_TOKEN_FILE": "/etc/parsedmarc/msgraph.token",
        }
        with patch.dict(os.environ, env, clear=False):
            _apply_env_overrides(config)
        self.assertEqual(config.get("general", "log_file"), "/var/log/parsedmarc.log")
        self.assertEqual(
            config.get("gmail_api", "credentials_file"),
            "/etc/parsedmarc/gmail.json",
        )
        self.assertEqual(
            config.get("gmail_api", "token_file"), "/etc/parsedmarc/gmail.token"
        )
        self.assertEqual(
            config.get("msgraph", "token_file"), "/etc/parsedmarc/msgraph.token"
        )

    def test_file_env_var_double_suffix_wraps_direct_file_key(self):
        """GMAIL_API_CREDENTIALS_FILE_FILE provides the file path via a secret."""
        from parsedmarc.cli import _apply_env_overrides

        with NamedTemporaryFile(
            mode="w", suffix=".secret", delete=False, encoding="utf-8"
        ) as f:
            f.write("/run/secrets/real-gmail-credentials.json\n")
            secret_path = f.name

        try:
            config = ConfigParser()
            env = {"PARSEDMARC_GMAIL_API_CREDENTIALS_FILE_FILE": secret_path}
            with patch.dict(os.environ, env, clear=False):
                _apply_env_overrides(config)
            self.assertEqual(
                config.get("gmail_api", "credentials_file"),
                "/run/secrets/real-gmail-credentials.json",
            )
        finally:
            os.unlink(secret_path)

    def test_direct_file_keys_matches_parse_config_source(self):
        """``_DIRECT_FILE_KEYS`` must cover every ``*_file`` key in ``_parse_config``.

        Regression guard for the keep-in-sync comment: when someone adds a new
        ``[section] some_file`` config option in ``_parse_config`` without
        also extending ``_DIRECT_FILE_KEYS``, ``PARSEDMARC_SECTION_SOME_FILE``
        would silently be treated as a Docker-secret wrapper (and try to read
        a file at the supplied path) instead of as the direct value.
        """
        import re
        import inspect
        import parsedmarc.cli as cli_module

        # Scan the cli source for every ``<section>_config[...]("<key>_file")``
        # / ``["<key>_file"]`` access and rebuild the expected upper-case set.
        # Skip ``_filename`` keys (e.g. ``aggregate_json_filename``).
        src = inspect.getsource(cli_module)
        pattern = re.compile(
            r'(\w+?)_config(?:\.get|\[)\(?["\'](\w+_file)["\']',
        )
        seen: set[str] = set()
        for sect_var, key in pattern.findall(src):
            if key.endswith("_filename"):
                continue
            # Map the local variable name (graph_config / general_config /
            # gmail_api_config / ...) to its config-section name. The
            # convention is "<section>_config", but ``msgraph`` is bound to
            # ``graph_config`` — handle that one alias.
            section = "msgraph" if sect_var == "graph" else sect_var
            seen.add(f"{section.upper()}_{key.upper()}")
        self.assertEqual(
            seen,
            set(cli_module._DIRECT_FILE_KEYS),
            "_DIRECT_FILE_KEYS is out of sync with *_file keys in _parse_config",
        )


class TestGmailAuthModes(unittest.TestCase):
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.GmailConnection")
    def testCliPassesGmailServiceAccountAuthSettings(
        self, mock_gmail_connection, mock_get_mailbox_reports
    ):
        mock_gmail_connection.return_value = MagicMock()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        config = """[general]
silent = true

[gmail_api]
credentials_file = /tmp/service-account.json
auth_mode = service_account
service_account_user = dmarc@example.com
scopes = https://www.googleapis.com/auth/gmail.modify
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg_file:
            cfg_file.write(config)
            config_path = cfg_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("auth_mode"), "service_account"
        )
        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("service_account_user"),
            "dmarc@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.GmailConnection")
    def testCliAcceptsDelegatedUserAlias(self, mock_gmail_connection, mock_get_reports):
        mock_gmail_connection.return_value = MagicMock()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        config = """[general]
silent = true

[gmail_api]
credentials_file = /tmp/service-account.json
auth_mode = service_account
delegated_user = delegated@example.com
scopes = https://www.googleapis.com/auth/gmail.modify
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg_file:
            cfg_file.write(config)
            config_path = cfg_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("service_account_user"),
            "delegated@example.com",
        )


class TestMailboxWatchSince(unittest.TestCase):
    def setUp(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = True
        self._stdout_patch = patch("sys.stdout", new_callable=io.StringIO)
        self._stderr_patch = patch("sys.stderr", new_callable=io.StringIO)
        self._stdout_patch.start()
        self._stderr_patch.start()

    def tearDown(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = False
        self._stderr_patch.stop()
        self._stdout_patch.stop()

    def testWatchInboxPassesSinceToMailboxFetch(self):
        mailbox_connection = SimpleNamespace()

        def fake_watch(check_callback, check_timeout, config_reloading=None):
            check_callback(mailbox_connection)
            raise _BreakLoop()

        mailbox_connection.watch = fake_watch
        callback = MagicMock()
        with patch.object(
            parsedmarc, "get_dmarc_reports_from_mailbox", return_value={}
        ) as mocked:
            with self.assertRaises(_BreakLoop):
                parsedmarc.watch_inbox(
                    mailbox_connection=cast(
                        parsedmarc.MailboxConnection, mailbox_connection
                    ),
                    callback=callback,
                    check_timeout=1,
                    batch_size=10,
                    since="1d",
                )
        self.assertEqual(mocked.call_args.kwargs.get("since"), "1d")

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testCliPassesSinceToWatchInbox(
        self, mock_imap_connection, mock_watch_inbox, mock_get_mailbox_reports
    ):
        mock_imap_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        mock_watch_inbox.side_effect = FileExistsError("stop-watch-loop")

        config_text = """[general]
silent = true

[imap]
host = imap.example.com
user = user
password = pass

[mailbox]
watch = true
since = 2d
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, 1)
        self.assertEqual(mock_watch_inbox.call_args.kwargs.get("since"), "2d")


class TestMailboxPerformance(unittest.TestCase):
    def setUp(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = True
        self._stdout_patch = patch("sys.stdout", new_callable=io.StringIO)
        self._stderr_patch = patch("sys.stderr", new_callable=io.StringIO)
        self._stdout_patch.start()
        self._stderr_patch.start()

    def tearDown(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = False
        self._stderr_patch.stop()
        self._stdout_patch.stop()

    def testBatchModeAvoidsExtraFullFetch(self):
        connection = _DummyMailboxConnection()
        parsedmarc.get_dmarc_reports_from_mailbox(
            connection=connection,
            reports_folder="INBOX",
            test=True,
            batch_size=10,
            create_folders=False,
        )
        self.assertEqual(len(connection.fetch_calls), 1)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliPassesMsGraphCertificateAuthSettings(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
certificate_password = cert-pass
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"), "Certificate"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("certificate_path"),
            "/tmp/msgraph-cert.pem",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("certificate_password"),
            "cert-pass",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphCertificatePath(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "certificate_path setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliUsesMsGraphUserAsMailboxForUsernamePasswordAuth(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = UsernamePassword
client_id = client-id
client_secret = client-secret
user = owner@example.com
password = test-password
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "owner@example.com",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("username"),
            "owner@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphPasswordForUsernamePasswordAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = UsernamePassword
client_id = client-id
client_secret = client-secret
user = owner@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "password setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()


class TestMSGraphCliValidation(unittest.TestCase):
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliPassesMsGraphClientSecretAuthSettings(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
client_secret = client-secret
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"), "ClientSecret"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("client_secret"),
            "client-secret",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("tenant_id"), "tenant-id"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "shared@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphClientSecretForClientSecretAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "client_secret setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphTenantIdForClientSecretAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
client_secret = client-secret
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "tenant_id setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphMailboxForClientSecretAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientSecret
client_id = client-id
client_secret = client-secret
tenant_id = tenant-id
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "mailbox setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliAllowsMsGraphDeviceCodeWithoutUser(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = DeviceCode
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"), "DeviceCode"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "shared@example.com",
        )
        self.assertIsNone(mock_graph_connection.call_args.kwargs.get("username"))

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphTenantIdForDeviceCodeAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = DeviceCode
client_id = client-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "tenant_id setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphMailboxForDeviceCodeAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = DeviceCode
client_id = client-id
tenant_id = tenant-id
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "mailbox setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphTenantIdForCertificateAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "tenant_id setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphMailboxForCertificateAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id
tenant_id = tenant-id
certificate_path = /tmp/msgraph-cert.pem
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "mailbox setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliPassesMsGraphClientAssertionAuthSettings(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientAssertion
client_id = client-id
client_assertion = signed-jwt-assertion
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"),
            "ClientAssertion",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("client_assertion"),
            "signed-jwt-assertion",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("tenant_id"), "tenant-id"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "shared@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphClientAssertionForClientAssertionAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientAssertion
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "client_assertion setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphTenantIdForClientAssertionAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientAssertion
client_id = client-id
client_assertion = signed-jwt-assertion
mailbox = shared@example.com
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "tenant_id setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRequiresMsGraphMailboxForClientAssertionAuth(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = ClientAssertion
client_id = client-id
client_assertion = signed-jwt-assertion
tenant_id = tenant-id
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "mailbox setting missing from the msgraph config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliAcceptsLowercaseMsGraphCertificateAuthMethod(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """auth_method values are case-insensitive (e.g. ``certificate``)."""
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        config_text = """[general]
silent = true

[msgraph]
auth_method = certificate
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
certificate_password = cert-pass
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("auth_method"), "Certificate"
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("mailbox"),
            "shared@example.com",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("certificate_path"),
            "/tmp/msgraph-cert.pem",
        )
        self.assertEqual(
            mock_graph_connection.call_args.kwargs.get("certificate_password"),
            "cert-pass",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliRejectsInvalidMsGraphAuthMethod(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        config_text = """[general]
silent = true

[msgraph]
auth_method = NotARealMethod
client_id = client-id
tenant_id = tenant-id
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
"""

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as system_exit:
                parsedmarc.cli._main()

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once()
        critical_message = mock_logger.critical.call_args.args[0]
        self.assertIn("Invalid msgraph auth_method", critical_message)
        self.assertIn("NotARealMethod", critical_message)
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()


class TestMSGraphConnectionLogging(unittest.TestCase):
    """MS Graph connection observability (issue #814): a redacted
    connection summary is logged before connecting, timing after, secret
    values never appear in log output, and the dependency loggers that
    carry the actual auth/HTTP activity (mailsuite, azure, msgraph,
    httpx, httpcore) follow parsedmarc's --verbose/--debug level."""

    CERT_CONFIG = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id-1234
tenant_id = tenant-id-5678
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
certificate_password = s3cret-cert-pass
"""

    def setUp(self):
        # _configure_dependency_logging mutates process-global loggers;
        # snapshot and restore their levels and handlers so these tests
        # don't leak state into the rest of the suite.
        saved = {}
        for name in parsedmarc.cli._DEPENDENCY_LOGGERS:
            dep = logging.getLogger(name)
            saved[name] = (dep.level, list(dep.handlers), dep.propagate)

        def restore():
            for name, (level, handlers, propagate) in saved.items():
                dep = logging.getLogger(name)
                dep.setLevel(level)
                dep.handlers = handlers
                dep.propagate = propagate

        self.addCleanup(restore)

    def _write_config(self, config_text):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))
        return cfg_path

    def _run_main(self, cfg_path, *cli_args):
        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path, *cli_args]):
            parsedmarc.cli._main()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliLogsMsGraphConnectionSummaryAndTiming(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """The INFO summary identifies the auth method, tenant, client,
        mailbox, and Graph URL before any network I/O, and a timing line
        follows once the connection object is initialized."""
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        cfg_path = self._write_config(self.CERT_CONFIG)

        with self.assertLogs("parsedmarc.log", level="INFO") as cm:
            self._run_main(cfg_path, "--verbose")

        output = "\n".join(cm.output)
        self.assertIn("Connecting to Microsoft Graph", output)
        self.assertIn("auth_method=Certificate", output)
        self.assertIn("tenant_id=tenant-id-5678", output)
        self.assertIn("client_id=client-id-1234", output)
        self.assertIn("mailbox=shared@example.com", output)
        self.assertIn("graph_url=https://graph.microsoft.com", output)
        self.assertIn("Microsoft Graph connection initialized in", output)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliMsGraphLoggingNeverLogsSecretValues(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """Even at --debug, secret values (certificate_password and
        client_assertion here) must not appear anywhere in parsedmarc's
        log output — the debug detail line reports set/not-set flags
        instead."""
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        cfg_path = self._write_config(self.CERT_CONFIG)

        with self.assertLogs("parsedmarc.log", level="DEBUG") as cm:
            self._run_main(cfg_path, "--debug")

        output = "\n".join(cm.output)
        self.assertNotIn("s3cret-cert-pass", output)
        self.assertIn("certificate_path=/tmp/msgraph-cert.pem", output)
        self.assertIn("certificate_password set", output)
        self.assertIn("client_assertion not set", output)

        assertion_config = """[general]
silent = true

[msgraph]
auth_method = ClientAssertion
client_id = client-id-1234
tenant_id = tenant-id-5678
mailbox = shared@example.com
client_assertion = s3cret-signed-jwt-assertion
"""
        cfg_path = self._write_config(assertion_config)

        with self.assertLogs("parsedmarc.log", level="DEBUG") as cm:
            self._run_main(cfg_path, "--debug")

        output = "\n".join(cm.output)
        self.assertNotIn("s3cret-signed-jwt-assertion", output)
        self.assertIn("client_assertion set", output)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliDebugEnablesDependencyLoggers(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """--debug propagates DEBUG level and parsedmarc's handlers to the
        mailsuite/azure/msgraph/httpx/httpcore loggers, so token and HTTP
        activity reaches the console (and log file) instead of being
        dropped."""
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        cfg_path = self._write_config(self.CERT_CONFIG)
        self._run_main(cfg_path, "--debug")

        parsedmarc_logger = logging.getLogger("parsedmarc.log")
        for name in parsedmarc.cli._DEPENDENCY_LOGGERS:
            dep = logging.getLogger(name)
            self.assertEqual(dep.level, logging.DEBUG, name)
            # Propagation is disabled so a stray logging.basicConfig()
            # elsewhere in the process can't double-print these records.
            self.assertFalse(dep.propagate, name)
            for wanted in parsedmarc_logger.handlers:
                self.assertIn(wanted, dep.handlers, name)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliDefaultKeepsDependencyLoggersAtWarning(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """Without --verbose/--debug, dependency loggers sit at WARNING —
        their warnings surface (formatted) but no new noise appears."""
        mock_graph_connection.return_value = object()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        cfg_path = self._write_config(self.CERT_CONFIG)
        self._run_main(cfg_path)

        for name in parsedmarc.cli._DEPENDENCY_LOGGERS:
            self.assertEqual(logging.getLogger(name).level, logging.WARNING, name)


class TestMSGraphEmailResults(unittest.TestCase):
    """#472: the periodic summary email is sent via the same
    already-authenticated Microsoft Graph mailbox connection when
    [smtp] host is not configured but [msgraph] is, so M365 tenants that
    block legacy SMTP AUTH can still receive the summary from the
    mailbox they already read reports from. SMTP is preferred when
    [smtp] host is set."""

    CERT_CONFIG = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id-1234
tenant_id = tenant-id-5678
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
certificate_password = s3cret-cert-pass
"""

    def setUp(self):
        # _configure_dependency_logging mutates process-global loggers;
        # snapshot and restore their levels and handlers so these tests
        # don't leak state into the rest of the suite.
        saved = {}
        for name in parsedmarc.cli._DEPENDENCY_LOGGERS:
            dep = logging.getLogger(name)
            saved[name] = (dep.level, list(dep.handlers), dep.propagate)

        def restore():
            for name, (level, handlers, propagate) in saved.items():
                dep = logging.getLogger(name)
                dep.setLevel(level)
                dep.handlers = handlers
                dep.propagate = propagate

        self.addCleanup(restore)

    def _write_config(self, config_text):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))
        return cfg_path

    def _run_main(self, cfg_path, *cli_args):
        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path, *cli_args]):
            parsedmarc.cli._main()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliSendsSummaryEmailViaMsGraphWhenNoSmtpHost(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """[smtp] with only to/subject (no host) plus [msgraph] sends the
        summary via Microsoft Graph's sendMail."""
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        config_text = (
            self.CERT_CONFIG
            + """
[smtp]
to = admin@example.com
subject = DMARC Summary
"""
        )
        cfg_path = self._write_config(config_text)
        self._run_main(cfg_path)

        send_message = mock_graph_connection.return_value.send_message
        send_message.assert_called_once()
        call_kwargs = send_message.call_args.kwargs
        self.assertEqual(call_kwargs["message_to"], ["admin@example.com"])
        self.assertEqual(call_kwargs["subject"], "DMARC Summary")

        filename, payload = call_kwargs["attachments"][0]
        self.assertRegex(filename, r"^DMARC-\d{4}-\d{2}-\d{2}\.zip$")
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            self.assertIsNone(zf.testzip())

    @patch("parsedmarc.cli.email_results")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliPrefersSmtpWhenBothSmtpAndMsGraphConfigured(
        self, mock_graph_connection, mock_get_mailbox_reports, mock_email_results
    ):
        """SMTP is preferred over Microsoft Graph when [smtp] host is
        set, even with [msgraph] also configured — no fallback, no
        dual-send."""
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        config_text = (
            self.CERT_CONFIG
            + """
[smtp]
host = smtp.example.com
user = smtp-user
password = smtp-password
from = dmarc@example.com
to = admin@example.com
"""
        )
        cfg_path = self._write_config(config_text)
        self._run_main(cfg_path)

        mock_email_results.assert_called_once()
        call_args = mock_email_results.call_args
        self.assertEqual(call_args.args[1], "smtp.example.com")
        self.assertEqual(call_args.args[2], "dmarc@example.com")
        self.assertEqual(call_args.args[3], ["admin@example.com"])
        self.assertEqual(call_args.kwargs["username"], "smtp-user")
        self.assertEqual(call_args.kwargs["password"], "smtp-password")
        mock_graph_connection.return_value.send_message.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliSkipsGraphSendWithoutSmtpSection(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """A [msgraph]-only, read-only config (no [smtp] section at all)
        sends nothing — unchanged behavior for existing reading-only
        users."""
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        cfg_path = self._write_config(self.CERT_CONFIG)
        self._run_main(cfg_path)

        mock_graph_connection.return_value.send_message.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    @patch("parsedmarc.cli.logger")
    def testCliSmtpWithoutHostRequiresMsGraph(
        self, mock_logger, mock_graph_connection, mock_get_mailbox_reports
    ):
        """[smtp] with to but no host, and no [msgraph] configured at
        all, still fails config parsing exactly as it did before this
        feature — host is only optional when a Graph connection can
        send instead."""
        config_text = """[general]
silent = true

[smtp]
to = admin@example.com
"""
        cfg_path = self._write_config(config_text)

        with self.assertRaises(SystemExit) as system_exit:
            self._run_main(cfg_path)

        self.assertEqual(system_exit.exception.code, -1)
        mock_logger.critical.assert_called_once_with(
            "host setting missing from the smtp config section"
        )
        mock_graph_connection.assert_not_called()
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliLogsMsGraphSendFailure(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """A Graph sendMail failure gets the same single-ERROR-line
        treatment as connection/fetch failures."""
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        mock_graph_connection.return_value.send_message.side_effect = ODataError(
            response_status_code=403,
            error=MainError(
                message="Access is denied",
                inner_error=InnerError(request_id="rid-1", client_request_id="crid-1"),
            ),
        )
        config_text = (
            self.CERT_CONFIG
            + """
[smtp]
to = admin@example.com
subject = DMARC Summary
"""
        )
        cfg_path = self._write_config(config_text)

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            with self.assertRaises(SystemExit) as system_exit:
                self._run_main(cfg_path)

        self.assertEqual(system_exit.exception.code, 1)
        output = "\n".join(cm.output)
        self.assertIn("Microsoft Graph message send failed", output)
        self.assertIn("mailbox=", output)
        self.assertIn("tenant_id=", output)
        self.assertIn("auth_method=Certificate", output)
        self.assertIn("status=403", output)
        self.assertIn("request-id=rid-1", output)
        self.assertIn("client-request-id=crid-1", output)


class TestMSGraphFailureLogging(unittest.TestCase):
    """Microsoft Graph connection/fetch/watch failures log a single
    clear ERROR line identifying the mailbox/tenant/auth method and
    the Graph request-id/client-request-id when available, instead of
    a bare logger.exception() that hides the actual error."""

    CERT_CONFIG = """[general]
silent = true

[msgraph]
auth_method = Certificate
client_id = client-id-1234
tenant_id = tenant-id-5678
mailbox = shared@example.com
certificate_path = /tmp/msgraph-cert.pem
certificate_password = s3cret-cert-pass
"""

    def setUp(self):
        saved = {}
        for name in parsedmarc.cli._DEPENDENCY_LOGGERS:
            dep = logging.getLogger(name)
            saved[name] = (dep.level, list(dep.handlers), dep.propagate)

        def restore():
            for name, (level, handlers, propagate) in saved.items():
                dep = logging.getLogger(name)
                dep.setLevel(level)
                dep.handlers = handlers
                dep.propagate = propagate

        self.addCleanup(restore)

    def _write_config(self, config_text):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_text)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))
        return cfg_path

    def _run_main(self, cfg_path, *cli_args):
        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path, *cli_args]):
            parsedmarc.cli._main()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliLogsMsGraphConnectionAuthFailureContext(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """An auth failure during connection construction logs the
        redacted context plus the actionable AADSTS code verbatim."""
        mock_graph_connection.side_effect = ClientAuthenticationError(
            "AADSTS7000215: Invalid client secret"
        )
        cfg_path = self._write_config(self.CERT_CONFIG)

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            with self.assertRaises(SystemExit) as system_exit:
                self._run_main(cfg_path)

        self.assertEqual(system_exit.exception.code, 1)
        output = "\n".join(cm.output)
        self.assertIn("Microsoft Graph connection failed", output)
        self.assertIn("mailbox=shared@example.com", output)
        self.assertIn("tenant_id=tenant-id-5678", output)
        self.assertIn("auth_method=Certificate", output)
        self.assertIn("AADSTS7000215", output)
        mock_get_mailbox_reports.assert_not_called()

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliLogsMsGraphMailboxFetchFailureWithRequestId(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """A mailbox-fetch failure (the most common real-world auth
        failure point, since app-only auth defers token acquisition to
        first use) surfaces both OData inner-error request ids."""
        mock_get_mailbox_reports.side_effect = ODataError(
            response_status_code=503,
            error=MainError(
                message="Service unavailable",
                inner_error=InnerError(request_id="rid-2", client_request_id="crid-2"),
            ),
        )
        cfg_path = self._write_config(self.CERT_CONFIG)

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            with self.assertRaises(SystemExit) as system_exit:
                self._run_main(cfg_path)

        self.assertEqual(system_exit.exception.code, 1)
        output = "\n".join(cm.output)
        self.assertIn("Microsoft Graph mailbox fetch failed", output)
        self.assertIn("request-id=rid-2", output)
        self.assertIn("client-request-id=crid-2", output)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliMsGraphErrorFallsBackToResponseHeaderRequestId(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """When the response body didn't deserialize into a proper OData
        inner error, the request-id still surfaces from the raw
        response headers."""
        mock_get_mailbox_reports.side_effect = ODataError(
            response_status_code=503,
            response_headers={"request-id": "hdr-rid"},
            error=None,
        )
        cfg_path = self._write_config(self.CERT_CONFIG)

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            with self.assertRaises(SystemExit):
                self._run_main(cfg_path)

        output = "\n".join(cm.output)
        self.assertIn("request-id=hdr-rid", output)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testCliMsGraphErrorOmitsRequestIdWhenAbsent(
        self, mock_graph_connection, mock_get_mailbox_reports
    ):
        """When neither an inner error nor a response header carries a
        request id, the ERROR line simply omits the suffix rather than
        printing an empty/misleading id."""
        mock_get_mailbox_reports.side_effect = ODataError(response_status_code=500)
        cfg_path = self._write_config(self.CERT_CONFIG)

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            with self.assertRaises(SystemExit) as system_exit:
                self._run_main(cfg_path)

        self.assertEqual(system_exit.exception.code, 1)
        output = "\n".join(cm.output)
        self.assertNotIn("request-id=", output)

    @patch("parsedmarc.cli.watch_inbox", side_effect=httpx.ConnectError("dns failure"))
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.MSGraphConnection")
    def testWatchModeLogsMsGraphErrorAndExits(
        self, mock_graph_connection, mock_get_mailbox_reports, mock_watch_inbox
    ):
        """Before this fix, --watch had no catch-all at all for Graph
        errors, so a token/cert expiry mid-watch crashed with a raw
        uncaught traceback. It now gets the same single ERROR line."""
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        config_text = self.CERT_CONFIG + "\n[mailbox]\nwatch = true\n"
        cfg_path = self._write_config(config_text)

        with self.assertLogs("parsedmarc.log", level="ERROR") as cm:
            with self.assertRaises(SystemExit) as system_exit:
                self._run_main(cfg_path)

        self.assertEqual(system_exit.exception.code, 1)
        output = "\n".join(cm.output)
        self.assertIn("Microsoft Graph mailbox watch failed", output)
        self.assertIn("ConnectError", output)


class TestSighupReload(unittest.TestCase):
    """Tests for SIGHUP-driven configuration reload in watch mode."""

    def setUp(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = True
        self._stdout_patch = patch("sys.stdout", new_callable=io.StringIO)
        self._stderr_patch = patch("sys.stderr", new_callable=io.StringIO)
        self._stdout_patch.start()
        self._stderr_patch.start()

    def tearDown(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = False
        self._stderr_patch.stop()
        self._stdout_patch.stop()

    _BASE_CONFIG = """[general]
silent = true

[imap]
host = imap.example.com
user = user
password = pass

[mailbox]
watch = true
"""

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testSighupTriggersReloadAndWatchRestarts(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """SIGHUP causes watch to return, config is re-parsed, and watch restarts."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        def parse_side_effect(config, opts):
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            return None

        mock_parse_config.side_effect = parse_side_effect
        mock_init_clients.return_value = {}

        call_count = [0]

        def watch_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # Simulate SIGHUP arriving while watch is running
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return  # Normal return — reload loop will continue
            else:
                raise FileExistsError("stop-watch-loop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as cm:
                parsedmarc.cli._main()

        # Exited with code 1 (from FileExistsError handler)
        self.assertEqual(cm.exception.code, 1)
        # watch_inbox was called twice: initial run + after reload
        self.assertEqual(mock_watch.call_count, 2)
        # _parse_config called for initial load + reload
        self.assertGreaterEqual(mock_parse_config.call_count, 2)

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testInvalidConfigOnReloadKeepsPreviousState(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """A failing reload leaves opts and clients unchanged."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        # Initial parse sets required opts; reload parse raises
        initial_map = {"prefix_": ["example.com"]}
        call_count = [0]

        def parse_side_effect(config, opts):
            call_count[0] += 1
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            if call_count[0] == 1:
                return initial_map
            raise RuntimeError("bad config")

        mock_parse_config.side_effect = parse_side_effect

        initial_clients = {"s3_client": MagicMock()}
        mock_init_clients.return_value = initial_clients

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit) as cm:
                parsedmarc.cli._main()

        self.assertEqual(cm.exception.code, 1)
        # watch was still called twice (reload loop continued after failed reload)
        self.assertEqual(mock_watch.call_count, 2)
        # Old clients should NOT have been closed (reload failed before swap)
        initial_clients["s3_client"].close.assert_not_called()

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testReloadClosesOldClients(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """Successful reload closes the old output clients before replacing them."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        def parse_side_effect(config, opts):
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            return None

        mock_parse_config.side_effect = parse_side_effect

        old_client = MagicMock()
        new_client = MagicMock()
        init_call = [0]

        def init_side_effect(opts):
            init_call[0] += 1
            if init_call[0] == 1:
                return {"kafka_client": old_client}
            return {"kafka_client": new_client}

        mock_init_clients.side_effect = init_side_effect

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit):
                parsedmarc.cli._main()

        # Old client must have been closed when reload succeeded
        old_client.close.assert_called_once()

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testRemovedConfigSectionTakesEffectOnReload(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_init_clients,
    ):
        """Removing a config section on reload resets that option to its default."""
        import signal as signal_module

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }
        mock_init_clients.return_value = {}

        # First config sets kafka_hosts (with required topics); second removes it.
        config_v1 = (
            self._BASE_CONFIG
            + "\n[kafka]\nhosts = kafka.example.com:9092\n"
            + "aggregate_topic = dmarc_agg\n"
            + "forensic_topic = dmarc_forensic\n"
            + "smtp_tls_topic = smtp_tls\n"
        )
        config_v2 = self._BASE_CONFIG  # no [kafka] section

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(config_v1)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                # Rewrite config to remove kafka before triggering reload
                with open(cfg_path, "w") as f:
                    f.write(config_v2)
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        # Capture opts used on each _init_output_clients call
        init_opts_captures = []

        def init_side_effect(opts):
            from argparse import Namespace as NS

            init_opts_captures.append(NS(**vars(opts)))
            return {}

        mock_init_clients.side_effect = init_side_effect

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit):
                parsedmarc.cli._main()

        # First init: kafka_hosts should be set from v1 config
        self.assertIsNotNone(init_opts_captures[0].kafka_hosts)
        # Second init (after reload with v2 config): kafka_hosts should be None
        self.assertIsNone(init_opts_captures[1].kafka_hosts)

    @unittest.skipUnless(
        hasattr(signal, "SIGHUP"),
        "SIGHUP not available on this platform",
    )
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testReloadRefreshesReverseDnsMap(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """SIGHUP reload repopulates the reverse DNS map so lookups still work."""
        import signal as signal_module

        from parsedmarc import REVERSE_DNS_MAP

        mock_imap.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

        mock_load_config.return_value = ConfigParser()

        def parse_side_effect(config, opts):
            opts.imap_host = "imap.example.com"
            opts.imap_user = "user"
            opts.imap_password = "pass"
            opts.mailbox_watch = True
            return None

        mock_parse_config.side_effect = parse_side_effect
        mock_init_clients.return_value = {}

        # Snapshot the map state after each watch_inbox call
        map_snapshots = []

        watch_calls = [0]

        def watch_side_effect(*args, **kwargs):
            watch_calls[0] += 1
            if watch_calls[0] == 1:
                if hasattr(signal_module, "SIGHUP"):
                    import os

                    os.kill(os.getpid(), signal_module.SIGHUP)
                return
            else:
                # Capture the map state after reload, before we stop the loop
                map_snapshots.append(dict(REVERSE_DNS_MAP))
                raise FileExistsError("stop")

        mock_watch.side_effect = watch_side_effect

        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))

        # Pre-populate the map so we can verify it gets refreshed
        REVERSE_DNS_MAP.clear()
        REVERSE_DNS_MAP["stale.example.com"] = {
            "name": "Stale",
            "type": "stale",
        }
        original_contents = dict(REVERSE_DNS_MAP)

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            with self.assertRaises(SystemExit):
                parsedmarc.cli._main()

        self.assertEqual(mock_watch.call_count, 2)
        # The map should have been repopulated (not empty, not the stale data)
        self.assertEqual(len(map_snapshots), 1)
        refreshed = map_snapshots[0]
        self.assertGreater(len(refreshed), 0, "Map should not be empty after reload")
        self.assertNotEqual(
            refreshed,
            original_contents,
            "Map should have been refreshed, not kept stale data",
        )
        self.assertNotIn(
            "stale.example.com",
            refreshed,
            "Stale entry should have been cleared by reload",
        )


class TestSigtermShutdown(unittest.TestCase):
    """Tests for graceful SIGTERM/SIGINT shutdown."""

    def setUp(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = True
        self._stdout_patch = patch("sys.stdout", new_callable=io.StringIO)
        self._stderr_patch = patch("sys.stderr", new_callable=io.StringIO)
        self._stdout_patch.start()
        self._stderr_patch.start()

    def tearDown(self):
        from parsedmarc.log import logger as _logger

        _logger.disabled = False
        self._stderr_patch.stop()
        self._stdout_patch.stop()

    _BASE_CONFIG = """[general]
silent = true

[imap]
host = imap.example.com
user = user
password = pass

[mailbox]
watch = true
"""

    def _write_config(self, body=None):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg:
            cfg.write(body if body is not None else self._BASE_CONFIG)
            cfg_path = cfg.name
        self.addCleanup(lambda: os.path.exists(cfg_path) and os.remove(cfg_path))
        return cfg_path

    @staticmethod
    def _empty_reports():
        return {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [],
        }

    @staticmethod
    def _parse_config_side_effect(config, opts):
        opts.imap_host = "imap.example.com"
        opts.imap_user = "user"
        opts.imap_password = "pass"
        opts.mailbox_watch = True
        return None

    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testSigtermDuringWatchExitsCleanlyAndClosesClients(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """SIGTERM during watch: the backend polls config_reloading,
        observes the flag, and returns at a safe boundary; _main breaks
        the watch loop, returns normally, and closes every output client
        that exposes a `.close()`."""
        mock_imap.return_value = object()
        mock_load_config.return_value = ConfigParser()
        mock_parse_config.side_effect = self._parse_config_side_effect
        mock_get_reports.return_value = self._empty_reports()

        kafka_client = MagicMock(spec=["close"])
        elasticsearch_client = MagicMock(spec=["close"])
        no_close_client = MagicMock(spec=[])  # no `close` attr → skipped
        mock_init_clients.return_value = {
            "kafka": kafka_client,
            "elasticsearch": elasticsearch_client,
            "syslog": no_close_client,
        }

        observed = []

        def watch_side_effect(*args, **kwargs):
            # SIGTERM lands while watching; the backend then polls
            # config_reloading at its next safe boundary and returns.
            os.kill(os.getpid(), signal.SIGTERM)
            observed.append(kwargs["config_reloading"]())

        mock_watch.side_effect = watch_side_effect
        cfg_path = self._write_config()

        with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
            parsedmarc.cli._main()

        self.assertEqual(mock_watch.call_count, 1)
        self.assertEqual(observed, [True])
        kafka_client.close.assert_called()
        elasticsearch_client.close.assert_called()

    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli._parse_config")
    @patch("parsedmarc.cli._load_config")
    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.watch_inbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testFirstSigintGracefulSecondSigintHardExits(
        self,
        mock_imap,
        mock_watch,
        mock_get_reports,
        mock_load_config,
        mock_parse_config,
        mock_init_clients,
    ):
        """First SIGINT → graceful flag, second SIGINT → os._exit(130).

        The installed handler is invoked directly via signal.getsignal()
        because two POSIX SIGINTs sent in rapid succession from the same
        process can be coalesced by the kernel (standard signals don't
        queue)."""
        mock_imap.return_value = object()
        mock_load_config.return_value = ConfigParser()
        mock_parse_config.side_effect = self._parse_config_side_effect
        mock_get_reports.return_value = self._empty_reports()
        mock_init_clients.return_value = {}

        sentinel = SystemExit("os._exit was reached")

        def fake_exit(code):
            raise sentinel

        def watch_side_effect(*args, **kwargs):
            handler = signal.getsignal(signal.SIGINT)
            # getsignal() can return SIG_DFL/SIG_IGN/None; narrow the type
            # so the handler can be invoked directly.
            assert callable(handler)
            handler(signal.SIGINT, None)  # first press: graceful flag
            handler(signal.SIGINT, None)  # second press: hits os._exit

        mock_watch.side_effect = watch_side_effect
        cfg_path = self._write_config()

        with patch("parsedmarc.cli.os._exit", side_effect=fake_exit) as mock_exit:
            with patch.object(sys, "argv", ["parsedmarc", "-c", cfg_path]):
                with self.assertRaises(SystemExit) as cm:
                    parsedmarc.cli._main()

        self.assertIs(cm.exception, sentinel)
        mock_exit.assert_called_once_with(130)

    @patch("parsedmarc.cli.get_dmarc_reports_from_mbox")
    @patch("parsedmarc.cli.is_mbox", side_effect=lambda p: p.endswith(".mbox"))
    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli.Process")
    @patch("parsedmarc.cli.glob")
    def testSigtermDuringOneShotStopsBetweenBatchesAndMbox(
        self,
        mock_glob,
        mock_process_cls,
        mock_init_clients,
        mock_is_mbox,
        mock_get_mbox,
    ):
        """SIGTERM during one-shot processing: the in-flight child is
        joined normally (no work lost), the file-batch loop stops before
        spawning the next batch, and the subsequent mbox loop breaks on
        its first iteration (the flag is already set). Output clients are
        still closed.

        Two ``.xml`` files give the batch loop a second iteration to hit
        its break; one ``.mbox`` file routes into ``mbox_paths`` so the
        mbox break is exercised too. ``is_mbox`` is keyed by suffix so the
        fake filenames don't trigger ``mailbox.mbox(path, create=True)``."""
        mock_glob.return_value = ["a.xml", "b.xml", "c.mbox"]

        kafka_client = MagicMock(spec=["close"])
        mock_init_clients.return_value = {"kafka": kafka_client}

        starts = []

        class FakeProc:
            """Stand-in child that finishes its file and sends a result
            even though SIGTERM arrived mid-batch."""

            def __init__(self, target=None, args=()):
                self._args = args

            def start(self):
                starts.append(self._args[0])
                if len(starts) == 1:
                    os.kill(os.getpid(), signal.SIGTERM)
                # Child still completes and reports back over the pipe.
                self._args[-3].send([None, self._args[0]])

            def join(self, timeout=None):
                return None

        mock_process_cls.side_effect = FakeProc

        with patch.object(sys, "argv", ["parsedmarc", "a.xml", "b.xml", "c.mbox"]):
            parsedmarc.cli._main()

        # Only the first xml batch ran before the batch loop broke, and the
        # mbox loop broke before processing its file.
        self.assertEqual(len(starts), 1)
        mock_get_mbox.assert_not_called()
        kafka_client.close.assert_called()

    @patch("parsedmarc.cli._init_output_clients")
    @patch("parsedmarc.cli.cli_parse")
    @patch("parsedmarc.cli.glob")
    def testNormalOneShotExitClosesOutputClients(
        self,
        mock_glob,
        mock_cli_parse,
        mock_init_clients,
    ):
        """A successful one-shot run with no signal still closes its
        output clients — regression for the long-standing leak where
        _close_output_clients was only called inside the SIGHUP
        reload path."""
        mock_glob.return_value = []
        kafka_client = MagicMock(spec=["close"])
        es_client = MagicMock(spec=["close"])
        mock_init_clients.return_value = {
            "kafka": kafka_client,
            "elasticsearch": es_client,
        }

        # No watch, no mailbox, no files → _main runs through with
        # empty parsing_results and returns normally.
        with patch.object(sys, "argv", ["parsedmarc", "nothing-here.xml"]):
            try:
                parsedmarc.cli._main()
            except SystemExit:
                pass

        kafka_client.close.assert_called_once()
        es_client.close.assert_called_once()


class TestIndexPrefixDomainMapTlsFiltering(unittest.TestCase):
    """Tests that SMTP TLS reports for unmapped domains are filtered out
    when index_prefix_domain_map is configured."""

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.IMAPConnection")
    def testTlsReportsFilteredByDomainMap(
        self,
        mock_imap_connection,
        mock_get_reports,
    ):
        """TLS reports for domains not in the map should be silently dropped."""
        mock_imap_connection.return_value = object()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "failure_reports": [],
            "smtp_tls_reports": [
                {
                    "organization_name": "Allowed Org",
                    "begin_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-01T23:59:59Z",
                    "report_id": "allowed-1",
                    "contact_info": "tls@allowed.example.com",
                    "policies": [
                        {
                            "policy_domain": "allowed.example.com",
                            "policy_type": "sts",
                            "successful_session_count": 1,
                            "failed_session_count": 0,
                        }
                    ],
                },
                {
                    "organization_name": "Unmapped Org",
                    "begin_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-01T23:59:59Z",
                    "report_id": "unmapped-1",
                    "contact_info": "tls@unmapped.example.net",
                    "policies": [
                        {
                            "policy_domain": "unmapped.example.net",
                            "policy_type": "sts",
                            "successful_session_count": 5,
                            "failed_session_count": 0,
                        }
                    ],
                },
                {
                    "organization_name": "Mixed Case Org",
                    "begin_date": "2024-01-01T00:00:00Z",
                    "end_date": "2024-01-01T23:59:59Z",
                    "report_id": "mixed-case-1",
                    "contact_info": "tls@mixedcase.example.com",
                    "policies": [
                        {
                            "policy_domain": "MixedCase.Example.Com",
                            "policy_type": "sts",
                            "successful_session_count": 2,
                            "failed_session_count": 0,
                        }
                    ],
                },
            ],
        }

        domain_map = {"tenant_a": ["example.com"]}
        with NamedTemporaryFile("w", suffix=".yaml", delete=False) as map_file:
            import yaml

            yaml.dump(domain_map, map_file)
            map_path = map_file.name
        self.addCleanup(lambda: os.path.exists(map_path) and os.remove(map_path))

        config = f"""[general]
save_smtp_tls = true
silent = false
index_prefix_domain_map = {map_path}

[imap]
host = imap.example.com
user = test-user
password = test-password
"""
        with NamedTemporaryFile("w", suffix=".ini", delete=False) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        captured = io.StringIO()
        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            with patch("sys.stdout", captured):
                parsedmarc.cli._main()

        output = json.loads(captured.getvalue())
        tls_reports = output["smtp_tls_reports"]
        self.assertEqual(len(tls_reports), 2)
        report_ids = {r["report_id"] for r in tls_reports}
        self.assertIn("allowed-1", report_ids)
        self.assertIn("mixed-case-1", report_ids)
        self.assertNotIn("unmapped-1", report_ids)


class TestConfigAliases(unittest.TestCase):
    """Tests for config key aliases (env var friendly short names)."""

    def test_maildir_create_alias(self):
        """[maildir] create works as alias for maildir_create."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        env = {
            "PARSEDMARC_MAILDIR_CREATE": "true",
            "PARSEDMARC_MAILDIR_PATH": "/tmp/test",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)
        opts = Namespace()
        _parse_config(config, opts)
        self.assertTrue(opts.maildir_create)

    def test_maildir_path_alias(self):
        """[maildir] path works as alias for maildir_path."""
        from argparse import Namespace
        from parsedmarc.cli import _load_config, _parse_config

        env = {"PARSEDMARC_MAILDIR_PATH": "/var/mail/dmarc"}
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)
        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.maildir_path, "/var/mail/dmarc")

    def test_msgraph_url_alias(self):
        """[msgraph] url works as alias for graph_url."""
        from parsedmarc.cli import _load_config, _parse_config
        from argparse import Namespace

        env = {
            "PARSEDMARC_MSGRAPH_AUTH_METHOD": "ClientSecret",
            "PARSEDMARC_MSGRAPH_CLIENT_ID": "test-id",
            "PARSEDMARC_MSGRAPH_CLIENT_SECRET": "test-secret",
            "PARSEDMARC_MSGRAPH_TENANT_ID": "test-tenant",
            "PARSEDMARC_MSGRAPH_MAILBOX": "test@example.com",
            "PARSEDMARC_MSGRAPH_URL": "https://custom.graph.example.com",
        }
        with patch.dict(os.environ, env, clear=False):
            config = _load_config(None)
        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.graph_url, "https://custom.graph.example.com")

    def test_original_keys_still_work(self):
        """Original INI key names (maildir_create, maildir_path) still work."""
        from argparse import Namespace
        from parsedmarc.cli import _parse_config

        config = ConfigParser(interpolation=None)
        config.add_section("maildir")
        config.set("maildir", "maildir_path", "/original/path")
        config.set("maildir", "maildir_create", "true")

        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.maildir_path, "/original/path")
        self.assertTrue(opts.maildir_create)

    def test_ipinfo_url_option(self):
        """[general] ipinfo_url lands on opts.ipinfo_url."""
        from argparse import Namespace
        from parsedmarc.cli import _parse_config

        config = ConfigParser(interpolation=None)
        config.add_section("general")
        config.set("general", "ipinfo_url", "https://mirror.example/mmdb")

        opts = Namespace()
        _parse_config(config, opts)
        self.assertEqual(opts.ipinfo_url, "https://mirror.example/mmdb")

    def test_ip_db_url_deprecated_alias(self):
        """[general] ip_db_url is accepted as an alias for ipinfo_url but
        emits a deprecation warning."""
        from argparse import Namespace
        from parsedmarc.cli import _parse_config

        config = ConfigParser(interpolation=None)
        config.add_section("general")
        config.set("general", "ip_db_url", "https://old.example/mmdb")

        opts = Namespace()
        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            _parse_config(config, opts)
        self.assertEqual(opts.ipinfo_url, "https://old.example/mmdb")
        self.assertTrue(
            any("ip_db_url" in line and "deprecated" in line for line in cm.output),
            f"expected deprecation warning, got: {cm.output}",
        )


class TestExpandPath(unittest.TestCase):
    """Tests for _expand_path config path expansion."""

    def test_expand_tilde(self):
        from parsedmarc.cli import _expand_path

        result = _expand_path("~/some/path")
        self.assertFalse(result.startswith("~"))
        self.assertTrue(result.endswith("/some/path"))

    def test_expand_env_var(self):
        from parsedmarc.cli import _expand_path

        with patch.dict(os.environ, {"PARSEDMARC_TEST_DIR": "/opt/data"}):
            result = _expand_path("$PARSEDMARC_TEST_DIR/tokens/.token")
        self.assertEqual(result, "/opt/data/tokens/.token")

    def test_expand_both(self):
        from parsedmarc.cli import _expand_path

        with patch.dict(os.environ, {"MY_APP": "parsedmarc"}):
            result = _expand_path("~/$MY_APP/config")
        self.assertNotIn("~", result)
        self.assertIn("parsedmarc/config", result)

    def test_no_expansion_needed(self):
        from parsedmarc.cli import _expand_path

        self.assertEqual(_expand_path("/absolute/path"), "/absolute/path")
        self.assertEqual(_expand_path("relative/path"), "relative/path")


# ---------------------------------------------------------------------------
# _parse_config: per-section INI → opts mapping
#
# Each section of the INI is consumed by a different branch of
# _parse_config. The tests below build a minimal config for one
# section at a time and verify every documented key lands on the right
# opts attribute. A rename, typo, or dropped backwards-compat alias
# would be caught here.
# ---------------------------------------------------------------------------


class _StrToListTests(unittest.TestCase):
    def test_str_to_list_strips_leading_whitespace_per_element(self):
        from parsedmarc.cli import _str_to_list

        self.assertEqual(_str_to_list("a, b ,c"), ["a", "b ", "c"])

    def test_str_to_list_single_value(self):
        from parsedmarc.cli import _str_to_list

        self.assertEqual(_str_to_list("solo"), ["solo"])


def _opts():
    """A fresh Namespace with no attributes — _parse_config sets fields
    via attribute assignment on whatever it's given."""
    from argparse import Namespace

    return Namespace()


def _config_with(section: str, settings: dict) -> "ConfigParser":
    """Build a ConfigParser holding exactly one section."""
    from configparser import ConfigParser

    cp = ConfigParser()
    cp.add_section(section)
    for k, v in settings.items():
        cp.set(section, k, str(v))
    return cp


class TestParseConfigGeneral(unittest.TestCase):
    """The [general] section sets dozens of flags. Hit a representative
    subset: filenames, save-toggles, DNS settings, output dir."""

    def test_general_filenames_and_output(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "general",
            {
                "silent": "false",
                "output": "/tmp/dmarc-out",
                "aggregate_json_filename": "agg.json",
                "failure_json_filename": "fail.json",
                "smtp_tls_json_filename": "tls.json",
                "aggregate_csv_filename": "agg.csv",
                "failure_csv_filename": "fail.csv",
                "smtp_tls_csv_filename": "tls.csv",
                "save_aggregate": "true",
                "save_failure": "true",
                "save_smtp_tls": "true",
                "debug": "false",
                "verbose": "false",
                "warnings": "false",
                "fail_on_output_error": "false",
                "offline": "true",
                "strip_attachment_payloads": "true",
                "n_procs": "4",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.output, "/tmp/dmarc-out")
        self.assertEqual(opts.aggregate_json_filename, "agg.json")
        self.assertEqual(opts.failure_json_filename, "fail.json")
        self.assertEqual(opts.smtp_tls_csv_filename, "tls.csv")
        self.assertTrue(opts.save_aggregate)
        self.assertTrue(opts.save_failure)
        self.assertTrue(opts.save_smtp_tls)
        self.assertTrue(opts.offline)
        self.assertTrue(opts.strip_attachment_payloads)
        self.assertEqual(opts.n_procs, 4)
        self.assertFalse(opts.silent)
        self.assertFalse(opts.debug)

    def test_general_save_forensic_alias_sets_save_failure(self):
        """Backwards compat: save_forensic in INI sets opts.save_failure."""
        from parsedmarc.cli import _parse_config

        cp = _config_with("general", {"save_forensic": "true"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertTrue(opts.save_failure)

    def test_general_forensic_filename_aliases_set_failure(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "general",
            {
                "forensic_json_filename": "fa.json",
                "forensic_csv_filename": "fa.csv",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.failure_json_filename, "fa.json")
        self.assertEqual(opts.failure_csv_filename, "fa.csv")

    def test_general_dns_settings_with_defaults(self):
        from parsedmarc.cli import _parse_config

        # dns_timeout/dns_retries are typed via getfloat/getint which
        # return non-None values for any valid input.
        cp = _config_with(
            "general",
            {
                "dns_timeout": "5.0",
                "dns_retries": "2",
                "dns_test_address": "1.1.1.1",
                "nameservers": "1.1.1.1, 8.8.8.8",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.dns_timeout, 5.0)
        self.assertEqual(opts.dns_retries, 2)
        self.assertEqual(opts.nameservers, ["1.1.1.1", "8.8.8.8"])

    def test_general_normalize_timespan_threshold(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with("general", {"normalize_timespan_threshold_hours": "48"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.normalize_timespan_threshold_hours, 48.0)


class TestParseConfigElasticsearch(unittest.TestCase):
    def test_elasticsearch_basic(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "elasticsearch",
            {
                "hosts": "es1:9200, es2:9200",
                "timeout": "30.0",
                "number_of_shards": "3",
                "number_of_replicas": "1",
                "index_suffix": "tenant_a",
                "index_prefix": "cust_",
                "monthly_indexes": "true",
                "ssl": "true",
                "cert_path": "/etc/ca.pem",
                "skip_certificate_verification": "true",
                "user": "alice",
                "password": "secret",
                "api_key": "base64key",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.elasticsearch_hosts, ["es1:9200", "es2:9200"])
        self.assertEqual(opts.elasticsearch_timeout, 30.0)
        self.assertEqual(opts.elasticsearch_number_of_shards, 3)
        self.assertEqual(opts.elasticsearch_number_of_replicas, 1)
        self.assertEqual(opts.elasticsearch_index_suffix, "tenant_a")
        self.assertEqual(opts.elasticsearch_index_prefix, "cust_")
        self.assertTrue(opts.elasticsearch_monthly_indexes)
        self.assertTrue(opts.elasticsearch_ssl)
        self.assertEqual(opts.elasticsearch_ssl_cert_path, "/etc/ca.pem")
        self.assertTrue(opts.elasticsearch_skip_certificate_verification)
        self.assertEqual(opts.elasticsearch_username, "alice")
        self.assertEqual(opts.elasticsearch_password, "secret")
        self.assertEqual(opts.elasticsearch_api_key, "base64key")

    def test_elasticsearch_apikey_camelcase_alias_pre_8_20(self):
        """`apiKey` (camelCase) is the legacy 8.20-and-earlier name."""
        from parsedmarc.cli import _parse_config

        cp = _config_with("elasticsearch", {"hosts": "es:9200", "apiKey": "legacy"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.elasticsearch_api_key, "legacy")

    def test_elasticsearch_missing_hosts_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("elasticsearch", {"timeout": "30"})
        with self.assertRaises(ConfigurationError) as ctx:
            _parse_config(cp, _opts())
        self.assertIn("hosts", str(ctx.exception))

    def test_elasticsearch_serverless_flag(self):
        """``[elasticsearch] serverless = true`` flips ``opts.elasticsearch_serverless``."""
        from parsedmarc.cli import _parse_config

        cp = _config_with("elasticsearch", {"hosts": "es:9200", "serverless": "true"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertIs(opts.elasticsearch_serverless, True)

    def test_elasticsearch_serverless_passed_to_set_hosts(self):
        """End-to-end: a Serverless config reaches ``elastic.set_hosts(serverless=True)``.

        Regression guard: catches anyone who later parses the flag but forgets
        to plumb it through to ``set_hosts`` (or vice-versa).
        """
        config = """[general]
save_aggregate = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[elasticsearch]
hosts = localhost
serverless = true
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with (
            patch("parsedmarc.cli.elastic.migrate_indexes"),
            patch("parsedmarc.cli.elastic.set_hosts") as mock_set_hosts,
            patch(
                "parsedmarc.cli.get_dmarc_reports_from_mailbox",
                return_value={
                    "aggregate_reports": [],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
            ),
            patch("parsedmarc.cli.IMAPConnection", return_value=object()),
            patch.object(sys, "argv", ["parsedmarc", "-c", config_path]),
        ):
            parsedmarc.cli._main()

        mock_set_hosts.assert_called_once()
        self.assertIs(mock_set_hosts.call_args.kwargs.get("serverless"), True)


class TestParseConfigOpenSearch(unittest.TestCase):
    def test_opensearch_basic(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "opensearch",
            {
                "hosts": "os1:9200",
                "timeout": "45.0",
                "number_of_shards": "2",
                "number_of_replicas": "0",
                "index_suffix": "x",
                "index_prefix": "y_",
                "monthly_indexes": "true",
                "ssl": "true",
                "cert_path": "/etc/ca.pem",
                "skip_certificate_verification": "true",
                "user": "u",
                "password": "p",
                "api_key": "k",
                "auth_type": "BASIC",
                "aws_region": "us-east-1",
                "aws_service": "es",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.opensearch_hosts, ["os1:9200"])
        self.assertEqual(opts.opensearch_timeout, 45.0)
        self.assertEqual(opts.opensearch_number_of_shards, 2)
        self.assertEqual(opts.opensearch_number_of_replicas, 0)
        self.assertEqual(opts.opensearch_index_suffix, "x")
        self.assertEqual(opts.opensearch_index_prefix, "y_")
        self.assertTrue(opts.opensearch_monthly_indexes)
        self.assertTrue(opts.opensearch_ssl)
        self.assertEqual(opts.opensearch_ssl_cert_path, "/etc/ca.pem")
        self.assertTrue(opts.opensearch_skip_certificate_verification)
        self.assertEqual(opts.opensearch_username, "u")
        self.assertEqual(opts.opensearch_password, "p")
        self.assertEqual(opts.opensearch_api_key, "k")
        # auth_type is lowercased/stripped.
        self.assertEqual(opts.opensearch_auth_type, "basic")
        self.assertEqual(opts.opensearch_aws_region, "us-east-1")
        self.assertEqual(opts.opensearch_aws_service, "es")

    def test_opensearch_authentication_type_legacy_alias(self):
        """`authentication_type` is the legacy spelling of `auth_type`."""
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "opensearch",
            {"hosts": "os:9200", "authentication_type": "AWSSigV4"},
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.opensearch_auth_type, "awssigv4")

    def test_opensearch_apikey_camelcase_alias(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with("opensearch", {"hosts": "os:9200", "apiKey": "legacy"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.opensearch_api_key, "legacy")

    def test_opensearch_missing_hosts_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("opensearch", {"timeout": "30"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())


class TestParseConfigSplunkHec(unittest.TestCase):
    def test_splunk_hec_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "splunk_hec",
            {
                "url": "https://splunk:8088",
                "token": "abc-token",
                "index": "dmarc",
                "skip_certificate_verification": "true",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.hec, "https://splunk:8088")
        self.assertEqual(opts.hec_token, "abc-token")
        self.assertEqual(opts.hec_index, "dmarc")
        self.assertTrue(opts.hec_skip_certificate_verification)

    def test_splunk_hec_missing_url_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("splunk_hec", {"token": "t", "index": "i"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_splunk_hec_missing_token_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("splunk_hec", {"url": "https://splunk:8088", "index": "i"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_splunk_hec_missing_index_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("splunk_hec", {"url": "https://splunk:8088", "token": "t"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())


class TestParseConfigKafka(unittest.TestCase):
    def test_kafka_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "kafka",
            {
                "hosts": "kafka1:9092, kafka2:9092",
                "user": "u",
                "password": "p",
                "ssl": "true",
                "skip_certificate_verification": "true",
                "aggregate_topic": "dmarc-aggregate",
                "failure_topic": "dmarc-failure",
                "smtp_tls_topic": "smtp-tls",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.kafka_hosts, ["kafka1:9092", "kafka2:9092"])
        self.assertEqual(opts.kafka_username, "u")
        self.assertEqual(opts.kafka_password, "p")
        self.assertTrue(opts.kafka_ssl)
        self.assertTrue(opts.kafka_skip_certificate_verification)
        self.assertEqual(opts.kafka_aggregate_topic, "dmarc-aggregate")
        self.assertEqual(opts.kafka_failure_topic, "dmarc-failure")
        self.assertEqual(opts.kafka_smtp_tls_topic, "smtp-tls")

    def test_kafka_forensic_topic_alias_sets_failure_topic(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "kafka",
            {
                "hosts": "k:9092",
                "aggregate_topic": "agg",
                "forensic_topic": "old-fail",
                "smtp_tls_topic": "tls",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.kafka_failure_topic, "old-fail")

    def test_kafka_missing_hosts_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with(
            "kafka",
            {
                "aggregate_topic": "a",
                "failure_topic": "f",
                "smtp_tls_topic": "t",
            },
        )
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_kafka_missing_aggregate_topic_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with(
            "kafka",
            {"hosts": "k:9092", "failure_topic": "f", "smtp_tls_topic": "t"},
        )
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_kafka_missing_failure_topic_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with(
            "kafka",
            {"hosts": "k:9092", "aggregate_topic": "a", "smtp_tls_topic": "t"},
        )
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_kafka_missing_smtp_tls_topic_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with(
            "kafka",
            {"hosts": "k:9092", "aggregate_topic": "a", "failure_topic": "f"},
        )
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())


class TestParseConfigSmtp(unittest.TestCase):
    def test_smtp_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "smtp",
            {
                "host": "smtp.example.com",
                "port": "587",
                "ssl": "true",
                "skip_certificate_verification": "true",
                "user": "u",
                "password": "p",
                "from": "dmarc@example.com",
                "to": "admin@example.com, alert@example.com",
                "subject": "DMARC Report",
                "attachment": "/tmp/dmarc.zip",
                "message": "See attached",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.smtp_host, "smtp.example.com")
        self.assertEqual(opts.smtp_port, 587)
        self.assertTrue(opts.smtp_ssl)
        self.assertTrue(opts.smtp_skip_certificate_verification)
        self.assertEqual(opts.smtp_user, "u")
        self.assertEqual(opts.smtp_password, "p")
        self.assertEqual(opts.smtp_from, "dmarc@example.com")
        self.assertEqual(opts.smtp_to, ["admin@example.com", "alert@example.com"])
        self.assertEqual(opts.smtp_subject, "DMARC Report")
        self.assertEqual(opts.smtp_attachment, "/tmp/dmarc.zip")
        self.assertEqual(opts.smtp_message, "See attached")

    def test_smtp_missing_host_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("smtp", {"user": "u", "password": "p"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_smtp_missing_user_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("smtp", {"host": "smtp.example.com", "password": "p"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_smtp_missing_password_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("smtp", {"host": "smtp.example.com", "user": "u"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())


class TestParseConfigS3(unittest.TestCase):
    def test_s3_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "s3",
            {
                "bucket": "my-bucket",
                "path": "/dmarc/",
                "region_name": "us-east-1",
                "endpoint_url": "https://s3.example.com",
                "access_key_id": "AKIA-x",
                "secret_access_key": "secret",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.s3_bucket, "my-bucket")
        # Leading and trailing slashes are stripped.
        self.assertEqual(opts.s3_path, "dmarc")
        self.assertEqual(opts.s3_region_name, "us-east-1")
        self.assertEqual(opts.s3_endpoint_url, "https://s3.example.com")
        self.assertEqual(opts.s3_access_key_id, "AKIA-x")
        self.assertEqual(opts.s3_secret_access_key, "secret")

    def test_s3_default_path_is_empty(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with("s3", {"bucket": "b"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.s3_path, "")

    def test_s3_missing_bucket_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("s3", {"path": "x"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())


class TestParseConfigPostgreSQL(unittest.TestCase):
    def test_postgresql_individual_params(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "postgresql",
            {
                "host": "db.example.com",
                "port": "6543",
                "user": "pmarc",
                "password": "secret",
                "database": "dmarc",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.postgresql_host, "db.example.com")
        self.assertEqual(opts.postgresql_port, 6543)
        self.assertEqual(opts.postgresql_user, "pmarc")
        self.assertEqual(opts.postgresql_password, "secret")
        self.assertEqual(opts.postgresql_database, "dmarc")

    def test_postgresql_connection_string_takes_precedence(self):
        """connection_string is read and host parsing is skipped."""
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "postgresql",
            {
                "connection_string": "postgresql://u:p@h/db",
                "host": "ignored.example.com",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.postgresql_connection_string, "postgresql://u:p@h/db")
        # The host branch is skipped entirely when a connection_string is set.
        self.assertFalse(hasattr(opts, "postgresql_host"))

    def test_postgresql_missing_host_and_dsn_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("postgresql", {"port": "5432"})
        with self.assertRaises(ConfigurationError) as ctx:
            _parse_config(cp, _opts())
        self.assertIn("postgresql", str(ctx.exception))


class TestPostgreSQLCliWiring(unittest.TestCase):
    """End-to-end: a [postgresql] config reaches PostgreSQLClient + create_tables.

    Regression guard so the config parse, the Namespace defaults, and the
    _init_output_clients wiring can't drift apart.
    """

    def test_postgresql_config_constructs_client_and_creates_tables(self):
        config = """[general]
save_aggregate = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[postgresql]
host = db.example.com
port = 6543
user = pmarc
password = secret
database = dmarc
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with (
            patch("parsedmarc.cli.postgres.PostgreSQLClient") as mock_client_cls,
            patch(
                "parsedmarc.cli.get_dmarc_reports_from_mailbox",
                return_value={
                    "aggregate_reports": [],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
            ),
            patch("parsedmarc.cli.IMAPConnection", return_value=object()),
            patch.object(sys, "argv", ["parsedmarc", "-c", config_path]),
        ):
            parsedmarc.cli._main()

        mock_client_cls.assert_called_once()
        kwargs = mock_client_cls.call_args.kwargs
        self.assertEqual(kwargs.get("host"), "db.example.com")
        self.assertEqual(kwargs.get("port"), 6543)
        self.assertEqual(kwargs.get("user"), "pmarc")
        self.assertEqual(kwargs.get("database"), "dmarc")
        mock_client_cls.return_value.create_tables.assert_called_once()

    def test_postgresql_aggregate_report_is_saved(self):
        """An aggregate report reaches the client's save method via the loop."""
        config = """[general]
save_aggregate = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[postgresql]
host = db.example.com
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        report = {"policy_published": {"domain": "example.com"}, "records": []}
        with (
            patch("parsedmarc.cli.postgres.PostgreSQLClient") as mock_client_cls,
            patch(
                "parsedmarc.cli.get_dmarc_reports_from_mailbox",
                return_value={
                    "aggregate_reports": [report],
                    "failure_reports": [],
                    "smtp_tls_reports": [],
                },
            ),
            patch("parsedmarc.cli.IMAPConnection", return_value=object()),
            patch.object(sys, "argv", ["parsedmarc", "-c", config_path]),
        ):
            parsedmarc.cli._main()

        pg_client = mock_client_cls.return_value
        pg_client.save_aggregate_report_to_postgresql.assert_called_once_with(report)

    def _run_main(self, reports, save_side_effect=None):
        """Run _main with all save flags on and PostgreSQLClient mocked.

        Returns the mocked client instance for assertions. *save_side_effect*,
        if given, is applied to every save_* method so error-handling branches
        can be exercised.
        """
        config = """[general]
save_aggregate = true
save_failure = true
save_smtp_tls = true
silent = true

[imap]
host = imap.example.com
user = test-user
password = test-password

[postgresql]
host = db.example.com
"""
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ini", delete=False
        ) as config_file:
            config_file.write(config)
            config_path = config_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with (
            patch("parsedmarc.cli.postgres.PostgreSQLClient") as mock_client_cls,
            patch(
                "parsedmarc.cli.get_dmarc_reports_from_mailbox",
                return_value=reports,
            ),
            patch("parsedmarc.cli.IMAPConnection", return_value=object()),
            patch.object(sys, "argv", ["parsedmarc", "-c", config_path]),
        ):
            client = mock_client_cls.return_value
            if save_side_effect is not None:
                for m in (
                    "save_aggregate_report_to_postgresql",
                    "save_failure_report_to_postgresql",
                    "save_smtp_tls_report_to_postgresql",
                ):
                    getattr(client, m).side_effect = save_side_effect
            parsedmarc.cli._main()
        return client

    def test_postgresql_all_report_types_saved(self):
        """Failure and SMTP-TLS reports also reach their save methods."""
        agg = {"policy_published": {"domain": "example.com"}, "records": []}
        fail = {"reported_domain": "example.com", "parsed_sample": {}}
        tls = {"organization_name": "Org", "policies": [{"policy_domain": "d"}]}
        client = self._run_main(
            {
                "aggregate_reports": [agg],
                "failure_reports": [fail],
                "smtp_tls_reports": [tls],
            }
        )
        client.save_aggregate_report_to_postgresql.assert_called_once_with(agg)
        client.save_failure_report_to_postgresql.assert_called_once_with(fail)
        client.save_smtp_tls_report_to_postgresql.assert_called_once_with(tls)

    def test_postgresql_already_saved_is_warned_not_fatal(self):
        """AlreadySaved from any save is swallowed (logged), not propagated."""
        from parsedmarc import postgres

        agg = {"policy_published": {"domain": "example.com"}, "records": []}
        fail = {"reported_domain": "example.com", "parsed_sample": {}}
        tls = {"organization_name": "Org", "policies": []}
        # Should not raise despite every save raising AlreadySaved.
        self._run_main(
            {
                "aggregate_reports": [agg],
                "failure_reports": [fail],
                "smtp_tls_reports": [tls],
            },
            save_side_effect=postgres.AlreadySaved("dup"),
        )

    def test_postgresql_error_is_logged_not_fatal(self):
        """PostgreSQLError from any save is logged, not propagated."""
        from parsedmarc import postgres

        agg = {"policy_published": {"domain": "example.com"}, "records": []}
        fail = {"reported_domain": "example.com", "parsed_sample": {}}
        tls = {"organization_name": "Org", "policies": []}
        self._run_main(
            {
                "aggregate_reports": [agg],
                "failure_reports": [fail],
                "smtp_tls_reports": [tls],
            },
            save_side_effect=postgres.PostgreSQLError("boom"),
        )


class TestParseConfigSyslog(unittest.TestCase):
    def test_syslog_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "syslog",
            {
                "server": "syslog.example.com",
                "port": "6514",
                "protocol": "tls",
                "cafile_path": "/etc/ca.pem",
                "certfile_path": "/etc/c.pem",
                "keyfile_path": "/etc/k.pem",
                "timeout": "10.0",
                "retry_attempts": "5",
                "retry_delay": "2",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.syslog_server, "syslog.example.com")
        self.assertEqual(opts.syslog_port, "6514")
        self.assertEqual(opts.syslog_protocol, "tls")
        self.assertEqual(opts.syslog_cafile_path, "/etc/ca.pem")
        self.assertEqual(opts.syslog_certfile_path, "/etc/c.pem")
        self.assertEqual(opts.syslog_keyfile_path, "/etc/k.pem")
        self.assertEqual(opts.syslog_timeout, 10.0)
        self.assertEqual(opts.syslog_retry_attempts, 5)
        self.assertEqual(opts.syslog_retry_delay, 2)

    def test_syslog_defaults(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with("syslog", {"server": "s"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.syslog_port, 514)
        self.assertEqual(opts.syslog_protocol, "udp")
        self.assertEqual(opts.syslog_timeout, 5.0)
        self.assertEqual(opts.syslog_retry_attempts, 3)
        self.assertEqual(opts.syslog_retry_delay, 5)

    def test_syslog_missing_server_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("syslog", {"port": "514"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())


class TestParseConfigGmailApi(unittest.TestCase):
    def test_gmail_api_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "gmail_api",
            {
                "credentials_file": "/etc/gmail-creds.json",
                "token_file": "/var/lib/parsedmarc/gmail.token",
                "include_spam_trash": "true",
                "paginate_messages": "false",
                "scopes": "https://www.googleapis.com/auth/gmail.readonly",
                "oauth2_port": "8888",
                "auth_mode": "device_code",
                "service_account_user": "user@example.com",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.gmail_api_credentials_file, "/etc/gmail-creds.json")
        self.assertEqual(opts.gmail_api_token_file, "/var/lib/parsedmarc/gmail.token")
        self.assertTrue(opts.gmail_api_include_spam_trash)
        self.assertFalse(opts.gmail_api_paginate_messages)
        self.assertEqual(
            opts.gmail_api_scopes,
            ["https://www.googleapis.com/auth/gmail.readonly"],
        )
        self.assertEqual(opts.gmail_api_oauth2_port, 8888)
        self.assertEqual(opts.gmail_api_auth_mode, "device_code")
        self.assertEqual(opts.gmail_api_service_account_user, "user@example.com")

    def test_gmail_api_delegated_user_alias(self):
        """`delegated_user` is the legacy spelling of `service_account_user`."""
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "gmail_api",
            {
                "credentials_file": "/c",
                "delegated_user": "legacy@example.com",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.gmail_api_service_account_user, "legacy@example.com")

    def test_gmail_api_default_scope(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with("gmail_api", {"credentials_file": "/c"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(
            opts.gmail_api_scopes,
            ["https://www.googleapis.com/auth/gmail.modify"],
        )


class TestParseConfigLogAnalytics(unittest.TestCase):
    def test_log_analytics_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "log_analytics",
            {
                "client_id": "cid",
                "client_secret": "csec",
                "tenant_id": "tid",
                "dce": "https://dce.example.com",
                "dcr_immutable_id": "dcr-1",
                "dcr_aggregate_stream": "Custom-Aggregate_CL",
                "dcr_failure_stream": "Custom-Failure_CL",
                "dcr_smtp_tls_stream": "Custom-SMTPTLS_CL",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.la_client_id, "cid")
        self.assertEqual(opts.la_client_secret, "csec")
        self.assertEqual(opts.la_tenant_id, "tid")
        self.assertEqual(opts.la_dce, "https://dce.example.com")
        self.assertEqual(opts.la_dcr_immutable_id, "dcr-1")
        self.assertEqual(opts.la_dcr_aggregate_stream, "Custom-Aggregate_CL")
        self.assertEqual(opts.la_dcr_failure_stream, "Custom-Failure_CL")
        self.assertEqual(opts.la_dcr_smtp_tls_stream, "Custom-SMTPTLS_CL")

    def test_log_analytics_forensic_stream_alias(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "log_analytics",
            {
                "client_id": "c",
                "dcr_forensic_stream": "Old-Forensic_CL",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.la_dcr_failure_stream, "Old-Forensic_CL")


class TestParseConfigGelf(unittest.TestCase):
    def test_gelf_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "gelf", {"host": "graylog.example.com", "port": "12201", "mode": "tls"}
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.gelf_host, "graylog.example.com")
        self.assertEqual(opts.gelf_port, "12201")
        self.assertEqual(opts.gelf_mode, "tls")

    def test_gelf_missing_host_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("gelf", {"port": "12201", "mode": "udp"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_gelf_missing_port_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("gelf", {"host": "g", "mode": "udp"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())

    def test_gelf_missing_mode_raises(self):
        from parsedmarc.cli import ConfigurationError, _parse_config

        cp = _config_with("gelf", {"host": "g", "port": "12201"})
        with self.assertRaises(ConfigurationError):
            _parse_config(cp, _opts())


class TestParseConfigWebhook(unittest.TestCase):
    def test_webhook_complete(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with(
            "webhook",
            {
                "aggregate_url": "https://hooks.example.com/agg",
                "failure_url": "https://hooks.example.com/fail",
                "smtp_tls_url": "https://hooks.example.com/tls",
                "timeout": "30",
            },
        )
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.webhook_aggregate_url, "https://hooks.example.com/agg")
        self.assertEqual(opts.webhook_failure_url, "https://hooks.example.com/fail")
        self.assertEqual(opts.webhook_smtp_tls_url, "https://hooks.example.com/tls")
        self.assertEqual(opts.webhook_timeout, 30)

    def test_webhook_forensic_url_alias_sets_failure_url(self):
        from parsedmarc.cli import _parse_config

        cp = _config_with("webhook", {"forensic_url": "https://old.example.com/fail"})
        opts = _opts()
        _parse_config(cp, opts)
        self.assertEqual(opts.webhook_failure_url, "https://old.example.com/fail")


class TestConfigureLogging(unittest.TestCase):
    """_configure_logging is called in every child process for parallel
    parsing — if it stops attaching a handler, log output goes dark in
    multiprocessing mode."""

    def setUp(self):
        from parsedmarc.log import logger as plog

        self._saved_handlers = list(plog.handlers)
        self._saved_level = plog.level

    def tearDown(self):
        from parsedmarc.log import logger as plog

        plog.handlers[:] = self._saved_handlers
        plog.setLevel(self._saved_level)

    def test_sets_log_level(self):
        import logging as _logging
        from parsedmarc.cli import _configure_logging
        from parsedmarc.log import logger as plog

        _configure_logging(_logging.DEBUG)
        self.assertEqual(plog.level, _logging.DEBUG)

    def test_adds_stream_handler_when_none_present(self):
        import logging as _logging
        from parsedmarc.cli import _configure_logging
        from parsedmarc.log import logger as plog

        # Clear any existing StreamHandler so we know addHandler runs.
        plog.handlers[:] = [
            h for h in plog.handlers if type(h) is not _logging.StreamHandler
        ]
        _configure_logging(_logging.INFO)
        self.assertTrue(any(type(h) is _logging.StreamHandler for h in plog.handlers))

    def test_does_not_duplicate_stream_handler(self):
        import logging as _logging
        from parsedmarc.cli import _configure_logging
        from parsedmarc.log import logger as plog

        # Start with a single StreamHandler attached.
        plog.handlers[:] = [_logging.StreamHandler()]
        before = len(plog.handlers)
        _configure_logging(_logging.INFO)
        after = len(plog.handlers)
        self.assertEqual(before, after)

    def test_adds_file_handler_when_log_file_given(self):
        import logging as _logging
        import tempfile
        from parsedmarc.cli import _configure_logging
        from parsedmarc.log import logger as plog

        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
            path = tf.name
        try:
            _configure_logging(_logging.INFO, log_file=path)
            self.assertTrue(
                any(isinstance(h, _logging.FileHandler) for h in plog.handlers)
            )
        finally:
            for h in list(plog.handlers):
                if isinstance(h, _logging.FileHandler):
                    plog.removeHandler(h)
                    h.close()
            os.remove(path)

    def test_unwritable_log_file_logs_warning_does_not_raise(self):
        """If the log file can't be opened, we warn and continue. A
        regression that raised would crash the whole parse pipeline."""
        import logging as _logging
        from parsedmarc.cli import _configure_logging

        with self.assertLogs("parsedmarc.log", level="WARNING") as cm:
            _configure_logging(_logging.INFO, log_file="/proc/nonexistent/x.log")
        self.assertTrue(any("Unable to write to log file" in m for m in cm.output))


class TestCliParse(unittest.TestCase):
    """cli_parse is the multiprocessing worker — it shells out to
    parse_report_file, then sends the result (or error) back over a
    pipe. Both branches matter: a regression would silently drop
    results in parallel mode."""

    def test_cli_parse_sends_results_on_success(self):
        from multiprocessing import Pipe
        from unittest.mock import patch
        from parsedmarc.cli import cli_parse

        parent_conn, child_conn = Pipe()
        with patch("parsedmarc.cli.parse_report_file") as mock_parse:
            mock_parse.return_value = {"report_type": "aggregate", "report": {}}
            cli_parse(
                "/path/to/report.xml",
                False,
                None,
                2.0,
                0,
                None,
                True,
                True,
                None,
                None,
                24.0,
                child_conn,
            )
        sent = parent_conn.recv()
        self.assertEqual(sent[0], {"report_type": "aggregate", "report": {}})
        self.assertEqual(sent[1], "/path/to/report.xml")

    def test_cli_parse_sends_error_on_parser_error(self):
        from multiprocessing import Pipe
        from unittest.mock import patch
        from parsedmarc.cli import cli_parse
        from parsedmarc import ParserError

        parent_conn, child_conn = Pipe()
        with patch("parsedmarc.cli.parse_report_file") as mock_parse:
            err = ParserError("bad report")
            mock_parse.side_effect = err
            cli_parse(
                "/bad.xml",
                False,
                None,
                2.0,
                0,
                None,
                True,
                True,
                None,
                None,
                24.0,
                child_conn,
            )
        sent = parent_conn.recv()
        self.assertIsInstance(sent[0], ParserError)
        self.assertEqual(sent[1], "/bad.xml")


if __name__ == "__main__":
    unittest.main(verbosity=2)
