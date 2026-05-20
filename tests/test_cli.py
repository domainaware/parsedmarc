"""Tests for parsedmarc.cli — CLI entry point, config parsing,
env-var overrides, mailbox watch wiring, and SIGHUP reload."""

import io
import json
import os
import signal
import sys
import tempfile
import unittest
from configparser import ConfigParser
from tempfile import NamedTemporaryFile
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import parsedmarc
import parsedmarc.cli
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

    def fetch_message(self, message_id) -> str:
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
        # The failed reload must not have closed the original clients
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
