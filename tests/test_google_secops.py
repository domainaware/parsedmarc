"""Tests for the Google SecOps output module (parsedmarc/google_secops.py).

Covers conversion of aggregate, failure, and SMTP TLS reports to Google
SecOps (Chronicle) UDM format with proper event types, metadata, and field structure.
"""

import json
import os
import tempfile
import unittest
import warnings
from unittest.mock import MagicMock, patch

import parsedmarc


class TestGoogleSecOps(unittest.TestCase):
    """Tests for Google SecOps (Chronicle) UDM output."""

    def test_aggregate_report_conversion(self):
        """Test Google SecOps aggregate report conversion."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        client = GoogleSecOpsClient(use_stdout=True)
        sample_path = "samples/aggregate/example.net!example.com!1529366400!1529452799.xml"

        parsed_file = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True
        )
        parsed_report = parsed_file["report"]

        events = client.save_aggregate_report_to_google_secops(parsed_report)

        # Verify we got events
        assert len(events) > 0, "Expected at least one event"

        # Verify each event is valid JSON
        for event in events:
            event_dict = json.loads(event)
            assert "event_type" in event_dict
            assert event_dict["event_type"] == "DMARC_AGGREGATE"
            assert "metadata" in event_dict
            assert "principal" in event_dict
            assert "target" in event_dict
            assert "security_result" in event_dict

    def test_failure_report_conversion(self):
        """Test Google SecOps failure report conversion."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        # Test without payload
        client = GoogleSecOpsClient(include_failure_payload=False, use_stdout=True)
        sample_path = "samples/failure/dmarc_ruf_report_linkedin.eml"

        parsed_file = parsedmarc.parse_report_file(sample_path)
        parsed_report = parsed_file["report"]

        events = client.save_failure_report_to_google_secops(parsed_report)

        # Verify we got events
        assert len(events) > 0, "Expected at least one event"

        # Verify each event is valid JSON
        for event in events:
            event_dict = json.loads(event)
            assert "event_type" in event_dict
            assert event_dict["event_type"] == "DMARC_FAILURE"

            # Verify no payload in additional fields
            if "additional" in event_dict and "fields" in event_dict["additional"]:
                for field in event_dict["additional"]["fields"]:
                    assert (
                        field["key"] != "message_sample"
                    ), "Payload should not be included when disabled"

        # Test with payload
        client_with_payload = GoogleSecOpsClient(
            include_failure_payload=True, failure_payload_max_bytes=100, use_stdout=True
        )

        events_with_payload = client_with_payload.save_failure_report_to_google_secops(
            parsed_report
        )

        # Verify we got events
        assert len(events_with_payload) > 0, "Expected at least one event"

        # Verify payload is included
        for event in events_with_payload:
            event_dict = json.loads(event)

            # Check if message_sample is in additional fields
            has_sample = False
            if "additional" in event_dict and "fields" in event_dict["additional"]:
                for field in event_dict["additional"]["fields"]:
                    if field["key"] == "message_sample":
                        has_sample = True
                        # Verify truncation: max_bytes (100) + "... [truncated]" suffix (16 chars)
                        # Allow some margin for the actual payload length
                        max_expected_length = 100 + len("... [truncated]") + 10
                        assert (
                            len(field["value"]) <= max_expected_length
                        ), f"Payload should be truncated, got {len(field['value'])} bytes"
                        break

            assert has_sample, "Payload should be included when enabled"

    def test_configuration(self):
        """Test Google SecOps client configuration."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        # Test stdout configuration
        client1 = GoogleSecOpsClient(use_stdout=True)
        assert client1.include_failure_payload is False
        assert client1.failure_payload_max_bytes == 4096
        assert client1.static_observer_vendor == "parsedmarc"
        assert client1.static_observer_name is None
        assert client1.static_environment is None
        assert client1.use_stdout is True

        # Test custom configuration
        client2 = GoogleSecOpsClient(
            include_failure_payload=True,
            failure_payload_max_bytes=8192,
            static_observer_name="test-observer",
            static_observer_vendor="test-vendor",
            static_environment="prod",
            use_stdout=True,
        )
        assert client2.include_failure_payload is True
        assert client2.failure_payload_max_bytes == 8192
        assert client2.static_observer_name == "test-observer"
        assert client2.static_observer_vendor == "test-vendor"
        assert client2.static_environment == "prod"

    def test_smtp_tls_report_conversion(self):
        """Test Google SecOps SMTP TLS report conversion."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        client = GoogleSecOpsClient(use_stdout=True)
        sample_path = "samples/smtp_tls/rfc8460.json"

        parsed_file = parsedmarc.parse_report_file(sample_path)
        parsed_report = parsed_file["report"]

        events = client.save_smtp_tls_report_to_google_secops(parsed_report)

        # Verify we got events
        assert len(events) > 0, "Expected at least one event"

        # Verify each event is valid JSON
        for event in events:
            event_dict = json.loads(event)
            assert "event_type" in event_dict
            assert event_dict["event_type"] == "SMTP_TLS_REPORT"
            assert "metadata" in event_dict
            assert "target" in event_dict
            assert "security_result" in event_dict

            # Verify failed_session_count is in detection_fields as an integer
            found_count = False
            for field in event_dict["security_result"][0]["detection_fields"]:
                if field["key"] == "smtp_tls.failed_session_count":
                    assert isinstance(
                        field["value"], int
                    ), "failed_session_count should be an integer"
                    found_count = True
                    break
            assert (
                found_count
            ), "failed_session_count should be in detection_fields"

    def test_backward_compatibility_deprecated_parameters(self):
        """Test backward compatibility with deprecated parameter names."""
        from parsedmarc.google_secops import GoogleSecOpsClient
        from unittest.mock import patch

        # Test include_ruf_payload -> include_failure_payload
        with patch("parsedmarc.google_secops.logger.warning") as mock_warning:
            client = GoogleSecOpsClient(include_ruf_payload=True, use_stdout=True)
            assert mock_warning.call_count >= 1
            assert any(
                "include_ruf_payload is deprecated" in str(call)
                for call in mock_warning.call_args_list
            )
            assert client.include_failure_payload is True

        # Test ruf_payload_max_bytes -> failure_payload_max_bytes
        with patch("parsedmarc.google_secops.logger.warning") as mock_warning:
            client = GoogleSecOpsClient(ruf_payload_max_bytes=2048, use_stdout=True)
            assert mock_warning.call_count >= 1
            assert any(
                "ruf_payload_max_bytes is deprecated" in str(call)
                for call in mock_warning.call_args_list
            )
            assert client.failure_payload_max_bytes == 2048

        # Test both deprecated parameters together
        with patch("parsedmarc.google_secops.logger.warning") as mock_warning:
            client = GoogleSecOpsClient(
                include_ruf_payload=True, ruf_payload_max_bytes=2048, use_stdout=True
            )
            assert mock_warning.call_count >= 2
            assert client.include_failure_payload is True
            assert client.failure_payload_max_bytes == 2048

    def test_deprecated_forensic_function_alias(self):
        """Test the deprecated save_forensic_report_to_google_secops alias."""
        from parsedmarc.google_secops import GoogleSecOpsClient
        from unittest.mock import patch

        client = GoogleSecOpsClient(use_stdout=True)
        sample_path = "samples/failure/dmarc_ruf_report_linkedin.eml"

        parsed_file = parsedmarc.parse_report_file(sample_path)
        parsed_report = parsed_file["report"]

        # Test deprecated function with warning
        with patch("parsedmarc.google_secops.logger.warning") as mock_warning:
            events = client.save_forensic_report_to_google_secops(parsed_report)
            assert mock_warning.call_count >= 1
            assert any(
                "save_forensic_report_to_google_secops is deprecated" in str(call)
                for call in mock_warning.call_args_list
            )
            assert len(events) > 0

    def test_api_client_initialization_error(self):
        """Test that API client initialization fails without required parameters."""
        from parsedmarc.google_secops import GoogleSecOpsClient, GoogleSecOpsError

        # Test missing credentials when use_stdout=False
        with self.assertRaises(GoogleSecOpsError) as context:
            GoogleSecOpsClient(use_stdout=False)
        assert "api_credentials_file and api_customer_id are required" in str(
            context.exception
        )

        # Test missing customer_id
        with self.assertRaises(GoogleSecOpsError) as context:
            GoogleSecOpsClient(api_credentials_file="/tmp/fake.json", use_stdout=False)
        assert "api_credentials_file and api_customer_id are required" in str(
            context.exception
        )

    def test_get_api_endpoint(self):
        """Test API endpoint URL generation."""
        from parsedmarc.google_secops import GoogleSecOpsClient
        from urllib.parse import urlparse

        client = GoogleSecOpsClient(use_stdout=True)
        client.api_customer_id = "test-customer-123"
        client.api_region = "us"
        client.api_log_type = "DMARC"

        endpoint = client._get_api_endpoint()
        parsed_url = urlparse(endpoint)
        assert parsed_url.scheme == "https"
        assert parsed_url.netloc == "us-chronicle.googleapis.com"
        assert "test-customer-123" in parsed_url.path
        assert "DMARC" in parsed_url.path

        # Test different region
        client.api_region = "europe"
        endpoint = client._get_api_endpoint()
        parsed_url = urlparse(endpoint)
        assert parsed_url.netloc == "europe-chronicle.googleapis.com"

    def test_helper_methods(self):
        """Test helper methods for severity, description, and timestamp formatting."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        client = GoogleSecOpsClient(use_stdout=True)

        # Test _get_severity
        assert client._get_severity("reject", False, False) == "HIGH"
        assert client._get_severity("quarantine", False, False) == "MEDIUM"
        assert client._get_severity("quarantine", True, False) == "LOW"
        assert client._get_severity("none", False, False) == "LOW"

        # Test _get_description - note the actual signature
        desc = client._get_description(
            dmarc_pass=False,
            spf_result="pass",
            dkim_result="fail",
            spf_aligned=False,
            dkim_aligned=False,
            disposition="none",
        )
        assert "DMARC fail" in desc
        assert "disposition=none" in desc

        desc_pass = client._get_description(
            dmarc_pass=True,
            spf_result="pass",
            dkim_result="pass",
            spf_aligned=True,
            dkim_aligned=True,
            disposition="none",
        )
        assert "DMARC pass" in desc_pass

        # Test _format_timestamp
        timestamp = client._format_timestamp("2024-06-01 12:00:00")
        assert timestamp == "2024-06-01T12:00:00+00:00"

        # Test with timezone already present
        timestamp_tz = client._format_timestamp("2024-06-01T12:00:00+00:00")
        assert timestamp_tz == "2024-06-01T12:00:00+00:00"

    def test_detection_fields_structure(self):
        """Test that detection_fields are properly structured in all event types."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        client = GoogleSecOpsClient(use_stdout=True)

        # Test aggregate report detection fields
        sample_path = "samples/aggregate/example.net!example.com!1529366400!1529452799.xml"
        parsed_file = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True
        )
        events = client.save_aggregate_report_to_google_secops(parsed_file["report"])

        for event in events:
            event_dict = json.loads(event)
            detection_fields = event_dict["security_result"][0]["detection_fields"]

            # Verify key fields are present
            field_keys = [field["key"] for field in detection_fields]
            assert "dmarc.disposition" in field_keys
            assert "dmarc.policy" in field_keys
            assert "dmarc.pass" in field_keys
            assert "dmarc.spf_aligned" in field_keys
            assert "dmarc.dkim_aligned" in field_keys
            assert "dmarc.header_from" in field_keys
            assert "dmarc.report_org" in field_keys
            assert "dmarc.report_id" in field_keys

    def test_ip_enrichment_fields(self):
        """Test that IP enrichment fields are included in detection_fields."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        client = GoogleSecOpsClient(use_stdout=True)

        sample_path = "samples/aggregate/example.net!example.com!1529366400!1529452799.xml"
        parsed_file = parsedmarc.parse_report_file(
            sample_path, always_use_local_files=True
        )
        events = client.save_aggregate_report_to_google_secops(parsed_file["report"])

        for event in events:
            event_dict = json.loads(event)
            detection_fields = event_dict["security_result"][0]["detection_fields"]
            field_keys = [field["key"] for field in detection_fields]

            # Check for IP enrichment fields (if present in the sample data)
            # These are optional but should be in detection_fields when present
            if "dmarc.source_service_name" in field_keys:
                # Verify it's properly structured
                for field in detection_fields:
                    if field["key"] == "dmarc.source_service_name":
                        assert isinstance(field["value"], str)

    @patch("parsedmarc.google_secops.service_account.Credentials")
    @patch("parsedmarc.google_secops.requests.Session")
    def test_api_event_submission(self, mock_session_class, mock_credentials_class):
        """Test event submission to Chronicle API."""
        from parsedmarc.google_secops import GoogleSecOpsClient

        # Create a temporary credentials file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp_file:
            json.dump(
                {
                    "type": "service_account",
                    "project_id": "test-project",
                    "private_key_id": "key123",
                    "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
                    "client_email": "test@test-project.iam.gserviceaccount.com",
                    "client_id": "123456789",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                },
                tmp_file,
            )
            tmp_credentials = tmp_file.name

        try:
            # Mock credentials
            mock_creds = MagicMock()
            mock_creds.valid = True
            mock_creds.token = "test-token"
            mock_credentials_class.from_service_account_file.return_value = mock_creds

            # Mock session and response
            mock_session = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_session.post.return_value = mock_response
            mock_session_class.return_value = mock_session

            # Create client with API mode
            client = GoogleSecOpsClient(
                api_credentials_file=tmp_credentials,
                api_customer_id="test-customer",
                api_region="us",
                use_stdout=False,
            )

            # Send test events
            test_events = ['{"test": "event1"}', '{"test": "event2"}']
            client._send_events_to_api(test_events)

            # Verify API was called
            mock_session.post.assert_called_once()
            call_args = mock_session.post.call_args

            # Verify endpoint
            from urllib.parse import urlparse
            endpoint_url = call_args[0][0]
            parsed_url = urlparse(endpoint_url)
            assert parsed_url.scheme == "https"
            assert parsed_url.netloc == "us-chronicle.googleapis.com"

            # Verify payload structure
            payload = call_args[1]["json"]
            assert "inline_source" in payload
            assert "logs" in payload["inline_source"]
            assert len(payload["inline_source"]["logs"]) == 2

        finally:
            os.unlink(tmp_credentials)

    @patch("parsedmarc.google_secops.service_account.Credentials")
    @patch("parsedmarc.google_secops.requests.Session")
    def test_api_error_handling(self, mock_session_class, mock_credentials_class):
        """Test error handling when Chronicle API returns errors."""
        from parsedmarc.google_secops import GoogleSecOpsClient, GoogleSecOpsError

        # Create a temporary credentials file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp_file:
            json.dump(
                {
                    "type": "service_account",
                    "project_id": "test-project",
                    "private_key_id": "key123",
                    "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
                    "client_email": "test@test-project.iam.gserviceaccount.com",
                    "client_id": "123456789",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                },
                tmp_file,
            )
            tmp_credentials = tmp_file.name

        try:
            # Mock credentials
            mock_creds = MagicMock()
            mock_creds.valid = True
            mock_creds.token = "test-token"
            mock_credentials_class.from_service_account_file.return_value = mock_creds

            # Mock session and error response
            mock_session = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 400
            mock_response.text = "Invalid request"
            mock_session.post.return_value = mock_response
            mock_session_class.return_value = mock_session

            # Create client with API mode
            client = GoogleSecOpsClient(
                api_credentials_file=tmp_credentials,
                api_customer_id="test-customer",
                use_stdout=False,
            )

            # Test error handling
            test_events = ['{"test": "event"}']
            with self.assertRaises(GoogleSecOpsError) as context:
                client._send_events_to_api(test_events)

            assert "Chronicle API error: 400" in str(context.exception)

        finally:
            os.unlink(tmp_credentials)


if __name__ == "__main__":
    unittest.main()
