"""Tests for the Google SecOps output module (parsedmarc/google_secops.py).

Covers conversion of aggregate, failure, and SMTP TLS reports to Google
SecOps (Chronicle) UDM format with proper event types, metadata, and field structure.
"""

import json
import unittest

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


if __name__ == "__main__":
    unittest.main()
