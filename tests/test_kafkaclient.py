"""Tests for parsedmarc.kafkaclient"""

import json
import unittest
from unittest.mock import MagicMock, patch

from kafka.errors import NoBrokersAvailable, UnknownTopicOrPartitionError

from parsedmarc.kafkaclient import KafkaClient, KafkaError


def _aggregate_report():
    return {
        "report_metadata": {
            "org_name": "TestOrg",
            "org_email": "test@example.com",
            "report_id": "r-123",
            "begin_date": "2024-01-01 00:00:00",
            "end_date": "2024-01-02 00:00:00",
        },
        "policy_published": {"domain": "example.com", "p": "none"},
        "records": [
            {"source": {"ip_address": "192.0.2.1"}, "count": 1},
            {"source": {"ip_address": "192.0.2.2"}, "count": 2},
        ],
    }


class TestKafkaClientInit(unittest.TestCase):
    """KafkaProducer config wiring: SSL, SASL, plain — each branch has
    user-facing security consequences if it's wrong."""

    def test_init_plain_no_ssl(self):
        """No SSL, no auth: just bootstrap_servers and serializer."""
        with patch("parsedmarc.kafkaclient.KafkaProducer") as mock_producer:
            KafkaClient(kafka_hosts=["broker:9092"])
        kwargs = mock_producer.call_args.kwargs
        self.assertEqual(kwargs["bootstrap_servers"], ["broker:9092"])
        self.assertNotIn("security_protocol", kwargs)
        self.assertNotIn("sasl_plain_username", kwargs)

    def test_init_ssl_enables_ssl_security_protocol(self):
        with (
            patch("parsedmarc.kafkaclient.KafkaProducer") as mock_producer,
            patch("parsedmarc.kafkaclient.create_default_context") as mock_ctx,
        ):
            KafkaClient(kafka_hosts=["broker:9093"], ssl=True)
        kwargs = mock_producer.call_args.kwargs
        self.assertEqual(kwargs["security_protocol"], "SSL")
        self.assertIs(kwargs["ssl_context"], mock_ctx.return_value)

    def test_init_username_implies_ssl(self):
        """Doc says ssl=True is implied when username/password supplied."""
        with (
            patch("parsedmarc.kafkaclient.KafkaProducer") as mock_producer,
            patch("parsedmarc.kafkaclient.create_default_context"),
        ):
            KafkaClient(kafka_hosts=["broker:9093"], username="user", password="pass")
        kwargs = mock_producer.call_args.kwargs
        self.assertEqual(kwargs["security_protocol"], "SSL")
        self.assertEqual(kwargs["sasl_plain_username"], "user")
        self.assertEqual(kwargs["sasl_plain_password"], "pass")

    def test_init_uses_provided_ssl_context(self):
        """A caller-supplied SSLContext takes precedence over the
        default context — this lets ops pin to a private CA."""
        custom_ctx = MagicMock()
        with (
            patch("parsedmarc.kafkaclient.KafkaProducer") as mock_producer,
            patch("parsedmarc.kafkaclient.create_default_context") as mock_default,
        ):
            KafkaClient(kafka_hosts=["b:9093"], ssl=True, ssl_context=custom_ctx)
        self.assertIs(mock_producer.call_args.kwargs["ssl_context"], custom_ctx)
        mock_default.assert_not_called()

    def test_init_value_serializer_emits_utf8_json(self):
        """The value_serializer turns Python objects into UTF-8 JSON
        bytes. A regression here would corrupt every event sent."""
        with patch("parsedmarc.kafkaclient.KafkaProducer") as mock_producer:
            KafkaClient(kafka_hosts=["b"])
        serializer = mock_producer.call_args.kwargs["value_serializer"]
        result = serializer({"hello": "world", "n": 1})
        self.assertEqual(json.loads(result.decode("utf-8")), {"hello": "world", "n": 1})

    def test_init_no_brokers_available_raises_kafka_error(self):
        with patch(
            "parsedmarc.kafkaclient.KafkaProducer",
            side_effect=NoBrokersAvailable(),
        ):
            with self.assertRaises(KafkaError) as ctx:
                KafkaClient(kafka_hosts=["unreachable:9092"])
        self.assertIn("No Kafka brokers", str(ctx.exception))


class TestKafkaClientHelpers(unittest.TestCase):
    """Static helpers used by save_aggregate."""

    def test_strip_metadata_lifts_keys_to_root_and_drops_metadata(self):
        report = _aggregate_report()
        result = KafkaClient.strip_metadata(report)
        self.assertEqual(result["org_name"], "TestOrg")
        self.assertEqual(result["org_email"], "test@example.com")
        self.assertEqual(result["report_id"], "r-123")
        self.assertNotIn("report_metadata", result)

    def test_generate_date_range_iso_format(self):
        report = _aggregate_report()
        date_range = KafkaClient.generate_date_range(report)
        self.assertEqual(date_range, ["2024-01-01T00:00:00", "2024-01-02T00:00:00"])


class TestSaveAggregateReportsToKafka(unittest.TestCase):
    """save_aggregate sends one Kafka message per record (slice), with
    the metadata + policy duplicated onto each slice for Kibana parity."""

    def _client(self):
        with patch("parsedmarc.kafkaclient.KafkaProducer"):
            return KafkaClient(kafka_hosts=["b:9092"])

    def test_sends_one_message_per_record(self):
        client = self._client()
        client.save_aggregate_reports_to_kafka(_aggregate_report(), "dmarc-aggregate")
        # 2 records in the sample report → 2 producer.send calls.
        self.assertEqual(client.producer.send.call_count, 2)
        # Topic is forwarded verbatim.
        for call in client.producer.send.call_args_list:
            self.assertEqual(call.args[0], "dmarc-aggregate")

    def test_each_slice_carries_metadata(self):
        client = self._client()
        client.save_aggregate_reports_to_kafka(_aggregate_report(), "topic")
        sent = [call.args[1] for call in client.producer.send.call_args_list]
        for slice_ in sent:
            self.assertEqual(slice_["org_name"], "TestOrg")
            self.assertEqual(slice_["org_email"], "test@example.com")
            self.assertEqual(slice_["report_id"], "r-123")
            self.assertEqual(
                slice_["date_range"], ["2024-01-01T00:00:00", "2024-01-02T00:00:00"]
            )
            self.assertEqual(
                slice_["policy_published"], {"domain": "example.com", "p": "none"}
            )

    def test_empty_list_is_a_noop(self):
        client = self._client()
        client.save_aggregate_reports_to_kafka([], "topic")
        client.producer.send.assert_not_called()

    def test_dict_input_normalized_to_list(self):
        """Single-report dict input is wrapped to a list."""
        client = self._client()
        client.save_aggregate_reports_to_kafka(_aggregate_report(), "topic")
        # 2 records still sent (one report with 2 records, not multiple reports).
        self.assertEqual(client.producer.send.call_count, 2)

    def test_unknown_topic_translates_to_kafka_error(self):
        client = self._client()
        client.producer.send.side_effect = UnknownTopicOrPartitionError()
        with self.assertRaises(KafkaError) as ctx:
            client.save_aggregate_reports_to_kafka(_aggregate_report(), "missing")
        self.assertIn("Unknown topic or partition", str(ctx.exception))

    def test_generic_send_exception_translates_to_kafka_error(self):
        client = self._client()
        client.producer.send.side_effect = RuntimeError("transport failure")
        with self.assertRaises(KafkaError) as ctx:
            client.save_aggregate_reports_to_kafka(_aggregate_report(), "topic")
        self.assertIn("transport failure", str(ctx.exception))

    def test_flush_exception_translates_to_kafka_error(self):
        client = self._client()
        client.producer.flush.side_effect = RuntimeError("flush failure")
        with self.assertRaises(KafkaError) as ctx:
            client.save_aggregate_reports_to_kafka(_aggregate_report(), "topic")
        self.assertIn("flush failure", str(ctx.exception))


class TestSaveFailureReportsToKafka(unittest.TestCase):
    def _client(self):
        with patch("parsedmarc.kafkaclient.KafkaProducer"):
            return KafkaClient(kafka_hosts=["b:9092"])

    def test_sends_full_list_in_one_message(self):
        """Failure reports go in a single Kafka message — the comment
        in source code documents the 1MB-per-message default."""
        client = self._client()
        reports = [{"id": "f1"}, {"id": "f2"}]
        client.save_failure_reports_to_kafka(reports, "dmarc-failure")
        client.producer.send.assert_called_once_with("dmarc-failure", reports)

    def test_dict_input_normalized_to_list(self):
        client = self._client()
        client.save_failure_reports_to_kafka({"id": "single"}, "topic")
        # The send payload is wrapped to a single-element list.
        args = client.producer.send.call_args.args
        self.assertEqual(args[1], [{"id": "single"}])

    def test_empty_list_is_a_noop(self):
        client = self._client()
        client.save_failure_reports_to_kafka([], "topic")
        client.producer.send.assert_not_called()

    def test_unknown_topic_translates_to_kafka_error(self):
        client = self._client()
        client.producer.send.side_effect = UnknownTopicOrPartitionError()
        with self.assertRaises(KafkaError):
            client.save_failure_reports_to_kafka([{"a": 1}], "missing")

    def test_generic_send_error_translates_to_kafka_error(self):
        client = self._client()
        client.producer.send.side_effect = OSError("net")
        with self.assertRaises(KafkaError):
            client.save_failure_reports_to_kafka([{"a": 1}], "topic")

    def test_flush_error_translates_to_kafka_error(self):
        client = self._client()
        client.producer.flush.side_effect = OSError("flush")
        with self.assertRaises(KafkaError):
            client.save_failure_reports_to_kafka([{"a": 1}], "topic")


class TestSaveSmtpTlsReportsToKafka(unittest.TestCase):
    def _client(self):
        with patch("parsedmarc.kafkaclient.KafkaProducer"):
            return KafkaClient(kafka_hosts=["b:9092"])

    def test_sends_full_list_in_one_message(self):
        client = self._client()
        reports = [{"organization_name": "x"}]
        client.save_smtp_tls_reports_to_kafka(reports, "smtp-tls")
        client.producer.send.assert_called_once_with("smtp-tls", reports)

    def test_dict_input_normalized_to_list(self):
        client = self._client()
        client.save_smtp_tls_reports_to_kafka({"organization_name": "x"}, "topic")
        args = client.producer.send.call_args.args
        self.assertEqual(args[1], [{"organization_name": "x"}])

    def test_empty_list_is_a_noop(self):
        client = self._client()
        client.save_smtp_tls_reports_to_kafka([], "topic")
        client.producer.send.assert_not_called()

    def test_unknown_topic_translates_to_kafka_error(self):
        client = self._client()
        client.producer.send.side_effect = UnknownTopicOrPartitionError()
        with self.assertRaises(KafkaError):
            client.save_smtp_tls_reports_to_kafka([{"a": 1}], "missing")

    def test_generic_send_error_translates_to_kafka_error(self):
        client = self._client()
        client.producer.send.side_effect = RuntimeError("oops")
        with self.assertRaises(KafkaError):
            client.save_smtp_tls_reports_to_kafka([{"a": 1}], "topic")

    def test_flush_error_translates_to_kafka_error(self):
        client = self._client()
        client.producer.flush.side_effect = RuntimeError("flush")
        with self.assertRaises(KafkaError):
            client.save_smtp_tls_reports_to_kafka([{"a": 1}], "topic")


class TestKafkaClientClose(unittest.TestCase):
    def test_close_calls_underlying_producer_close(self):
        with patch("parsedmarc.kafkaclient.KafkaProducer"):
            client = KafkaClient(kafka_hosts=["b"])
        client.close()
        client.producer.close.assert_called_once()


class TestKafkaBackwardCompatAlias(unittest.TestCase):
    def test_forensic_alias_points_to_failure_method(self):
        self.assertIs(
            KafkaClient.save_forensic_reports_to_kafka,  # type: ignore[attr-defined]
            KafkaClient.save_failure_reports_to_kafka,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
