# -*- coding: utf-8 -*-

"""Google SecOps (Chronicle) output module for parsedmarc"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from parsedmarc.log import logger
from parsedmarc.utils import human_timestamp_to_datetime


class GoogleSecOpsClient:
    """A client for Google SecOps (Chronicle) UDM output"""

    def __init__(
        self,
        include_ruf_payload: bool = False,
        ruf_payload_max_bytes: int = 4096,
        static_observer_name: Optional[str] = None,
        static_observer_vendor: str = "parsedmarc",
        static_environment: Optional[str] = None,
    ):
        """
        Initializes the GoogleSecOpsClient

        Args:
            include_ruf_payload: Include RUF message payload in output
            ruf_payload_max_bytes: Maximum bytes of RUF payload to include
            static_observer_name: Static observer name for telemetry
            static_observer_vendor: Static observer vendor (default: parsedmarc)
            static_environment: Static environment (prod/dev/custom string)
        """
        self.include_ruf_payload = include_ruf_payload
        self.ruf_payload_max_bytes = ruf_payload_max_bytes
        self.static_observer_name = static_observer_name
        self.static_observer_vendor = static_observer_vendor
        self.static_environment = static_environment

    def _get_severity(self, disposition: str, spf_aligned: bool, dkim_aligned: bool) -> str:
        """
        Derive severity from DMARC disposition and alignment

        Args:
            disposition: DMARC policy disposition
            spf_aligned: Whether SPF is aligned
            dkim_aligned: Whether DKIM is aligned

        Returns:
            Severity level: HIGH, MEDIUM, or LOW
        """
        if disposition == "reject":
            return "HIGH"
        elif disposition == "quarantine" and not (spf_aligned or dkim_aligned):
            return "MEDIUM"
        else:
            return "LOW"

    def _get_description(
        self,
        dmarc_pass: bool,
        spf_result: Optional[str],
        dkim_result: Optional[str],
        spf_aligned: bool,
        dkim_aligned: bool,
        disposition: str,
    ) -> str:
        """
        Generate description for the event

        Args:
            dmarc_pass: Whether DMARC passed
            spf_result: SPF result
            dkim_result: DKIM result
            spf_aligned: Whether SPF is aligned
            dkim_aligned: Whether DKIM is aligned
            disposition: DMARC disposition

        Returns:
            Human-readable description
        """
        parts = []
        
        if dmarc_pass:
            parts.append("DMARC pass")
        else:
            parts.append("DMARC fail")
        
        if spf_result:
            parts.append(f"SPF={spf_result}")
        if dkim_result:
            parts.append(f"DKIM={dkim_result}")
        
        if spf_aligned:
            parts.append("SPF aligned")
        elif spf_result:
            parts.append("SPF not aligned")
        
        if dkim_aligned:
            parts.append("DKIM aligned")
        elif dkim_result:
            parts.append("DKIM not aligned")
        
        parts.append(f"disposition={disposition}")
        
        return "; ".join(parts)

    def _format_timestamp(self, timestamp_str: str) -> str:
        """
        Convert parsedmarc timestamp to RFC 3339 format

        Args:
            timestamp_str: Timestamp string from parsedmarc

        Returns:
            RFC 3339 formatted timestamp
        """
        try:
            dt = human_timestamp_to_datetime(timestamp_str)
            # Ensure timezone-aware datetime
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            # Fallback to current time if parsing fails
            return datetime.now(timezone.utc).isoformat()

    def save_aggregate_report_to_google_secops(
        self, aggregate_report: dict[str, Any]
    ) -> list[str]:
        """
        Convert aggregate DMARC report to Google SecOps UDM format (NDJSON)

        Args:
            aggregate_report: Aggregate report dictionary from parsedmarc

        Returns:
            List of NDJSON event strings
        """
        logger.debug("Converting aggregate report to Google SecOps UDM format")
        events = []

        try:
            report_metadata = aggregate_report["report_metadata"]
            policy_published = aggregate_report["policy_published"]

            for record in aggregate_report["records"]:
                # Extract values
                source_ip = record["source"]["ip_address"]
                source_country = record["source"].get("country")
                source_reverse_dns = record["source"].get("reverse_dns")
                source_base_domain = record["source"].get("base_domain")
                source_name = record["source"].get("name")
                
                header_from = record["identifiers"]["header_from"]
                envelope_from = record["identifiers"]["envelope_from"]
                
                disposition = record["policy_evaluated"]["disposition"]
                spf_aligned = record["alignment"]["spf"]
                dkim_aligned = record["alignment"]["dkim"]
                dmarc_pass = record["alignment"]["dmarc"]
                
                count = record["count"]
                interval_begin = record["interval_begin"]
                interval_end = record["interval_end"]
                
                # Get auth results
                spf_results = record["auth_results"].get("spf", [])
                dkim_results = record["auth_results"].get("dkim", [])
                
                spf_result = spf_results[0]["result"] if spf_results else None
                dkim_result = dkim_results[0]["result"] if dkim_results else None
                
                # Build UDM event
                event: dict[str, Any] = {
                    "event_type": "DMARC_AGGREGATE",
                    "metadata": {
                        "event_timestamp": self._format_timestamp(interval_begin),
                        "event_type": "GENERIC_EVENT",
                        "product_name": "parsedmarc",
                        "vendor_name": self.static_observer_vendor,
                    },
                    "principal": {
                        "ip": [source_ip],
                    },
                    "target": {
                        "domain": {
                            "name": header_from,
                        }
                    },
                    "security_result": [
                        {
                            "severity": self._get_severity(
                                disposition, spf_aligned, dkim_aligned
                            ),
                            "description": self._get_description(
                                dmarc_pass,
                                spf_result,
                                dkim_result,
                                spf_aligned,
                                dkim_aligned,
                                disposition,
                            ),
                            "detection_fields": [
                                {"key": "dmarc_disposition", "value": disposition},
                                {"key": "dmarc_policy", "value": policy_published["p"]},
                                {"key": "dmarc_pass", "value": str(dmarc_pass).lower()},
                                {"key": "spf_aligned", "value": str(spf_aligned).lower()},
                                {"key": "dkim_aligned", "value": str(dkim_aligned).lower()},
                            ],
                        }
                    ],
                    "additional": {
                        "fields": [
                            {"key": "report_org", "value": report_metadata["org_name"]},
                            {"key": "report_id", "value": report_metadata["report_id"]},
                            {"key": "report_begin", "value": report_metadata["begin_date"]},
                            {"key": "report_end", "value": report_metadata["end_date"]},
                            {"key": "message_count", "value": str(count)},
                            {"key": "interval_begin", "value": interval_begin},
                            {"key": "interval_end", "value": interval_end},
                            {"key": "envelope_from", "value": envelope_from},
                        ]
                    },
                }
                
                # Add optional fields
                if source_country:
                    event["principal"]["location"] = {"country_or_region": source_country}
                
                if source_reverse_dns:
                    event["principal"]["hostname"] = source_reverse_dns
                
                if source_base_domain:
                    event["additional"]["fields"].append(
                        {"key": "source_base_domain", "value": source_base_domain}
                    )
                
                if source_name:
                    event["additional"]["fields"].append(
                        {"key": "source_name", "value": source_name}
                    )
                
                if self.static_observer_name:
                    event["metadata"]["product_deployment_id"] = self.static_observer_name
                
                if self.static_environment:
                    event["additional"]["fields"].append(
                        {"key": "environment", "value": self.static_environment}
                    )
                
                # Add SPF results
                if spf_results:
                    for idx, spf in enumerate(spf_results):
                        event["additional"]["fields"].append(
                            {"key": f"spf_{idx}_domain", "value": spf.get("domain", "")}
                        )
                        event["additional"]["fields"].append(
                            {"key": f"spf_{idx}_result", "value": spf.get("result", "")}
                        )
                
                # Add DKIM results
                if dkim_results:
                    for idx, dkim in enumerate(dkim_results):
                        event["additional"]["fields"].append(
                            {"key": f"dkim_{idx}_domain", "value": dkim.get("domain", "")}
                        )
                        event["additional"]["fields"].append(
                            {"key": f"dkim_{idx}_result", "value": dkim.get("result", "")}
                        )
                
                events.append(json.dumps(event, ensure_ascii=False))
        
        except Exception as e:
            logger.error(f"Error converting aggregate report to Google SecOps format: {e}")
            # Generate error event
            error_event: dict[str, Any] = {
                "event_type": "DMARC_PARSE_ERROR",
                "metadata": {
                    "event_timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "GENERIC_EVENT",
                    "product_name": "parsedmarc",
                    "vendor_name": self.static_observer_vendor,
                },
                "security_result": [
                    {
                        "severity": "ERROR",
                        "description": f"Failed to parse DMARC aggregate report: {str(e)}",
                    }
                ],
            }
            events.append(json.dumps(error_event, ensure_ascii=False))
        
        return events

    def save_forensic_report_to_google_secops(
        self, forensic_report: dict[str, Any]
    ) -> list[str]:
        """
        Convert forensic DMARC report to Google SecOps UDM format (NDJSON)

        Args:
            forensic_report: Forensic report dictionary from parsedmarc

        Returns:
            List of NDJSON event strings
        """
        logger.debug("Converting forensic report to Google SecOps UDM format")
        events = []

        try:
            source_ip = forensic_report["source"]["ip_address"]
            source_country = forensic_report["source"].get("country")
            source_reverse_dns = forensic_report["source"].get("reverse_dns")
            
            reported_domain = forensic_report["reported_domain"]
            arrival_date = forensic_report["arrival_date_utc"]
            auth_failure = forensic_report.get("auth_failure", [])
            
            # Determine severity - forensic reports indicate failures
            # Default to MEDIUM for authentication failures
            severity = "MEDIUM"
            
            # Build description
            auth_failure_str = ", ".join(auth_failure) if auth_failure else "unknown"
            description = f"DMARC forensic report: authentication failure ({auth_failure_str})"
            
            # Build UDM event
            event: dict[str, Any] = {
                "event_type": "DMARC_FORENSIC",
                "metadata": {
                    "event_timestamp": self._format_timestamp(arrival_date),
                    "event_type": "GENERIC_EVENT",
                    "product_name": "parsedmarc",
                    "vendor_name": self.static_observer_vendor,
                },
                "principal": {
                    "ip": [source_ip],
                },
                "target": {
                    "domain": {
                        "name": reported_domain,
                    }
                },
                "security_result": [
                    {
                        "severity": severity,
                        "description": description,
                        "detection_fields": [
                            {"key": "auth_failure", "value": auth_failure_str},
                        ],
                    }
                ],
                "additional": {
                    "fields": [
                        {"key": "arrival_date", "value": arrival_date},
                        {"key": "feedback_type", "value": forensic_report.get("feedback_type", "")},
                    ]
                },
            }
            
            # Add optional fields
            if source_country:
                event["principal"]["location"] = {"country_or_region": source_country}
            
            if source_reverse_dns:
                event["principal"]["hostname"] = source_reverse_dns
            
            if forensic_report.get("message_id"):
                event["additional"]["fields"].append(
                    {"key": "message_id", "value": forensic_report["message_id"]}
                )
            
            if forensic_report.get("authentication_results"):
                event["additional"]["fields"].append(
                    {"key": "authentication_results", "value": forensic_report["authentication_results"]}
                )
            
            if forensic_report.get("delivery_result"):
                event["additional"]["fields"].append(
                    {"key": "delivery_result", "value": forensic_report["delivery_result"]}
                )
            
            if self.static_observer_name:
                event["metadata"]["product_deployment_id"] = self.static_observer_name
            
            if self.static_environment:
                event["additional"]["fields"].append(
                    {"key": "environment", "value": self.static_environment}
                )
            
            # Add payload excerpt if enabled
            if self.include_ruf_payload and forensic_report.get("sample"):
                sample = forensic_report["sample"]
                if len(sample) > self.ruf_payload_max_bytes:
                    sample = sample[:self.ruf_payload_max_bytes] + "... [truncated]"
                event["additional"]["fields"].append(
                    {"key": "message_sample", "value": sample}
                )
            
            events.append(json.dumps(event, ensure_ascii=False))
        
        except Exception as e:
            logger.error(f"Error converting forensic report to Google SecOps format: {e}")
            # Generate error event
            error_event: dict[str, Any] = {
                "event_type": "DMARC_PARSE_ERROR",
                "metadata": {
                    "event_timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "GENERIC_EVENT",
                    "product_name": "parsedmarc",
                    "vendor_name": self.static_observer_vendor,
                },
                "security_result": [
                    {
                        "severity": "ERROR",
                        "description": f"Failed to parse DMARC forensic report: {str(e)}",
                    }
                ],
            }
            events.append(json.dumps(error_event, ensure_ascii=False))
        
        return events

    def save_smtp_tls_report_to_google_secops(
        self, smtp_tls_report: dict[str, Any]
    ) -> list[str]:
        """
        Convert SMTP TLS report to Google SecOps UDM format (NDJSON)

        Args:
            smtp_tls_report: SMTP TLS report dictionary from parsedmarc

        Returns:
            List of NDJSON event strings
        """
        logger.debug("Converting SMTP TLS report to Google SecOps UDM format")
        events = []

        try:
            organization_name = smtp_tls_report.get("organization_name", "")
            begin_date = smtp_tls_report["begin_date"]
            end_date = smtp_tls_report["end_date"]
            
            for policy in smtp_tls_report.get("policies", []):
                policy_domain = policy["policy_domain"]
                
                for failure in policy.get("failure_details", []):
                    # Build UDM event for each failure
                    event: dict[str, Any] = {
                        "event_type": "SMTP_TLS_REPORT",
                        "metadata": {
                            "event_timestamp": self._format_timestamp(begin_date),
                            "event_type": "GENERIC_EVENT",
                            "product_name": "parsedmarc",
                            "vendor_name": self.static_observer_vendor,
                        },
                        "target": {
                            "domain": {
                                "name": policy_domain,
                            }
                        },
                        "security_result": [
                            {
                                "severity": "LOW",
                                "description": f"SMTP TLS failure: {failure.get('result_type', 'unknown')}",
                            }
                        ],
                        "additional": {
                            "fields": [
                                {"key": "organization_name", "value": organization_name},
                                {"key": "report_begin", "value": begin_date},
                                {"key": "report_end", "value": end_date},
                                {"key": "result_type", "value": failure.get("result_type", "")},
                                {"key": "failed_session_count", "value": str(failure.get("failed_session_count", 0))},
                            ]
                        },
                    }
                    
                    if failure.get("sending_mta_ip"):
                        event["principal"] = {"ip": [failure["sending_mta_ip"]]}
                    
                    if self.static_observer_name:
                        event["metadata"]["product_deployment_id"] = self.static_observer_name
                    
                    if self.static_environment:
                        event["additional"]["fields"].append(
                            {"key": "environment", "value": self.static_environment}
                        )
                    
                    events.append(json.dumps(event, ensure_ascii=False))
        
        except Exception as e:
            logger.error(f"Error converting SMTP TLS report to Google SecOps format: {e}")
            # Generate error event
            error_event: dict[str, Any] = {
                "event_type": "DMARC_PARSE_ERROR",
                "metadata": {
                    "event_timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "GENERIC_EVENT",
                    "product_name": "parsedmarc",
                    "vendor_name": self.static_observer_vendor,
                },
                "security_result": [
                    {
                        "severity": "ERROR",
                        "description": f"Failed to parse SMTP TLS report: {str(e)}",
                    }
                ],
            }
            events.append(json.dumps(error_event, ensure_ascii=False))
        
        return events
