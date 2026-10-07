"""Normalize Zeek and Suricata JSON records for network detection."""

from __future__ import annotations

from math import isfinite
from typing import Any

MAX_INGEST_EVENTS = 1_000
MAX_EVENT_PORTS = 1_024
MAX_EVENT_TIMESTAMPS = 512


def _number(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    return int(number) if isfinite(number) and number > 0 else 0


def normalize_network_events(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    entries = payload.get("events", payload.get("flows", payload.get("records")))
    if entries is None:
        entries = [payload]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Provide a non-empty events, flows, or records array.")
    if len(entries) > MAX_INGEST_EVENTS:
        raise ValueError(f"Network ingestion is limited to {MAX_INGEST_EVENTS} events per request.")

    normalized = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"Network event {index} must be a JSON object.")

        flow = entry.get("flow") if isinstance(entry.get("flow"), dict) else {}
        alert = entry.get("alert") if isinstance(entry.get("alert"), dict) else {}
        source_ip = entry.get("src_ip", entry.get("id.orig_h", ""))
        destination_ip = entry.get("dest_ip", entry.get("dst_ip", entry.get("id.resp_h", "")))
        source_port = entry.get("source_port", entry.get("src_port", entry.get("id.orig_p")))
        destination_port = entry.get("dest_port", entry.get("dst_port", entry.get("id.resp_p")))
        if not any((source_ip, destination_ip, destination_port, entry.get("event_type"), alert.get("signature"))):
            raise ValueError(f"Network event {index} does not contain a supported Zeek or Suricata field.")

        destination_ports = entry.get("destination_ports", entry.get("dst_ports", []))
        if not isinstance(destination_ports, list):
            raise ValueError(f"Network event {index} destination_ports must be an array.")
        if len(destination_ports) > MAX_EVENT_PORTS:
            raise ValueError(f"Network event {index} exceeds the {MAX_EVENT_PORTS}-port limit.")
        valid_ports = sorted({
            port for port in (_number(value) for value in destination_ports)
            if 0 < port <= 65_535
        })
        source_ports = entry.get("source_ports", entry.get("src_ports", []))
        if not isinstance(source_ports, list):
            raise ValueError(f"Network event {index} source_ports must be an array.")
        if len(source_ports) > MAX_EVENT_PORTS:
            raise ValueError(f"Network event {index} exceeds the {MAX_EVENT_PORTS}-source-port limit.")
        valid_source_ports = sorted({
            port for port in (_number(value) for value in source_ports)
            if 0 < port <= 65_535
        })

        timestamps = entry.get("timestamps", [])
        if not isinstance(timestamps, list):
            raise ValueError(f"Network event {index} timestamps must be an array.")
        if len(timestamps) > MAX_EVENT_TIMESTAMPS:
            raise ValueError(f"Network event {index} exceeds the {MAX_EVENT_TIMESTAMPS}-timestamp limit.")

        normalized_event = {
            "src_ip": str(source_ip)[:128],
            "dst_ip": str(destination_ip)[:128],
            "source_port": _number(source_port),
            "src_port": _number(source_port),
            "source_ports": valid_source_ports,
            "destination_port": _number(destination_port),
            "dst_port": _number(destination_port),
            "destination_ports": valid_ports,
            "protocol": str(entry.get("proto", entry.get("proto_name", entry.get("protocol", ""))))[:24],
            "bytes_out": _number(entry.get("orig_bytes", flow.get("bytes_toserver", entry.get("bytes_out", 0)))),
            "bytes_in": _number(entry.get("resp_bytes", flow.get("bytes_toclient", entry.get("bytes_in", 0)))),
            "packet_count": _number(entry.get("packet_count", flow.get("pkts", 0))),
            "packets_out": _number(flow.get("pkts_toserver", entry.get("packets_out", 0))),
            "packets_in": _number(flow.get("pkts_toclient", entry.get("packets_in", 0))),
            "timestamp": str(entry.get("ts", entry.get("timestamp", "")))[:64],
            "event_type": str(entry.get("event_type", entry.get("event", "alert" if alert else "")))[:80],
            "signature": str(alert.get("signature", entry.get("signature", "")))[:256],
            "signature_category": str(alert.get("category", entry.get("signature_category", "")))[:160],
            "signature_severity": str(alert.get("severity", entry.get("signature_severity", "")))[:24],
            "signature_action": str(alert.get("action", entry.get("signature_action", "")))[:32],
            "signature_id": str(alert.get("signature_id", alert.get("sid", entry.get("signature_id", ""))))[:64],
        }
        if any(not isinstance(timestamp, str) for timestamp in timestamps):
            raise ValueError(f"Network event {index} timestamps must contain strings.")
        if timestamps:
            normalized_event["timestamps"] = [timestamp[:64] for timestamp in timestamps]
        normalized.append(normalized_event)

    return {"flows": normalized}
