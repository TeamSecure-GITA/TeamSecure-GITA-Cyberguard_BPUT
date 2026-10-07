from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi import HTTPException

import detection_engine
import main
from network_ingestion import normalize_network_events


def test_zeek_and_suricata_records_normalize_to_flow_telemetry():
    normalized = normalize_network_events({
        "events": [
            {
                "ts": "2026-10-01T10:00:00Z",
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 443,
                "orig_bytes": 1200,
                "resp_bytes": 400,
                "proto": "tcp",
            },
            {
                "timestamp": "2026-10-01T10:01:00Z",
                "src_ip": "10.0.0.6",
                "dest_ip": "1.1.1.1",
                "dest_port": 53,
                "proto": "udp",
                "flow": {"bytes_toserver": 900, "bytes_toclient": 600},
                "alert": {"signature": "DNS policy event"},
            },
        ]
    })

    assert normalized["flows"][0]["destination_port"] == 443
    assert normalized["flows"][0]["bytes_out"] == 1200
    assert normalized["flows"][0]["bytes_in"] == 400
    assert normalized["flows"][1]["destination_port"] == 53
    assert normalized["flows"][1]["bytes_out"] == 900
    assert normalized["flows"][1]["signature"] == "DNS policy event"
    assert normalized["flows"][1]["event_type"] == "alert"


def test_suricata_alert_severity_is_preserved_and_scored_as_bounded_evidence():
    normalized = normalize_network_events({
        "events": [
            {
                "event_type": "alert",
                "src_ip": "10.0.0.5",
                "dest_ip": "8.8.8.8",
                "proto": "tcp",
                "alert": {
                    "signature": "ET MALWARE C2 callback",
                    "signature_id": 2026001,
                    "category": "A Network Trojan was detected",
                    "severity": 1,
                    "action": "allowed",
                },
            },
            {
                "event_type": "alert",
                "alert": {
                    "signature": "ET MALWARE C2 callback",
                    "severity": 2,
                },
            },
        ]
    })

    score, reasons, indicators = detection_engine.analyze_technical_activity(
        json.dumps(normalized),
        "network",
    )

    assert score == 60
    assert len(indicators) == 1
    assert indicators[0]["name"] == "Suricata IDS Alert"
    assert indicators[0]["weight"] == 45
    assert indicators[0]["signature"] == "ET MALWARE C2 callback"
    assert indicators[0]["severity"] == "critical"
    assert indicators[0]["category"] == "A Network Trojan was detected"
    assert indicators[0]["action"] == "allowed"
    assert any("a critical severity IDS alert" in reason for reason in reasons)


def test_network_alert_without_recognized_severity_is_not_scored_as_sensor_evidence():
    score, reasons, indicators = detection_engine.analyze_technical_activity(
        '{"events":[{"event_type":"alert","signature":"unrated alert","signature_severity":"urgent"}]}',
        "network",
    )

    assert score == 15
    assert reasons == []
    assert indicators == []


def test_network_ingestion_creates_incident_for_port_scan_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "network-ingestion.sqlite")
    main.initialize_database()
    payload = {
        "events": [
            {
                "ts": f"2026-10-01T10:00:{port:02d}Z",
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "8.8.8.8",
                "id.resp_p": port,
                "orig_bytes": 80,
                "resp_bytes": 0,
                "proto": "tcp",
            }
            for port in range(20, 32)
        ]
    }

    result = main.ingest_network_telemetry(payload, {"username": "analyst", "role": "analyst"})
    incident = main.incident_context(result["incident_id"])

    assert result["status"] == "incident_created"
    assert result["detected"] is True
    assert incident["category"] == "network"
    assert any(
        indicator["name"] == "Flow Port-Scan Breadth"
        for indicator in incident["assessment"]["indicators"]
    )


def test_network_ingestion_accepts_benign_flow_without_opening_incident(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "benign-network-ingestion.sqlite")
    main.initialize_database()

    result = main.ingest_network_telemetry({
        "events": [{
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "bytes_out": 500,
            "bytes_in": 1200,
            "proto": "tcp",
        }]
    }, {"username": "analyst", "role": "analyst"})

    assert result["status"] == "accepted"
    assert result["detected"] is False
    assert result["incident_id"] is None


def test_network_ingestion_detects_aggregated_scan_ports_and_beacon_timestamps(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "aggregated-network-ingestion.sqlite")
    main.initialize_database()
    payload = {
        "events": [{
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "proto": "tcp",
            "destination_ports": list(range(20, 32)),
            "timestamps": [
                (datetime(2026, 10, 1, 10, tzinfo=timezone.utc) + timedelta(seconds=60 * index)).isoformat()
                for index in range(5)
            ],
        }]
    }

    result = main.ingest_network_telemetry(payload, {"username": "analyst", "role": "analyst"})
    names = {item["name"] for item in result["assessment"]["indicators"]}

    assert result["status"] == "incident_created"
    assert "Flow Port-Scan Breadth" in names
    assert "Regular Flow Beaconing" in names


def test_network_ingestion_rejects_invalid_and_oversized_batches():
    with pytest.raises(HTTPException) as invalid:
        main.ingest_network_telemetry({"events": [{}]}, {"username": "analyst", "role": "analyst"})
    assert invalid.value.status_code == 422

    with pytest.raises(HTTPException) as oversized:
        main.ingest_network_telemetry(
            {"events": [{}] * 1001},
            {"username": "analyst", "role": "analyst"},
        )
    assert oversized.value.status_code == 422
