from datetime import datetime, timedelta, timezone

import pytest
from scapy.all import Ether, IP, TCP, UDP

from network_ingestion import normalize_network_events
import network_sensor
from network_sensor import CyberGuardSensorClient, FlowAggregator, SensorConfig, submit_batches


def test_sensor_configuration_requires_credentials_and_secure_remote_origin():
    with pytest.raises(ValueError, match="CYBERGUARD_SENSOR_API_URL"):
        SensorConfig.from_environment({})

    values = {
        "CYBERGUARD_SENSOR_API_URL": "http://cyberguard.example",
        "CYBERGUARD_SENSOR_USERNAME": "network-sensor",
        "CYBERGUARD_SENSOR_PASSWORD": "sensor-secret",
    }
    with pytest.raises(ValueError, match="requires HTTPS"):
        SensorConfig.from_environment(values)


def test_sensor_configuration_accepts_loopback_http_and_rejects_invalid_window():
    values = {
        "CYBERGUARD_SENSOR_API_URL": "http://127.0.0.1:8001",
        "CYBERGUARD_SENSOR_USERNAME": "network-sensor",
        "CYBERGUARD_SENSOR_PASSWORD": "sensor-secret",
    }
    assert SensorConfig.from_environment(values).batch_seconds == 300
    values["CYBERGUARD_SENSOR_BATCH_SECONDS"] = "3601"
    with pytest.raises(ValueError, match="between 1 and 3600"):
        SensorConfig.from_environment(values)


def test_flow_aggregator_groups_ports_and_retains_bounded_beacon_timestamps():
    aggregator = FlowAggregator()
    base = 1_700_000_000
    for index, port in enumerate((22, 23, 24, 25, 26)):
        packet = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=45000, dport=port)
        packet.time = base + index * 60
        aggregator.add_packet(packet)

    flows = aggregator.drain()
    assert len(flows) == 1
    assert flows[0]["source_ports"] == [45000]
    assert flows[0]["destination_ports"] == [22, 23, 24, 25, 26]
    assert flows[0]["packet_count"] == 5
    assert flows[0]["bytes_out"] > 0
    assert flows[0]["timestamps"] == [
        datetime.fromtimestamp(base + index * 60, timezone.utc).isoformat()
        for index in range(5)
    ]
    assert aggregator.drain() == []


def test_network_ingestion_preserves_port_sets_and_timestamps():
    normalized = normalize_network_events({
        "events": [{
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "proto": "tcp",
            "source_ports": [50000],
            "destination_ports": [443, 22, 443, 0, 65536],
            "packet_count": 9,
            "timestamps": ["2026-10-01T10:00:00Z", "2026-10-01T10:01:00Z"],
        }]
    })
    assert normalized["flows"][0]["destination_ports"] == [22, 443]
    assert normalized["flows"][0]["source_ports"] == [50000]
    assert normalized["flows"][0]["timestamps"] == [
        "2026-10-01T10:00:00Z",
        "2026-10-01T10:01:00Z",
    ]
    assert normalized["flows"][0]["packet_count"] == 9


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.body


class FakeSession:
    def __init__(self):
        self.calls = []
        self.responses = [
            FakeResponse(200, {"access_token": "token-one"}),
            FakeResponse(401, {}),
            FakeResponse(200, {"access_token": "token-two"}),
            FakeResponse(200, {"status": "accepted", "detected": False, "incident_id": None}),
        ]

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)

    def close(self):
        pass


def test_sensor_refreshes_expired_session_and_posts_authenticated_batch():
    session = FakeSession()
    client = CyberGuardSensorClient("https://cyberguard.example", "sensor", "password", session)

    result = client.submit([{"src_ip": "10.0.0.5"}])

    assert result["status"] == "accepted"
    assert session.calls[0][0].endswith("/api/v1/auth/login")
    assert session.calls[1][1]["headers"]["Authorization"] == "Bearer token-one"
    assert session.calls[2][0].endswith("/api/v1/auth/login")
    assert session.calls[3][1]["headers"]["Authorization"] == "Bearer token-two"


def test_sensor_splits_batches_at_api_event_limit():
    class Client:
        def __init__(self):
            self.sizes = []

        def submit(self, events):
            self.sizes.append(len(events))
            return {"status": "accepted"}

    client = Client()
    results = submit_batches(client, [{"event": index} for index in range(2_001)])
    assert client.sizes == [1_000, 1_000, 1]
    assert len(results) == 3


def test_sensor_authenticates_before_starting_capture(monkeypatch):
    calls = []

    class Client:
        def __init__(self, *args):
            pass

        def authenticate(self):
            calls.append("authenticated")

        def close(self):
            calls.append("closed")

    def stop_capture(**kwargs):
        calls.append("capturing")
        raise KeyboardInterrupt

    monkeypatch.setattr(network_sensor, "CyberGuardSensorClient", Client)
    monkeypatch.setattr(network_sensor, "sniff", stop_capture)
    config = SensorConfig(
        api_url="http://127.0.0.1:8001",
        username="sensor",
        password="test-only",
        interface=None,
        capture_filter="ip or ip6",
        batch_seconds=300,
    )

    network_sensor.run_sensor(config)

    assert calls == ["authenticated", "capturing", "closed"]
