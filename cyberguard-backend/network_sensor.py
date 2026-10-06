"""Authorized live flow-metadata collection and delivery to CyberGuard."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import os
from typing import Any, Mapping
from urllib.parse import urlparse

import requests
from scapy.all import IP, IPv6, TCP, UDP, sniff

from network_ingestion import MAX_INGEST_EVENTS, MAX_EVENT_PORTS, MAX_EVENT_TIMESTAMPS

MAX_SENSOR_FLOWS = 25_000
MAX_SENSOR_TIMESTAMPS = 20_000
MAX_SENSOR_TIMESTAMPS_PER_FLOW = 64
MAX_SENSOR_SECONDS = 3_600
DEFAULT_BATCH_SECONDS = 300
REQUEST_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class SensorConfig:
    api_url: str
    username: str
    password: str
    interface: str | None
    capture_filter: str
    batch_seconds: int

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "SensorConfig":
        values = os.environ if environment is None else environment
        api_url = values.get("CYBERGUARD_SENSOR_API_URL", "").strip().rstrip("/")
        username = values.get("CYBERGUARD_SENSOR_USERNAME", "").strip()
        password = values.get("CYBERGUARD_SENSOR_PASSWORD", "")
        if not api_url or not username or not password:
            raise ValueError(
                "Set CYBERGUARD_SENSOR_API_URL, CYBERGUARD_SENSOR_USERNAME, "
                "and CYBERGUARD_SENSOR_PASSWORD."
            )

        parsed = urlparse(api_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("CYBERGUARD_SENSOR_API_URL must be an HTTP(S) origin without embedded credentials.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("CYBERGUARD_SENSOR_API_URL must be an origin without a path, query, or fragment.")
        if parsed.scheme != "https" and not _is_loopback_host(parsed.hostname):
            raise ValueError("The network sensor requires HTTPS except when connecting to a loopback API.")

        try:
            batch_seconds = int(values.get("CYBERGUARD_SENSOR_BATCH_SECONDS", str(DEFAULT_BATCH_SECONDS)))
        except ValueError as error:
            raise ValueError("CYBERGUARD_SENSOR_BATCH_SECONDS must be an integer.") from error
        if not 1 <= batch_seconds <= MAX_SENSOR_SECONDS:
            raise ValueError(f"CYBERGUARD_SENSOR_BATCH_SECONDS must be between 1 and {MAX_SENSOR_SECONDS}.")

        capture_filter = values.get("CYBERGUARD_SENSOR_BPF_FILTER", "ip or ip6").strip()
        if not capture_filter:
            raise ValueError("CYBERGUARD_SENSOR_BPF_FILTER cannot be empty.")
        return cls(
            api_url=api_url,
            username=username,
            password=password,
            interface=values.get("CYBERGUARD_SENSOR_INTERFACE", "").strip() or None,
            capture_filter=capture_filter,
            batch_seconds=batch_seconds,
        )


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


class FlowAggregator:
    def __init__(self) -> None:
        self._flows: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
        self._timestamp_count = 0

    def add_packet(self, packet: Any) -> None:
        if packet.haslayer(IP):
            network = packet[IP]
        elif packet.haslayer(IPv6):
            network = packet[IPv6]
        else:
            return

        if packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "tcp"
        elif packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "udp"
        else:
            return

        source_ip = str(network.src)
        destination_ip = str(network.dst)
        destination_port = int(transport.dport)
        key = (source_ip, destination_ip, protocol)
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= MAX_SENSOR_FLOWS:
                raise RuntimeError(f"Sensor batch exceeds the {MAX_SENSOR_FLOWS}-flow memory limit.")
            flow = {
                "src_ip": source_ip,
                "dest_ip": destination_ip,
                "proto": protocol,
                "source_ports": [],
                "destination_ports": [],
                "timestamps": [],
                "bytes_out": 0,
                "bytes_in": 0,
                "packet_count": 0,
            }
            self._flows[key] = flow

        if destination_port not in flow["destination_ports"]:
            if len(flow["destination_ports"]) >= MAX_EVENT_PORTS:
                raise RuntimeError(f"Sensor flow exceeds the {MAX_EVENT_PORTS}-port ingestion limit.")
            flow["destination_ports"].append(destination_port)
        source_port = int(transport.sport)
        if source_port not in flow["source_ports"]:
            if len(flow["source_ports"]) >= MAX_EVENT_PORTS:
                raise RuntimeError(f"Sensor flow exceeds the {MAX_EVENT_PORTS}-source-port ingestion limit.")
            flow["source_ports"].append(source_port)

        timestamp = _packet_timestamp(packet)
        if (
            timestamp
            and len(flow["timestamps"]) < min(MAX_EVENT_TIMESTAMPS, MAX_SENSOR_TIMESTAMPS_PER_FLOW)
            and self._timestamp_count < MAX_SENSOR_TIMESTAMPS
        ):
            flow["timestamps"].append(timestamp)
            self._timestamp_count += 1

        flow["packet_count"] += 1
        packet_size = len(packet)
        source_is_private = ipaddress.ip_address(source_ip).is_private
        destination_is_private = ipaddress.ip_address(destination_ip).is_private
        if source_is_private and not destination_is_private:
            flow["bytes_out"] += packet_size
        elif destination_is_private and not source_is_private:
            flow["bytes_in"] += packet_size

    def drain(self) -> list[dict[str, Any]]:
        flows = list(self._flows.values())
        self._flows.clear()
        self._timestamp_count = 0
        return flows


def _packet_timestamp(packet: Any) -> str | None:
    try:
        return datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
    except (AttributeError, OSError, OverflowError, TypeError, ValueError):
        return None


class CyberGuardSensorClient:
    def __init__(
        self,
        api_url: str,
        username: str,
        password: str,
        session: requests.Session | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.username = username
        self.password = password
        self.session = session or requests.Session()
        self._token: str | None = None

    def authenticate(self) -> None:
        response = self.session.post(
            f"{self.api_url}/api/v1/auth/login",
            json={"username": self.username, "password": self.password},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        try:
            token = response.json().get("access_token")
        except (AttributeError, ValueError) as error:
            raise RuntimeError("CyberGuard login returned an invalid response.") from error
        if not isinstance(token, str) or not token:
            raise RuntimeError("CyberGuard login response did not contain an access token.")
        self._token = token

    def submit(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if not events:
            return {"status": "empty", "detected": False, "incident_id": None}
        if len(events) > MAX_INGEST_EVENTS:
            raise ValueError(f"Sensor requests are limited to {MAX_INGEST_EVENTS} flows.")
        for attempt in range(2):
            if self._token is None:
                self.authenticate()
            response = self.session.post(
                f"{self.api_url}/api/v1/network/ingest",
                json={"events": events},
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code == 401 and attempt == 0:
                self._token = None
                continue
            response.raise_for_status()
            try:
                result = response.json()
            except ValueError as error:
                raise RuntimeError("CyberGuard network ingestion returned invalid JSON.") from error
            if not isinstance(result, dict) or result.get("status") not in {"accepted", "incident_created"}:
                raise RuntimeError("CyberGuard network ingestion returned an unexpected response.")
            return result
        raise RuntimeError("CyberGuard authentication failed after refreshing the session.")

    def close(self) -> None:
        self.session.close()


def submit_batches(client: CyberGuardSensorClient, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for offset in range(0, len(flows), MAX_INGEST_EVENTS):
        results.append(client.submit(flows[offset:offset + MAX_INGEST_EVENTS]))
    return results


def run_sensor(config: SensorConfig) -> None:
    client = CyberGuardSensorClient(config.api_url, config.username, config.password)
    aggregator = FlowAggregator()
    try:
        client.authenticate()
        print(
            f"Capturing flow metadata on {config.interface or 'the default interface'} "
            f"with BPF filter {config.capture_filter!r}; batch window {config.batch_seconds}s."
        )
        while True:
            sniff(
                iface=config.interface,
                filter=config.capture_filter,
                prn=aggregator.add_packet,
                store=False,
                timeout=config.batch_seconds,
            )
            results = submit_batches(client, aggregator.drain())
            for result in results:
                print(
                    f"Telemetry {result['status']}; detected={result.get('detected', False)}; "
                    f"incident_id={result.get('incident_id')}"
                )
    except KeyboardInterrupt:
        print("Stopping capture and submitting the final in-memory batch.")
        for result in submit_batches(client, aggregator.drain()):
            print(
                f"Telemetry {result['status']}; detected={result.get('detected', False)}; "
                f"incident_id={result.get('incident_id')}"
            )
    finally:
        client.close()


def main() -> None:
    try:
        config = SensorConfig.from_environment()
        run_sensor(config)
    except (requests.RequestException, RuntimeError, ValueError) as error:
        raise SystemExit(f"CyberGuard network sensor failed: {error}") from error


if __name__ == "__main__":
    main()
