import asyncio
from io import BytesIO
import json

import pytest
from fastapi import UploadFile
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

import detection_engine
import main
from pcap_inspector import analyze_pcap


def make_port_scan_capture(tmp_path):
    packets = []
    for index, destination_port in enumerate(range(20, 32)):
        packet = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / TCP(
            sport=40000 + index,
            dport=destination_port,
            flags="S",
        ) / Raw(load=b"probe")
        packet.time = 1_700_000_000 + index
        packets.append(packet)

    capture_path = tmp_path / "port-scan.pcap"
    wrpcap(str(capture_path), packets)
    return capture_path.read_bytes()


def make_beacon_capture(tmp_path):
    packets = []
    for index in range(5):
        packet = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=45000, dport=443) / Raw(load=b"beacon")
        packet.time = 1_700_000_000 + index * 60
        packets.append(packet)
    capture_path = tmp_path / "beacon.pcap"
    wrpcap(str(capture_path), packets)
    return capture_path.read_bytes()


def test_pcap_rebuilds_tcp_flows_and_triggers_port_scan_detection(tmp_path):
    telemetry = analyze_pcap(make_port_scan_capture(tmp_path))
    score, reasons, indicators = detection_engine.analyze_technical_activity(
        json.dumps(telemetry),
        "network",
    )

    assert telemetry["packet_count"] == 12
    assert len(telemetry["flows"]) == 12
    assert telemetry["flows"][0]["src_ip"] == "10.0.0.5"
    assert telemetry["flows"][0]["bytes_out"] > 0
    assert score >= 40
    assert any("destination ports" in reason for reason in reasons)
    assert any(item["name"] == "Flow Port-Scan Breadth" for item in indicators)


def test_pcap_rebuilds_repeated_flow_timestamps_for_beacon_detection(tmp_path):
    telemetry = analyze_pcap(make_beacon_capture(tmp_path))
    score, reasons, indicators = detection_engine.analyze_technical_activity(
        json.dumps(telemetry),
        "network",
    )

    assert len(telemetry["flows"]) == 1
    assert len(telemetry["flows"][0]["timestamps"]) == 5
    assert score >= 40
    assert any("regular interval" in reason for reason in reasons)
    assert any(item["name"] == "Regular Flow Beaconing" for item in indicators)


def test_pcap_upload_integrates_network_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "pcap-upload.db")
    main.initialize_database()

    result = asyncio.run(main.analyze_file(
        category="network",
        file=UploadFile(
            file=BytesIO(make_port_scan_capture(tmp_path)),
            filename="port-scan.pcap",
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        ),
        metadata="{}",
        user={"username": "analyst", "role": "analyst"},
    ))

    assert result["assessment"]["network_capture_summary"] == {"packet_count": 12, "flow_count": 12}
    assert any(item["name"] == "Flow Port-Scan Breadth" for item in result["assessment"]["indicators"])


def test_pcap_rejects_invalid_capture():
    with pytest.raises(ValueError):
        analyze_pcap(b"not a PCAP capture")