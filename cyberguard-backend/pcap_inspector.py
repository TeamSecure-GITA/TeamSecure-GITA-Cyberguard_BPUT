"""PCAP flow extraction for network incident analysis."""

from collections import OrderedDict
from datetime import datetime, timezone
from io import BytesIO
import ipaddress
from typing import Any

MAX_PCAP_PACKETS = 100_000
MAX_PCAP_FLOWS = 25_000


def analyze_pcap(content: bytes) -> dict[str, Any]:
    try:
        from scapy.all import IP, IPv6, TCP, UDP, PcapReader
    except ImportError as error:
        raise RuntimeError("PCAP analysis requires Scapy; install the backend requirements.") from error

    if not content:
        raise ValueError("The PCAP capture is empty.")

    try:
        reader = PcapReader(BytesIO(content))
    except Exception as error:
        raise ValueError("The uploaded file is not a valid PCAP or PCAPNG capture.") from error

    flows: OrderedDict[tuple[str, str, int, int, str], dict[str, Any]] = OrderedDict()
    packet_count = 0
    try:
        for packet in reader:
            packet_count += 1
            if packet_count > MAX_PCAP_PACKETS:
                raise ValueError(f"PCAP capture exceeds the {MAX_PCAP_PACKETS}-packet analysis limit.")

            if packet.haslayer(IP):
                network = packet[IP]
            elif packet.haslayer(IPv6):
                network = packet[IPv6]
            else:
                continue

            if packet.haslayer(TCP):
                transport = packet[TCP]
                protocol = "tcp"
            elif packet.haslayer(UDP):
                transport = packet[UDP]
                protocol = "udp"
            else:
                continue

            source_ip = str(network.src)
            destination_ip = str(network.dst)
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
            flow_key = (source_ip, destination_ip, source_port, destination_port, protocol)
            try:
                timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat()
            except (AttributeError, OSError, OverflowError, TypeError, ValueError):
                timestamp = None

            flow = flows.get(flow_key)
            if flow is None:
                if len(flows) >= MAX_PCAP_FLOWS:
                    raise ValueError(f"PCAP capture exceeds the {MAX_PCAP_FLOWS}-flow analysis limit.")
                flow = {
                    "src_ip": source_ip,
                    "dst_ip": destination_ip,
                    "src_port": source_port,
                    "dst_port": destination_port,
                    "protocol": protocol,
                    "destination_port": destination_port,
                    "timestamp": timestamp,
                    "timestamps": [],
                    "packets": 0,
                    "bytes_out": 0,
                    "bytes_in": 0,
                }
                flows[flow_key] = flow

            flow["packets"] += 1
            if timestamp:
                flow["timestamps"].append(timestamp)
            packet_size = len(packet)
            source_is_private = ipaddress.ip_address(source_ip).is_private
            destination_is_private = ipaddress.ip_address(destination_ip).is_private
            if source_is_private and not destination_is_private:
                flow["bytes_out"] += packet_size
            elif destination_is_private and not source_is_private:
                flow["bytes_in"] += packet_size
            if timestamp and (not flow["timestamp"] or timestamp < flow["timestamp"]):
                flow["timestamp"] = timestamp
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("The uploaded PCAP capture could not be parsed.") from error
    finally:
        reader.close()

    if not flows:
        raise ValueError("The capture contains no supported IPv4/IPv6 TCP or UDP packets.")

    return {"packet_count": packet_count, "flows": list(flows.values())}