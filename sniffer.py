#!/usr/bin/env python3
"""
Basic Network Sniffer
CodeAlpha Cyber Security Internship - Task 1

Captures live packets on a chosen interface and prints
source/destination IP, protocol, ports and a payload preview.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

LOG_FILE = "sniffer_log.txt"


def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def process_packet(packet):
    if not packet.haslayer(IP):
        return  # skip non-IP traffic (e.g. ARP)

    ip_layer = packet[IP]
    proto = get_protocol_name(packet)
    timestamp = datetime.now().strftime("%H:%M:%S")

    src_port = dst_port = "-"
    if packet.haslayer(TCP):
        src_port, dst_port = packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port, dst_port = packet[UDP].sport, packet[UDP].dport

    payload_preview = ""
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        payload_preview = raw_bytes[:40].decode(errors="replace")

    summary = (
        f"[{timestamp}] {proto:<5} "
        f"{ip_layer.src}:{src_port} -> {ip_layer.dst}:{dst_port} "
        f"len={len(packet)}"
    )

    print(summary)
    if payload_preview:
        print(f"   payload: {payload_preview!r}")

    with open(LOG_FILE, "a") as f:
        f.write(summary + "\n")


def main():
    print("Starting Basic Network Sniffer... Press Ctrl+C to stop.")
    try:
        sniff(prn=process_packet, store=False)
    except PermissionError:
        print("Run this script with administrator/root privileges.")
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")


if __name__ == "__main__":
    main()
