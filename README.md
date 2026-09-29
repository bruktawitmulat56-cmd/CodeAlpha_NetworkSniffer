# CodeAlpha_NetworkSniffer

**CodeAlpha Cyber Security Internship — Task 1**

A basic network sniffer built in Python using Scapy. It captures live
packets, parses the TCP/IP layers (Ethernet → IP → TCP/UDP/ICMP), and
displays source/destination IP, protocol, ports, and a short payload
preview. Summaries are also logged to `sniffer_log.txt`.

---

## Features
- Live packet capture on the default network interface
- Protocol detection: TCP, UDP, ICMP
- Source/destination IP and port extraction
- 40-byte payload preview for inspection
- Timestamped console output + file logging
- Validated against Wireshark on the same interface

---

## Requirements
- Python 3.8+
- Scapy (`pip install scapy`)
- Root / Administrator privileges (needed for raw socket access)

---

## Usage

```bash
# Linux / macOS
sudo python3 sniffer.py

# Windows (run terminal as Administrator)
python sniffer.py
