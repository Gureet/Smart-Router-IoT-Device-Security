# Smart Router — IoT Device Security
INSE 6170 · Concordia University

A Flask web app that turns a Windows hotspot into an IoT security gateway. It monitors connected devices, captures their traffic, enforces firewall rules, and detects abnormal behaviour through a browser-based admin interface.

## Prerequisites

- Python 3.10+
- Windows 10/11
- [Npcap](https://npcap.com/) — required for Scapy packet capture
- [WinDivert](https://reqrypt.org/windivert.html) — required for kernel-level packet filtering
- Must be run as **Administrator**

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Opens automatically at http://localhost:5000.

Create a `.env` file in the project root with your Gmail SMTP credentials:
```
SMTP_USER=your_gmail@gmail.com
SMTP_PASS=your_app_password
```

## Project Structure

```
├── app.py
├── requirements.txt
├── modules/
│   ├── device_discovery.py
│   ├── packet_capture.py
│   ├── firewall.py
│   └── ips.py
└── templates/
    ├── base.html
    ├── index.html
    ├── capture.html
    ├── firewall.html
    ├── ips.html
    └── logs.html
```

## Functions

**1. Device Discovery**
- ARP scan to find connected devices
- Vendor lookup from MAC, IPv6 derived using EUI-64
- Edit device name, model, description
- Block / unblock devices

**2. Packet Capture**
- Capture traffic per device, one PCAP file per device
- Stop by packet count, duration, or manually
- Pause and resume sessions

**3. Firewall**
- Whitelist rules by device IP, destination IP, port, protocol
- Kernel-level filtering via WinDivert
- Default-deny when filter is active

**4. Intrusion Prevention**
- Monitors traffic every 5 seconds in the background
- Throttles device via token bucket on threshold breach
- Auto-captures 10 seconds of traffic as evidence
- Sends email alert via SMTP

**5. Logs & Monitoring**
- Traffic history chart per device, auto-refreshes every 5s
- Configurable time window
- PCAP file management — view, download, delete

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/devices/scan` | run ARP scan |
| PATCH | `/api/devices/<mac>` | update device info |
| POST | `/api/devices/<mac>/block` | block / unblock |
| POST | `/api/capture/start` | start capture session |
| POST | `/api/firewall/filter/start` | start packet filter |
| POST | `/api/firewall/rules` | add whitelist rule |
| POST | `/api/ips/start` | start IPS monitor |
| POST | `/api/ips/config/<mac>` | set device threshold |
| GET | `/api/logs/history/<mac>?days=N` | get traffic history |
