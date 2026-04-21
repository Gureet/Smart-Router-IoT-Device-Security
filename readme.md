# Smart Router — IoT Device Security
INSE 6170 · Concordia University

A Flask web application that runs on a Windows machine sharing its internet as a hotspot. It monitors and controls IoT devices connected to that hotspot through a browser-based interface.

## Prerequisites

- Python 3.10+
- Windows 10/11
- [Npcap](https://npcap.com/) for packet capture (Scapy dependency)
- [WinDivert](https://reqrypt.org/windivert.html) for kernel-level packet filtering
- Must be run as **Administrator**

## Running the project

```bash
pip install -r requirements.txt
python app.py
```

Opens at http://localhost:5000. The hotspot subnet is set to `192.168.137.0/24` in `app.py` — change it if yours is different.

---

## Project structure

```
├── app.py                      # Flask entry point, all API routes
├── requirements.txt
├── modules/
│   ├── device_discovery.py     # ARP scanning, vendor lookup, EUI-64 IPv6
│   ├── packet_capture.py       # PCAP capture sessions per device
│   ├── firewall.py             # WinDivert packet filter, token bucket throttling
│   └── ips.py                  # Traffic collection, IPS alerting, email
└── templates/
    ├── base.html
    ├── index.html              # Function 1 — Device Discovery
    ├── capture.html            # Function 2 — Packet Capture
    ├── firewall.html           # Function 3 — Firewall
    ├── ips.html                # Function 4 — Intrusion Prevention
    └── logs.html               # Function 5 — Logs & Monitoring
```

---

## Implemented functions

### 1. Device Discovery
- ARP scan of the hotspot subnet to find connected devices
- MAC vendor lookup via macvendors.com API
- IPv6 link-local address derived from MAC using EUI-64
- Reverse DNS lookup for hostname
- Devices stored in SQLite, updated on each scan
- Device details (name, model, description) editable manually
- Individual devices can be blocked or unblocked

### 2. Packet Capture
- Capture live traffic for one or more devices simultaneously
- Each session runs in its own thread using Scapy, writes to a `.pcap` file
- Stop conditions: packet count, duration (seconds), or manual
- Sessions can be paused and resumed
- Saved files can be downloaded or deleted from the UI

### 3. Firewall
- Kernel-level packet filtering via WinDivert on the hotspot interface (`NETWORK_FORWARD`)
- Default-deny when filter is active — only whitelisted traffic passes
- Rules defined by device IP, destination IP, port, and protocol (TCP/UDP/ANY)
- Individual rules can be enabled or disabled without deleting them
- Blocked devices and IPS-throttled devices are also enforced here

### 4. Intrusion Prevention (IPS)
- Traffic is measured every 5 seconds in the background, independent of the IPS monitor
- IPS monitor is started manually — enables alerting and throttling
- Per-device thresholds: max rate (kbps), min rate (kbps), throttle duration
- Devices exceeding the max rate are throttled using a token bucket algorithm
- A PCAP is automatically captured as evidence on each alert
- Email alert sent via SMTP when a threshold is exceeded
- Stopping the monitor also stops the firewall filter

### 5. Logs & Monitoring
- Data rate history chart (Chart.js) per device, loads on selection
- Chart refreshes every 5 seconds automatically
- Time window configurable by typing days and pressing Enter
- Shows avg rate, peak rate, and sample count above the chart
- Saved PCAP files (manual and IPS auto-capture) listed with download and delete

---

## Database schema

```
devices          — mac, ipv4, ipv6, vendor, name, model, version, description,
                   first_seen, last_seen, is_blocked, throttle_until
traffic_history  — mac, ipv4, bytes_in, bytes_out, rate_kbps, recorded_at
ips_alerts       — mac, ipv4, rate_kbps, threshold_kbps, throttle_until, recorded_at
ips_config       — mac, max_rate_kbps, min_rate_kbps, throttle_minutes, enabled
firewall_rules   — name, device_ip, dest_ip, dest_port, protocol, direction, enabled, created_at
app_settings     — key, value
```

---

## API reference

**Devices**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | list all devices |
| POST | `/api/devices/scan` | run ARP scan |
| PATCH | `/api/devices/<mac>` | update device fields |
| POST | `/api/devices/<mac>/block` | toggle block/unblock |

**Capture**
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/capture/start` | start a session |
| POST | `/api/capture/<id>/pause` | pause |
| POST | `/api/capture/<id>/resume` | resume |
| POST | `/api/capture/<id>/stop` | stop |
| GET | `/api/capture/sessions` | list active sessions |
| GET | `/api/capture/files` | list saved pcap files |
| DELETE | `/api/capture/files/<filename>` | delete a file |
| GET | `/api/capture/files/<filename>/download` | download a file |

**Firewall**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/firewall/rules` | list rules |
| POST | `/api/firewall/rules` | add a rule |
| DELETE | `/api/firewall/rules/<id>` | delete a rule |
| POST | `/api/firewall/rules/<id>/toggle` | enable/disable a rule |
| POST | `/api/firewall/filter/start` | start packet filter |
| POST | `/api/firewall/filter/stop` | stop packet filter |
| GET | `/api/firewall/filter/status` | filter status |
| POST | `/api/firewall/cleanup` | remove all rules |

**IPS**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ips/status` | monitor on/off |
| POST | `/api/ips/start` | start monitor |
| POST | `/api/ips/stop` | stop monitor |
| GET | `/api/ips/configs` | list device thresholds |
| POST | `/api/ips/config/<mac>` | save threshold config |
| GET | `/api/ips/alerts` | list alerts |
| DELETE | `/api/ips/alerts/<id>` | delete an alert |
| POST | `/api/ips/alerts/clear` | clear all alerts |
| GET | `/api/ips/settings` | get email settings |
| POST | `/api/ips/settings` | save email settings |

**Logs**
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs/history/<mac>?days=N` | get traffic history |
| DELETE | `/api/logs/history?mac=<mac>` | delete history for a device |
| DELETE | `/api/logs/history` | delete all history |
