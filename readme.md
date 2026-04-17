# Smart Router — IoT Device Security
INSE 6170 · Concordia University

## Project Structure

```
smart-router/
├── app.py                        # Flask entry point + all API routes
├── requirements.txt
├── smart_router.db               # SQLite DB (auto-created on first run)
├── modules/
│   └── device_discovery.py       # ARP scan, MAC vendor lookup, DB helpers
└── templates/
    └── index.html                # Device Discovery UI
```

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure your hotspot network

Edit `app.py` line:
```python
HOTSPOT_NETWORK = "192.168.1.0/24"
```

| Platform       | Typical hotspot range  |
|----------------|------------------------|
| Windows 10/11  | `192.168.137.0/24`     |
| macOS          | `192.168.2.0/24`       |
| Linux hostapd  | `10.0.0.0/24`          |

### 3. Run (must be root for ARP scanning)

```bash
sudo python app.py
```

Then open: **http://localhost:5000**

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/api/devices` | List all devices |
| POST   | `/api/devices/scan` | Trigger ARP scan |
| PATCH  | `/api/devices/<mac>` | Edit device info |
| POST   | `/api/devices/<mac>/block` | Toggle block |
| POST   | `/api/autoscan/start` | Start background scan |
| POST   | `/api/autoscan/stop` | Stop background scan |

### Example: trigger scan with custom network
```bash
curl -X POST http://localhost:5000/api/devices/scan \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.137.0/24"}'
```

### Example: name a device
```bash
curl -X PATCH http://localhost:5000/api/devices/A4:C3:F0:12:34:56 \
  -H "Content-Type: application/json" \
  -d '{"name": "Smart Thermostat", "model": "Nest 3rd Gen", "description": "Living room"}'
```

---

## Module 1 — Device Discovery

**What it does:**
- ARP-sweeps every host on the hotspot subnet
- Resolves MAC → vendor via macvendors.com API (cached)
- Upserts device records in SQLite (new devices added; known MACs get IP + timestamp updated)
- Logs every scan in `scan_history` table
- Supports background auto-scan every N seconds

**Database schema:**
```sql
devices(id, mac, ipv4, ipv6, vendor, name, model, description,
        first_seen, last_seen, is_blocked)

scan_history(id, scanned_at, devices_found)
```

---

## Upcoming modules

- [ ] Module 2: Packet Capture (Scapy → PCAP files)
- [ ] Module 3: Firewall (iptables whitelist)
- [ ] Module 4: IPS / Anomaly Detection (rate monitor + throttle)
- [ ] Module 5: Logs & Visualization (Chart.js history graphs)
