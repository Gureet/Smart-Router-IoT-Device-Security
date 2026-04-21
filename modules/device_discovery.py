import sqlite3
import json
import requests
from datetime import datetime
from scapy.all import ARP, Ether, srp
import socket

DB_PATH = "smart_router.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac         TEXT UNIQUE NOT NULL,
            ipv4        TEXT,
            ipv6        TEXT,
            vendor      TEXT,
            name        TEXT,
            model       TEXT,
            description TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            is_blocked  INTEGER DEFAULT 0
        )
    """)
    # version column was added later, alter table handles existing dbs
    try:
        c.execute("ALTER TABLE devices ADD COLUMN version TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()

# cache so we dont hit the api for every scan
_vendor_cache = {}

def lookup_vendor(mac: str) -> str:
    mac_prefix = mac.upper().replace(":", "")[:6]
    if mac_prefix in _vendor_cache:
        return _vendor_cache[mac_prefix]
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        vendor = resp.text.strip() if resp.status_code == 200 else "Unknown"
    except Exception:
        vendor = "Unknown"
    _vendor_cache[mac_prefix] = vendor
    return vendor

def lookup_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# derive ipv6 link-local from mac using eui-64 since hotspot doesnt assign ipv6
def derive_ipv6_from_mac(mac: str) -> str:
    parts = mac.upper().split(":")
    parts.insert(3, "FE")
    parts.insert(3, "FF")
    first = int(parts[0], 16) ^ 0x02  # flip universal/local bit
    parts[0] = f"{first:02X}"
    groups = []
    for i in range(0, 8, 2):
        groups.append(parts[i].lower() + parts[i+1].lower())
    return "fe80::" + ":".join(groups[1:])

def arp_scan(network: str = "192.168.137.0/24") -> list[dict]:
    HOTSPOT_IFACE = "Local Area Connection* 4"
    arp_req = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_req, iface=HOTSPOT_IFACE, timeout=2, verbose=False)
    devices = []
    for _, received in answered:
        if received.psrc == "192.168.137.1":  # skip the gateway
            continue
        devices.append({"ip": received.psrc, "mac": received.hwsrc.upper()})
    return devices

def run_scan(network: str = "192.168.137.0/24") -> list[dict]:
    print(f"[{datetime.now():%H:%M:%S}] Scanning {network}")
    raw_devices = arp_scan(network)
    enriched = []
    for d in raw_devices:
        d["vendor"]   = lookup_vendor(d["mac"])
        d["hostname"] = lookup_hostname(d["ip"])
        d["ipv6"]     = derive_ipv6_from_mac(d["mac"])
        enriched.append(d)
    _upsert_devices(enriched)
    print(f"[{datetime.now():%H:%M:%S}] Found {len(enriched)} device(s).")
    return enriched

def _upsert_devices(devices: list[dict]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat(timespec="seconds")
    for d in devices:
        c.execute("""
            INSERT INTO devices (mac, ipv4, ipv6, vendor, name, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ipv4      = excluded.ipv4,
                ipv6      = CASE WHEN excluded.ipv6 IS NOT NULL THEN excluded.ipv6 ELSE ipv6 END,
                vendor    = CASE WHEN vendor IS NULL OR vendor = 'Unknown' THEN excluded.vendor ELSE vendor END,
                name      = CASE WHEN name IS NULL OR name = '' THEN excluded.name ELSE name END,
                last_seen = excluded.last_seen
        """, (d["mac"], d["ip"], d.get("ipv6"), d["vendor"], d.get("hostname"), now, now))
    conn.commit()
    conn.close()

def get_all_devices() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_device(mac: str, fields: dict):
    allowed = {"name", "vendor", "model", "version", "description", "ipv6"}
    safe = {k: v for k, v in fields.items() if k in allowed}
    if not safe:
        return
    set_clause = ", ".join(f"{k} = ?" for k in safe)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"UPDATE devices SET {set_clause} WHERE mac = ?", list(safe.values()) + [mac])
    conn.commit()
    conn.close()

def toggle_block(mac: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT is_blocked FROM devices WHERE mac = ?", (mac,)).fetchone()
    new_state = 0 if row and row[0] else 1
    conn.execute("UPDATE devices SET is_blocked = ? WHERE mac = ?", (new_state, mac))
    conn.commit()
    conn.close()
    return bool(new_state)
