import sqlite3
import threading
import time
import json
import requests
from datetime import datetime
from scapy.all import ARP, Ether, srp
import socket
import subprocess

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
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at  TEXT,
            devices_found INTEGER
        )
    """)
    conn.commit()
    conn.close()

_vendor_cache = {}

def lookup_vendor(mac: str) -> str:
    mac_prefix = mac.upper().replace(":", "")[:6]
    if mac_prefix in _vendor_cache:
        return _vendor_cache[mac_prefix]
    try:
        resp = requests.get(
            f"https://api.macvendors.com/{mac}",
            timeout=3
        )
        vendor = resp.text.strip() if resp.status_code == 200 else "Unknown"
    except Exception:
        vendor = "Unknown"
    _vendor_cache[mac_prefix] = vendor
    return vendor

def lookup_hostname(ip: str) -> str | None:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None

def lookup_ipv6(ip: str) -> str | None:
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if ip in line and ":" in line:
                parts = line.split()
                for p in parts:
                    if ":" in p and len(p) > 10:
                        return p
    except Exception:
        pass
    return None

def arp_scan(network: str = "192.168.137.0/24") -> list[dict]:
    HOTSPOT_IFACE = "Local Area Connection* 4"
    arp_req = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req
    answered, _ = srp(packet, iface=HOTSPOT_IFACE, timeout=2, verbose=False)
    devices = []
    for _, received in answered:
        if received.psrc == "192.168.137.1":
            continue
        devices.append({
            "ip":  received.psrc,
            "mac": received.hwsrc.upper()
        })
    return devices

def run_scan(network: str = "192.168.137.0/24") -> list[dict]:
    print(f"[{datetime.now():%H:%M:%S}] Scanning {network}")
    raw_devices = arp_scan(network)
    enriched = []
    for d in raw_devices:
        vendor   = lookup_vendor(d["mac"])
        hostname = lookup_hostname(d["ip"])
        d["vendor"]   = vendor
        d["hostname"] = hostname
        enriched.append(d)
    _upsert_devices(enriched)
    _log_scan(len(enriched))
    print(f"[{datetime.now():%H:%M:%S}] Found {len(enriched)} device(s).")
    return enriched

def _upsert_devices(devices: list[dict]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat(timespec="seconds")
    for d in devices:
        c.execute("""
            INSERT INTO devices (mac, ipv4, vendor, name, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ipv4      = excluded.ipv4,
                vendor    = CASE WHEN vendor IS NULL OR vendor = 'Unknown'
                                 THEN excluded.vendor ELSE vendor END,
                name      = CASE WHEN name IS NULL OR name = ''
                                 THEN excluded.name ELSE name END,
                last_seen = excluded.last_seen
        """, (d["mac"], d["ip"], d["vendor"], d.get("hostname"), now, now))
    conn.commit()
    conn.close()

def _log_scan(count: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scan_history (scanned_at, devices_found) VALUES (?, ?)",
        (datetime.now().isoformat(timespec="seconds"), count)
    )
    conn.commit()
    conn.close()

_scan_thread = None
_scan_stop   = threading.Event()

def start_auto_scan(network: str = "192.168.137.0/24", interval: int = 30):
    global _scan_thread
    _scan_stop.clear()
    def _loop():
        while not _scan_stop.is_set():
            try:
                run_scan(network)
            except Exception as e:
                print(f"[scan error] {e}")
            _scan_stop.wait(interval)
    _scan_thread = threading.Thread(target=_loop, daemon=True, name="auto-scan")
    _scan_thread.start()

def stop_auto_scan():
    _scan_stop.set()
    if _scan_thread:
        _scan_thread.join(timeout=5)

def get_all_devices() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM devices ORDER BY last_seen DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def update_device(mac: str, fields: dict):
    allowed = {"name", "model", "description", "ipv6"}
    safe = {k: v for k, v in fields.items() if k in allowed}
    if not safe:
        return
    set_clause = ", ".join(f"{k} = ?" for k in safe)
    values = list(safe.values()) + [mac]
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"UPDATE devices SET {set_clause} WHERE mac = ?", values)
    conn.commit()
    conn.close()

def toggle_block(mac: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT is_blocked FROM devices WHERE mac = ?", (mac,)
    ).fetchone()
    new_state = 0 if row and row[0] else 1
    conn.execute(
        "UPDATE devices SET is_blocked = ? WHERE mac = ?", (new_state, mac)
    )
    conn.commit()
    conn.close()
    return bool(new_state)