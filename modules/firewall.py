import sqlite3
import threading
from datetime import datetime

DB_PATH = "smart_router.db"

def _is_device_blocked(ip: str | None) -> bool:
    if not ip:
        return False
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT is_blocked FROM devices WHERE ipv4 = ?", (ip,)).fetchone()
    conn.close()
    return bool(row and row[0])

_filter_thread = None
_filter_stop   = threading.Event()
_filter_active = False

def init_firewall_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE NOT NULL,
            device_ip   TEXT NOT NULL,
            dest_ip     TEXT NOT NULL,
            dest_port   TEXT NOT NULL,
            protocol    TEXT NOT NULL,
            direction   TEXT NOT NULL DEFAULT 'out',
            enabled     INTEGER DEFAULT 1,
            created_at  TEXT
        )
    """)
    conn.commit()
    conn.close()

def _rule_name(rule_id: int, device_ip: str) -> str:
    return f"SmartRouter_{device_ip.replace('.','_')}_{rule_id}"

def get_all_rules() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM firewall_rules ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_rule(device_ip: str, dest_ip: str, dest_port: str, protocol: str, direction: str = "out") -> tuple[bool, str]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat(timespec="seconds")
    temp_name = f"SmartRouter_{device_ip.replace('.','_')}_temp"
    c.execute("""
        INSERT INTO firewall_rules (name, device_ip, dest_ip, dest_port, protocol, direction, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    """, (temp_name, device_ip, dest_ip, dest_port, protocol.upper(), direction, now))
    rule_id = c.lastrowid or 0
    real_name = _rule_name(rule_id, device_ip)
    c.execute("UPDATE firewall_rules SET name = ? WHERE id = ?", (real_name, rule_id))
    conn.commit()
    conn.close()
    return True, real_name

def delete_rule(rule_id: int) -> tuple[bool, str]:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT name FROM firewall_rules WHERE id = ?", (rule_id,)).fetchone()
    if not row:
        conn.close()
        return False, "Rule not found"
    conn.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return True, "Deleted"

def toggle_rule(rule_id: int) -> tuple[bool, str]:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT enabled FROM firewall_rules WHERE id = ?", (rule_id,)).fetchone()
    if not row:
        conn.close()
        return False, "Rule not found"
    new_state = 0 if row[0] else 1
    conn.execute("UPDATE firewall_rules SET enabled = ? WHERE id = ?", (new_state, rule_id))
    conn.commit()
    conn.close()
    return True, "Toggled"

def cleanup_all_rules():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM firewall_rules")
    conn.commit()
    conn.close()

def _is_allowed(src_ip: str, dst_ip: str, proto: str, dst_port: int, rules: list[dict]) -> bool:
    device_rules = [r for r in rules if r["device_ip"] == src_ip and r["enabled"]]
    if not device_rules:
        return True
    for rule in device_rules:
        proto_match = rule["protocol"] == "ANY" or rule["protocol"] == proto
        ip_match    = rule["dest_ip"] == dst_ip or rule["dest_ip"] == "any"
        port_match  = rule["dest_port"].lower() in ("any", "*", "") or int(rule["dest_port"]) == dst_port
        if proto_match and ip_match and port_match:
            return True
    return False

def _filter_loop():
    global _filter_active
    try:
        import pydivert
        print("[Firewall] WinDivert filter started")
        with pydivert.WinDivert("true", layer=pydivert.Layer.NETWORK_FORWARD) as w:
            for packet in w:
                if _filter_stop.is_set():
                    w.send(packet)
                    break
                src  = packet.src_addr
                dst  = packet.dst_addr
                if not src.startswith("192.168.137."):
                    w.send(packet)
                    continue
                if _is_device_blocked(src):
                    print(f"[Firewall] BLOCKED (device) {src} -> {dst}")
                    continue
                rules = get_all_rules()
                proto = "TCP" if packet.tcp else "UDP" if packet.udp else "OTHER"
                port  = 0
                if packet.tcp:
                    port = packet.tcp.dst_port
                elif packet.udp:
                    port = packet.udp.dst_port
                if _is_allowed(src, dst, proto, port, rules):
                    w.send(packet)
                else:
                    print(f"[Firewall] DROPPED {src} -> {dst}:{port} ({proto})")
    except ImportError:
        print("[Firewall] pydivert not installed — run: pip install pydivert")
    except Exception as e:
        print(f"[Firewall] Error: {e}")
    finally:
        _filter_active = False
        print("[Firewall] Filter stopped")

def start_filter() -> bool:
    global _filter_thread, _filter_active
    if _filter_active:
        return True
    _filter_stop.clear()
    _filter_thread = threading.Thread(target=_filter_loop, daemon=True, name="fw-filter")
    _filter_thread.start()
    _filter_active = True
    return True

def stop_filter():
    global _filter_active
    _filter_stop.set()
    _filter_active = False

def get_filter_status() -> bool:
    return _filter_active