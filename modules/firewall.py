import sqlite3
import threading
import time
from datetime import datetime

DB_PATH = "smart_router.db"

_filter_thread = None
_filter_stop   = threading.Event()
_filter_active = False
_filter_error  = None

# token buckets per ip
_token_buckets = {}
_tb_lock       = threading.Lock()



def _is_device_blocked(ip: str | None) -> bool:
    if not ip:
        return False
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT is_blocked FROM devices WHERE ipv4 = ?", (ip,)).fetchone()
    conn.close()
    return bool(row and row[0])


def _get_throttle_info(ip: str | None) -> tuple[bool, float]:
    if not ip:
        return False, 0.0
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("""
        SELECT d.throttle_until, c.min_rate_kbps
        FROM devices d
        LEFT JOIN ips_config c ON d.mac = c.mac
        WHERE d.ipv4 = ?
    """, (ip,)).fetchone()
    conn.close()
    if not row or not row[0]:
        return False, 0.0
    try:
        if datetime.now() < datetime.fromisoformat(row[0]):
            return True, float(row[1] or 10.0)
    except Exception:
        pass
    return False, 0.0


def _check_token_bucket(ip: str, packet_size: int, min_rate_kbps: float) -> bool:
    # token bucket — refill by elapsed time, drop packet if not enough tokens
    bytes_per_sec = (min_rate_kbps * 1000.0) / 8.0
    now = time.time()
    with _tb_lock:
        if ip not in _token_buckets:
            _token_buckets[ip] = {"tokens": bytes_per_sec, "last": now}
        bucket = _token_buckets[ip]
        elapsed = now - bucket["last"]
        bucket["tokens"] += bytes_per_sec * elapsed
        bucket["last"]    = now
        if bucket["tokens"] > bytes_per_sec:
            bucket["tokens"] = bytes_per_sec  # cap at 1 second worth
        if bucket["tokens"] >= packet_size:
            bucket["tokens"] -= packet_size
            return True
        return False


def init_firewall_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
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
    # insert with temp name first so we can use the rowid in the real name
    temp_name = f"SmartRouter_{device_ip.replace('.','_')}_temp"
    c.execute("""
        INSERT INTO firewall_rules (name, device_ip, dest_ip, dest_port, protocol, direction, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    """, (temp_name, device_ip, dest_ip, dest_port, protocol.upper(), direction, now))
    rule_id   = c.lastrowid or 0
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
    conn.execute("UPDATE firewall_rules SET enabled = ? WHERE id = ?", (0 if row[0] else 1, rule_id))
    conn.commit()
    conn.close()
    return True, "Toggled"


def cleanup_all_rules():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM firewall_rules")
    conn.commit()
    conn.close()


def _is_allowed(src_ip: str, dst_ip: str, proto: str, dst_port: int, rules: list[dict]) -> bool:
    # if no rules for this device then allow everything
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
    global _filter_active, _filter_error
    try:
        import pydivert
        print("[Firewall] WinDivert filter started")

        # NETWORK_FORWARD layer intercepts routed packets from the hotspot
        with pydivert.WinDivert("true", layer=pydivert.Layer.NETWORK_FORWARD) as w:
            for packet in w:
                if _filter_stop.is_set():
                    w.send(packet)
                    break

                src      = packet.src_addr
                dst      = packet.dst_addr
                pkt_size = len(packet.raw)

                # handle inbound packets going to a device
                if dst and dst.startswith("192.168.137."):
                    if _is_device_blocked(dst):
                        continue
                    is_throttled, min_rate = _get_throttle_info(dst)
                    if is_throttled and not _check_token_bucket(dst, pkt_size, min_rate):
                        continue
                    all_rules = get_all_rules()
                    dev_rules = [r for r in all_rules if r["device_ip"] == dst and r["enabled"]]
                    if dev_rules:
                        proto_in = "TCP" if packet.tcp else "UDP" if packet.udp else "OTHER"
                        port_in  = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
                        if not _is_allowed(dst, src or "", proto_in, port_in, all_rules):
                            continue
                    w.send(packet)
                    continue

                # pass through anything not from a hotspot device
                if not src or not src.startswith("192.168.137."):
                    w.send(packet)
                    continue


                # outbound — check block, throttle, whitelist
                if _is_device_blocked(src):
                    print(f"[Firewall] BLOCKED {src} -> {dst}")
                    continue

                is_throttled, min_rate = _get_throttle_info(src)
                if is_throttled and not _check_token_bucket(src, pkt_size, min_rate):
                    print(f"[Firewall] THROTTLED {src} -> {dst}")
                    continue

                rules = get_all_rules()
                proto = "TCP" if packet.tcp else "UDP" if packet.udp else "OTHER"
                port  = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)
                if _is_allowed(src, dst, proto, port, rules):
                    w.send(packet)
                else:
                    print(f"[Firewall] DROPPED {src} -> {dst}:{port} ({proto})")

    except ImportError:
        _filter_error = "pydivert not installed — run: pip install pydivert"
        print(f"[Firewall] {_filter_error}")
    except Exception as e:
        _filter_error = str(e)
        print(f"[Firewall] Error: {e}")
    finally:
        _filter_active = False
        print("[Firewall] Filter stopped")


def start_filter() -> bool:
    global _filter_thread, _filter_active, _filter_error
    # flag can be stale if thread crashed, re-check the thread
    if _filter_active and _filter_thread and _filter_thread.is_alive():
        return True
    _filter_active = False
    _filter_error  = None
    _filter_stop.clear()

    _filter_thread = threading.Thread(target=_filter_loop, daemon=True, name="fw-filter")
    _filter_thread.start()
    _filter_active = True
    return True


def stop_filter():
    global _filter_active
    _filter_stop.set()
    _filter_active = False


def get_filter_status() -> dict:
    return {"active": _filter_active, "error": _filter_error}
