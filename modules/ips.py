import sqlite3
import threading
import smtplib
import time
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from scapy.all import IP, sniff

DB_PATH       = "smart_router.db"
HOTSPOT_IFACE = "Local Area Connection* 4"
SAMPLE_INTERVAL = 5  # seconds between traffic samples

_collector_thread = None
_collector_stop   = threading.Event()
_monitor_active   = False  # controls whether IPS alerting runs

_bytes_out   = {}
_bytes_in    = {}
_counts_lock = threading.Lock()
_last_alert  = {}  # mac -> timestamp, prevents alert spam



def init_ips_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS traffic_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac         TEXT NOT NULL,
            ipv4        TEXT,
            bytes_in    INTEGER DEFAULT 0,
            bytes_out   INTEGER DEFAULT 0,
            rate_kbps   REAL DEFAULT 0,
            recorded_at TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ips_alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            mac             TEXT NOT NULL,
            ipv4            TEXT,
            rate_kbps       REAL,
            threshold_kbps  REAL,
            throttle_until  TEXT,
            recorded_at     TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ips_config (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            mac              TEXT UNIQUE NOT NULL,
            max_rate_kbps    REAL DEFAULT 1000.0,
            min_rate_kbps    REAL DEFAULT 10.0,
            throttle_minutes INTEGER DEFAULT 5,
            alert_email      TEXT DEFAULT '',
            enabled          INTEGER DEFAULT 1
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT UNIQUE NOT NULL,
            value TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('retention_days', '7')")
    c.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('alert_email', '')")
    conn.commit()
    # throttle_until added later, ignore if already exists
    try:
        conn.execute("ALTER TABLE devices ADD COLUMN throttle_until TEXT")
        conn.commit()
    except Exception:
        pass
    conn.close()


def get_setting(key):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row[0] if row else None


def set_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def get_all_settings():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
    conn.close()
    return {r[0]: r[1] for r in rows}


def get_all_ips_configs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    devices  = conn.execute("SELECT mac, ipv4, name FROM devices ORDER BY last_seen DESC").fetchall()
    cfg_rows = conn.execute("SELECT * FROM ips_config").fetchall()
    conn.close()

    configs = {row["mac"]: dict(row) for row in cfg_rows}
    result  = []
    for d in devices:
        mac = d["mac"]
        cfg = configs.get(mac, {})
        result.append({
            "mac":              mac,
            "ipv4":             d["ipv4"],
            "name":             d["name"],
            "max_rate_kbps":    cfg.get("max_rate_kbps", 1000.0),
            "min_rate_kbps":    cfg.get("min_rate_kbps", 10.0),
            "throttle_minutes": cfg.get("throttle_minutes", 5),
            "alert_email":      cfg.get("alert_email", ""),
            "enabled":          cfg.get("enabled", 1),
        })
    return result


def set_ips_config(mac, max_rate_kbps, min_rate_kbps, throttle_minutes, alert_email, enabled=1):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO ips_config (mac, max_rate_kbps, min_rate_kbps, throttle_minutes, alert_email, enabled)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            max_rate_kbps    = excluded.max_rate_kbps,
            min_rate_kbps    = excluded.min_rate_kbps,
            throttle_minutes = excluded.throttle_minutes,
            alert_email      = excluded.alert_email,
            enabled          = excluded.enabled
    """, (mac, float(max_rate_kbps), float(min_rate_kbps), int(throttle_minutes), alert_email, int(enabled)))
    conn.commit()
    conn.close()


def get_alerts(limit=100):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT a.*, d.name AS device_name
        FROM ips_alerts a
        LEFT JOIN devices d ON a.mac = d.mac
        ORDER BY a.recorded_at DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_alert(alert_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM ips_alerts WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()


def clear_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM ips_alerts")
    conn.commit()
    conn.close()


def get_traffic_history(mac, days=7):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    since = (datetime.now() - timedelta(days=int(days))).isoformat(timespec="seconds")
    rows = conn.execute("""
        SELECT recorded_at, rate_kbps, bytes_in, bytes_out
        FROM traffic_history
        WHERE mac = ? AND recorded_at >= ?
        ORDER BY recorded_at ASC
    """, (mac, since)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_history(mac=None):
    conn = sqlite3.connect(DB_PATH)
    if mac:
        conn.execute("DELETE FROM traffic_history WHERE mac = ?", (mac,))
    else:
        conn.execute("DELETE FROM traffic_history")
    conn.commit()
    conn.close()


def cleanup_old_records():
    try:
        days = int(get_setting("retention_days") or 7)
    except Exception:
        days = 7
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM traffic_history WHERE recorded_at < ?", (cutoff,))
    conn.execute("DELETE FROM ips_alerts WHERE recorded_at < ?", (cutoff,))
    conn.commit()
    conn.close()


SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "gureet2609@gmail.com"
SMTP_PASS = "nnqh jnfr aqhl kcad"



def _send_email(to_addr, ip, name, rate, threshold):
    if not to_addr:
        return
    try:
        device_label = name or "Unknown"
        subject = "[SmartRouter] IPS Alert"
        body  = "SmartRouter IPS Alert\n"
        body += "=" * 30 + "\n\n"
        body += "Device Name  : " + device_label + "\n"
        body += "IP Address   : " + ip + "\n"
        body += "Detected Rate: " + str(round(rate, 1)) + " kbps\n"
        body += "Max Allowed  : " + str(round(threshold, 1)) + " kbps\n"
        body += "Time         : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n"
        body += "The device has been throttled automatically."
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = to_addr
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print("[IPS] email sent to " + to_addr)
    except Exception as e:
        print("[IPS] email failed:", e)


def _auto_capture(mac, ip):
    try:
        from modules.packet_capture import start_capture
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = "ips_" + ip.replace(".", "_") + "_" + ts + ".pcap"
        start_capture(mac, ip, fname, max_duration=10)
    except Exception as e:
        print("[IPS] auto capture error:", e)


def _count_packet(pkt):
    if IP not in pkt:
        return
    src  = pkt[IP].src
    dst  = pkt[IP].dst
    size = len(pkt)
    with _counts_lock:
        # track bytes out from hotspot devices and bytes in to them
        if src.startswith("192.168.137.") and src != "192.168.137.1":
            _bytes_out[src] = _bytes_out.get(src, 0) + size
        if dst.startswith("192.168.137.") and dst != "192.168.137.1":
            _bytes_in[dst] = _bytes_in.get(dst, 0) + size


def _process_window(snap_out, snap_in, elapsed):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    devs   = conn.execute("SELECT mac, ipv4, name FROM devices WHERE ipv4 IS NOT NULL AND ipv4 != ''").fetchall()
    ip_map = {d["ipv4"]: dict(d) for d in devs}

    # always include known devices so idle shows 0 not a gap in the chart
    all_ips = set(snap_out.keys()) | set(snap_in.keys()) | set(ip_map.keys())

    cfgs = {r["mac"]: dict(r) for r in conn.execute("SELECT * FROM ips_config WHERE enabled = 1").fetchall()}

    row          = conn.execute("SELECT value FROM app_settings WHERE key = 'alert_email'").fetchone()
    global_email = row[0] if row else ""
    now          = datetime.now().isoformat(timespec="seconds")

    for ip in all_ips:
        bout  = snap_out.get(ip, 0)
        bin_  = snap_in.get(ip, 0)
        rate  = ((bin_ + bout) * 8.0) / elapsed / 1000.0

        dev = ip_map.get(ip)
        mac = dev["mac"] if dev else ip.replace(".", ":")

        conn.execute(
            "INSERT INTO traffic_history (mac, ipv4, bytes_in, bytes_out, rate_kbps, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (mac, ip, bin_, bout, round(rate, 2), now)
        )

        # skip alerting if monitor is off or device not in db
        if not _monitor_active or not dev:
            continue

        cfg = cfgs.get(mac)
        if not cfg:
            continue

        max_rate     = cfg["max_rate_kbps"]
        throttle_min = cfg["throttle_minutes"]

        # 60 second cooldown per device so we dont spam alerts
        last_t = _last_alert.get(mac, 0)
        if rate > max_rate and (time.time() - last_t) > 60:
            _last_alert[mac] = time.time()
            until = (datetime.now() + timedelta(minutes=int(throttle_min))).isoformat(timespec="seconds")
            conn.execute("UPDATE devices SET throttle_until = ? WHERE mac = ?", (until, mac))
            conn.execute(
                "INSERT INTO ips_alerts (mac, ipv4, rate_kbps, threshold_kbps, throttle_until, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                (mac, ip, round(rate, 2), max_rate, until, now)
            )
            print("[IPS] alert:", dev["name"] or ip, "rate=" + str(round(rate, 1)) + " kbps")
            # start firewall to enforce the throttle
            try:
                from modules.firewall import start_filter, get_filter_status
                start_filter()
                time.sleep(0.5)
                if not get_filter_status()["active"]:
                    print("[IPS] firewall filter failed to start")
            except Exception as fe:
                print("[IPS] could not start firewall filter:", fe)
            threading.Thread(target=_auto_capture, args=(mac, ip), daemon=True).start()
            if global_email:
                threading.Thread(target=_send_email, args=(global_email, ip, dev["name"], rate, max_rate), daemon=True).start()

    conn.commit()
    conn.close()


def _collector_loop():
    cleanup_old_records()
    tick = 0

    while not _collector_stop.is_set():
        with _counts_lock:
            _bytes_out.clear()
            _bytes_in.clear()

        t0 = time.time()
        try:
            sniff(iface=HOTSPOT_IFACE, prn=_count_packet, timeout=SAMPLE_INTERVAL, store=False)
        except Exception as e:
            print("[traffic] sniff error:", e)
            _collector_stop.wait(SAMPLE_INTERVAL)
            continue

        if _collector_stop.is_set():
            break

        elapsed = time.time() - t0
        if elapsed < 0.1:
            elapsed = SAMPLE_INTERVAL


        with _counts_lock:
            snap_out = dict(_bytes_out)
            snap_in  = dict(_bytes_in)

        try:
            _process_window(snap_out, snap_in, elapsed)
        except Exception as e:
            print("[traffic] processing error:", e)

        tick += 1
        # run cleanup roughly every 30 minutes
        if tick % 360 == 0:
            cleanup_old_records()

    print("[traffic] collector stopped")


def start_traffic_collector():
    global _collector_thread
    if _collector_thread and _collector_thread.is_alive():
        return
    _collector_stop.clear()
    _collector_thread = threading.Thread(target=_collector_loop, daemon=True, name="traffic-collector")
    _collector_thread.start()
    print("[traffic] collector started")


def start_monitor():
    global _monitor_active
    if not (_collector_thread and _collector_thread.is_alive()):
        start_traffic_collector()
    _monitor_active = True
    print("[IPS] monitor enabled")


def stop_monitor():
    global _monitor_active
    _monitor_active = False
    _last_alert.clear()
    try:
        from modules.firewall import stop_filter
        stop_filter()
    except Exception as e:
        print("[IPS] could not stop firewall filter:", e)
    print("[IPS] monitor disabled — firewall filter stopped")


def get_monitor_status():
    return _monitor_active
