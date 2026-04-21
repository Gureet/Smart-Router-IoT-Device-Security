from flask import Flask, jsonify, request, render_template, abort, send_from_directory, redirect
from datetime import datetime
from modules.device_discovery import (
    init_db, run_scan, get_all_devices, update_device, toggle_block,
)
from modules.packet_capture import (
    start_capture, pause_capture, resume_capture, stop_capture,
    get_all_sessions, list_pcap_files, delete_pcap, CAPTURES_DIR,
)
from modules.firewall import (
    init_firewall_db, get_all_rules, add_rule, delete_rule,
    toggle_rule, cleanup_all_rules,
    start_filter, stop_filter, get_filter_status,
)
from modules.ips import (
    init_ips_db, get_all_ips_configs, set_ips_config,
    get_alerts, delete_alert, clear_alerts,
    get_traffic_history, delete_history,
    get_all_settings, set_setting,
    start_monitor, stop_monitor, get_monitor_status,
    start_traffic_collector,
)

app = Flask(__name__)
init_db()
init_firewall_db()
init_ips_db()
start_traffic_collector()  # always-on, separate from IPS monitor

HOTSPOT_NETWORK = "192.168.137.0/24"

@app.route("/")
def index():
    return render_template("index.html", active_page="devices")

@app.route("/capture")
def capture_page():
    return render_template("capture.html", active_page="capture")

@app.route("/firewall")
def firewall_page():
    return render_template("firewall.html", active_page="firewall")

@app.route("/ips")
def ips_page():
    return render_template("ips.html", active_page="ips")

@app.route("/logs")
def logs_page():
    return render_template("logs.html", active_page="logs")

@app.route("/api/devices", methods=["GET"])
def api_get_devices():
    return jsonify(get_all_devices())

@app.route("/api/devices/scan", methods=["POST"])
def api_scan():
    body = request.get_json(silent=True) or {}
    network = body.get("network", HOTSPOT_NETWORK)
    try:
        devices = run_scan(network)
        return jsonify({"status": "ok", "found": len(devices), "devices": devices})
    except PermissionError:
        return jsonify({"status": "error", "message": "Admin privileges required for ARP scan."}), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/devices/<mac>", methods=["PATCH"])
def api_update_device(mac: str):
    mac = mac.upper()
    data = request.get_json(silent=True)
    if not data:
        abort(400, "JSON body required")
    update_device(mac, data)
    return jsonify({"status": "ok"})

@app.route("/api/devices/<mac>/block", methods=["POST"])
def api_toggle_block(mac: str):
    mac = mac.upper()
    new_state = toggle_block(mac)
    return jsonify({"status": "ok", "blocked": new_state})


@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    body = request.get_json(silent=True) or {}
    mac          = body.get("mac", "").upper()
    ip           = body.get("ip", "")
    filename     = body.get("filename", f"capture_{mac.replace(':','')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    max_packets  = body.get("max_packets")
    max_duration = body.get("max_duration")
    if not mac or not ip:
        return jsonify({"status": "error", "message": "mac and ip required"}), 400
    session_id = start_capture(mac, ip, filename, max_packets, max_duration)
    return jsonify({"status": "ok", "session_id": session_id})

@app.route("/api/capture/<session_id>/pause", methods=["POST"])
def api_capture_pause(session_id):
    pause_capture(session_id)
    return jsonify({"status": "ok"})

@app.route("/api/capture/<session_id>/resume", methods=["POST"])
def api_capture_resume(session_id):
    resume_capture(session_id)
    return jsonify({"status": "ok"})

@app.route("/api/capture/<session_id>/stop", methods=["POST"])
def api_capture_stop(session_id):
    stop_capture(session_id)
    return jsonify({"status": "ok"})

@app.route("/api/capture/sessions", methods=["GET"])
def api_capture_sessions():
    return jsonify(get_all_sessions())

@app.route("/api/capture/files", methods=["GET"])
def api_capture_files():
    return jsonify(list_pcap_files())

@app.route("/api/capture/files/<filename>", methods=["DELETE"])
def api_delete_pcap(filename):
    ok = delete_pcap(filename)
    return jsonify({"status": "ok" if ok else "not_found"})

@app.route("/api/capture/files/<filename>/download")
def api_download_pcap(filename):
    return send_from_directory(CAPTURES_DIR, filename, as_attachment=True)

@app.route("/api/firewall/rules", methods=["GET"])
def api_get_rules():
    return jsonify(get_all_rules())

@app.route("/api/firewall/rules", methods=["POST"])
def api_add_rule():
    body      = request.get_json(silent=True) or {}
    device_ip = body.get("device_ip", "")
    dest_ip   = body.get("dest_ip", "")
    dest_port = body.get("dest_port", "any")
    protocol  = body.get("protocol", "TCP")
    direction = body.get("direction", "out")
    if not device_ip or not dest_ip:
        return jsonify({"status": "error", "message": "device_ip and dest_ip required"}), 400
    ok, msg = add_rule(device_ip, dest_ip, dest_port, protocol, direction)
    return jsonify({"status": "ok" if ok else "error", "message": msg})

@app.route("/api/firewall/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    ok, msg = delete_rule(rule_id)
    return jsonify({"status": "ok" if ok else "error", "message": msg})

@app.route("/api/firewall/rules/<int:rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id):
    ok, msg = toggle_rule(rule_id)
    return jsonify({"status": "ok" if ok else "error", "message": msg})

@app.route("/api/firewall/filter/start", methods=["POST"])
def api_filter_start():
    start_filter()
    return jsonify({"status": "ok", "active": True})

@app.route("/api/firewall/filter/stop", methods=["POST"])
def api_filter_stop():
    stop_filter()
    return jsonify({"status": "ok", "active": False})

@app.route("/api/firewall/filter/status", methods=["GET"])
def api_filter_status():
    return jsonify(get_filter_status())

@app.route("/api/firewall/cleanup", methods=["POST"])
def api_cleanup_rules():
    cleanup_all_rules()
    return jsonify({"status": "ok"})



@app.route("/api/ips/status", methods=["GET"])
def api_ips_status():
    return jsonify({"active": get_monitor_status()})

@app.route("/api/ips/start", methods=["POST"])
def api_ips_start():
    start_monitor()
    return jsonify({"status": "ok", "active": True})

@app.route("/api/ips/stop", methods=["POST"])
def api_ips_stop():
    stop_monitor()
    return jsonify({"status": "ok", "active": False})

@app.route("/api/ips/configs", methods=["GET"])
def api_ips_configs():
    return jsonify(get_all_ips_configs())

@app.route("/api/ips/config/<mac>", methods=["POST"])
def api_set_ips_config(mac):
    mac  = mac.upper()
    body = request.get_json(silent=True) or {}
    set_ips_config(
        mac,
        body.get("max_rate_kbps",    1000.0),
        body.get("min_rate_kbps",    10.0),
        body.get("throttle_minutes", 5),
        body.get("alert_email",      ""),
        body.get("enabled",          1),
    )
    return jsonify({"status": "ok"})

@app.route("/api/ips/alerts", methods=["GET"])
def api_ips_alerts():
    limit = int(request.args.get("limit", 100))
    return jsonify(get_alerts(limit))

@app.route("/api/ips/alerts/<int:alert_id>", methods=["DELETE"])
def api_delete_alert(alert_id):
    delete_alert(alert_id)
    return jsonify({"status": "ok"})

@app.route("/api/ips/alerts/clear", methods=["POST"])
def api_clear_alerts():
    clear_alerts()
    return jsonify({"status": "ok"})

@app.route("/api/ips/settings", methods=["GET"])
def api_ips_settings():
    return jsonify(get_all_settings())

@app.route("/api/ips/settings", methods=["POST"])
def api_save_settings():
    body = request.get_json(silent=True) or {}
    # only alert_email is exposed in the UI; smtp creds are hardcoded in ips.py
    for k in ("alert_email",):
        if k in body:
            set_setting(k, body[k])
    return jsonify({"status": "ok"})

@app.route("/api/logs/history/<mac>", methods=["GET"])
def api_traffic_history(mac):
    mac  = mac.upper()
    days = int(request.args.get("days", 7))
    return jsonify(get_traffic_history(mac, days))

@app.route("/api/logs/history", methods=["DELETE"])
def api_delete_history():
    mac = request.args.get("mac")
    if mac:
        mac = mac.upper()
    delete_history(mac)
    return jsonify({"status": "ok"})


@app.errorhandler(404)
def not_found(e):
    return redirect("/")

if __name__ == "__main__":
    import threading, webbrowser
    threading.Timer(1.0, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
