"""
Smart Router — Flask Application
=================================
Entry point. Registers all routes for the Device Discovery module.

Run:
    sudo python app.py          # root needed for ARP scanning
    or
    sudo flask run --host=0.0.0.0
"""

from flask import Flask, jsonify, request, render_template, abort
from modules.device_discovery import (
    init_db,
    run_scan,
    get_all_devices,
    update_device,
    toggle_block,
    start_auto_scan,
    stop_auto_scan,
)

app = Flask(__name__)

# ─── Startup ──────────────────────────────────────────────────────────────────

init_db()

# Change this to match your hotspot network range, e.g.:
#   Windows hotspot:  192.168.137.0/24
#   macOS hotspot:    192.168.2.0/24
#   Linux hostapd:    10.0.0.0/24
HOTSPOT_NETWORK = "192.168.1.0/24"


# ─── Page routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── API: Devices ─────────────────────────────────────────────────────────────

@app.route("/api/devices", methods=["GET"])
def api_get_devices():
    """Return all devices as JSON."""
    return jsonify(get_all_devices())


@app.route("/api/devices/scan", methods=["POST"])
def api_scan():
    """
    Trigger an immediate scan.
    Optional JSON body: { "network": "192.168.1.0/24" }
    """
    body = request.get_json(silent=True) or {}
    network = body.get("network", HOTSPOT_NETWORK)
    try:
        devices = run_scan(network)
        return jsonify({"status": "ok", "found": len(devices), "devices": devices})
    except PermissionError:
        return jsonify({"status": "error", "message": "Root/admin privileges required for ARP scan."}), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/devices/<mac>", methods=["PATCH"])
def api_update_device(mac: str):
    """
    Update editable fields for a device.
    Body: { "name": "...", "model": "...", "description": "...", "ipv6": "..." }
    """
    mac = mac.upper()
    data = request.get_json(silent=True)
    if not data:
        abort(400, "JSON body required")
    update_device(mac, data)
    return jsonify({"status": "ok"})


@app.route("/api/devices/<mac>/block", methods=["POST"])
def api_toggle_block(mac: str):
    """Toggle the blocked state for a device."""
    mac = mac.upper()
    new_state = toggle_block(mac)
    return jsonify({"status": "ok", "blocked": new_state})


# ─── API: Auto-scan control ───────────────────────────────────────────────────

@app.route("/api/autoscan/start", methods=["POST"])
def api_start_autoscan():
    body = request.get_json(silent=True) or {}
    interval = int(body.get("interval", 30))
    network  = body.get("network", HOTSPOT_NETWORK)
    start_auto_scan(network, interval)
    return jsonify({"status": "ok", "interval": interval})


@app.route("/api/autoscan/stop", methods=["POST"])
def api_stop_autoscan():
    stop_auto_scan()
    return jsonify({"status": "ok"})


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
