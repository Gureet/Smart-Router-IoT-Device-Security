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

init_db()

HOTSPOT_NETWORK = "192.168.137.0/24"

@app.route("/")
def index():
    return render_template("index.html")

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
    mac = mac.upper()
    new_state = toggle_block(mac)
    return jsonify({"status": "ok", "blocked": new_state})


#  API: Auto-scan control 

@app.route("/api/hotspot/status", methods=["GET"])
def api_hotspot_status():
    
    import subprocess
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "hostednetwork"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout.lower()
        if "started" in output:
            return jsonify({"active": True})
        result2 = subprocess.run(
            ["netsh", "wlan", "show", "settings"],
            capture_output=True, text=True, timeout=5
        )
        import scapy.all as scapy
        HOTSPOT_IFACE = "Local Area Connection* 4"
        ifaces = scapy.conf.ifaces
        for i in ifaces:
            if ifaces[i].name == HOTSPOT_IFACE:
                ip = ifaces[i].ip
                if ip and ip != "0.0.0.0":

                    from scapy.all import ARP, Ether, srp
                    arp_req = ARP(pdst="192.168.137.2/30")
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    answered, _ = srp(broadcast/arp_req, iface=HOTSPOT_IFACE, timeout=1, verbose=False)
                    gw = ARP(pdst="192.168.137.1")
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/gw, iface=HOTSPOT_IFACE, timeout=1, verbose=False)
                    return jsonify({"active": True})
        return jsonify({"active": False})
    except Exception as e:
        return jsonify({"active": False, "error": str(e)})



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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
