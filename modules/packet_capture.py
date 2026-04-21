import os
import threading
import time
from datetime import datetime
from scapy.all import sniff, PcapWriter

CAPTURES_DIR  = "captures"
HOTSPOT_IFACE = "Local Area Connection* 4"

# active sessions keyed by session_id
_captures = {}
_lock     = threading.Lock()

def _ensure_dir():
    os.makedirs(CAPTURES_DIR, exist_ok=True)

def start_capture(mac: str, ip: str, filename: str,
                  max_packets: int | None = None, max_duration: int | None = None) -> str:
    _ensure_dir()
    session_id = f"{mac.replace(':','')}_{int(time.time())}"
    filepath   = os.path.join(CAPTURES_DIR, filename if filename.endswith(".pcap") else filename + ".pcap")

    state = {
        "session_id":       session_id,
        "mac":              mac,
        "ip":               ip,
        "filename":         os.path.basename(filepath),
        "filepath":         filepath,
        "status":           "running",
        "packets_captured": 0,
        "max_packets":      max_packets,
        "max_duration":     max_duration,
        "start_time":       datetime.now().isoformat(timespec="seconds"),
        "stop_event":       threading.Event(),
        "pause_event":      threading.Event(),
        "error":            None,
    }

    with _lock:
        _captures[session_id] = state

    t = threading.Thread(target=_capture_loop, args=(session_id,), daemon=True)
    state["thread"] = t
    t.start()
    return session_id

def _capture_loop(session_id: str):
    state        = _captures[session_id]
    stop_event   = state["stop_event"]
    pause_event  = state["pause_event"]
    filepath     = state["filepath"]
    ip           = state["ip"]
    max_packets  = state["max_packets"]
    max_duration = state["max_duration"]
    start_ts     = time.time()

    try:
        writer = PcapWriter(filepath, append=False, sync=True)

        # scapy calls this to decide when to stop sniffing
        def _stop_filter(pkt):
            if stop_event.is_set():
                return True
            if max_duration and (time.time() - start_ts) >= max_duration:
                return True
            if max_packets and state["packets_captured"] >= max_packets:
                return True
            return False

        def _process(pkt):
            # wait while paused, drop if stopped
            while pause_event.is_set() and not stop_event.is_set():
                time.sleep(0.1)
            if stop_event.is_set():
                return
            writer.write(pkt)
            with _lock:
                state["packets_captured"] += 1

        sniff(filter=f"host {ip}", prn=_process, stop_filter=_stop_filter,
              store=False, iface=HOTSPOT_IFACE)
        writer.close()

        with _lock:
            state["status"] = "stopped" if stop_event.is_set() else "done"

    except Exception as e:
        with _lock:
            state["status"] = "error"
            state["error"]  = str(e)

def pause_capture(session_id: str):
    with _lock:
        s = _captures.get(session_id)
    if s and s["status"] == "running":
        s["pause_event"].set()
        with _lock:
            s["status"] = "paused"

def resume_capture(session_id: str):
    with _lock:
        s = _captures.get(session_id)
    if s and s["status"] == "paused":
        s["pause_event"].clear()
        with _lock:
            s["status"] = "running"

def stop_capture(session_id: str):
    with _lock:
        s = _captures.get(session_id)
    if s:
        s["pause_event"].clear()
        s["stop_event"].set()

def get_all_sessions() -> list[dict]:
    with _lock:
        return [{
            "session_id":       s["session_id"],
            "mac":              s["mac"],
            "ip":               s["ip"],
            "filename":         s["filename"],
            "status":           s["status"],
            "packets_captured": s["packets_captured"],
            "max_packets":      s["max_packets"],
            "max_duration":     s["max_duration"],
            "start_time":       s["start_time"],
            "error":            s["error"],
        } for s in _captures.values()]

def list_pcap_files() -> list[dict]:
    _ensure_dir()
    files = []
    for fname in os.listdir(CAPTURES_DIR):
        if fname.endswith(".pcap"):
            fpath = os.path.join(CAPTURES_DIR, fname)
            stat  = os.stat(fpath)
            files.append({
                "filename": fname,
                "size_kb":  round(stat.st_size / 1024, 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
    return sorted(files, key=lambda x: x["modified"], reverse=True)

def delete_pcap(filename: str) -> bool:
    fpath = os.path.join(CAPTURES_DIR, os.path.basename(filename))
    if os.path.exists(fpath):
        os.remove(fpath)
        return True
    return False
