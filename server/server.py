import time
import psutil
from scapy.all import sniff, TCP, IP, UDP, get_if_list
from collections import defaultdict, deque
import numpy as np
from flask import Flask, jsonify, request, render_template
import threading
from flask_socketio import SocketIO
import joblib
import pandas as pd
from pathlib import Path
import ipaddress
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
import socket
import os
import logging
import json
import datetime
# -------------------------------
# 🛡️ SOC Logging Configuration
# -------------------------------
HOME_DIR = os.path.expanduser("~")
APP_DIR = os.path.join(HOME_DIR, ".nids_app")

# Create the directory if it doesn't exist
if not os.path.exists(APP_DIR):
    os.makedirs(APP_DIR)

log_file_path = os.path.join(APP_DIR, 'nids.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - NIDS_CORE - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__) 

# -------------------------------
# Wazuh Syslog Integration
# -------------------------------
WAZUH_ENABLED = os.getenv("WAZUH_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
WAZUH_HOST = os.getenv("WAZUH_HOST", "wazuh.manager")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "514"))
WAZUH_PROTOCOL = os.getenv("WAZUH_PROTOCOL", "udp").lower()
WAZUH_FACILITY = int(os.getenv("WAZUH_FACILITY", "1"))  # 1 = user
WAZUH_APP_NAME = os.getenv("WAZUH_APP_NAME", "cic-ids-nids")
WAZUH_FORWARDER_HOSTNAME = os.getenv("HOSTNAME", socket.gethostname())


def send_wazuh_alert(result):
    """Forward an alert to Wazuh using syslog (UDP or TCP)."""
    if not WAZUH_ENABLED:
        return False

    alert = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "integration": "cic-ids-2017",
        "rule": {"description": "CIC-IDS-2017 network intrusion detected"},
        "data": dict(result),
    }
    priority = WAZUH_FACILITY * 8 + 4  # warning
    message = (
        f"<{priority}>1 {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
        f"{WAZUH_FORWARDER_HOSTNAME} {WAZUH_APP_NAME} - - - {json.dumps(alert, default=str)}"
    ).encode("utf-8")

    try:
        if WAZUH_PROTOCOL == "tcp":
            with socket.create_connection((WAZUH_HOST, WAZUH_PORT), timeout=3) as sock:
                sock.sendall(message + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(message, (WAZUH_HOST, WAZUH_PORT))
        return True
    except Exception as exc:
        logger.error("Failed to forward alert to Wazuh %s:%s: %s", WAZUH_HOST, WAZUH_PORT, exc)
        return False

# Load trained model
BASE_DIR = Path(__file__).resolve().parent

# Load the model relative to server.py
model_path = BASE_DIR / "ids_model.pkl"
model = joblib.load(model_path)

FEATURES = [
    "Destination Port","Flow Duration","Flow Bytes/s","Flow Packets/s",
    "Total Fwd Packets","Total Backward Packets",
    "Total Length of Fwd Packets","Total Length of Bwd Packets",
    "Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Mean","Bwd Packet Length Std",
    "Packet Length Mean","Packet Length Std",
    "Flow IAT Mean","Flow IAT Std",
    "Fwd IAT Mean","Fwd IAT Std",
    "Bwd IAT Mean","Bwd IAT Std",
    "Fwd Packets/s","Bwd Packets/s",
    "Fwd Header Length","Bwd Header Length",
    "SYN Flag Count","ACK Flag Count","PSH Flag Count",
    "RST Flag Count","FIN Flag Count",
    "Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size",
    "Subflow Fwd Packets","Subflow Fwd Bytes",
    "Subflow Bwd Packets","Subflow Bwd Bytes",
    "Init_Win_bytes_forward","Init_Win_bytes_backward",
    "Active Mean","Active Std","Idle Mean","Idle Std"
]

def predict_flow(flow_dict):
    # Convert dict to list in FEATURE order (defaulting missing features to 0)
    flow_array = [flow_dict.get(f, 0) for f in FEATURES]  # list of 42 values
    df = pd.DataFrame([flow_array], columns=FEATURES)
    prediction = model.predict(df)[0]
    return prediction

# -------------------------------
# 🛡️ Trusted Whitelist (Google DNS & False-Positive Prevention)
# -------------------------------
DEFAULT_WHITELIST = {
    "8.8.8.8": "Google Public DNS Primary",
    "8.8.4.4": "Google Public DNS Secondary",
    "2001:4860:4860::8888": "Google Public DNS IPv6",
    "2001:4860:4860::8884": "Google Public DNS IPv6",
    "1.1.1.1": "Cloudflare DNS Primary",
    "1.0.0.1": "Cloudflare DNS Secondary",
    "9.9.9.9": "Quad9 DNS Primary"
}
whitelisted_ips = dict(DEFAULT_WHITELIST)

def is_whitelisted(src, dst, src_port=0, dst_port=0):
    if src in whitelisted_ips:
        return True, whitelisted_ips[src]
    if dst in whitelisted_ips:
        return True, whitelisted_ips[dst]
    return False, None

# -------------------------------
# 🔍 WHOIS Intelligence & Threat Attribution
# -------------------------------
whois_cache = {}
whois_pending = set()
whois_executor = ThreadPoolExecutor(max_workers=5)

def perform_whois_lookup(ip_str):
    if not ip_str or not isinstance(ip_str, str):
        return {"error": "Invalid IP address"}

    if ip_str in whois_cache:
        return whois_cache[ip_str]

    # Check for private/bogon/loopback IP
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            hostname = ip_str
            try:
                hostname = socket.gethostbyaddr(ip_str)[0]
            except Exception:
                pass
            info = {
                "ip": ip_str,
                "is_private": True,
                "org": "Private / Internal LAN (RFC 1918)",
                "net_name": "Local Network Subnet",
                "country": "LOCAL / LAN",
                "net_range": "Private IP Space (Non-routable)",
                "hostname": hostname,
                "raw": f"IP Address: {ip_str}\nClassification: RFC 1918 Private / Local Network\nHostname / Reverse DNS: {hostname}\nNote: Local and private addresses cannot be queried on public WHOIS registries."
            }
            whois_cache[ip_str] = info
            return info
    except Exception:
        pass

    # Public IP lookup
    info = {
        "ip": ip_str,
        "is_private": False,
        "org": "Unknown Organization",
        "net_name": "Unknown Network",
        "country": "Unknown",
        "net_range": "Unknown Range",
        "hostname": ip_str,
        "raw": ""
    }

    try:
        info["hostname"] = socket.gethostbyaddr(ip_str)[0]
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["whois", ip_str],
            capture_output=True,
            text=True,
            timeout=6
        )
        out = proc.stdout if proc.stdout else proc.stderr or ""
        info["raw"] = out[:4000]

        org_match = re.search(r'(?i)(?:OrgName|organisation|organization|descr|owner):\s*([^\r\n]+)', out)
        net_match = re.search(r'(?i)(?:NetName|netname):\s*([^\r\n]+)', out)
        country_match = re.search(r'(?i)(?:Country|country):\s*([A-Za-z]{2,})', out)
        range_match = re.search(r'(?i)(?:CIDR|inetnum|NetRange):\s*([^\r\n]+)', out)

        if org_match: info["org"] = org_match.group(1).strip()
        if net_match: info["net_name"] = net_match.group(1).strip()
        if country_match: info["country"] = country_match.group(1).strip().upper()
        if range_match: info["net_range"] = range_match.group(1).strip()
    except subprocess.TimeoutExpired:
        info["org"] = "Lookup Timeout"
        info["raw"] = f"WHOIS query for {ip_str} timed out after 6 seconds."
    except Exception as e:
        info["org"] = "Lookup Failed"
        info["raw"] = f"Error during WHOIS query: {e}"

    whois_cache[ip_str] = info
    return info

def _async_whois_handler(src_ip, threat_type, dst_ip, src_port, dst_port):
    try:
        whois_data = perform_whois_lookup(src_ip)
        logger.warning(
            f"WHOIS SOURCE TRACE: IP={src_ip}, Threat='{threat_type}', Org='{whois_data.get('org')}', Net='{whois_data.get('net_name')}', Country='{whois_data.get('country')}'"
        )
        socketio.emit("whois_result", {
            "src_ip": src_ip,
            "threat_type": threat_type,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "whois": whois_data
        })
    except Exception as e:
        logger.error(f"Error during async WHOIS lookup for {src_ip}: {e}")
    finally:
        whois_pending.discard(src_ip)



# -------------------------------
# Flow storage & Globals
# -------------------------------
flows = defaultdict(lambda: deque(maxlen=1000))
last_emit_time = 0 
sniff_thread = None
stop_sniff_flag = False

# -------------------------------
# Interface Helpers
# -------------------------------
# -------------------------------
# Interface Helpers
# -------------------------------
import socket

def get_active_interfaces():

    interfaces = []

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    print("\n===== DEBUGGING INTERFACES =====")

    for iface, stat in stats.items():

        print(f"\nInterface: {iface}")
        print(f"UP: {stat.isup}")

        if iface in addrs:

            for addr in addrs[iface]:

                print("ADDR:", addr.family, addr.address)

        interfaces.append(iface)

    print("================================\n")

    return interfaces


def auto_select_interface():
    active = get_active_interfaces()

    for iface in active:
        if iface.startswith("wl"):
            return iface

    for iface in active:
        if iface.startswith("en"):
            return iface

    return active[0] if active else None

def auto_select_interface():
    active = get_active_interfaces()
    for iface in active:
        if any(keyword in iface.lower() for keyword in ["wl", "eth", "wi-fi", "ethernet"]):
            return iface
    return active[0] if active else None

# -------------------------------
# Feature extraction
# -------------------------------
def extract_features(flow_packets):
    if not flow_packets: return None
    packets = flow_packets
    total_fwd = sum(1 for p in packets if p['dir'] == 'fwd')
    total_bwd = sum(1 for p in packets if p['dir'] == 'bwd')
    total_pkts = len(packets)

    fwd_bytes = sum(p['len'] for p in packets if p['dir'] == 'fwd')
    bwd_bytes = sum(p['len'] for p in packets if p['dir'] == 'bwd')

    pkt_lengths = [p['len'] for p in packets]
    fwd_lengths = [p['len'] for p in packets if p['dir'] == 'fwd']
    bwd_lengths = [p['len'] for p in packets if p['dir'] == 'bwd']

    times = [p['time'] for p in packets]
    flow_duration = max(times) - min(times) if times else 0
    flow_iat = np.diff(times) if len(times) > 1 else np.array([0])
    fwd_iat = np.diff([p['time'] for p in packets if p['dir'] == 'fwd']) if total_fwd > 1 else np.array([0])
    bwd_iat = np.diff([p['time'] for p in packets if p['dir'] == 'bwd']) if total_bwd > 1 else np.array([0])

    syn_count = sum('S' in p['flags'] for p in packets)
    ack_count = sum('A' in p['flags'] for p in packets)
    psh_count = sum('P' in p['flags'] for p in packets)
    rst_count = sum('R' in p['flags'] for p in packets)
    fin_count = sum('F' in p['flags'] for p in packets)

    safe_mean = lambda arr: float(np.mean(arr)) if len(arr) > 0 else 0
    safe_std = lambda arr: float(np.std(arr, ddof=0)) if len(arr) > 0 else 0

    iats = np.diff(times) if len(times) > 1 else np.array([0])
    idle_times = iats[iats > 1.0] if np.any(iats > 1.0) else np.array([0])
    active_times = iats[iats <= 1.0] if np.any(iats <= 1.0) else np.array([0])

    init_win_fwd = packets[0]['window'] if total_fwd > 0 else 0
    init_win_bwd = packets[0]['window'] if total_bwd > 0 else 0

    features = {
        "Destination Port": packets[-1]['dst_port'],
        "Flow Duration": flow_duration,
        "Flow Bytes/s": sum(pkt_lengths)/flow_duration if flow_duration > 0 else 0,
        "Flow Packets/s": total_pkts/flow_duration if flow_duration > 0 else 0,
        "Total Fwd Packets": total_fwd,
        "Total Backward Packets": total_bwd,
        "Total Length of Fwd Packets": fwd_bytes,
        "Total Length of Bwd Packets": bwd_bytes,
        "Fwd Packet Length Mean": safe_mean(fwd_lengths),
        "Fwd Packet Length Std": safe_std(fwd_lengths),
        "Bwd Packet Length Mean": safe_mean(bwd_lengths),
        "Bwd Packet Length Std": safe_std(bwd_lengths),
        "Packet Length Mean": safe_mean(pkt_lengths),
        "Packet Length Std": safe_std(pkt_lengths),
        "Flow IAT Mean": safe_mean(flow_iat),
        "Flow IAT Std": safe_std(flow_iat),
        "Fwd IAT Mean": safe_mean(fwd_iat),
        "Fwd IAT Std": safe_std(fwd_iat),
        "Bwd IAT Mean": safe_mean(bwd_iat),
        "Bwd IAT Std": safe_std(bwd_iat),
        "Fwd Packets/s": total_fwd/flow_duration if flow_duration>0 else 0,
        "Bwd Packets/s": total_bwd/flow_duration if flow_duration>0 else 0,
        "Fwd Header Length": 0,
        "Bwd Header Length": 0,
        "SYN Flag Count": syn_count,
        "ACK Flag Count": ack_count,
        "PSH Flag Count": psh_count,
        "RST Flag Count": rst_count,
        "FIN Flag Count": fin_count,
        "Average Packet Size": safe_mean(pkt_lengths),
        "Avg Fwd Segment Size": safe_mean(fwd_lengths),
        "Avg Bwd Segment Size": safe_mean(bwd_lengths),
        "Subflow Fwd Packets": total_fwd,
        "Subflow Fwd Bytes": fwd_bytes,
        "Subflow Bwd Packets": total_bwd,
        "Subflow Bwd Bytes": bwd_bytes,
        "Init_Win_bytes_forward": init_win_fwd,
        "Init_Win_bytes_backward": init_win_bwd,
        "Active Mean": safe_mean(active_times),
        "Active Std": safe_std(active_times),
        "Idle Mean": safe_mean(idle_times),
        "Idle Std": safe_std(idle_times)
    }
    return features

# -------------------------------
# Packet processing
# -------------------------------
def process_packet(pkt):
    global last_emit_time

    if IP not in pkt:
        return

    proto = pkt[IP].proto
    src = pkt[IP].src
    dst = pkt[IP].dst
    src_port = pkt.sport if hasattr(pkt, 'sport') else 0
    dst_port = pkt.dport if hasattr(pkt, 'dport') else 0

    direction = 'fwd' if src < dst else 'bwd'
    window = pkt[TCP].window if TCP in pkt else 0
    flags = pkt[TCP].sprintf('%TCP.flags%') if TCP in pkt else ''

    flow_key = (src, dst, src_port, dst_port, proto)

    flows[flow_key].append({
        'time': pkt.time, 'len': len(pkt), 'dir': direction,
        'window': window, 'flags': flags, 'src_port': src_port, 'dst_port': dst_port
    })

    features = extract_features(flows[flow_key])

    if features:
        try:
            raw_pred = predict_flow(features)
            
            # 🛡️ Check Whitelist (Google DNS, trusted services) to suppress false positives
            whitelisted, wl_reason = is_whitelisted(src, dst, src_port, dst_port)
            if whitelisted and raw_pred != "BENIGN":
                pred = "BENIGN"
                logger.info(f"BENIGN OVERRIDE: Suppressed false alarm '{raw_pred}' for trusted traffic ({src}:{src_port} -> {dst}:{dst_port}) matching '{wl_reason}'.")
            else:
                pred = raw_pred
            
            latest_result = {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other",
                "Flow Bytes/s": features.get("Flow Bytes/s", 0),
                "Flow Duration": features.get("Flow Duration", 0) * 1000, 
                "Flow Packets/s": features.get("Flow Packets/s", 0),
                "prediction": pred,
                "whitelisted": whitelisted,
                "whitelist_reason": wl_reason if whitelisted else None
            }

            current_time = time.time()
            
            # 🛡️ SOC Logging & WHOIS Attribution
            if pred != "BENIGN":
                logger.warning(f"THREAT DETECTED: Type='{pred}', Source={src}:{src_port}, Target={dst}:{dst_port}, Proto={latest_result['protocol']}")
                send_wazuh_alert(latest_result)
                
                # Check WHOIS cache or dispatch non-blocking background lookup
                cached_whois = whois_cache.get(src)
                if cached_whois:
                    latest_result["whois"] = cached_whois
                else:
                    latest_result["whois"] = {"status": "resolving", "ip": src, "org": "Resolving WHOIS..."}
                    if src not in whois_pending:
                        whois_pending.add(src)
                        whois_executor.submit(_async_whois_handler, src, pred, dst, src_port, dst_port)

            # Always emit if it is an attack, OR if 0.5 seconds have passed (for smooth graph)
            if pred != "BENIGN" or (current_time - last_emit_time > 0.5):
                socketio.emit("new_prediction", latest_result)
                last_emit_time = current_time

        except Exception as e:
            pass

# -------------------------------
# Flask API Routes
# -------------------------------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*",async_mode='threading')

@app.route("/", methods=["GET"])
def get_flows():
    return render_template("dashboard.html")    

@app.route("/form", methods=["GET"])
def form_view():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True) or {}
        src = data.get("src_ip", "")
        dst = data.get("dst_ip", "")
        raw_pred = predict_flow(data)
        whitelisted, wl_reason = is_whitelisted(src, dst)
        if whitelisted and raw_pred != "BENIGN":
            prediction = "BENIGN"
        else:
            prediction = raw_pred
        return jsonify({
            "prediction": str(prediction),
            "status": "success",
            "whitelisted": whitelisted,
            "whitelist_reason": wl_reason if whitelisted else None
        })
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        return jsonify({"error": str(e), "status": "error"}), 400

@app.route("/whois/<path:ip>", methods=["GET"])
def get_whois(ip):
    try:
        data = perform_whois_lookup(ip)
        return jsonify(data)
    except Exception as e:
        logger.error(f"WHOIS lookup error for {ip}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/whitelist", methods=["GET"])
def get_whitelist():
    return jsonify({"whitelist": whitelisted_ips, "count": len(whitelisted_ips)})

@app.route("/whitelist/add", methods=["POST"])
def add_whitelist():
    try:
        body = request.get_json(force=True) or {}
        ip = body.get("ip", "").strip()
        desc = body.get("description", "User Added Trusted Host").strip()
        if not ip:
            return jsonify({"error": "IP address is required"}), 400
        whitelisted_ips[ip] = desc
        logger.info(f"Added IP '{ip}' ({desc}) to trusted whitelist.")
        return jsonify({"status": "added", "ip": ip, "description": desc, "whitelist": whitelisted_ips})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/whitelist/remove", methods=["POST"])
def remove_whitelist():
    try:
        body = request.get_json(force=True) or {}
        ip = body.get("ip", "").strip()
        if ip in whitelisted_ips:
            desc = whitelisted_ips.pop(ip)
            logger.info(f"Removed IP '{ip}' ({desc}) from trusted whitelist.")
            return jsonify({"status": "removed", "ip": ip, "whitelist": whitelisted_ips})
        return jsonify({"error": f"IP '{ip}' not found in whitelist"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/interfaces", methods=["GET"])
def interfaces():
    try:
        ifaces = get_active_interfaces()

        print("Detected interfaces:", ifaces)

        logger.info(f"Loaded {len(ifaces)} network interfaces.")
        return jsonify(ifaces)

    except Exception as e:
        print(e)
        logger.error(f"Failed to load interfaces: {str(e)}")
        return jsonify({"error": str(e)}), 500
        

@app.route("/start", methods=["POST"])
def start_sniff():
    global sniff_thread, stop_sniff_flag
    iface = request.json.get("interface") or auto_select_interface()
    
    if sniff_thread and sniff_thread.is_alive():
        return jsonify({"status": "already running"})

    stop_sniff_flag = False
    def run_sniff():
        try:
            sniff(iface=iface, prn=process_packet, store=0, stop_filter=lambda x: stop_sniff_flag)
        except PermissionError:
            logger.error(
                f"Permission denied for live packet capture on interface '{iface}'. "
                "Packet sniffing requires raw socket capabilities: "
                "sudo setcap cap_net_raw,cap_net_admin=eip <python_binary>"
            )
        except Exception as e:
            logger.error(f"Error while sniffing on interface '{iface}': {e}")

    sniff_thread = threading.Thread(target=run_sniff)
    sniff_thread.daemon = True
    sniff_thread.start()
    
    logger.info(f"Started network monitoring on interface: {iface}")
    return jsonify({"status": "started", "interface": iface})

@app.route("/stop", methods=["POST"])
def stop_sniff():
    global sniff_thread, stop_sniff_flag
    if sniff_thread and sniff_thread.is_alive():
        stop_sniff_flag = True 
        sniff_thread.join(timeout=2.0) 
        sniff_thread = None
        
        logger.info("Network monitoring stopped by user.")
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not running"})

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "uptime": get_uptime_seconds()})

def get_uptime_seconds():
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            return int(uptime_seconds)
    except Exception:
        return 0

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "status": "running",
        "active_flows": len(flows),
        "capture_running": bool(sniff_thread and sniff_thread.is_alive()),
        "wazuh": {
            "enabled": WAZUH_ENABLED,
            "host": WAZUH_HOST,
            "port": WAZUH_PORT,
            "protocol": WAZUH_PROTOCOL
        },
        "whitelisted_ips": whitelisted_ips,
        "model_features": FEATURES
    })


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    logger.info("Starting NIDS web server on http://%s:%s", host, port)
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False)
