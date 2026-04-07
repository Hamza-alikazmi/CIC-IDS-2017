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

# Load trained model
model = joblib.load("ids_model.pkl")

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
    # Convert dict to list in FEATURE order
    flow_array = [flow_dict[f] for f in FEATURES]  # list of 42 values
    df = pd.DataFrame([flow_array], columns=FEATURES)
    prediction = model.predict(df)[0]
    return prediction


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
def get_active_interfaces():
    interfaces = []
    blacklist = ["lo", "docker", "virbr", "veth", "loopback"]
    try:
        for iface in get_if_list():
            if not any(b in iface.lower() for b in blacklist):
                interfaces.append(iface)
    except Exception:
        pass

    if not interfaces:
        stats = psutil.net_if_stats()
        for iface, stat in stats.items():
            if stat.isup and not any(b in iface.lower() for b in blacklist):
                interfaces.append(iface)
    return list(set(interfaces))

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
            pred = predict_flow(features)
            
            latest_result = {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other",
                "Flow Bytes/s": features.get("Flow Bytes/s", 0),
                "Flow Duration": features.get("Flow Duration", 0) * 1000, 
                "Flow Packets/s": features.get("Flow Packets/s", 0),
                "prediction": pred
            }

            current_time = time.time()
            
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
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route("/", methods=["GET"])
def get_flows():
    return render_template("dashboard.html")    

@app.route("/interfaces", methods=["GET"])
def interfaces():
    try:
        return jsonify(get_active_interfaces())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/start", methods=["POST"])
def start_sniff():
    global sniff_thread, stop_sniff_flag
    iface = request.json.get("interface") or auto_select_interface()
    
    if sniff_thread and sniff_thread.is_alive():
        return jsonify({"status": "already running"})

    stop_sniff_flag = False
    sniff_thread = threading.Thread(target=lambda: sniff(
        iface=iface, prn=process_packet, store=0, stop_filter=lambda x: stop_sniff_flag
    ))
    sniff_thread.daemon = True
    sniff_thread.start()
    return jsonify({"status": "started", "interface": iface})

@app.route("/stop", methods=["POST"])
def stop_sniff():
    global sniff_thread, stop_sniff_flag
    if sniff_thread and sniff_thread.is_alive():
        stop_sniff_flag = True 
        sniff_thread.join(timeout=2.0) 
        sniff_thread = None
        return jsonify({"status": "stopped"})
    return jsonify({"status": "not running"})

if __name__ == "__main__":
    print("[*] Starting IDS Server...")
    print("[*] Flask running with WebSocket at http://localhost:5000")
    socketio.run(app, debug=False)