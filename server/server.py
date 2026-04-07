import time
from scapy.all import sniff, TCP, IP, UDP
from collections import defaultdict, deque
import numpy as np
from detector import FEATURES, predict_flow
from flask import Flask, jsonify, request, render_template
import threading
from flask_socketio import SocketIO
# -------------------------------
# Flow storage
# -------------------------------
flows = defaultdict(lambda: deque(maxlen=1000))  # store last 1000 packets per flow
latest_features = None
latest_prediction = "BENIGN"

latest_result = {
    "Flow Bytes/s": 0,
    "Flow Duration": 0,
    "Flow Packets/s": 0,
    "prediction": "BENIGN"
}


last_emit_time = 0 

# Add these globals

stats_buffer = {

    "packets": 0,

    "bytes": 0,

    "latest_pred": "BENIGN",

    "last_flow": {}

}


def emit_loop():

    """Background thread to send updates once per second"""

    global stats_buffer

    while True:

        time.sleep(1) # Wait 1 second

        if stats_buffer["packets"] > 0:

            # Emit the aggregated stats

            socketio.emit("new_prediction", {

                "Flow Packets/s": stats_buffer["packets"],

                "Flow Bytes/s": stats_buffer["bytes"],

                "prediction": stats_buffer["latest_pred"],

                "details": stats_buffer["last_flow"]

            })

            # Reset buffer for the next second

            stats_buffer["packets"] = 0

            stats_buffer["bytes"] = 0


# -------------------------------
# Feature extraction
# -------------------------------
def extract_features(flow_packets):
    if not flow_packets:
        return None

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
    global latest_result, last_emit_time # Add last_emit_time here

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
        'time': pkt.time,
        'len': len(pkt),
        'dir': direction,
        'window': window,
        'flags': flags,
        'src_port': src_port,
        'dst_port': dst_port
    })

    features = extract_features(flows[flow_key])

    if features:
        try:
            pred = predict_flow(features)
            
            # Print to backend console for debugging
            print(f"[+] Flow {flow_key} -> {pred}")

            latest_result = {
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other",
                "Flow Bytes/s": features.get("Flow Bytes/s", 0),
                "Flow Duration": features.get("Flow Duration", 0), 
                "Flow Packets/s": features.get("Flow Packets/s", 0),
                "prediction": pred
            }

            current_time = time.time()
            
            # 🔥 THE FIX: Emit immediately if it's an attack, OR if 0.5 seconds have passed
            if pred != "BENIGN" or (current_time - last_emit_time > 0.5):
                socketio.emit("new_prediction", latest_result)
                last_emit_time = current_time

        except Exception as e:
            print(f"Prediction error: {e}")

# -------------------------------
# Flask API
# -------------------------------
app = Flask(__name__)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# @app.route("/predict", methods=["POST"])
# def predict():
#     global latest_result
#     return jsonify(latest_result), 200

@app.route("/", methods=["GET"])
def get_flows():
    return render_template("dashboard.html")    
# -------------------------------
# Run sniffing in background thread
# -------------------------------
if __name__ == "__main__":
    print("[*] Starting IDS...")

    sniff_thread = threading.Thread(target=lambda: sniff(
        iface="wlxe009bf682ec1",
        prn=process_packet,
        store=0
    ))
    sniff_thread.daemon = True
    sniff_thread.start()

    print("[*] Flask running with WebSocket at http://localhost:5000")
    socketio.run(app, debug=True)