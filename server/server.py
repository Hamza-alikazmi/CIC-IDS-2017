import time
from scapy.all import sniff, TCP, IP, UDP
from collections import defaultdict, deque
import numpy as np
from detector import predict_flow

# Flow key = (src_ip, dst_ip, src_port, dst_port, protocol)
flows = defaultdict(lambda: deque(maxlen=1000))  # store last 1000 packets per flow
import numpy as np

def extract_features(flow_packets):
    if not flow_packets:
        return None
    
    packets = flow_packets

    # Basic packet counts
    total_fwd = sum(1 for p in packets if p['dir'] == 'fwd')
    total_bwd = sum(1 for p in packets if p['dir'] == 'bwd')
    total_pkts = len(packets)
    
    # Bytes
    fwd_bytes = sum(p['len'] for p in packets if p['dir'] == 'fwd')
    bwd_bytes = sum(p['len'] for p in packets if p['dir'] == 'bwd')
    
    # Packet lengths
    pkt_lengths = [p['len'] for p in packets]
    fwd_lengths = [p['len'] for p in packets if p['dir'] == 'fwd']
    bwd_lengths = [p['len'] for p in packets if p['dir'] == 'bwd']

    # Inter-arrival times
    times = [p['time'] for p in packets]
    flow_duration = max(times) - min(times) if times else 0
    flow_iat = np.diff(times) if len(times) > 1 else np.array([0])
    fwd_iat = np.diff([p['time'] for p in packets if p['dir']=='fwd']) if total_fwd > 1 else np.array([0])
    bwd_iat = np.diff([p['time'] for p in packets if p['dir']=='bwd']) if total_bwd > 1 else np.array([0])
    
    # Flags counts
    syn_count = sum('S' in p['flags'] for p in packets)
    ack_count = sum('A' in p['flags'] for p in packets)
    psh_count = sum('P' in p['flags'] for p in packets)
    rst_count = sum('R' in p['flags'] for p in packets)
    fin_count = sum('F' in p['flags'] for p in packets)

    # Average sizes (safe)
    avg_pkt_size = np.mean(pkt_lengths) if pkt_lengths else 0
    avg_fwd_seg = np.mean(fwd_lengths) if fwd_lengths else 0
    avg_bwd_seg = np.mean(bwd_lengths) if bwd_lengths else 0

    # Window sizes (approximate)
    init_win_fwd = packets[0]['window'] if total_fwd > 0 else 0
    init_win_bwd = packets[0]['window'] if total_bwd > 0 else 0

    # Active/Idle times
    iats = np.diff(times) if len(times) > 1 else np.array([0])
    idle_times = iats[iats > 1.0] if np.any(iats > 1.0) else np.array([0])
    active_times = iats[iats <= 1.0] if np.any(iats <= 1.0) else np.array([0])

    # Safe mean/std function
    safe_mean = lambda arr: float(np.mean(arr)) if len(arr) > 0 else 0
    safe_std  = lambda arr: float(np.std(arr, ddof=0)) if len(arr) > 0 else 0

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
        "Fwd Header Length": 0,  # optional
        "Bwd Header Length": 0,
        "SYN Flag Count": syn_count,
        "ACK Flag Count": ack_count,
        "PSH Flag Count": psh_count,
        "RST Flag Count": rst_count,
        "FIN Flag Count": fin_count,
        "Average Packet Size": avg_pkt_size,
        "Avg Fwd Segment Size": avg_fwd_seg,
        "Avg Bwd Segment Size": avg_bwd_seg,
        "Subflow Fwd Packets": total_fwd,  # approximate
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

def process_packet(pkt):
    if IP not in pkt:
        return

    proto = pkt[IP].proto
    src = pkt[IP].src
    dst = pkt[IP].dst
    src_port = pkt.sport if hasattr(pkt, 'sport') else 0
    dst_port = pkt.dport if hasattr(pkt, 'dport') else 0

    # Determine direction (fwd if src is local)
    direction = 'fwd' if src.startswith('192.168.') else 'bwd'
    window = pkt[TCP].window if TCP in pkt else 0
    flags = pkt[TCP].sprintf('%TCP.flags%') if TCP in pkt else ''

    # Save packet info
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

    # Extract features and predict
    features = extract_features(flows[flow_key])
    if features:
        pred = predict_flow(features)
        print(f"[+] Flow {flow_key} -> {pred}")
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    prediction = predict_flow(data)
    print(f"Received data for prediction: {data} -> {prediction}")

    # Return a proper JSON response
    return jsonify({
        "Flow Bytes/s": data.get("Flow Bytes/s"),
        "Flow Duration": data.get("Flow Duration"),
        "Flow Packets/s": data.get("Flow Packets/s"),
        "prediction": prediction
    }), 200

if __name__ == "__main__":
    print("[*] Starting live capture...")
    sniff(iface="wlxe009bf682ec1", prn=process_packet, store=0)