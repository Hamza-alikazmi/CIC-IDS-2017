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