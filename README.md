# CIC-IDS-2017

A research prototype for network intrusion detection using the CIC-IDS-2017 dataset.

This repository contains a simple flow-based IDS pipeline that extracts network flow features, loads a pre-trained model, and exposes a Flask prediction endpoint. It also includes cleaned dataset exports and analysis notebooks for preprocessing and evaluation.

## Why this project is useful

- Demonstrates live packet capture, flow feature extraction, and model prediction in Python.
- Provides an end-to-end research workflow for CIC-IDS-2017 data and traffic flows.
- Includes a ready-to-use trained model (`server/ids_model.pkl`) and a Flask `/predict` API.

## Project structure

- `main.py` — dataset preview script for `flows.csv`
- `server/server.py` — live capture and Flask prediction server
- `server/detector.py` — model loader and prediction logic
- `server/ids_model.pkl` — pre-trained IDS model used by `detector.py`
- `Cleaned_CSVs/` — cleaned CSV exports from CIC-IDS-2017 flows
- `uncleaned_csvs/` — raw CIC-IDS-2017 CSV files
- `cleaning.ipynb`, `main.ipynb` — notebooks for data cleaning and analysis

## Getting started

### 1. Create a virtual environment

```bash
cd /home/darkmatter/Project/FYP
python -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Preview the dataset

```bash
python main.py
```

### 4. Run the IDS server

```bash
python server/server.py
```

> Note: `server/server.py` currently uses the interface `wlxe009bf682ec1` for live packet capture and assumes local traffic is in the `192.168.*` subnet. Update those values to match your environment before running.

## Using the prediction API

The server exposes a JSON endpoint at `http://127.0.0.1:5000/predict`.

```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"Flow Bytes/s": 0, "Flow Duration": 1, "Flow Packets/s": 0, ... }'
```

## Threat Attribution (WHOIS) & Trusted Whitelist

- **WHOIS Intelligence**: When an attack is flagged, an asynchronous WHOIS query is dispatched on the source IP to determine the attacking organization, network name, CIDR, and country code without blocking packet sniffing.
  - API endpoint: `GET http://127.0.0.1:5000/whois/<ip>`
- **Trusted Whitelist (Google DNS)**: High-frequency queries to known DNS resolvers (such as Google DNS `8.8.8.8`, `8.8.4.4` and Cloudflare `1.1.1.1`) are pre-whitelisted and marked `BENIGN` to avoid false alerts when running recon tools.
  - View Whitelist: `GET http://127.0.0.1:5000/whitelist`
  - Add Whitelisted Host: `POST http://127.0.0.1:5000/whitelist/add` with `{"ip": "...", "description": "..."}`
  - Remove Whitelisted Host: `POST http://127.0.0.1:5000/whitelist/remove` with `{"ip": "..."}`
  - Web UI: Click the **Trusted Whitelist** button in the dashboard to view and manage whitelisted IPs.

The request body should contain flow features matching the feature set defined in `server/detector.py`.

## Important details

- `server/server.py` captures live packets using `scapy` and extracts features per flow.
- `server/detector.py` loads a LightGBM model from `server/ids_model.pkl` and predicts a label using the defined feature order.
- `main.py` is a simple dataset preview script and does not run the IDS server.

## Demo

Watch the project demonstration: [`CIC NIDS Demo.mp4`](Demo/CIC%20NIDS%20Demo.mp4).

The video is also stored in the [`Demo/`](Demo/) folder.

## Docker and Wazuh integration

### Run locally

```bash
./run.sh
```

The script creates or uses `.venv`, installs dependencies, and starts the server with sudo when needed for packet capture.

### Run with Docker

```bash
cp .env.example .env
./run-docker.sh
```

The dashboard is available at `http://127.0.0.1:5000`. Docker uses host networking and privileged mode so Scapy can access host interfaces.

Useful endpoints:

- `GET /health`
- `GET /status`
- `POST /start` with `{"interface":"eth0"}`
- `POST /stop`

### Forward alerts to Wazuh

Configure these environment variables before starting the server:

```bash
WAZUH_ENABLED=true
WAZUH_HOST=192.168.1.100
WAZUH_PORT=514
WAZUH_PROTOCOL=udp
```

Supported protocols are `udp` and `tcp`. Alert forwarding uses RFC 5424-style syslog and sends the detected flow as JSON. Configure the Wazuh manager or agent to listen on the selected syslog port and add/adjust a local decoder/rule for the `cic-ids-nids` application name.

Check configuration through `GET /status`.

## Model performance

The intrusion detection model is a Random Forest classifier trained on the CIC-IDS-2017 network flow dataset.

- **Training set score:** 0.9984 (99.84%)
- **Test set score:** 0.9984 (99.84%)

The consistent training and test scores indicate strong classification performance without a substantial score gap in this evaluation.

### Confusion matrix

The confusion matrix below compares the true traffic labels with the labels predicted by the Random Forest model across BENIGN traffic and multiple attack categories.

![Random Forest confusion matrix](Demo/confusion%20matrix.png)

### Top 20 selected features

Feature selection identified the following flow attributes as the most influential for model predictions:

- Destination Port
- Init_Win_bytes_backward
- Total Length of Bwd Packets
- Subflow Bwd Bytes
- Packet Length Mean
- Bwd Packet Length Mean
- Bwd Packets/s
- Flow Duration
- Fwd IAT Mean
- Flow IAT Mean
- Total Length of Fwd Packets
- Init_Win_bytes_forward
- Subflow Fwd Bytes
- Fwd Header Length
- Average Packet Size
- Packet Length Std
- Flow IAT Std
- Fwd Packet Length Mean
- Fwd IAT Std
- Fwd Packets/s

![Top 20 influential network features](Demo/Top%2020%20features.png)

## Contributing

- Fork the repository and create a feature branch.
- Submit a pull request with a clear description of changes.
- If you add new scripts or notebooks, update `README.md` accordingly.

## Need help?

- Open an issue in this repository.
- Inspect `server/server.py` and `server/detector.py` for implementation details.
- Use the included notebooks in `cleaning.ipynb` and `main.ipynb` for dataset and model exploration.

