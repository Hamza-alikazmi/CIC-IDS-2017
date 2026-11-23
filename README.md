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

The trained intrusion detection model loaded from `server/ids_model.pkl` is a **LightGBM classifier** trained on the CIC-IDS-2017 network flow dataset.

- **Training set score:** 0.9984 (99.84%)
- **Test set score:** 0.9984 (99.84%)
- **Model input size:** 42 features

The consistent training and test scores indicate strong classification performance without a substantial score gap in this evaluation.

### Feature handling and the 21st feature

The live server passes all 42 model features in the feature order defined in `server/server.py`. Missing features are defaulted to `0` by `flow_dict.get(feature, 0)`. This is not the same as feature selection: omitting or removing the 21st feature would be incorrect because the loaded model expects 42 columns.

According to the loaded model's `feature_importances_`, the 21st most important feature is **`Bwd IAT Std`**. It is calculated from backward inter-arrival times and is passed normally; it is **not automatically assigned zero** during live prediction.

Several features can naturally be zero in an individual flow, while `Fwd Header Length` and `Bwd Header Length` are currently hardcoded to `0` by the live feature extractor. The loaded model also reports these features as having zero importance:

- `RST Flag Count`
- `Avg Fwd Segment Size`
- `Avg Bwd Segment Size`
- `Subflow Fwd Packets`
- `Subflow Fwd Bytes`
- `Subflow Bwd Packets`
- `Subflow Bwd Bytes`

These values should not be removed or re-arranged unless the model is retrained with the reduced feature set. The feature-importance chart should be interpreted as a ranking, not as evidence that a later feature is automatically replaced with zero by the prediction code.

### Confusion matrix

The confusion matrix below compares the true traffic labels with the labels predicted by the trained model across BENIGN traffic and multiple attack categories.

![Model confusion matrix](Demo/confusion%20matrix.png)

### Top 20 selected features

The following chart illustrates the top 20 features from the model analysis:

![Top 20 influential network features](Demo/Top%2020%20features.png)

## Contributing

- Fork the repository and create a feature branch.
- Submit a pull request with a clear description of changes.
- If you add new scripts or notebooks, update `README.md` accordingly.

## Need help?

- Open an issue in this repository.
- Inspect `server/server.py` and `server/detector.py` for implementation details.
- Use the included notebooks in `cleaning.ipynb` and `main.ipynb` for dataset and model exploration.

