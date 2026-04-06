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

The request body should contain flow features matching the feature set defined in `server/detector.py`.

## Important details

- `server/server.py` captures live packets using `scapy` and extracts features per flow.
- `server/detector.py` loads a LightGBM model from `server/ids_model.pkl` and predicts a label using the defined feature order.
- `main.py` is a simple dataset preview script and does not run the IDS server.

## Contributing

- Fork the repository and create a feature branch.
- Submit a pull request with a clear description of changes.
- If you add new scripts or notebooks, update `README.md` accordingly.

## Need help?

- Open an issue in this repository.
- Inspect `server/server.py` and `server/detector.py` for implementation details.
- Use the included notebooks in `cleaning.ipynb` and `main.ipynb` for dataset and model exploration.

