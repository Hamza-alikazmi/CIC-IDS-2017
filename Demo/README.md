# CIC NIDS Demo

The project demo video is available in this folder:

- [`CIC NIDS Demo.mp4`](CIC%20NIDS%20Demo.mp4)

The video demonstrates the CIC-IDS-2017 network intrusion detection system and dashboard workflow.

## Model results

- [`confusion matrix.png`](confusion%20matrix.png) — Random Forest confusion matrix for BENIGN and attack categories.
- [`Top 20 features.png`](Top%2020%20features.png) — relative importance of the top 20 selected network features.

### Scores

- Training set score: **0.9984**
- Test set score: **0.9984**

### Model notes

- Model: **LightGBM classifier**
- Model input: **42 features**
- Training score: **0.9984**
- Test score: **0.9984**
- The 21st-ranked feature is **`Bwd IAT Std`**. It is not assigned zero automatically; missing live values default to zero only.
- Features ranked after the top 20 remain included in the 42-feature model input and must not be removed without retraining.
