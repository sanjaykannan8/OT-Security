# dga

Status: **learned model (simulation-trained)**. The bundle is not committed; it is produced deterministically in the Docker build stage `model` (`python -m sih_ml.train_dga`) and baked into both runtime images at `/opt/sih/models/dga/<version>/`:`n
- `model.onnx`: standardization + logistic regression + sigmoid, written by `model-training/sih_ml/onnx_writer.py`
- `metadata.json`: model manifest (schemas/model-manifest.v1.schema.json) with evaluation, calibration status and coefficients for explanations
- `feature_schema.json`, `preprocessing.json` (benign bigram table), `golden.json`, `evaluation.json`, `checksums.sha256`

`models/deployment.json` selects the version and pins its checksums. Scores are `heuristic_score` with calibration status `simulation_only`: the training data are synthetic, so reported metrics measure separability of the simulation, not field accuracy.
