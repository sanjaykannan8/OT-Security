# Schemas

Versioned JSON Schema (draft 2020-12) contracts shared by the sender, receiver, Flink job, consumers, API and training code. Semantics are described in `docs/contracts.md`; this directory is the machine-readable source of truth.

| File | Purpose |
|---|---|
| `event.v1.schema.json` | Envelope + normalized payload per `log_type` on `raw-events.v1` |
| `alert.v1.schema.json` | Incident update on `alerts.v1` |
| `feature.v1.schema.json` | Feature snapshot on `features.v1` |
| `sensor-health.v1.schema.json` | Outward sensor health on `sensor-health.v1` |
| `invalid-event.v1.schema.json` | Quarantine record on `invalid-events.v1` |
| `model-manifest.v1.schema.json` | `metadata.json` inside a model version directory |
| `deployment-manifest.v1.schema.json` | `models/deployment.json` version selection |
| `features/*.json` | Ordered feature contracts shared by training and the PyFlink runtime |
| `examples/` | Generated valid and invalid vectors (`build_examples.py`) with `expectations.json` |

The validator (schema + cross-field rules) is `lib/sih_common/contracts.py`; deterministic identifiers are in `lib/sih_common/ids.py`.

## Validation layers

1. JSON Schema: types, enums, required keys, `additionalProperties: false`, string length/pattern and numeric bounds. Format assertions for `ipv4`/`ipv6` are enabled; timestamps are enforced by pattern.
2. Cross-field rules (`lib/sih_common/contracts.py`):
   - `availability_null`: a null payload value requires an availability entry.
   - `availability_on_value`: a non-null value must not carry an availability entry.
   - `reason_without_availability`: every `availability_reasons` key must be an `availability` key.
   - `original_record_null`: a null `original_record` requires `original_record_truncated = true`.
   - Alerts: `confidence_consistency`, `calibration_consistency`, `model_version_consistency`, `time_order`.
   - Features: `availability_null`, `availability_on_value`, `capped_unknown`.

## Evolution policy

- Every record carries an explicit version string. Producers only emit versions listed here.
- **Minor** (`1.0.0` → `1.1.0`): adding optional, nullable fields or enum values that old consumers may safely ignore. Validators keep every supported minor version of the current major. Because schemas are strict (`additionalProperties: false`), a consumer only accepts a minor version it knows. The deployment order is therefore consumers first, then producers.
- **Major** (`1.x` → `2.0.0`): removing or renaming fields, changing types, units or semantics. A major version is published on a new topic (`raw-events.v2`) and both run in parallel during migration.
- A record with an unknown or unsupported version is quarantined with reason `unsupported_schema_version`, never coerced.
- Feature contracts (`features/*.json`) are versioned independently (`dga_lexical-1.0.0`). Any change to order, formula, clipping or normalization bumps the version and requires retraining. The model manifest pins the feature contract by version and SHA-256.
- Avro or Protobuf migration is out of scope until measurements show JSON parsing is a bottleneck. It would get a new topic version and a compatibility plan.

## Regenerating examples

```bash
python schemas/examples/build_examples.py
python -m unittest discover -s tests/schema -v
```

The build script is deterministic. The schema test fails if the committed examples differ from a fresh build.
