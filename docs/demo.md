# Demo guide

Each step states what it proves and how to see it. Run on the Docker host after `docs/deployment.md` stage 1.

```bash
bash scripts/provision-secrets.sh
docker compose up -d
docker compose --profile demo up -d
docker compose ps                       # all healthy; *-init jobs exited 0; job-supervisor running
```

## Reaching the UI when the stack runs on a server

Every published port binds to `127.0.0.1` on the Docker host on purpose: nothing is exposed to the network.
When the stack runs on a remote machine, forward the ports over SSH from the laptop doing the presenting and
keep the terminal open for the whole demo:

```bash
ssh -L 8080:127.0.0.1:8080 -L 8081:127.0.0.1:8081 -L 3000:127.0.0.1:3000 <user>@<host>
```

Then `http://127.0.0.1:8080` (SOC UI), `:8081` (Flink) and `:3000` (Grafana) work in the laptop's browser.
Do not republish the ports on `0.0.0.0` to avoid the tunnel: the bind address is a deliberate control.

Credentials come from `scripts/provision-secrets.sh`, which prints them and writes them under `secrets/`:

```bash
echo "analyst / $(cat secrets/api_analyst_password)"      # SOC UI
echo "admin / $(cat secrets/grafana_admin_password)"      # Grafana
```

## Starting from clean state for a presentation

A stack that has been benchmarked or fault-tested carries old incidents, gap counters and notifications, and
open incidents suppress repeat alerts for up to `incident_idle_ms` (300 s). For a demo that looks like a fresh
deployment, reset the volumes first and allow about three minutes before presenting:

```bash
docker compose --profile demo --profile tools down -v
docker compose up -d && docker compose --profile demo up -d
bash scripts/doctor.sh                  # every service healthy before you start talking
```

## 1. Streaming detection from real Zeek output

```bash
bash scripts/run-scenario.sh mixed      # 10-minute scenario at speed 1
```

- Open http://127.0.0.1:8080 and sign in as `analyst`. Alerts appear in the live table while the replay is still running: scan, DGA burst, DNS tunnel, TLS metadata, SYN flood refined to spoofed-source-like, amplification, exfiltration and beaconing (after about 4 minutes of connections).
- The Flink UI (http://127.0.0.1:8081) shows `sih-detection` RUNNING, with records flowing through the named operators.

## 2. Passive, one-way, no decryption

- `docker compose exec sender-pcap python -c "import socket; socket.create_connection(('redpanda', 9092), 2)"` fails: the sensor side has no route to the SOC network.
- Zeek runs with `network_mode: none` and reads the PCAP files read-only.
- The TLS alert's detail lists metadata indicators only (`tls_version`, `server_name` unavailable). No key material exists anywhere in the stack.
- The UI banner states that Docker networking models one-way semantics and is not a hardware diode.

## 3. Explanations and honest uncertainty

Open any incident. It shows:
- observed values, thresholds and baselines;
- unavailable features, such as `failed_ratio` when only one direction is visible;
- capped (lower-bound) sketches;
- detector and model versions;
- model eligibility, and the confidence kind with its calibration status (`heuristic score`, `simulation only`);
- the update timeline and the related raw Zeek records.

No accuracy figure is shown for live traffic.

## 4. Model fallback

- Healthy: Grafana, panel "DGA model active" = 1. The DGA incident shows method `hybrid` or `model` with `model_version dga-lr-1.0.0-sim`.
- Failure path, covered by unit tests: a corrupt or missing bundle leaves the model inactive and `dga_nxdomain_burst` still fires with method `rule` (`tests/unit/test_ml.py::test_corrupt_or_missing_model_falls_back`, `tests/unit/test_detect.py::test_dga_burst_rules_only_without_model`).
- Live demonstration:
  1. Stop the supervisor.
  2. Cancel the job.
  3. Start the supervisor with `SIH_MODEL_ROOT=/nonexistent` (`docker compose run -d -e SIH_MODEL_ROOT=/nonexistent job-supervisor`).
  4. Replay `dga`. The burst alert arrives with method `rule`, and Grafana shows the model inactive.

## 5. Restart recovery

```bash
docker compose kill flink-taskmanager && docker compose up -d flink-taskmanager   # task failover, same job id
docker compose restart flink-jobmanager                                          # supervisor restores from checkpoint
docker compose down && docker compose up -d                                      # volumes kept; job restored
```

The Flink UI's "Checkpoints → Latest Restore" shows the `s3://flink-checkpoints/...` path. `bash tests/failure/run_failure_suite.sh` automates these and also covers:
- broker restart during replay;
- a ClickHouse outage, during which the notifier keeps recording and consumers catch up afterwards;
- injected malformed, unauthenticated and gap frames.

## 6. Measured throughput and latency

```bash
bash scripts/verify.sh                   # results in benchmarks/results/verify-*/
bash benchmarks/run_benchmark.sh         # open-loop synthetic load; results in benchmarks/results/bench-*/
```

The UI's latency panel shows detection latency from stored timestamps and API-visible latency for the current API process, with p50/p90/p95/p99, the maximum and the number of samples over 5 s. Report only numbers produced on declared hardware (see `docs/status.md`).
