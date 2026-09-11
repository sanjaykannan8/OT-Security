# Deployment

## Prerequisites

- Linux Docker host with Docker Engine and Docker Compose 2.24 or newer (the compose file uses `!reset`). `bash scripts/doctor.sh` checks this.
- About 9 GiB of container memory for the core runtime plus the demo senders (search profile adds about 1.5 GiB), 4 or more CPUs, and 20 GiB or more of free disk. These are planning figures, not measured minimums.
- Connected build machine only: registry access to Docker Hub, Maven Central (Kafka connector JAR), PyPI and npm.

## Stage 1: build (connected machine)

```bash
bash scripts/provision-secrets.sh   # local credentials in ./secrets (0700 dir, gitignored)
docker compose --profile demo --profile tools --profile search build
```

The build fails if unit tests, schema example checks or model training fail. These run in the `test` and `model` stages of `docker/Dockerfile`. The trained model bundle is copied into both runtime images.

To transfer to an air-gapped target:

```bash
bash scripts/build-offline-bundle.sh      # images.tar, lockfiles, model bundle, test report, SBOM/scan if syft/grype exist, SHA256SUMS
```

## Stage 2: offline target

```bash
bash scripts/load-offline-bundle.sh offline-bundle/sih-1.0.0-YYYYMMDD ./sih
cd sih
bash scripts/provision-secrets.sh   # new credentials for this installation
bash scripts/doctor.sh
docker compose up -d
```

Nothing is pulled at runtime. The UI ships its own compiled bundle: no CDN, external fonts or telemetry. Grafana update checks and reporting are disabled.

## Operating the stack

| Task | Command |
|---|---|
| Start the core SOC runtime | `docker compose up -d` |
| Start the simulated sensor side | `docker compose --profile demo up -d` |
| Run a scenario end to end | `bash scripts/run-scenario.sh mixed` |
| Search profile | `docker compose --profile search up -d` |
| Status | `docker compose ps` |
| Logs | `docker compose logs -f receiver job-supervisor flink-taskmanager` |
| Restart one service | `docker compose restart <service>` |
| Stop (keeps data) | `docker compose down` (never `down -v` in routine operation) |
| Full verification | `bash scripts/verify.sh` |
| Benchmark | `bash benchmarks/run_benchmark.sh` |

Local endpoints (published on 127.0.0.1 only):

| URL | What | Login |
|---|---|---|
| http://127.0.0.1:8080 | SOC UI and API | `admin` / `analyst`, passwords in `secrets/api_*_password` |
| http://127.0.0.1:3000 | Grafana (platform health) | `admin`, password in `secrets/grafana_admin_password` |
| http://127.0.0.1:9090 | Prometheus | none; localhost only |
| http://127.0.0.1:8081 | Flink UI | none; localhost only. Exposes job details, keep on localhost |

Use an SSH tunnel to reach these from another machine. Set `API_COOKIE_SECURE=true` when TLS termination is added in front of the API.

## Profiles

| Profile | Adds | Selection |
|---|---|---|
| (default) | Redpanda, MinIO, ClickHouse, Flink JM/TM, job supervisor, receiver, consumers, archive exporter, API, Prometheus, Grafana | plain `docker compose up -d` |
| `demo` | `sender-pcap` (Zeek logs), `sender-synth` (synthetic runs) | `--profile demo` |
| `search` | OpenSearch 2.19.3 and the `alerts-opensearch` consumer | `--profile search` |
| `tools` | one-shot `fixtures`, `synthetic`, `zeek-replay`, `link-inject`, `tools` | `docker compose --profile tools run --rm <service>` |
| `production-like` | **Not implemented.** Needs 3 brokers (RF3, `min.insync.replicas=2`), 2+ TaskManagers, Flink HA and replicated storage. On one host this would demonstrate process failover only. See `docs/status.md` | — |

## Rotating credentials

`docker compose up -d` does not recreate a running container when only the contents of a secret file change. After `bash scripts/provision-secrets.sh --rotate`, or after `./secrets` was regenerated for any reason, reload the servers that read credentials at startup:

```bash
docker compose up -d --force-recreate minio clickhouse
docker compose up -d --force-recreate   # all services pick up the new files
```

Named volumes are kept. The init jobs re-apply users and policies idempotently. Their error output names the service to recreate if MinIO or ClickHouse still rejects the credentials.

## Recovery behaviour

- Detection job: the `job-supervisor` resubmits `sih-detection` whenever no active job exists. It restores from the newest complete retained checkpoint in `s3://flink-checkpoints/checkpoints/`, and prunes all but the 3 newest job directories. TaskManager failures are handled by Flink's restart strategy.
- If a restore fails because the job graph changed incompatibly, set `SIH_ALLOW_NON_RESTORED=true` on the supervisor only after deciding that the dropped state is acceptable. Operator UIDs are fixed to avoid this.

## Model promotion and rollback

1. Train a new version: change `MODEL_VERSION` in `model-training/sih_ml/train_dga.py` and rebuild. The new bundle and `models/deployment.json` are baked into the images.
2. Take a savepoint: `docker compose exec job-supervisor flink stop --savepointPath s3://flink-checkpoints/savepoints <jid>`. With the job stopped, the supervisor would immediately restart it from the newest checkpoint, so first run `docker compose stop job-supervisor`.
3. Deploy the new images (`docker compose up -d`) and start the supervisor. It restores the newest checkpoint or savepoint. Model state is not part of Flink state: the `dns-score` operator loads the selected version in `open()` and verifies its checksums and golden vectors.
4. Rollback: redeploy the previous image tag (`SIH_IMAGE_TAG`) the same way. A checksum mismatch or a failed golden check leaves the job rules-only (`sih_model_active = 0`), never silently degraded.

## Retention and archive

- Hot tables have no TTL. `archive-exporter` exports each closed daily partition (`SELECT … FINAL`, gzip JSONEachRow) to the object-locked `archive` bucket (default governance retention 7 d), with a manifest. It verifies the object by read-back (sha256 and row count, compared with ClickHouse). Only then may the partition be dropped, and only once it is older than `HOT_RETENTION_DAYS` (default 90).
- Retention hold: if `sih_archive_unverified_partitions` rises, partitions are simply not deleted. Watch disk use (`ClickHouseDiskPressure` should be added for your volume) and fix the archive path. Nothing is deleted without a verified manifest.
- Restore: `docker compose run --rm archive-exporter python -m sih_consumers.archive restore raw_events 2026-06-01`.

## Hardening summary and exceptions

Applied:
- Non-root users for application, Flink, Zeek and Grafana containers.
- `cap_drop: ALL` and `no-new-privileges` wherever the image allows.
- Read-only root filesystems with tmpfs `/tmp` for Python services, Zeek and Prometheus.
- File-mounted secrets and least-privilege ClickHouse and MinIO users.
- HMAC-authenticated link frames.
- Session auth with roles, login throttling, an audit log and a strict CSP.
- Localhost-only published ports.
- Pinned image tags; checksum-verified connector JAR.

Exceptions (documented, not hidden):
- **Flink:** the entrypoint appends `FLINK_PROPERTIES` to `conf/config.yaml`, so its root filesystem is writable.
- **ClickHouse, MinIO and Redpanda:** run with their images' default capabilities and users (entrypoints change ownership of data directories).
- **Secret file modes:** secret files are 0644 inside a 0700 directory, because Compose file secrets keep host permissions and containers run as different users.
- **OpenSearch:** runs with its security plugin disabled on the internal `soc` network in the search profile, with no published port.
- **Internal traffic:** there is no TLS inside the single-host Docker network.
- **Image pinning:** images are pinned by tag. Digests are recorded by `build-offline-bundle.sh` (`image-ids.txt`) and should be pinned for production.
- **Authenticity:** model checksums prove integrity against the deployment manifest, not authenticity. Production needs a signed bundle.

## Kubernetes mapping (not implemented)

- Redpanda as a StatefulSet (3 replicas).
- Flink via the Flink Kubernetes Operator in application mode with Kubernetes HA, and checkpoints on replicated S3.
- ClickHouse via its operator with replicas and Keeper.
- Consumers and API as Deployments.
- The receiver as a StatefulSet with a persistent volume.
- The sensor side stays outside the cluster behind a real one-way device.

Single-host Compose does not provide host-loss HA.
