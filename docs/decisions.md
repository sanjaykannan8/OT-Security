# Agreed decisions and provisional defaults

## Confirmed by the user

- Observed conversations include both directions.
- Zeek configuration and component choices are delegated to the implementer.
- The initial system is simulation-only.
- Throughput is measured primarily in events/second; no required event rate was supplied.
- Alerts must arrive within seconds, with a desired bound of 3–5 seconds.
- Deployment is offline, mostly air-gapped.
- Restart resilience is required.
- Hardware is undecided.
- The immediate deliverable is an implementation plan and agent-ready folder scaffold, not application implementation.

## Confirmed by the user during implementation (2026-09-11)

- **No Java code.** All project code is Python. The detection job uses PyFlink (Flink's Python DataStream API) on the official Flink 2.2.1 runtime, which keeps Flink's checkpoints, keyed state and restart recovery. This supersedes the "Java Flink job" wording in the original handoff.
- **Docker only, on a separate server.** Nothing is installed on the authoring laptop. Every dependency resolution, compilation, training run and test happens inside `docker/Dockerfile` build stages or Compose services. Runtime verification happens on the user's Docker server.

## Selected defaults

| Decision | Default | Reason / revisit condition |
|---|---|---|
| Sensor | Zeek 8.0 LTS line; resolve and pin an available tested patch | Stable baseline; verify package/native architecture support |
| Logs | conn, dns, ssl, weird; http/files metadata when present; quic only when supported and compliant | Sufficient initial coverage without claiming every log/field exists |
| Extra telemetry | Custom bounded flow-update summaries and optional bounded packet timing/size summaries | Terminal conn records are inadequate for timely long-flow detection |
| Suricata | Optional adapter/profile after Zeek vertical slice | Avoid duplicate sensor overhead initially |
| Runtime | PyFlink 2.2.1 on `flink:2.2.1-scala_2.12-java17` with `flink-sql-connector-kafka:5.0.0-2.2` (checksum-verified at build) | User decision: Python only. Connector 5.0.0 lists Flink 2.1/2.2 compatibility; runtime verification is on the server |
| Broker | Redpanda; one broker in default demo | Preserve supplied architecture |
| ML | NumPy training, hand-written ONNX export, ONNX Runtime (Python, CPU, 1 thread) inside the PyFlink operator | No GPU dependency, no inference RPC, no converter dependencies |
| Hot storage | ClickHouse | Independent analytics persistence |
| Search | OpenSearch, implemented but optional heavy profile | Preserve integration while controlling laptop memory |
| Archive/checkpoints | MinIO in demo; separate buckets and credentials | Offline S3-compatible storage; production durability differs |
| API/UI | Small FastAPI service serving a compiled React/TypeScript UI, REST plus SSE | One runtime container; Python stays out of detection |
| Persistence adapters | Small Python adapters (confluent-kafka, ClickHouse HTTP interface, OpenSearch bulk API), one container per pipeline | Independent consumer groups; offsets commit only after the durable write; tested poison/retry behaviour |
| Notifications | Offline local notification/audit sink by default | No external network dependency or automatic remediation |
| Authentication | Local provisioned admin/analyst accounts, role checks, secure sessions | OIDC can be added later without requiring online identity |
| Enrichment | Bundled asset inventory and optional licensed offline reference lists | No runtime external lookups |
| Retention | 90-day hot design, configurable short demo retention; PCAP disabled for broad archival by default | Hardware/storage budget unknown; do not allocate 90 days of raw volume blindly |
| Latency | Normal-load p95 <3 s, p99 <5 s after sufficient evidence reaches receiver | Explicit test targets; report maximum and every deadline violation |
| Throughput | Calibrate on declared hardware; initial trial levels 100/500/1000 events/s | Trial settings only, not performance claims or immutable targets |
| Simulation boundary | Separate sender/receiver roles with outward-only datagram transfer and no application return channel | Demonstrate design semantics, not physical enforcement |
| Application protocol handling | Metadata extraction only; no TLS keys, interception or QUIC Initial decoding | Conservative no-decryption interpretation |

The implementing agent must verify and pin actual image digests, Java dependencies and Python/JS lockfiles during packaging. Research candidate versions are not a tested lockfile.

## Resource assumptions

Initially budget for a Linux container environment with 8 CPU cores, 16 GiB available RAM and 50 GiB free SSD for small fixtures; 32 GiB RAM is a preferred full-profile development target. These are provisional planning budgets, not proven minimums. Inspect the actual environment before choosing heap sizes, concurrency and benchmark rates. Do not assume macOS, x86, ARM or a GPU based on a workstation name.

Production-like services on one machine demonstrate process failover only. Actual host-loss HA requires separate failure domains, broker replication/quorum, durable replicated checkpoint storage, Flink leadership recovery, replicated databases and redundant access services.
