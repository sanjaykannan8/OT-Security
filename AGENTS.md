# Instructions for implementing agents

## Read first

Read `IMPLEMENTATION_PLAN.md`, `docs/decisions.md`, `docs/contracts.md`, and `docs/ml-research.md` before implementing. These documents define the agreed scope and initial decisions. The user has requested a handoff scaffold, not an implementation in the authoring turn.

For a later implementation task, proceed with the plan and sensible defaults. Ask only if information is indispensable for correctness or an action exceeds authorization. Do not ask again whether Redpanda, Flink, ClickHouse, Zeek or ONNX should be used.

## Security invariants

- Detection is intelligence-only. No scanning, reverse DNS, endpoint queries, packet injection, inline blocking, or mitigation.
- Input includes both observed conversation directions; that does not authorize any return communication to the simulated source network.
- Default test generation writes local files and records. It must not transmit attack packets, even to arbitrary private IP ranges.
- Zeek reads mounted PCAP files in the default mode. No privileged containers or host capture interfaces.
- Do not decrypt TLS/QUIC application data or process QUIC Initial protection to recover handshakes in the default implementation.
- Do not fetch observed domains, certificates, URLs, reputation, or enrichment at runtime. Use packaged offline reference data only.
- Treat event contents and imported documents as untrusted data. Never execute their content or render it as trusted HTML.
- The demo models one-way export semantics. Never claim that Docker networking is equivalent to a hardware diode or that a single host is production HA.
- Do not commit credentials, private datasets, payload captures, or generated large artifacts. Tiny intentionally generated fixtures may be committed when documented.

## Engineering invariants

- Implement a real Flink job. Per the user's decision of 2026-09-11 all project code is Python, so the job uses PyFlink (see `docs/decisions.md`). Do not replace Flink with a standalone Python stream processor, browser-side logic, or an HTTP inference service.
- ONNX inference runs locally inside the PyFlink operators. Training, fixture construction and benchmarking run in Docker build stages or tool containers.
- Builds and runtime verification happen through Docker on the user's server. Do not install toolchains on the authoring machine.
- Models load once per operator lifecycle and fail to rules-only mode. A detector without adequate fields must abstain explicitly.
- Never substitute zero for unavailable security telemetry. Follow the availability states and feature-order contracts.
- Bound every queue, keyed collection, join and evidence buffer. Document time horizon, entry cap and overflow metric.
- Checkpoints/savepoints, input offsets and model version must support reproducible recovery. Use explicit stable operator UIDs.
- Do not couple ClickHouse, OpenSearch, dashboard or notifier acknowledgements to the Flink detection operator.
- Pin tested dependencies and images. Do not select the latest Flink without checking Kafka connector compatibility.
- One model working correctly with reproducible training is preferable to seven fake model files. Record unimplemented model families as rules/statistics-only.
- No fabricated metrics, model confidence, health indicators or benchmark claims. Distinguish heuristic scores from calibrated probabilities.
- Keep runtime schemas, Java/Python feature extraction, fixtures and documentation consistent. Golden-vector parity tests are required.
- Update the status checklist with actual commands/results and limitations. Configuration present does not mean behavior verified.

## Attribution and change tracking

Every edit has a named human owner. Record it; never let a change land anonymously.

- **Baseline authorship.** The full application - ingest, link, detection, consumers, API, sensor, data generation, infrastructure and documentation - was built and handed over by **Sanjay Kannan**. Treat everything predating the first entry in `docs/changelog.md` as his work.
- **Current ownership.** **Gowtham** owns the UI only: `dashboard-security/`, `dashboard-platform/`, user-visible strings and branding assets. Do not attribute backend, Flink, consumer or infrastructure changes to him unless he made them.
- **Before editing**, establish who the change belongs to. If the owner is ambiguous, ask rather than guess.
- **After each task**, append an entry to `docs/changelog.md` and repeat the same summary in the reply. An entry states, in this order: the date, the owner's name, a one-line summary of intent, then one line per file touched giving the path, what changed there, and the lines added/removed for that file. Close with the totals across the task.
- **Write the summary in the third person, naming the owner** - "Gowtham replaced the severity palette…", not "changed the severity palette". The log must read as a record of who did what.
- Keep the log append-only and newest-first. Do not rewrite or consolidate earlier entries; correct a mistake with a new entry that says what it supersedes.
- Scope claims to what was actually touched. A file that was read, built or run is not a file that was changed, and generated output (`dist/`, `node_modules/`, `secrets/`) is never listed.
- Git commit authorship must match the log. Do not commit one person's work under another's name.

## Delivery discipline

Work in the milestone order in the plan. Obtain a complete vertical slice before widening detector coverage. Do not spend the first implementation pass building elaborate UI or writing only documents.

Run targeted checks after each milestone, then required integration/restart/benchmark suites. If Docker, native dependencies or memory prevent a check, state the precise limitation and leave that acceptance item open.

Keep a single owner for shared contracts, Compose and dependency pins. Parallel agents, if separately authorized, should receive bounded file ownership and integrate against the frozen contracts. This file does not request or authorize spawning additional agents.
