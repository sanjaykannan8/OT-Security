# Threat model

Scope: the offline simulation described in `docs/architecture.md`. This model covers the detection system itself, not the monitored OT process. Everything the system reads from observed traffic is attacker-influenced data.

## Assets

| ID | Asset | Why it matters |
|---|---|---|
| AS1 | Integrity of detection output (alerts, incidents, evidence) | Suppressed or forged alerts mislead analysts |
| AS2 | Isolation of the observed side | The SOC must never become a path back into the OT network |
| AS3 | Observed metadata (internal addresses, domains, SNI, asset inventory) | Reconnaissance value to an attacker |
| AS4 | SOC availability (broker, Flink, storage, UI) | Loss of monitoring during an attack |
| AS5 | Model and reference-data artifacts | Tampered model = silent blind spot |
| AS6 | Credentials, sessions, audit log | Unauthorized access or cover-up |
| AS7 | Archive and checkpoints | Loss of forensic history or of recoverable detector state |

## Trust boundaries

B1 observed network / PCAP content → B2 sensor host (Zeek, sender) → one-way link → B3 SOC enclave (receiver, Redpanda, Flink, storage, API) → B4 analyst browser. See the diagram in `docs/architecture.md` §3.

## Adversaries

| ID | Adversary | Capability assumed |
|---|---|---|
| T1 | Attacker on the observed network | Crafts arbitrary traffic: malformed packets, huge DNS names, many flows/keys, slow or jittered attacks, benign-looking mimicry |
| T2 | Compromised sensor host | Sends arbitrary datagrams on the link, forges sensor fields, stops sending |
| T3 | Adversary on the link network segment | Injects, replays, drops or reorders datagrams |
| T4 | Malicious or careless insider with UI access | Reads beyond role, tampers with incident state |
| T5 | Supply-chain tampering in the build or bundle | Modified image, dependency, model or reference file |

## Threats and mitigations

| Threat | Target | Mitigation in this design | Residual risk |
|---|---|---|---|
| Parser exploitation via crafted packets (T1) | AS2, AS4 | Zeek reads files unprivileged in a container without capabilities or host network. Receiver validates size before parsing. | Zeek parser bugs remain possible; container escape is out of scope. |
| Oversized fields / JSON bombs (T1, T2) | AS4 | Hard byte limits per datagram, per record and per field (schema `maxLength`). Fragment count capped. Invalid records are quarantined with reason codes. | Quarantine volume itself is bounded and counted. |
| Key-cardinality exhaustion (T1): random sources/ports/subdomains | AS4 | Per-key entry caps, global operator caps, event-time expiry and state TTL. Overflow sets `capped`/`UNKNOWN` availability and increments metrics. | Overflow reduces precision; it is reported, not hidden. |
| Evasion (T1): slow scan, jittered beacon, low-rate exfiltration, dictionary DGA | AS1 | Longer bounded horizons, robust statistics (median/MAD), DNS behaviour features alongside lexical ones. | Attacks below documented thresholds or beyond horizons are missed; limits are published in the feature catalog. |
| Baseline poisoning (T1) by slowly ramping volume | AS1 | Warmup period, bounded EWMA update speed, no baseline update from buckets that are already alerting. | Patient poisoning over long periods remains possible. |
| Alert/UI injection: script in domain names, SNI, URIs (T1) | AS6 | All event content is rendered as text in React (no `dangerouslySetInnerHTML`), with a strict CSP and no inline scripts. API returns JSON only. | None known; covered by escaped-render tests. |
| Spoofed or replayed link datagrams (T3) | AS1 | HMAC-SHA256 over every frame with a locally provisioned link key. Receiver tracks per-(sensor, boot) sequence windows: duplicates are dropped and counted, gaps counted. | A compromised sensor (T2) holds the key and can forge data; detection then relies on plausibility checks and health gaps. |
| Return channel abuse (any) | AS2 | Sender opens no listening socket. Receiver never transmits toward the sender network. No SOC-triggered retrieval. No active enrichment, reverse DNS, certificate fetching or probing anywhere. | Docker networking is not a hardware diode; a compromised host can bypass it. Stated in UI and docs. |
| Sensor silence (T2) hides an attack | AS1, AS4 | Heartbeats in `sensor_health`; stale-telemetry detection marks the source degraded in UI and Grafana. | Silence is detectable but not attributable. |
| Model tampering (T5) | AS5 | Deployment manifest pins version and sha256. Checksum is verified before activation, and on mismatch the job runs rules-only and reports degraded. | A checksum proves integrity against the manifest, not authenticity. Signing the bundle is a documented production requirement. |
| Dependency/image tampering (T5) | AS4, AS5 | Pinned versions/digests, SBOM and vulnerability scan in the bundle, checksum verification on load. | Scanner coverage limits. |
| Unauthorized UI access (T4) | AS3, AS6 | Local accounts with salted password hashes, server-side sessions, role checks on every endpoint, audit log of logins and state changes. | Local accounts only (no MFA) in the demo. |
| Credential leakage | AS6 | No committed secrets. `scripts/provision-secrets.sh` generates random per-install secrets into gitignored `secrets/`, mounted as files. | Host compromise exposes mounted secrets. |
| Storage loss / premature deletion | AS7 | Named volumes. Hot-table deletion only after a verified archive manifest. Checkpoints in a separate bucket with separate credentials. | Single-host demo storage has no redundancy. |
| Decryption / payload exposure | AS3 | No TLS keys, no interception, no QUIC Initial decryption, no payload capture in default mode. Only metadata fields are extracted. | Metadata still reveals communication patterns and must be access-controlled. |

## Explicit non-goals

- No blocking, mitigation, packet injection or commands to the observed side.
- No production HA claim for a single host, and no physical isolation claim for Docker networking.
- No claim that a synthetic label (for example "spoofed-source-like flood") proves real spoofing or real malware. Alerts state what was observed.
