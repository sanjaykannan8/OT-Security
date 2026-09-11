# ML research for passive OT threat detection

Status: initial design research, 11 September 2026. Recommendations await telemetry and hardware confirmation. No model has been trained, no performance has been measured, and no production validity is claimed.

## Decision

Use Java Flink DataStream for incremental features and bounded state, Python for training, and ONNX Runtime Java for supported compact models. Rules and statistical detection must work without an available model. Model loading, registry access, calibration fitting and expensive explanations stay outside per-event processing.

ONNX Runtime provides JVM inference and reusable sessions [1]. Limit native inference threads to avoid multiplying thread pools across Flink operators; benchmark single-thread execution first for small models [2]. Verify CPU architecture, native library availability, conversion operators, feature preprocessing and numerical parity before fixing dependency versions. A Java API alone does not establish support for every laptop architecture.

Apache currently lists Flink 2.3.0, while Kafka connector 5.0.0 explicitly lists compatibility with 2.1.x and 2.2.x. Flink ML 2.3.0 lists Flink 1.17 compatibility [3]. Prefer a tested runtime/connector combination; tentatively evaluate Flink 2.2.1 with Kafka connector 5.0.0. Do not assume similarly numbered Flink and Flink ML packages are compatible. Flink ML is not needed for local inference.

## Candidate comparison

These are engineering hypotheses to benchmark, not measured rankings. Let d be feature dimension, z nonzero input features, T number of trees, h tree depth, N training rows, W retained temporal observations, and P neural parameters. Costs exclude feature extraction.

| Candidate | Inference complexity | Training cost | Memory | Latency expectation | Explanation | Streaming fit | Decision |
|---|---|---|---|---|---|---|---|
| Logistic/linear classifier | O(d), or O(z) sparse | Low; repeated passes over data | Coefficients and vocabulary | Most predictable baseline | Signed feature contributions | Stateless inference | First DGA model; baseline elsewhere |
| Random forest / Extra Trees | O(T h) | Moderate; parallel tree construction | Potentially large forests | Predictable if trees/depth bounded | Path evidence; offline local attribution | Stateless inference | Comparators; cap artifact size |
| HistGradientBoosting / LightGBM / XGBoost | O(T h) | Moderate, iterative | Small to moderate when bounded | Strong candidate for tabular signals | Evidence plus offline SHAP | Stateless inference | Challenger for DNS, flood and encrypted metadata |
| Isolation Forest | O(T h) | Moderate, subsampled trees | Bounded trees | Usually manageable; benchmark | Anomaly contributions need care | Static model over streaming features | Shadow anomaly score only initially |
| Kernel one-class methods | Often O(Nsv d) | Can be expensive | Support vectors | Variable as support set grows | Weak analyst explanations | Inference possible; operational limits | Not initial hot path |
| EWMA / robust baseline / incremental statistics | O(1) for selected updates | Baseline acquisition | Bounded per key | Predictable with key limits | Direct deviations and rates | Excellent | Primary for rates, beaconing and exfiltration |
| ADWIN / Page-Hinkley | Algorithm-dependent | Incremental | Bounded configuration required | Monitor overhead separately | Distribution-change signal | Good monitoring fit | Drift signal; never automatic threat verdict |
| Compact neural / autoencoder | O(P) approximate dense work | Higher tuning and data demand | Weights and runtime | Must beat simpler models empirically | Attribution/reconstruction difficult | Inference possible | Research challenger only |
| Temporal neural / Transformer | Architecture/sequence dependent | High relative to baseline | Sequence state and weights | Unproven for this deployment | Costly and less direct | Possible but unnecessary initially | Defer |

Tree-family tradeoffs and calibration behavior are documented by scikit-learn [4,5]. These sources support evaluation, not a claim that any family wins on this dataset.

## Threat-specific selection

| Threat | Features and key/window | Initial detector and challenger | Dataset and labels | False-positive risk | Explanation and provisional model CPU budget |
|---|---|---|---|---|---|
| DDoS | Destination/service: short-bucket packet, byte and flow rates; source cardinality/entropy; observed TCP flags | Rate/burst baseline plus bounded GBDT when training labels exist | Isolated lab flood episodes; CIC-IDS2017/2018; CICIoT2023 for comparative evaluation | Legitimate fan-in, failover, historian bursts; entropy may rise or fall | Rate, baseline, cardinality and visibility; p95 <= 2 ms per eligible feature vector |
| Beaconing | Source/destination/service: bounded ordered connection times, IAT dispersion, persistence, size consistency; minutes-long horizon | Robust periodicity evidence and context; calibrated classifier only after enough labels | CTU-13 and controlled beacon schedules including jitter, loss and benign polling | OT polling, NTP, update agents and telemetry | Observed intervals, count, dispersion and observation span; p95 <= 1 ms scoring, excludes evidence accumulation |
| DGA | Query lexical statistics, fixed character n-grams, registrable-domain context; source-window query/NXDOMAIN behavior | Logistic regression; bounded lexical GBDT challenger | DGArchive where access/license permits, algorithm-generated families, representative benign local names | CDNs, tracking identifiers, dictionary DGAs, internal naming conventions | Linear contributions plus context; p95 <= 1 ms |
| DNS tunnelling | Source/registrable-domain: unique labels, length, entropy, qtype and rates; response statistics only when visible | Stateful anomaly rules plus calibrated GBDT | CIC-Bell-DNS-EXF-2021; isolated labelled DNS-tunnel lab | Security products, service discovery, legitimate TXT records | Window statistics and top label characteristics; p95 <= 2 ms |
| Encrypted malware-like sessions | Available TLS fingerprint/handshake fields, bounded size/timing sequences and flow statistics | Logistic and bounded GBDT comparison; explicit unsupported/abstain state | Labelled malware/benign captures with provenance; isolated current TLS/QUIC scenarios | Browser updates, shared TLS stacks, fingerprint imitation, infrastructure changes | Metadata-based suspicion with observable evidence; p95 <= 2 ms |
| Scanning | Source: host and port fan-out, failed connections if visible, sequentiality; short/long buckets | Stateful cardinality detector; sequential evidence score where outcomes are observable | Lab horizontal/vertical/slow scans; relevant CIC/UNSW scenarios | Inventory tools, maintenance, discovery protocols, partial capture | Distinct ports/hosts, span, rates and completeness; p95 <= 1 ms scoring |
| Exfiltration | Source/asset class: upload deltas, sustained rates, passive destination rarity, directional ratio only when meaningful | Robust per-asset baseline and sustained deviation; GBDT only with credible labels | Labelled lab uploads and backups; DNS-EXF for DNS-specific case | Backups, historian replication, failover and maintenance | Baseline deviation, transfer direction and duration; p95 <= 1 ms scoring |

All numerical budgets are proposed acceptance targets, not results. No universal elapsed detection target applies: a 60-second beacon requires multiple observed intervals. Slow scanning and low-rate exfiltration require appropriately long evidence horizons. Short buckets allow early threshold alerts without waiting for the full horizon to close.

Pleiades supports using DNS behavior alongside lexical features [6]. RITA is useful prior art for Zeek-based beacon and tunnelling analysis, but its import workflow does not replace a continuously processing Flink detector [7]. Passive scan evidence has longstanding research support; active blocking portions of historical designs are outside scope [8].

## Visibility and preprocessing contract

One-way export does not necessarily mean only one direction of the observed conversation is captured. Record capture direction and coverage explicitly. Missing reverse traffic is not evidence of a failed handshake, zero response bytes or an amplification ratio. Never infer source spoofing conclusively from entropy alone.

Represent telemetry as AVAILABLE, MISSING, NOT_APPLICABLE or UNKNOWN, with a separate value and reason. An available zero remains zero. Model-required fields gate eligibility; permitted imputation uses fixed training-derived preprocessing and missingness indicators. Do not quietly map missing values to security evidence.

Version the feature order, units, clipping, domain parsing, IPv4/IPv6 treatment and cumulative-versus-delta byte semantics. Scope flow identity by sensor, boot epoch and Zeek UID. Join log types with bounded state and explicit expiry. DGA lexical classification may run before connection enrichment is available.

Zeek normally reports complete connections at termination; intermediate logging is necessary for sustained-flow alerts [9]. Default connection logs cannot supply arbitrary packet-size/IAT sequences or accurate per-second SYN counts. Add bounded passive sensor summaries for those features and measure sensor overhead. Prevent double counting intermediate cumulative records and terminal summaries.

No TLS application decryption, certificate fetching, online reverse DNS or active enrichment. Older encrypted-traffic studies establish feasibility, not present-day QUIC accuracy [10]. JA4 is a fingerprint, not a malware label; verify telemetry availability and relevant component license [11]. QUIC Initial packet protection can require cryptographic processing to recover handshake fields: the strict initial configuration excludes that and uses exposed headers, sizes and timing. Any handshake metadata policy must be explicit [12].

## Data and evaluation

| Source | Appropriate use | Limits |
|---|---|---|
| CIC-IDS2017 and CSE-CIC-IDS2018 [13,14] | Historical labelled attack comparisons and PCAP re-extraction | Enterprise lab traffic; CICFlowMeter fields are not Zeek fields; not evidence of current OT or QUIC validity |
| UNSW-NB15 [15] | Additional traffic families and generalization checks | Historical generated mix and different extractor semantics |
| CTU-13 [16] | Botnet scenarios and labelled flows | Historical families; background label is not verified benign |
| CICIoT2023 [17] | Flood and IoT comparison | IoT is not a substitute for industrial process traffic |
| DGArchive-related research [18] | Reproducible DGA family research | Access, license, family coverage and generation date require checks |
| CIC-Bell-DNS-EXF-2021 [19] | DNS exfiltration cases | Tool/domain memorization and lab bias |
| CIRA-CIC-DoHBrw2020 [20] | Encrypted-DNS metadata experiment | Cannot expose query names; old resolver/tool mix; not generic malware truth |
| Current isolated lab captures | End-to-end extraction and known episode labels | Synthetic separability; must include realistic benign OT polling, backups and maintenance |

Re-extract allowed PCAPs with the deployment feature pipeline. Never rename incompatible CSV columns and assume equivalence. Ground truth is held in a sidecar, never a model input. Record dataset hashes, rights, family, scenario, host and capture dates.

Split by time and hold out hosts/scenarios; additionally hold out DGA and malware families. Apply weighting/resampling only within training partitions. Calibrate on a distinct validation partition with realistic prevalence; retain an untouched test set. Compare class weighting and thresholds before introducing synthetic oversampling. Time and spatial leakage can greatly overstate malware performance [21].

For every threat report precision, recall, F1, ROC-AUC where defined, PR-AUC, FPR, FNR, false incidents per benign hour, missed incidents, and onset-to-alert latency. Include confusion matrices, sample counts, per-family results and confidence intervals. Report event classification and incident-level detection separately. When labels are absent, the dashboard can report alert rate, not actual recall or detection accuracy.

Prefer sigmoid/Platt calibration with limited validation data; compare isotonic with enough independent calibration examples and temperature scaling for a justified neural classifier [5]. Measure Brier score and reliability diagrams. A normalized anomaly score is not automatically a probability. Emit calibration status alongside confidence and separate asset-impact severity from confidence.

For all seven classes, monitor missingness, feature/score distributions, alert rate and analyst-confirmed error rates. Use ADWIN or Page-Hinkley selectively; feature drift is not proof of concept drift [22]. Retraining is review-triggered with time/family holdout validation, shadow comparison and signed promotion. Baselines need warmup, bounded update speed and maintenance awareness to resist poisoning. Never auto-promote a model simply because drift fired.

## Runtime, explanations and rollback

Bundle immutable versioned ONNX, metadata, feature schema, checksum, training provenance and calibration artifact. Load once per operator lifecycle, validate and warm up before activation. A checksum verifies integrity against a trusted manifest; authenticity requires a trusted signing/distribution mechanism. Pin model version in deployment/checkpoint metadata for reproducible recovery. Close native tensors/results after use.

Missing or invalid model: expose degraded health and continue compatible rules. Catch ordinary inference errors, count failures, and disable repeatedly failing models. Native JVM process failure still requires Flink restart; Java exception handling cannot guarantee recovery from a native crash. A per-call wall-clock budget is observable, but a synchronous native call has no assumed safe cancellation guarantee.

Keep rule evidence and linear feature contributions in alerts. Global feature importance is not an explanation of an individual prediction. Compute expensive local SHAP asynchronously only where needed, keyed to the exact model and feature snapshot.

Correlate by threat/entity/service with deterministic incident and update IDs, bounded evidence, cooldown and severity escalation. Do not add correlated model probabilities as if independent. Preserve evidence separately. Replays require idempotent consumers and cannot promise exactly-once external notifications without recipient cooperation.

## Sources

1. ONNX Runtime. [Java inference](https://onnxruntime.ai/docs/get-started/with-java.html).
2. ONNX Runtime. [Thread management](https://onnxruntime.ai/docs/performance/tune-performance/threading.html).
3. Apache. [Flink downloads and compatibility](https://flink.apache.org/downloads/).
4. scikit-learn. [Ensemble methods](https://scikit-learn.org/stable/modules/ensemble.html).
5. scikit-learn. [Probability calibration](https://scikit-learn.org/stable/modules/calibration.html).
6. Antonakakis et al., 2012. [Pleiades](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/antonakakis).
7. Active Countermeasures. [RITA](https://github.com/activecm/rita).
8. Weaver et al., 2004. [Scan detection research](https://www.usenix.org/legacy/publications/library/proceedings/sec04/tech/full_papers/weaver/weaver_html/index.html).
9. Zeek package catalog. [Long Connections](https://packages.zeek.org/packages/view/c95c5bb0-9348-11eb-81e7-0a598146b5c6).
10. Anderson, Paul and McGrew, 2016/2017. [Deciphering Malware's use of TLS](https://arxiv.org/abs/1607.01639).
11. FoxIO. [JA4 specifications and licensing](https://github.com/FoxIO-LLC/ja4).
12. IETF, 2021. [RFC 9001](https://www.rfc-editor.org/info/rfc9001/).
13. UNB. [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html).
14. UNB. [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html).
15. UNSW. [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
16. Stratosphere Laboratory. [CTU-13](https://www.stratosphereips.org/datasets-ctu13).
17. UNB. [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html).
18. Plohmann et al., 2016. [Domain-generating malware measurement](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_plohmann.pdf).
19. UNB. [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html).
20. UNB. [CIRA-CIC-DoHBrw2020](https://www.unb.ca/cic/datasets/dohbrw-2020.html).
21. Pendlebury et al., 2019. [TESSERACT](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury).
22. River. [ADWIN](https://riverml.xyz/latest/api/drift/ADWIN/).
