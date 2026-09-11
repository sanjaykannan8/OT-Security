#!/usr/bin/env bash
# One-command verification on the Docker host. Results (machine-readable) go to benchmarks/results/verify-<ts>/.
#   scripts/verify.sh              # build + runtime + scenarios + failure suite
#   VERIFY_SKIP_FAILURE=1 scripts/verify.sh
#   VERIFY_SCENARIOS="scan dga" VERIFY_REPLAY_SPEED=4 scripts/verify.sh
# Speed > 1 compresses wall-clock replay only; observation-time rates and windows are unchanged.
. "$(dirname "$0")/lib.sh"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="benchmarks/results/verify-$TS"
mkdir -p "$OUT"
RES="$OUT/results.jsonl"
FAIL=0
step() {
  local name=$1; shift
  log "== $name"
  if "$@" > "$OUT/$name.log" 2>&1; then json_result "$RES" "$name" true ""
  else json_result "$RES" "$name" false "see $name.log"; FAIL=1; log "FAILED: $name (see $OUT/$name.log)"; fi
}

bash scripts/doctor.sh > "$OUT/doctor.txt" 2>&1 || true
[[ -s secrets/link_key ]] || bash scripts/provision-secrets.sh > "$OUT/provision.log"
{ date -u; uname -a; docker version; docker compose version; nproc; free -h 2>/dev/null; df -h .; } > "$OUT/environment.txt" 2>&1 || true

step build "${DC[@]}" --profile demo --profile tools --profile search build
step unit_test_results bash -c "docker run --rm --entrypoint cat sih-python:${SIH_IMAGE_TAG:-1.0.0} /app/test-results/python-unit.xml > '$OUT/python-unit.xml'"
step model_summary bash -c "docker run --rm --entrypoint cat sih-python:${SIH_IMAGE_TAG:-1.0.0} /opt/sih/models/training-summary.json > '$OUT/model-training-summary.json'"
step up up_stack 900
step job_running wait_job_running 600
step demo_up env SENDER_REPLAY_SPEED="${VERIFY_REPLAY_SPEED:-4}" "${DC[@]}" --profile demo up -d sender-pcap

SCEN=${VERIFY_SCENARIOS:-"benign scan dga dns_tunnel syn_flood udp_amplification encrypted exfiltration beaconing malformed"}
step scenarios bash -c "SENDER_REPLAY_SPEED=${VERIFY_REPLAY_SPEED:-4} bash scripts/run-scenario.sh $SCEN > '$OUT/runs.jsonl'"
step e2e "${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools \
  python tests/e2e/check_scenarios.py --runs /out/runs.jsonl --out /out/e2e.json --timeout "${VERIFY_TIMEOUT:-2400}"

if [[ "${VERIFY_SKIP_FAILURE:-0}" != "1" ]]; then
  step failure_suite bash tests/failure/run_failure_suite.sh "$OUT"
fi

"${DC[@]}" ps > "$OUT/compose-ps.txt" 2>&1 || true
docker stats --no-stream > "$OUT/docker-stats.txt" 2>&1 || true
log "results: $OUT/results.jsonl"
cat "$RES"
exit $FAIL
