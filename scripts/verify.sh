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
if [[ ! -s secrets/link_key ]]; then
  bash scripts/provision-secrets.sh > "$OUT/provision.log"
  # Servers started with earlier credentials must reload the new ones (volumes are kept).
  if [[ -n "$("${DC[@]}" ps -q minio clickhouse 2>/dev/null)" ]]; then
    log "new secrets generated: recreating minio and clickhouse so they load them"
    "${DC[@]}" up -d --force-recreate minio clickhouse >> "$OUT/provision.log" 2>&1
  fi
fi
{ date -u; uname -a; docker version; docker compose version; nproc; free -h 2>/dev/null; df -h .; } > "$OUT/environment.txt" 2>&1 || true

required() {  # a failed prerequisite makes every later step meaningless: stop here
  if [[ $FAIL -ne 0 ]]; then
    log "stopping: prerequisite '$1' failed. Last lines of $OUT/$1.log:"
    tail -n 60 "$OUT/$1.log" >&2
    local svcs=""
    case "$1" in
      up)
        svcs=$(grep -o 'services not ready: .*' "$OUT/up.log" | tail -1 | sed 's/services not ready: //')
        # Init jobs that exited non-zero make `docker compose up` abort before the readiness wait runs.
        svcs="$svcs $("${DC[@]}" ps -a --format '{{.Service}} {{.ExitCode}} {{.State}}' | awk '$3 == "exited" && $2 != 0 {print $1}' | tr '\n' ' ')"
        svcs=$(echo $svcs) ;;
      job_running) svcs="job-supervisor flink-jobmanager flink-taskmanager" ;;
    esac
    if [[ -n "$svcs" ]]; then
      "${DC[@]}" ps -a > "$OUT/$1-ps.txt" 2>&1 || true
      # shellcheck disable=SC2086
      "${DC[@]}" logs --no-color --tail 80 $svcs > "$OUT/$1-service-logs.txt" 2>&1 || true
      log "logs of: $svcs (saved to $OUT/$1-service-logs.txt)"
      tail -n 150 "$OUT/$1-service-logs.txt" >&2
    fi
    exit 1
  fi
}

step build "${DC[@]}" --profile demo --profile tools --profile search build
required build
step unit_test_results bash -c "docker run --rm --entrypoint cat sih-python:${SIH_IMAGE_TAG:-1.0.0} /app/test-results/python-unit.xml > '$OUT/python-unit.xml'"
step model_summary bash -c "docker run --rm --entrypoint cat sih-python:${SIH_IMAGE_TAG:-1.0.0} /opt/sih/models/training-summary.json > '$OUT/model-training-summary.json'"
step up up_stack 900
required up
step job_running wait_job_running 600
required job_running
step demo_up env SENDER_REPLAY_SPEED="${VERIFY_REPLAY_SPEED:-4}" "${DC[@]}" --profile demo up -d sender-pcap

SCEN=${VERIFY_SCENARIOS:-"benign scan dga dns_tunnel syn_flood udp_amplification encrypted exfiltration beaconing malformed"}
step scenarios bash -c "SENDER_REPLAY_SPEED=${VERIFY_REPLAY_SPEED:-4} bash scripts/run-scenario.sh $SCEN > '$OUT/runs.jsonl'"
step e2e "${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools \
  python tests/e2e/check_scenarios.py --runs /out/runs.jsonl --out /out/e2e.json --timeout "${VERIFY_TIMEOUT:-2400}"

if [[ "${VERIFY_SKIP_FAILURE:-0}" != "1" ]]; then
  step failure_suite bash tests/failure/run_failure_suite.sh -o "$OUT"
fi

"${DC[@]}" ps > "$OUT/compose-ps.txt" 2>&1 || true
docker stats --no-stream > "$OUT/docker-stats.txt" 2>&1 || true
log "results: $OUT/results.jsonl"
cat "$RES"
exit $FAIL
