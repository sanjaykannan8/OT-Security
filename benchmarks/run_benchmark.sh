#!/usr/bin/env bash
# Open-loop throughput/latency benchmark on declared hardware.
#   BENCH_RATES="100 500 1000" BENCH_DURATION=600 benchmarks/run_benchmark.sh
# For each offered rate: write a synthetic batch run (records laid out on a fixed schedule), let
# sender-synth replay it at speed 1 (the sender never waits for the receiver), sample container
# resources, then compute accepted/stored rates, drops/gaps and latency percentiles from stored data.
# No result is a performance claim until repeated trials pass the criteria in IMPLEMENTATION_PLAN.md.
. "$(dirname "$0")/../scripts/lib.sh"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="benchmarks/results/bench-$TS"
mkdir -p "$OUT"
RATES=${BENCH_RATES:-"100 500 1000"}
DUR=${BENCH_DURATION:-600}
{ date -u; uname -a; nproc; free -h 2>/dev/null; docker version --format '{{.Server.Version}}'; docker compose version --short;
  docker image inspect sih-python:${SIH_IMAGE_TAG:-1.0.0} sih-flink:${SIH_IMAGE_TAG:-1.0.0} --format '{{.RepoTags}} {{.Id}}'; } > "$OUT/environment.txt" 2>&1

wait_job_running 600 > /dev/null
"${DC[@]}" --profile demo up -d sender-synth > /dev/null
for rate in $RATES; do
  log "rate $rate eps for ${DUR}s"
  run_dir=$("${DC[@]}" --profile tools run --rm synthetic python -m sih_datagen.synthetic batch --out /data/synthetic-runs \
            --rate "$rate" --duration "$DUR" --attacks | tail -1)
  run_id=$(basename "$run_dir")
  echo "{\"rate\":$rate,\"duration_s\":$DUR,\"run_id\":\"$run_id\",\"started\":\"$(date -u +%FT%TZ)\"}" >> "$OUT/runs.jsonl"
  end=$((SECONDS + DUR + 120))
  while (( SECONDS < end )); do
    docker stats --no-stream --format '{{json .}}' | sed "s/^/{\"t\":\"$(date -u +%FT%TZ)\",\"s\":/; s/$/}/" >> "$OUT/stats-$rate.jsonl"
    sleep 10
  done
done
"${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools \
  python benchmarks/analyze.py --runs /out/runs.jsonl --out /out/summary.json
log "benchmark results in $OUT"
