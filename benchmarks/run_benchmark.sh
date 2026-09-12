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

# "<sent> <total>" as last reported outward by the sender for one run (empty before its first report).
replay_progress() {
  ch "SELECT argMax(JSONExtractInt(record_json, 'replay_records_sent'), health_seq),
             argMax(JSONExtractInt(record_json, 'replay_records_total'), health_seq)
      FROM sih.sensor_health FINAL
      WHERE JSONExtractString(record_json, 'replay_run_id') = '$1'" 2>/dev/null | tr '\t' ' '
}

for rate in $RATES; do
  log "rate $rate eps for ${DUR}s"
  run_dir=$("${DC[@]}" --profile tools run --rm synthetic python -m sih_datagen.synthetic batch --out /data/synthetic-runs \
            --rate "$rate" --duration "$DUR" --attacks | tail -1)
  run_id=$(basename "$run_dir")
  started=$(date -u +%FT%TZ)
  want=$(awk "BEGIN{printf \"%d\", $rate * $DUR}")
  gaps_before=$(metric receiver 9101 link_gap_records_total)
  # Wait for the replay itself, not a fixed timer: a run still in flight would otherwise be scored as loss.
  # Finished = the sender reported everything sent, or reported no progress for 60 s (it is no longer on this run).
  end=$((SECONDS + DUR + 600)); last=-1; stall=0; finished=false
  while (( SECONDS < end )); do
    docker stats --no-stream --format '{{json .}}' | sed "s/^/{\"t\":\"$(date -u +%FT%TZ)\",\"s\":/; s/$/}/" >> "$OUT/stats-$rate.jsonl"
    sent=""; total=""
    read -r sent total < <(replay_progress "$run_id") || true
    sent=${sent:-0}; total=${total:-0}
    # Stored rows are the ground truth. The sensor_health progress fields lag and, at rate 100, stalled at
    # 14087 of 60000 while every record was in fact delivered and stored (bench-20260912T082157Z).
    stored=$(ch "SELECT count() FROM sih.raw_events FINAL WHERE replay_run_id = '$run_id'" 2>/dev/null || echo 0)
    if (( ${stored:-0} >= want )); then finished=true; break; fi
    if (( total > 0 && sent >= total )); then finished=true; break; fi
    if (( sent == last )); then stall=$((stall + 1)); else stall=0; last=$sent; fi
    if (( sent > 0 && stall >= 6 )); then finished=true; break; fi
    sleep 10
  done
  [[ "$finished" == true ]] || log "rate $rate: replay did not finish within $((DUR + 600))s (last sent=$last, stored=${stored:-0}/$want)"
  sleep 90  # let the pipeline drain into ClickHouse before measuring
  gaps_after=$(metric receiver 9101 link_gap_records_total)
  # Per-rate gap delta: the raw counter is cumulative, so reporting its snapshot tells you nothing per rate.
  echo "{\"rate\":$rate,\"duration_s\":$DUR,\"run_id\":\"$run_id\",\"started\":\"$started\",\"replay_finished\":$finished,\"link_gaps_during_run\":$(awk "BEGIN{printf \"%d\", $gaps_after - $gaps_before}")}" >> "$OUT/runs.jsonl"
done
"${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools \
  python benchmarks/analyze.py --runs /out/runs.jsonl --out /out/summary.json
log "benchmark results in $OUT"
