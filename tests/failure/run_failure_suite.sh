#!/usr/bin/env bash
# Failure-injection suite (docs/failure-model.md). Run on the Docker host after `docker compose up -d`.
#   tests/failure/run_failure_suite.sh <results-dir>
# Each check appends a JSON line to <results-dir>/failure.jsonl. Each fault replays a different short
# scenario afterwards to prove detection keeps working (see detect_after for why they must differ).
. "$(dirname "$0")/../../scripts/lib.sh"
OUT=${1:-benchmarks/results/failure-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"
RES="$OUT/failure.jsonl"
FAIL=0
record() { json_result "$RES" "$1" "$2" "$3"; [[ "$2" == true ]] || FAIL=1; log "$1: $2 $3"; }

# detect_after <name> <scenario>: replay one scenario after a fault and require its alert.
# Each fault MUST use a different scenario. Incidents stay open for incident_idle_ms (300 s) and
# incidents.py deliberately suppresses a repeat finding at the same severity when the evidence has not
# grown, so replaying one scenario at several faults minutes apart would report a design-correct
# suppression as a detection failure (observed 2026-09-12: three `scan` replays in four minutes).
detect_after() {
  local runs="$OUT/$1.runs.jsonl"
  SENDER_REPLAY_SPEED=${SENDER_REPLAY_SPEED:-4} bash scripts/run-scenario.sh "$2" > "$runs"
  "${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools \
    python tests/e2e/check_scenarios.py --runs "/out/$1.runs.jsonl" --out "/out/$1.e2e.json" --timeout 900 > /dev/null
}

count() { ch "SELECT count() FROM sih.$1 FINAL"; }

# ------------------------------------------------------------------ F6: TaskManager failure
jid=$(wait_job_running 300)
before=$(job_info "$jid")
wait_checkpoints "$jid" 2 180 || true
"${DC[@]}" kill flink-taskmanager >/dev/null
sleep 10
"${DC[@]}" up -d flink-taskmanager >/dev/null
if jid2=$(wait_job_running 300) && [[ "$jid2" == "$jid" ]]; then
  after=$(job_info "$jid")
  if detect_after tm_kill scan; then record taskmanager_kill true "same job recovered; before=$before after=$after"
  else record taskmanager_kill false "job recovered but detection check failed; after=$after"; fi
else
  record taskmanager_kill false "job not RUNNING again with the same id"
fi

# ------------------------------------------------------------------ F7: JobManager restart (supervisor resubmits from checkpoint)
jid=$(wait_job_running 300)
wait_checkpoints "$jid" 1 180 || true
"${DC[@]}" restart flink-jobmanager >/dev/null
sleep 20
if jid2=$(wait_job_running 420); then
  info=$(job_info "$jid2")
  if [[ "$info" == *'"restored_from": "s3://flink-checkpoints/checkpoints/'* ]] && detect_after jm_restart dga; then
    record jobmanager_restart true "new job $jid2 restored from retained checkpoint: $info"
  else
    record jobmanager_restart false "job $jid2 not restored from a checkpoint or detection failed: $info"
  fi
else
  record jobmanager_restart false "no running job after JobManager restart"
fi

# ------------------------------------------------------------------ F8: full compose down/up without volume deletion
raw_before=$(count raw_events); alerts_before=$(count alert_updates)
jid=$(wait_job_running 300); wait_checkpoints "$jid" 1 180 || true
"${DC[@]}" --profile demo down >/dev/null 2>&1
up_stack 900 >/dev/null
"${DC[@]}" --profile demo up -d sender-pcap >/dev/null
if jid2=$(wait_job_running 600); then
  raw_after=$(count raw_events); alerts_after=$(count alert_updates); info=$(job_info "$jid2")
  if (( raw_after >= raw_before && alerts_after >= alerts_before )) && [[ "$info" == *'checkpoints/'* ]] && detect_after compose_restart udp_amplification; then
    record compose_restart true "raw $raw_before->$raw_after alerts $alerts_before->$alerts_after; $info"
  else
    record compose_restart false "raw $raw_before->$raw_after alerts $alerts_before->$alerts_after; $info"
  fi
else
  record compose_restart false "job not running after compose up"
fi

# ------------------------------------------------------------------ F5: broker restart during replay (receiver spool absorbs it)
runs="$OUT/broker.runs.jsonl"
SENDER_REPLAY_SPEED=1 bash scripts/run-scenario.sh dns_tunnel > "$runs" &
bg=$!
sleep 25
"${DC[@]}" restart redpanda >/dev/null
wait $bg || true
if "${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools \
     python tests/e2e/check_scenarios.py --runs /out/broker.runs.jsonl --out /out/broker.e2e.json --timeout 900 >/dev/null; then
  record broker_restart true "all replayed records stored and tunnel detected after broker restart"
else
  record broker_restart false "see broker.e2e.json"
fi

# ------------------------------------------------------------------ F12: ClickHouse outage (detection and notifier continue)
notif() { "${DC[@]}" exec -T alerts-notifier python -c "import sqlite3; print(sqlite3.connect('/data/notifier/notifier.db').execute('select count(*) from notifications').fetchone()[0])"; }
n_before=$(notif)
"${DC[@]}" stop clickhouse >/dev/null
SENDER_REPLAY_SPEED=4 bash scripts/run-scenario.sh syn_flood > "$OUT/ch.runs.jsonl"
sleep 90
n_during=$(notif)
"${DC[@]}" start clickhouse >/dev/null
sleep 30
if (( n_during > n_before )) && "${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools \
     python tests/e2e/check_scenarios.py --runs /out/ch.runs.jsonl --out /out/ch.e2e.json --timeout 600 >/dev/null; then
  record clickhouse_outage true "notifications during outage $n_before->$n_during; consumers caught up after restart"
else
  record clickhouse_outage false "notifications $n_before->$n_during; see ch.e2e.json"
fi

# ------------------------------------------------------------------ F3/F19: injected link faults are quarantined and counted
inv_before=$(ch "SELECT count() FROM sih.invalid_events FINAL WHERE sensor_id = 'inject-test' OR sensor_id IS NULL")
gaps_before=$(metric receiver 9101 link_gap_records_total)
for c in malformed bad-hmac invalid-json schema-violation unsupported-version; do
  "${DC[@]}" --profile tools run --rm link-inject python -m sih_sender.inject "$c" 3 >/dev/null
done
"${DC[@]}" --profile tools run --rm link-inject python -m sih_sender.inject gap 2 >/dev/null
sleep 15
inv_after=$(ch "SELECT count() FROM sih.invalid_events FINAL WHERE sensor_id = 'inject-test' OR sensor_id IS NULL")
reasons=$(ch "SELECT groupUniqArray(reason_code) FROM sih.invalid_events FINAL WHERE detected_at > now() - INTERVAL 10 MINUTE")
gaps_after=$(metric receiver 9101 link_gap_records_total)
if (( inv_after >= inv_before + 15 )) && awk "BEGIN{exit !($gaps_after > $gaps_before)}"; then
  record link_injection true "quarantined $inv_before->$inv_after reasons=$reasons gaps $gaps_before->$gaps_after"
else
  record link_injection false "quarantined $inv_before->$inv_after reasons=$reasons gaps $gaps_before->$gaps_after"
fi

# ------------------------------------------------------------------ F17: archive lifecycle with accelerated age
# Rows aged 110 days (older than HOT_RETENTION_DAYS=90) must survive while the archive is unavailable,
# then be exported, verified, dropped from hot storage and restorable once it is back.
day=$(date -u -d '110 days ago' +%F)
ch "INSERT INTO sih.raw_events (event_id, sensor_id, sensor_boot_id, sequence, replay_run_id, log_type, event_time,
    observation_time, receiver_received_at, capture_mode, observation_coverage, uid, src_ip, src_port, dst_ip, dst_port,
    proto, event_json)
    SELECT generateUUIDv4(), 'archive-test', generateUUIDv4(), number, 'archive-lifecycle', 'conn',
           toDateTime64('$day 12:00:00', 6, 'UTC'), toDateTime64('$day 12:00:00', 3, 'UTC'), toDateTime64('$day 12:00:00', 6, 'UTC'),
           'synthetic_log', 'both_directions', NULL, '10.0.0.1', 1, '10.0.0.2', 2, 'tcp', '{}' FROM numbers(1000)"
# --no-deps is essential: archive-exporter depends_on minio-init, so a plain `run` would restart MinIO
# and silently undo the outage this test is injecting.
cycle() { "${DC[@]}" run --rm --no-deps archive-exporter python -c "from sih_consumers.archive import Archiver; print(Archiver().cycle())" 2>&1 | tail -1; }
arch_rows() { ch "SELECT count() FROM sih.raw_events WHERE sensor_id = 'archive-test'"; }
"${DC[@]}" stop minio >/dev/null
c1=$(cycle); r1=$(arch_rows)
"${DC[@]}" start minio >/dev/null
sleep 10
c2=$(cycle); r2=$(arch_rows)
status=$(ch "SELECT status FROM sih.archive_manifest FINAL WHERE table_name = 'raw_events' AND partition_id = '${day//-/}'")
"${DC[@]}" run --rm --no-deps archive-exporter python -m sih_consumers.archive restore raw_events "$day" >/dev/null 2>&1 || true
r3=$(arch_rows)
if [[ "$r1" == 1000 && "$r2" == 0 && "$status" == "deleted_hot" && "$r3" == 1000 ]]; then
  record archive_lifecycle true "archive down: kept $r1 rows ($c1); archive up: $c2, dropped; restored $r3"
else
  record archive_lifecycle false "rows down=$r1 after=$r2 restored=$r3 status=$status cycles: $c1 | $c2"
fi
ch "ALTER TABLE sih.raw_events DELETE WHERE sensor_id = 'archive-test'" >/dev/null || true

log "failure suite finished: $( [[ $FAIL -eq 0 ]] && echo PASS || echo FAIL ) ($RES)"
exit $FAIL
