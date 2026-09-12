#!/usr/bin/env bash
# Failure-injection suite (docs/failure-model.md). Run on the Docker host after `docker compose up -d`.
#   tests/failure/run_failure_suite.sh                                    # every check, in order
#   tests/failure/run_failure_suite.sh jobmanager_restart link_injection  # only these, in the order given
#   tests/failure/run_failure_suite.sh -o <results-dir> [check ...]       # append to an existing run dir
#   tests/failure/run_failure_suite.sh -l                                 # list check names
# Each check appends a JSON line to <results-dir>/failure.jsonl. Checks are independent: each waits for a
# RUNNING job first, injects its own fault and restores whatever it stopped, so any one can be re-run alone.
# A check that aborts is recorded as failed and the remaining checks still run.
#
# Two things to know before re-running:
#  * Code under ingest/, consumers/, flink/, tests/e2e/ and data-generator/ lives in the images, not on the
#    host: run `docker compose build` first or the containers keep executing the old code.
#  * Leave at least incident_idle_ms (300 s) since the previous run. Open incidents for the same entities
#    suppress the repeat alerts these checks assert on (see detect_after).
. "$(dirname "$0")/../../scripts/lib.sh"

CHECKS=(taskmanager_kill jobmanager_restart compose_restart broker_restart clickhouse_outage link_injection archive_lifecycle)
OUT=""
while getopts ":o:lh" opt; do
  case "$opt" in
    o) OUT=$OPTARG ;;
    l) printf '%s\n' "${CHECKS[@]}"; exit 0 ;;
    h) sed -n '2,15p' "$0"; exit 0 ;;
    *) sed -n '2,15p' "$0" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
OUT=${OUT:-benchmarks/results/failure-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"
RES="$OUT/failure.jsonl"
FAIL=0
record() { json_result "$RES" "$1" "$2" "$3"; [[ "$2" == true ]] || FAIL=1; log "$1: $2 $3"; }

SELECTED=("$@")
(( ${#SELECTED[@]} )) || SELECTED=("${CHECKS[@]}")
for c in "${SELECTED[@]}"; do
  case " ${CHECKS[*]} " in
    *" $c "*) ;;
    *) log "unknown check '$c'; valid names: ${CHECKS[*]}"; exit 2 ;;
  esac
done

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
notif() { "${DC[@]}" exec -T alerts-notifier python -c "import sqlite3; print(sqlite3.connect('/data/notifier/notifier.db').execute('select count(*) from notifications').fetchone()[0])"; }

# ------------------------------------------------------------------ F6: TaskManager failure
# Either recovery path is correct here, so the check asserts recovery, not a job id. The TaskManager is gone
# for ~25-30 s (sleep plus `up -d`), which is long enough that the job can lose its slots and the supervisor
# resubmits it from the newest retained checkpoint before Flink's own exponential-delay restart wins. Which
# path happens is a race; demanding the same job id made this check pass or fail on timing alone.
check_taskmanager_kill() {
  local jid before after jid2 path
  jid=$(wait_job_running 300)
  before=$(job_info "$jid")
  wait_checkpoints "$jid" 2 180 || true
  "${DC[@]}" kill flink-taskmanager >/dev/null
  sleep 10
  "${DC[@]}" up -d flink-taskmanager >/dev/null
  if ! jid2=$(wait_job_running 300); then
    record taskmanager_kill false "no RUNNING job after the TaskManager came back"
    return
  fi
  after=$(job_info "$jid2")
  if [[ "$jid2" == "$jid" ]]; then
    path="flink restart strategy kept job $jid"
  elif [[ "$after" == *'"restored_from": "s3://flink-checkpoints/checkpoints/'* ]]; then
    path="supervisor resubmitted as $jid2 from a retained checkpoint"
  else
    record taskmanager_kill false "new job $jid2 that was not restored from a checkpoint: $after"
    return
  fi
  if detect_after tm_kill scan; then record taskmanager_kill true "$path; before=$before after=$after"
  else record taskmanager_kill false "recovered ($path) but detection failed, see tm_kill.e2e.json; after=$after"; fi
}

# ------------------------------------------------------------------ F7: JobManager restart (supervisor resubmits from checkpoint)
check_jobmanager_restart() {
  local jid jid2 info
  jid=$(wait_job_running 300)
  wait_checkpoints "$jid" 1 180 || true
  "${DC[@]}" restart flink-jobmanager >/dev/null
  sleep 20
  if jid2=$(wait_job_running 420); then
    info=$(job_info "$jid2")
    if [[ "$info" != *'"restored_from": "s3://flink-checkpoints/checkpoints/'* ]]; then
      record jobmanager_restart false "job $jid2 not restored from a retained checkpoint: $info"
    elif detect_after jm_restart dga; then
      record jobmanager_restart true "new job $jid2 restored from retained checkpoint: $info"
    else
      record jobmanager_restart false "restored from a checkpoint but detection failed, see jm_restart.e2e.json: $info"
    fi
  else
    record jobmanager_restart false "no running job after JobManager restart"
  fi
}

# ------------------------------------------------------------------ F8: full compose down/up without volume deletion
check_compose_restart() {
  local raw_before alerts_before jid jid2 raw_after alerts_after info
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
}

# ------------------------------------------------------------------ F5: broker restart during replay (receiver spool absorbs it)
check_broker_restart() {
  local runs bg
  wait_job_running 300 >/dev/null
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
}

# ------------------------------------------------------------------ F12: ClickHouse outage (detection and notifier continue)
check_clickhouse_outage() {
  # F12 asserts two things: detection keeps producing alerts while ClickHouse is down (they land once it is
  # back), and the notifier keeps consuming, since it depends only on Kafka and its own SQLite file.
  # The notifier assertion is on committed offsets, NOT on the notification count: notifier.py records only
  # `new` and `escalated` updates, so when the entity already has an open incident the replay legitimately
  # yields `updated` rows and no notification (observed 2026-09-12: two `updated` ddos rows for 10.20.0.80,
  # correctly not notified). Notification growth is reported, not required.
  local jid n_before n_after commits_before commits_after e2e_ok run_id alerts
  jid=$(wait_job_running 300)
  n_before=$(notif)
  commits_before=$(metric alerts-notifier 9102 sih_consumer_commits_total)
  "${DC[@]}" stop clickhouse >/dev/null
  SENDER_REPLAY_SPEED=4 bash scripts/run-scenario.sh syn_flood > "$OUT/ch.runs.jsonl"
  # Poll rather than sleep a fixed 90 s: replay length varies a lot by scenario, and a slow one would look
  # like a stall. ClickHouse stays stopped for the whole poll, so this still proves independence.
  commits_after=$commits_before
  for _ in $(seq 30); do
    commits_after=$(metric alerts-notifier 9102 sih_consumer_commits_total)
    if awk "BEGIN{exit !($commits_after > $commits_before)}"; then break; fi
    sleep 10
  done
  n_after=$(notif)
  "${DC[@]}" start clickhouse >/dev/null
  sleep 30
  e2e_ok=true
  "${DC[@]}" --profile tools run --rm --user "$(id -u):$(id -g)" -v "$ROOT/$OUT:/out" tools     python tests/e2e/check_scenarios.py --runs /out/ch.runs.jsonl --out /out/ch.e2e.json --timeout 600 >/dev/null || e2e_ok=false
  run_id=$(python3 -c 'import json, sys; print(json.loads(open(sys.argv[1]).readline())["run_id"])' "$OUT/ch.runs.jsonl")
  alerts=$(ch "SELECT concat(toString(count()), ' alert rows, statuses=', arrayStringConcat(arraySort(groupUniqArray(status)), '|'), ', subtypes=', arrayStringConcat(arraySort(groupUniqArray(subtype)), '|')) FROM sih.alert_updates FINAL WHERE replay_run_id = '$run_id'")
  if awk "BEGIN{exit !($commits_after > $commits_before)}" && [[ "$e2e_ok" == true ]]; then
    record clickhouse_outage true "notifier kept committing while ClickHouse was stopped ($commits_before->$commits_after), notifications $n_before->$n_after; run $run_id produced $alerts and they were stored once ClickHouse returned"
  else
    record clickhouse_outage false "notifier commits $commits_before->$commits_after, notifications $n_before->$n_after (job $jid), e2e_ok=$e2e_ok; run $run_id: $alerts"
  fi
}

# ------------------------------------------------------------------ F3/F19: injected link faults are quarantined and counted
check_link_injection() {
  local inv_before gaps_before dups_before c inv_after by_reason gaps_after dups_after pair
  inv_before=$(ch "SELECT count() FROM sih.invalid_events FINAL WHERE sensor_id = 'inject-test' OR sensor_id IS NULL")
  gaps_before=$(metric receiver 9101 link_gap_records_total)
  dups_before=$(metric receiver 9101 link_duplicate_records_total)
  for c in malformed bad-hmac invalid-json schema-violation unsupported-version; do
    "${DC[@]}" --profile tools run --rm link-inject python -m sih_sender.inject "$c" 3 >/dev/null
  done
  "${DC[@]}" --profile tools run --rm link-inject python -m sih_sender.inject gap 2 >/dev/null
  sleep 15
  inv_after=$(ch "SELECT count() FROM sih.invalid_events FINAL WHERE sensor_id = 'inject-test' OR sensor_id IS NULL")
  by_reason=$(ch "SELECT reason_code, count() FROM sih.invalid_events FINAL WHERE detected_at > now() - INTERVAL 10 MINUTE GROUP BY reason_code ORDER BY reason_code")
  gaps_after=$(metric receiver 9101 link_gap_records_total)
  dups_after=$(metric receiver 9101 link_duplicate_records_total)
  # Assert per reason code, not on a total. `invalid_id` is deterministic in (reason, payload sha256, sensor,
  # boot, sequence) and invalid_events replaces on it, so the `malformed` case - fixed bytes with no frame
  # identity - collapses to a single row that already exists after the first ever run and adds nothing on a
  # re-run. Counting it made the old total-based threshold pass only on a virgin stack.
  # Expected new rows: bad-hmac 3, invalid-json 3, unsupported-version 3, schema-violation 3 + 2 gap frames
  # (which are schema violations too) = 5. Duplicates rising instead would mean the injector re-used a
  # (sensor, boot, sequence) triple: an image predating the per-invocation boot id, so rebuild and re-run.
  rc() { echo "$by_reason" | awk -v r="$1" -F'	' '$1 == r { print $2 }'; }
  local expect="frame_hmac_invalid:3 json_parse_error:3 schema_violation:5 unsupported_schema_version:3" short=""
  for pair in $expect; do
    local code=${pair%%:*} want=${pair##*:} got
    got=$(rc "$code"); got=${got:-0}
    (( got >= want )) || short="$short $code=$got/<$want"
  done
  if [[ -z "$short" ]] && awk "BEGIN{exit !($gaps_after > $gaps_before)}"; then
    record link_injection true "quarantined $inv_before->$inv_after by reason in the last 10 min: $(echo $by_reason); gaps $gaps_before->$gaps_after"
  else
    record link_injection false "short:$short; quarantined $inv_before->$inv_after by reason: $(echo $by_reason); gaps $gaps_before->$gaps_after duplicates $dups_before->$dups_after"
  fi
}

# ------------------------------------------------------------------ F17: archive lifecycle with accelerated age
# Rows aged 110 days (older than HOT_RETENTION_DAYS=90) must survive while the archive is unavailable,
# then be exported, verified, dropped from hot storage and restorable once it is back.
check_archive_lifecycle() {
  local day pid c1 r1 c2 r2 status r3
  day=$(date -u -d '110 days ago' +%F)
  pid=${day//-/}
  # Re-runs: an earlier run leaves this partition's manifest row at status deleted_hot, which makes the
  # exporter skip it entirely (neither None nor stale), so the test must start from a clean manifest.
  ch "ALTER TABLE sih.archive_manifest DELETE WHERE table_name = 'raw_events' AND partition_id = '$pid' SETTINGS mutations_sync = 1" >/dev/null || true
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
  status=$(ch "SELECT status FROM sih.archive_manifest FINAL WHERE table_name = 'raw_events' AND partition_id = '$pid'")
  "${DC[@]}" run --rm --no-deps archive-exporter python -m sih_consumers.archive restore raw_events "$day" >/dev/null 2>&1 || true
  r3=$(arch_rows)
  if [[ "$r1" == 1000 && "$r2" == 0 && "$status" == "deleted_hot" && "$r3" == 1000 ]]; then
    record archive_lifecycle true "archive down: kept $r1 rows ($c1); archive up: $c2, dropped; restored $r3"
  else
    record archive_lifecycle false "rows down=$r1 after=$r2 restored=$r3 status=$status cycles: $c1 | $c2"
  fi
  ch "ALTER TABLE sih.raw_events DELETE WHERE sensor_id = 'archive-test' SETTINGS mutations_sync = 1" >/dev/null || true
}

for c in "${SELECTED[@]}"; do
  log "== $c"
  # An aborted check must not take the rest of the run with it, and must still appear in the ledger.
  if ! "check_$c"; then
    grep -q "\"check\":\"$c\"" "$RES" 2>/dev/null || record "$c" false "check aborted before recording a result"
  fi
done
# Never leave a stopped dependency behind, whichever checks ran or aborted.
"${DC[@]}" start clickhouse minio >/dev/null 2>&1 || true

log "failure checks finished: $( [[ $FAIL -eq 0 ]] && echo PASS || echo FAIL ) (${SELECTED[*]}) ($RES)"
exit $FAIL
