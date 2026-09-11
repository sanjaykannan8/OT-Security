#!/usr/bin/env bash
# Shared helpers for scripts/ and tests/failure/. Source it:  . "$(dirname "$0")/lib.sh"
# Needs only bash, curl-free host tooling and Docker Compose; JSON work happens inside containers.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DC=(docker compose)

log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }

# ClickHouse query as the local default user inside the server container (localhost-only account).
ch() { "${DC[@]}" exec -T clickhouse clickhouse-client --query "$1"; }

# Run Python inside the job-supervisor container (has the Flink REST address and Python).
flinkpy() { "${DC[@]}" exec -T job-supervisor python - "$@"; }

# Prints "<jid> <state>" of the active detection job, or "none NONE".
job_state() {
  flinkpy <<'PY' 2>/dev/null || echo "none NONE"
import json, urllib.request
jobs = json.load(urllib.request.urlopen("http://flink-jobmanager:8081/jobs/overview", timeout=5))["jobs"]
act = [j for j in jobs if j["name"] == "sih-detection" and j["state"] not in ("FINISHED", "CANCELED", "FAILED")]
print(f"{act[0]['jid']} {act[0]['state']}" if act else "none NONE")
PY
}

# wait_job_running [timeout_s] -> prints jid
wait_job_running() {
  local timeout=${1:-300} end=$((SECONDS + ${1:-300})) jid st
  while (( SECONDS < end )); do
    read -r jid st < <(job_state)
    if [[ "$st" == "RUNNING" ]]; then echo "$jid"; return 0; fi
    sleep 5
  done
  log "detection job not RUNNING after ${timeout}s"
  return 1
}

# Prints JSON: {"jid","restarts","completed_checkpoints","restored_from"} for a job id.
job_info() {
  flinkpy "$1" <<'PY'
import json, sys, urllib.request
jid = sys.argv[1]
base = "http://flink-jobmanager:8081"
def get(p):
    return json.load(urllib.request.urlopen(base + p, timeout=5))
cp = get(f"/jobs/{jid}/checkpoints")
restored = (cp.get("latest") or {}).get("restored") or {}
restarts = None
for m in get(f"/jobs/{jid}/metrics?get=numRestarts"):
    restarts = int(float(m["value"]))
print(json.dumps({"jid": jid, "restarts": restarts, "completed_checkpoints": cp["counts"]["completed"],
                  "restored_from": restored.get("external_path")}))
PY
}

# wait_checkpoints <jid> <min_completed> [timeout]
wait_checkpoints() {
  local jid=$1 want=$2 end=$((SECONDS + ${3:-180}))
  while (( SECONDS < end )); do
    local n
    n=$(job_info "$jid" | sed -E 's/.*"completed_checkpoints": ([0-9]+).*/\1/')
    if [[ "$n" =~ ^[0-9]+$ ]] && (( n >= want )); then return 0; fi
    sleep 5
  done
  return 1
}

# Value of a Prometheus metric line on a service's metrics endpoint (sum over label sets).
metric() {  # metric <service> <port> <name>
  "${DC[@]}" exec -T "$1" python -c "
import urllib.request
total = 0.0
for line in urllib.request.urlopen('http://localhost:$2/metrics', timeout=5).read().decode().splitlines():
    if line.startswith('$3') and not line.startswith('#'):
        name = line.split('{')[0].split(' ')[0]
        if name == '$3':
            total += float(line.rsplit(' ', 1)[1])
print(int(total) if total.is_integer() else total)"
}

# wait_stack [timeout_s]: long-running services running (and healthy when they define a healthcheck),
# one-shot *-init jobs exited 0. Avoids relying on `up --wait` semantics for one-shot containers.
wait_stack() {
  local end=$((SECONDS + ${1:-900})) bad=""
  while (( SECONDS < end )); do
    bad=$("${DC[@]}" ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' | awk -F'|' '
      $1 ~ /-init$/ { if ($2 != "exited" || $4 != 0) print $1; next }
      { if ($2 != "running" || ($3 != "" && $3 != "healthy")) print $1 }')
    [[ -z "$bad" ]] && return 0
    sleep 5
  done
  log "services not ready: $(echo $bad)"
  return 1
}

up_stack() { "${DC[@]}" up -d && wait_stack "${1:-900}"; }

json_result() {  # json_result <file> <check> <ok:true|false> <detail>
  local detail=${4//\"/\'}
  printf '{"check":"%s","ok":%s,"detail":"%s","at":"%s"}\n' "$2" "$3" "$detail" "$(date -u +%FT%TZ)" >> "$1"
}
