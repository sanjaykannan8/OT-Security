#!/usr/bin/env bash
# Run Zeek on mounted fixture PCAPs and publish each result as a complete run directory for the sender.
#   replay.sh <scenario> [scenario ...]   |   replay.sh all
# Each run is written to a hidden temp directory, renamed atomically and then marked with `.done`,
# so the sender never reads a partially written run.
set -euo pipefail

PCAP_DIR="${PCAP_DIR:-/data/fixtures/pcaps}"
LOG_ROOT="${ZEEK_LOG_ROOT:-/data/zeek-logs}"
SCRIPTS="${ZEEK_SCRIPTS:-/opt/sih/zeek/local.zeek}"

if [[ $# -eq 0 ]]; then
  echo "usage: replay.sh <scenario>... | all" >&2
  exit 2
fi

if [[ "$1" == "all" ]]; then
  mapfile -t names < <(find "$PCAP_DIR" -maxdepth 1 -name '*.pcap' -printf '%f\n' | sed 's/\.pcap$//' | sort)
else
  names=("$@")
fi

mkdir -p "$LOG_ROOT"
for name in "${names[@]}"; do
  pcap="$PCAP_DIR/$name.pcap"
  if [[ ! -f "$pcap" ]]; then
    echo "missing $pcap (generate fixtures first)" >&2
    exit 1
  fi
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$name"
  tmp="$LOG_ROOT/.tmp-$run_id"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  (cd "$tmp" && zeek -C -r "$pcap" "$SCRIPTS")
  if [[ -f "$PCAP_DIR/$name.manifest.json" ]]; then
    cp "$PCAP_DIR/$name.manifest.json" "$tmp/manifest.json"
  fi
  mv "$tmp" "$LOG_ROOT/$run_id"
  touch "$LOG_ROOT/$run_id/.done"
  echo "{\"run_id\":\"$run_id\",\"scenario\":\"$name\",\"logs\":\"$LOG_ROOT/$run_id\"}"
  sleep 1  # distinct run ids for back-to-back scenarios
done
