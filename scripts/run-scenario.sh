#!/usr/bin/env bash
# Generate the scenario PCAPs (local files only), run Zeek on them and let sender-pcap replay the results
# across the one-way link. Prints one JSON line per run: {"run_id","scenario","logs"}.
#   scripts/run-scenario.sh mixed
#   scripts/run-scenario.sh scan dga syn_flood
# Scenarios: benign syn_flood syn_flood_few udp_amplification beaconing dga dns_tunnel encrypted scan
#            exfiltration malformed mixed
. "$(dirname "$0")/lib.sh"
if [[ $# -lt 1 ]]; then
  sed -n '2,9p' "$0" >&2
  exit 2
fi
log "generating fixtures: $*"
"${DC[@]}" --profile tools run --rm fixtures python -m sih_datagen.pcap --out /data/fixtures/pcaps --scenario "$@" >&2
log "ensuring sender-pcap is running"
"${DC[@]}" --profile demo up -d sender-pcap >&2
log "running Zeek (file analysis, network_mode none)"
"${DC[@]}" --profile tools run --rm zeek-replay "$@"
