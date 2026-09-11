#!/usr/bin/env bash
# Idempotent topic and cluster setup (docs/contracts.md "Topic configuration"). Runs as the redpanda-init job.
# Topic commands use the Kafka API; `cluster health` and `cluster config` use the Admin API (port 9644),
# so both addresses are passed explicitly (inside this container rpk would otherwise default to localhost).
set -euo pipefail
B="${REDPANDA_BROKERS:-redpanda:9092}"
A="${REDPANDA_ADMIN:-redpanda:9644}"
RF="${TOPIC_REPLICATION:-1}"
rpk() { command rpk "$@" -X brokers="$B" -X admin.hosts="$A"; }

healthy=0
for i in $(seq 1 60); do
  if rpk cluster health 2>/dev/null | grep -Eq 'Healthy:\s+true'; then healthy=1; break; fi
  echo "waiting for redpanda ($i)"; sleep 2
done
if [[ $healthy -ne 1 ]]; then
  echo "redpanda did not report healthy via admin API $A" >&2
  rpk cluster health >&2 || true
  exit 1
fi

rpk cluster config set auto_create_topics_enabled false

# name partitions retention.ms retention.bytes
TOPICS=(
  "raw-events.v1 3 86400000 1073741824"
  "features.v1 3 86400000 536870912"
  "alerts.v1 1 604800000 268435456"
  "invalid-events.v1 1 604800000 268435456"
  "sensor-health.v1 1 604800000 134217728"
)
for t in "${TOPICS[@]}"; do
  read -r name parts rms rbytes <<<"$t"
  if rpk topic describe "$name" >/dev/null 2>&1; then
    rpk topic alter-config "$name" --set cleanup.policy=delete --set retention.ms="$rms" \
      --set retention.bytes="$rbytes" --set message.timestamp.type=CreateTime
    echo "reconciled $name"
  else
    rpk topic create "$name" -p "$parts" -r "$RF" -c cleanup.policy=delete -c retention.ms="$rms" \
      -c retention.bytes="$rbytes" -c message.timestamp.type=CreateTime
  fi
done
rpk topic list
