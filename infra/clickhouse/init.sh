#!/usr/bin/env bash
# clickhouse-init job: wait for the server, then apply idempotent migrations as sih_admin.
set -euo pipefail
PASS="$(cat /run/secrets/clickhouse_admin_password)"
CH=(clickhouse-client --host "${CLICKHOUSE_HOST:-clickhouse}" --user sih_admin --password "$PASS")
for i in $(seq 1 60); do
  if "${CH[@]}" --query "SELECT 1" >/dev/null 2>&1; then break; fi
  echo "waiting for clickhouse ($i)"; sleep 2
done
for f in /migrations/*.sql; do
  echo "applying $f"
  "${CH[@]}" --multiquery < "$f"
done
"${CH[@]}" --query "SELECT max(version) FROM sih.schema_migrations"
