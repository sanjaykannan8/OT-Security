#!/usr/bin/env bash
# clickhouse-init job: wait for the server, then apply idempotent migrations as sih_admin.
set -euo pipefail
PASS="$(cat /run/secrets/clickhouse_admin_password)"
CH=(clickhouse-client --host "${CLICKHOUSE_HOST:-clickhouse}" --user sih_admin --password "$PASS")
ok=0
for i in $(seq 1 60); do
  if out=$("${CH[@]}" --query "SELECT 1" 2>&1); then ok=1; break; fi
  if grep -q "AUTHENTICATION_FAILED\|Code: 516" <<<"$out"; then
    echo "ClickHouse rejected sih_admin's password. If ./secrets was regenerated after the server started," >&2
    echo "recreate it so it loads the new users file:  docker compose up -d --force-recreate clickhouse" >&2
    echo "$out" | head -3 >&2
    exit 1
  fi
  echo "waiting for clickhouse ($i)"; sleep 2
done
if [[ $ok -ne 1 ]]; then
  echo "clickhouse not reachable as sih_admin: $out" >&2
  exit 1
fi
for f in /migrations/*.sql; do
  echo "applying $f"
  "${CH[@]}" --multiquery < "$f"
done
"${CH[@]}" --query "SELECT max(version) FROM sih.schema_migrations"
