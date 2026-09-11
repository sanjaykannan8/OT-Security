#!/usr/bin/env bash
# Generate per-installation credentials into ./secrets (gitignored). Idempotent: existing values are kept
# unless --rotate is given. Needs only bash + coreutils (no Python on the host).
#
# Files are 0644 inside a 0700 directory: containers run as different users and Compose file secrets are
# bind mounts that keep host permissions, while the directory mode keeps other host users out.
set -euo pipefail
cd "$(dirname "$0")/.."
ROTATE=0
[[ "${1:-}" == "--rotate" ]] && ROTATE=1

mkdir -p secrets
chmod 0700 secrets

rand() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "${1:-32}"; }

CHANGED=0
put() {  # put <name> <value>
  local f="secrets/$1"
  if [[ -s "$f" && $ROTATE -eq 0 ]]; then return; fi
  printf '%s' "$2" > "$f"
  chmod 0644 "$f"
  CHANGED=1
  echo "generated secrets/$1"
}

put link_key "$(rand 48)"
put minio_root_user "sihroot$(rand 6)"
put minio_root_password "$(rand 32)"
put minio_flink_secret "$(rand 32)"
put minio_archive_secret "$(rand 32)"
put clickhouse_admin_password "$(rand 32)"
put clickhouse_writer_password "$(rand 32)"
put clickhouse_reader_password "$(rand 32)"
put api_admin_password "$(rand 20)"
put api_analyst_password "$(rand 20)"
put grafana_admin_password "$(rand 20)"

sha() { printf '%s' "$(cat "secrets/$1")" | sha256sum | cut -d' ' -f1; }

cat > secrets/clickhouse-users.xml <<EOF
<clickhouse>
  <users>
    <default>
      <networks replace="replace"><ip>::1</ip><ip>127.0.0.1</ip></networks>
    </default>
    <sih_admin>
      <password_sha256_hex>$(sha clickhouse_admin_password)</password_sha256_hex>
      <networks><ip>::/0</ip></networks>
      <profile>default</profile>
      <quota>default</quota>
      <grants>
        <query>GRANT ALL ON sih.*</query>
        <query>GRANT SELECT ON system.parts</query>
      </grants>
    </sih_admin>
    <sih_writer>
      <password_sha256_hex>$(sha clickhouse_writer_password)</password_sha256_hex>
      <networks><ip>::/0</ip></networks>
      <profile>default</profile>
      <quota>default</quota>
      <grants><query>GRANT INSERT, SELECT ON sih.*</query></grants>
    </sih_writer>
    <sih_reader>
      <password_sha256_hex>$(sha clickhouse_reader_password)</password_sha256_hex>
      <networks><ip>::/0</ip></networks>
      <profile>readonly_sih</profile>
      <quota>default</quota>
      <grants><query>GRANT SELECT ON sih.*</query></grants>
    </sih_reader>
  </users>
  <profiles>
    <readonly_sih>
      <readonly>2</readonly>
      <max_execution_time>30</max_execution_time>
      <max_result_rows>100000</max_result_rows>
    </readonly_sih>
  </profiles>
</clickhouse>
EOF
chmod 0644 secrets/clickhouse-users.xml

if [[ $CHANGED -eq 1 ]] && command -v docker >/dev/null && [[ -n "$(docker compose ps -q minio clickhouse 2>/dev/null)" ]]; then
  echo
  echo "WARNING: credentials changed while MinIO/ClickHouse containers exist; they still use the old ones."
  echo "         Apply the new credentials (data volumes are kept):"
  echo "           docker compose up -d --force-recreate minio clickhouse && docker compose up -d"
fi

echo
echo "Secrets are in ./secrets (never commit them). UI accounts:"
echo "  admin   / $(cat secrets/api_admin_password)"
echo "  analyst / $(cat secrets/api_analyst_password)"
echo "Grafana admin password: secrets/grafana_admin_password"
