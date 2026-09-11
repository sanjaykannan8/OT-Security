#!/bin/sh
# minio-init job: buckets, least-privilege users and object-lock on the archive bucket. Idempotent.
set -eu
ROOT_USER="$(cat /run/secrets/minio_root_user)"
ROOT_PASS="$(cat /run/secrets/minio_root_password)"
i=0
until mc alias set sih http://minio:9000 "$ROOT_USER" "$ROOT_PASS" >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "minio not reachable" >&2; exit 1; }
  echo "waiting for minio ($i)"; sleep 2
done

mc mb --ignore-existing sih/flink-checkpoints
# Archive objects are write-once: object lock with a default governance retention.
if ! mc stat sih/archive >/dev/null 2>&1; then
  mc mb --with-lock sih/archive
fi
mc retention set --default GOVERNANCE "${ARCHIVE_RETENTION:-7d}" sih/archive || true

mc admin policy create sih sih-flink /policies/flink.json 2>/dev/null || mc admin policy create sih sih-flink /policies/flink.json || true
mc admin policy create sih sih-archive /policies/archive.json 2>/dev/null || true

mc admin user add sih flink "$(cat /run/secrets/minio_flink_secret)"
mc admin user add sih archive "$(cat /run/secrets/minio_archive_secret)"
mc admin policy attach sih sih-flink --user flink 2>/dev/null || true
mc admin policy attach sih sih-archive --user archive 2>/dev/null || true
echo "minio initialised"
