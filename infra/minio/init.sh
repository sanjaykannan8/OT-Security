#!/bin/sh
# minio-init job: buckets, least-privilege users and object-lock on the archive bucket. Idempotent.
set -eu
ROOT_USER="$(cat /run/secrets/minio_root_user)"
ROOT_PASS="$(cat /run/secrets/minio_root_password)"
i=0
until out=$(mc alias set sih http://minio:9000 "$ROOT_USER" "$ROOT_PASS" 2>&1); do
  i=$((i + 1))
  case "$out" in
    *InvalidAccessKeyId*|*SignatureDoesNotMatch*|*"Access Denied"*)
      echo "MinIO rejected the root credentials in ./secrets. If ./secrets was regenerated after MinIO started," >&2
      echo "recreate it so it loads them:  docker compose up -d --force-recreate minio" >&2
      echo "$out" >&2
      exit 1 ;;
  esac
  [ "$i" -gt 60 ] && { echo "minio not reachable: $out" >&2; exit 1; }
  echo "waiting for minio ($i)"; sleep 2
done

mc mb --ignore-existing sih/flink-checkpoints
# Archive objects are write-once: object lock with a default governance retention.
if ! mc stat sih/archive >/dev/null 2>&1; then
  mc mb --with-lock sih/archive
fi
mc retention set --default GOVERNANCE "${ARCHIVE_RETENTION:-7d}" sih/archive || true

mc admin policy create sih sih-flink /policies/flink.json >/dev/null 2>&1 || true
mc admin policy create sih sih-archive /policies/archive.json >/dev/null 2>&1 || true

mc admin user add sih flink "$(cat /run/secrets/minio_flink_secret)"
mc admin user add sih archive "$(cat /run/secrets/minio_archive_secret)"
mc admin policy attach sih sih-flink --user flink >/dev/null 2>&1 || true
mc admin policy attach sih sih-archive --user archive >/dev/null 2>&1 || true
# Fail loudly if a policy is not attached (attach is idempotent but its errors are silenced above).
mc admin user info sih flink | grep -q sih-flink || { echo "policy sih-flink not attached to user flink" >&2; exit 1; }
mc admin user info sih archive | grep -q sih-archive || { echo "policy sih-archive not attached to user archive" >&2; exit 1; }
echo "minio initialised"
