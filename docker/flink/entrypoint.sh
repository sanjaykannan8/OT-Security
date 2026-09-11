#!/usr/bin/env bash
# Adds the checkpoint-storage credential from the mounted secret to FLINK_PROPERTIES, then hands over to the
# official Flink entrypoint (which appends FLINK_PROPERTIES to conf/config.yaml).
set -euo pipefail
if [[ -r /run/secrets/minio_flink_secret ]]; then
  FLINK_PROPERTIES="${FLINK_PROPERTIES:-}
s3.access-key: ${MINIO_FLINK_USER:-flink}
s3.secret-key: $(cat /run/secrets/minio_flink_secret)"
  export FLINK_PROPERTIES
fi
exec /docker-entrypoint.sh "$@"
