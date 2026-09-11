#!/usr/bin/env bash
# Environment check for the Docker host. Prints facts; exits non-zero only for hard blockers.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0
say() { printf '%-28s %s\n' "$1" "$2"; }

say "host" "$(uname -srm)"
say "cpus" "$(nproc 2>/dev/null || echo unknown)"
if command -v free >/dev/null; then say "memory" "$(free -h | awk '/Mem:/ {print $2 " total, " $7 " available"}')"; fi
say "disk (repo)" "$(df -h . | awk 'NR==2 {print $4 " free of " $2}')"

if ! command -v docker >/dev/null; then say "docker" "MISSING (required)"; exit 1; fi
say "docker" "$(docker version --format '{{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})' 2>/dev/null || echo 'daemon not reachable')"
docker info >/dev/null 2>&1 || { say "docker daemon" "NOT REACHABLE"; fail=1; }
cv=$(docker compose version --short 2>/dev/null || echo 0)
say "docker compose" "$cv"
if [[ "$(printf '%s\n' "2.24.0" "$cv" | sort -V | head -1)" != "2.24.0" ]]; then
  say "" "Compose >= 2.24 required (uses !reset and --wait)"; fail=1
fi

mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if (( mem_kb > 0 && mem_kb < 12 * 1024 * 1024 )); then say "memory warning" "core runtime needs about 9 GiB of container memory"; fi

for s in link_key minio_root_user minio_root_password minio_flink_secret minio_archive_secret clickhouse_admin_password \
         clickhouse_writer_password clickhouse_reader_password api_admin_password api_analyst_password grafana_admin_password \
         clickhouse-users.xml; do
  [[ -s "secrets/$s" ]] || { say "secret missing" "secrets/$s (run scripts/provision-secrets.sh)"; }
done

for img in sih-python sih-flink sih-zeek; do
  if docker image inspect "$img:${SIH_IMAGE_TAG:-1.0.0}" >/dev/null 2>&1; then say "image $img" "present"; else say "image $img" "not built/loaded"; fi
done

if command -v ss >/dev/null; then
  for p in 8080 8081 3000 9090; do
    if ss -ltn "( sport = :$p )" 2>/dev/null | grep -q LISTEN; then
      if ! docker compose ps --format '{{.Ports}}' 2>/dev/null | grep -q ":$p->"; then say "port $p" "IN USE by another process"; fi
    fi
  done
fi
exit $fail
