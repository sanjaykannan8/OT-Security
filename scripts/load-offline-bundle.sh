#!/usr/bin/env bash
# Stage 2 (offline target): verify checksums, load images, unpack the repository. No registry pulls.
#   scripts/load-offline-bundle.sh <bundle-dir> [target-dir]
set -euo pipefail
B=${1:?usage: load-offline-bundle.sh <bundle-dir> [target-dir]}
T=${2:-./sih}
(cd "$B" && sha256sum -c SHA256SUMS)
docker load -i "$B/images.tar"
mkdir -p "$T"
tar -xf "$B/repo.tar" -C "$T"
cat <<EOF
Loaded. Next, on this offline host:
  cd $T
  bash scripts/provision-secrets.sh
  bash scripts/doctor.sh
  docker compose up -d                 # uses the loaded images; nothing is pulled
  docker compose --profile demo up -d
  bash scripts/run-scenario.sh mixed
EOF
