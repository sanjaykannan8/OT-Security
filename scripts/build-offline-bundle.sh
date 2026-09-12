#!/usr/bin/env bash
# Stage 1 (connected build machine): build every image (unit tests + model training run inside the build),
# export images, lockfiles, SBOM/scan reports when tools are available, and checksums.
set -euo pipefail
cd "$(dirname "$0")/.."
TAG=${SIH_IMAGE_TAG:-1.0.0}
OUT="offline-bundle/sih-$TAG-$(date -u +%Y%m%d)"
mkdir -p "$OUT"
docker compose --profile demo --profile tools --profile search build
mapfile -t images < <(docker compose --profile demo --profile tools --profile search config --images | sort -u)
printf '%s\n' "${images[@]}" > "$OUT/images.txt"
for i in "${images[@]}"; do docker image inspect "$i" --format '{{index .RepoTags 0}} {{.Id}} {{json .RepoDigests}}'; done > "$OUT/image-ids.txt"
docker save "${images[@]}" -o "$OUT/images.tar"

docker run --rm --entrypoint cat "sih-python:$TAG" /opt/venv/requirements.lock > "$OUT/python-requirements.lock"
docker run --rm --entrypoint cat "sih-flink:$TAG" /opt/venv/requirements.lock > "$OUT/flink-python-requirements.lock"
docker run --rm --entrypoint cat "sih-python:$TAG" /app/ui/package-lock.json > "$OUT/dashboard-package-lock.json"
docker run --rm --entrypoint cat "sih-flink:$TAG" /opt/flink/lib/connector.sha256 > "$OUT/flink-kafka-connector.sha256"
docker run --rm --entrypoint cat "sih-python:$TAG" /app/test-results/python-unit.xml > "$OUT/python-unit.xml"
docker run --rm --entrypoint sh "sih-python:$TAG" -c 'cd /opt/sih/models && tar -cf - .' > "$OUT/models.tar"

if command -v syft >/dev/null; then
  for i in "${images[@]}"; do syft "$i" -o spdx-json > "$OUT/sbom-$(echo "$i" | tr '/:' '__').spdx.json"; done
else
  echo "syft not installed: SBOM not generated (install syft on the build machine)" > "$OUT/SBOM-NOT-GENERATED.txt"
fi
if command -v grype >/dev/null; then
  for i in "${images[@]}"; do grype "$i" -o json > "$OUT/vuln-$(echo "$i" | tr '/:' '__').json" || true; done
else
  echo "grype not installed: vulnerability scan not run" > "$OUT/VULN-SCAN-NOT-RUN.txt"
fi

tar -cf "$OUT/repo.tar" --exclude=./offline-bundle --exclude=./secrets --exclude=./.git --exclude=node_modules \
  --exclude=./benchmarks/results .
# Never hash SHA256SUMS into itself: a re-run on the same date reuses $OUT, and a stale self-entry would
# make the offline host fail its own checksum verification.
(cd "$OUT" && find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "bundle written to $OUT"
