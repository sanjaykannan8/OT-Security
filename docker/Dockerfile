# syntax=docker/dockerfile:1.7
# One build graph for every SIH image. BuildKit builds shared stages once.
#   python-runtime : sender, receiver, consumers, API (+ compiled UI), generators, tools
#   flink-runtime  : Flink 2.2.1 + PyFlink job + local ONNX model + supervisor
# The runtime targets depend on the `test` stage, so `docker compose build` fails if unit tests fail.

ARG PYTHON_IMAGE=python:3.12.11-slim-bookworm
ARG NODE_IMAGE=node:22.23.2-bookworm-slim
ARG FLINK_IMAGE=flink:2.2.1-scala_2.12-java17

# ---------------------------------------------------------------- security dashboard (offline bundle)
FROM ${NODE_IMAGE} AS ui
WORKDIR /ui
COPY dashboard-security/package.json ./
RUN npm install --no-audit --no-fund
COPY dashboard-security/ ./
RUN npm run build && cp package-lock.json dist/package-lock.json

# ---------------------------------------------------------------- Python dependencies
FROM ${PYTHON_IMAGE} AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY docker/python/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install -r /tmp/requirements.txt \
 && /opt/venv/bin/pip freeze > /opt/venv/requirements.lock

FROM deps AS source
WORKDIR /app
COPY schemas /app/schemas
COPY lib /app/lib
COPY ingest /app/ingest
COPY flink/sih_detect /app/flink/sih_detect
COPY consumers /app/consumers
COPY backend /app/backend
COPY data-generator /app/data-generator
COPY model-training /app/model-training
COPY data/fixtures /app/data/fixtures
COPY tests /app/tests
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIH_SCHEMA_DIR=/app/schemas \
    PYTHONPATH=/app/lib:/app/ingest/sender:/app/ingest/receiver:/app/flink:/app/consumers:/app/backend:/app/data-generator:/app/model-training

# ---------------------------------------------------------------- model training (deterministic)
FROM source AS model
RUN python -m sih_ml.train_dga --out /build/models --datasets /build/datasets | tee /build/training-summary.json

# ---------------------------------------------------------------- unit tests (gate for runtime images)
FROM source AS test
COPY --from=model /build/models /opt/sih/models
RUN mkdir -p /build/test-results \
 && python schemas/examples/build_examples.py --check \
 && python -m pytest -q tests/unit tests/schema -p no:cacheprovider --junitxml=/build/test-results/python-unit.xml

# ---------------------------------------------------------------- Python runtime
FROM ${PYTHON_IMAGE} AS python-runtime
RUN groupadd -g 10001 sih && useradd -u 10001 -g sih -M -s /usr/sbin/nologin sih \
 && mkdir -p /data/receiver /data/notifier /data/api /data/fixtures/pcaps /data/zeek-logs /data/sender-state \
             /data/synthetic-runs /data/synthetic-live /opt/sih \
 && chown -R 10001:10001 /data
COPY --from=deps /opt/venv /opt/venv
COPY --from=source /app /app
COPY --from=model /build/models /opt/sih/models
COPY --from=model /build/training-summary.json /opt/sih/models/training-summary.json
COPY --from=ui /ui/dist /app/ui
COPY --from=test /build/test-results /app/test-results
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIH_SCHEMA_DIR=/app/schemas \
    UI_DIR=/app/ui \
    PYTHONPATH=/app/lib:/app/ingest/sender:/app/ingest/receiver:/app/flink:/app/consumers:/app/backend:/app/data-generator:/app/model-training
WORKDIR /app
USER 10001

# ---------------------------------------------------------------- Flink runtime (PyFlink)
FROM ${FLINK_IMAGE} AS flink-runtime
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY docker/flink/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && /opt/venv/bin/pip freeze > /opt/venv/requirements.lock
ARG KAFKA_CONNECTOR_VERSION=5.0.0-2.2
RUN set -eux; cd /opt/flink/lib; \
    jar="flink-sql-connector-kafka-${KAFKA_CONNECTOR_VERSION}.jar"; \
    base="https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/${KAFKA_CONNECTOR_VERSION}"; \
    curl -fsSLO "$base/$jar"; curl -fsSL "$base/$jar.sha1" -o /tmp/connector.sha1; \
    echo "$(cut -c1-40 /tmp/connector.sha1)  $jar" | sha1sum -c -; \
    sha256sum "$jar" > /opt/flink/lib/connector.sha256
RUN set -eux; \
    mkdir -p /opt/flink/plugins/s3-fs-presto; cp /opt/flink/opt/flink-s3-fs-presto-*.jar /opt/flink/plugins/s3-fs-presto/; \
    if [ ! -d /opt/flink/plugins/metrics-prometheus ]; then \
      mkdir -p /opt/flink/plugins/metrics-prometheus; cp /opt/flink/opt/flink-metrics-prometheus-*.jar /opt/flink/plugins/metrics-prometheus/; \
    fi; \
    ls /opt/flink/plugins/metrics-prometheus/*.jar; \
    if ls /opt/flink/opt/flink-python*.jar >/dev/null 2>&1; then cp /opt/flink/opt/flink-python*.jar /opt/flink/lib/; fi
COPY lib /opt/sih/lib
COPY flink/sih_detect /opt/sih/flink/sih_detect
COPY schemas /opt/sih/schemas
COPY data/fixtures/asset-inventory.json /opt/sih/reference/asset-inventory.json
COPY --from=model /build/models /opt/sih/models
COPY --from=test /build/test-results /opt/sih/test-results
COPY docker/flink/entrypoint.sh /opt/sih/entrypoint.sh
RUN chmod 0755 /opt/sih/entrypoint.sh && chown -R flink:flink /opt/flink/conf /opt/flink/log /opt/sih
ENV PATH=/opt/venv/bin:/opt/flink/bin:$PATH \
    PYTHONPATH=/opt/sih/lib:/opt/sih/flink \
    SIH_SCHEMA_DIR=/opt/sih/schemas \
    PYTHONDONTWRITEBYTECODE=1
USER flink
ENTRYPOINT ["/opt/sih/entrypoint.sh"]
