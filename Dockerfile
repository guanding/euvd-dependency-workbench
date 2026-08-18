FROM python:3.14-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements.lock ./
COPY scripts/bootstrap_demo_snapshot.py ./scripts/bootstrap_demo_snapshot.py
RUN python -m pip install --require-hashes --requirement requirements.lock --target /opt/site-packages \
    && mkdir -p /opt/runtime-data/uploads /opt/runtime-data/jobs \
        /opt/runtime-outputs /opt/runtime-euvd \
    && python ./scripts/bootstrap_demo_snapshot.py --output-dir /opt/runtime-euvd

FROM cgr.dev/chainguard/python:latest@sha256:b3d3fbb8b9fe48950bab73d49bffa7496ff6f8a46ba570b302fc366f1396011a

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/site-packages \
    EUVD_LOCAL_DB=/app/euvd/euvd-readonly.sqlite3 \
    EUVD_LOCAL_DB_SHA256_FILE=/app/euvd/euvd-readonly.sqlite3.sha256

WORKDIR /app

COPY --from=builder --chown=65532:65532 /opt/site-packages ./site-packages
COPY --from=builder --chown=65532:65532 /opt/runtime-data ./data
COPY --from=builder --chown=65532:65532 /opt/runtime-outputs ./outputs
COPY --from=builder --chown=65532:65532 /opt/runtime-euvd ./euvd
COPY --chown=65532:65532 app ./app
COPY --chown=65532:65532 config ./config
COPY --chown=65532:65532 LICENSE NOTICE THIRD_PARTY_NOTICES.md ./licenses/

USER 65532:65532

EXPOSE 8090

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/api/health', timeout=4).read()"]

ENTRYPOINT ["/usr/bin/python", "-m", "uvicorn"]
CMD ["app.main:app", "--host", "0.0.0.0", "--port", "8090"]
