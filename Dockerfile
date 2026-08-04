FROM python:3.14-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements.txt ./
RUN python -m pip install --requirement requirements.txt --target /opt/site-packages \
    && mkdir -p /opt/runtime-data/uploads /opt/runtime-data/jobs \
        /opt/runtime-outputs /opt/runtime-euvd

FROM cgr.dev/chainguard/python:latest@sha256:b3d3fbb8b9fe48950bab73d49bffa7496ff6f8a46ba570b302fc366f1396011a

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/site-packages

WORKDIR /app

COPY --from=builder --chown=65532:65532 /opt/site-packages ./site-packages
COPY --from=builder --chown=65532:65532 /opt/runtime-data ./data
COPY --from=builder --chown=65532:65532 /opt/runtime-outputs ./outputs
COPY --from=builder --chown=65532:65532 /opt/runtime-euvd ./euvd
COPY --chown=65532:65532 app ./app
COPY --chown=65532:65532 config ./config

USER 65532:65532

EXPOSE 8090

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/api/health', timeout=4).read()"]

ENTRYPOINT ["/usr/bin/python", "-m", "uvicorn"]
CMD ["app.main:app", "--host", "0.0.0.0", "--port", "8090"]
