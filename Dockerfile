FROM python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY ko-prompt-guard /src/ko-prompt-guard
COPY ko-output-guard /src/ko-output-guard
RUN python -m pip wheel --wheel-dir /wheels \
      /src/ko-prompt-guard \
      /src/ko-output-guard \
      "ko-pii @ https://github.com/Marker-Inc-Korea/ko-pii/archive/b128773fc6b6d656393d936bb7be675cd616917a.tar.gz"


FROM python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28 AS runtime

ARG VCS_REF
LABEL org.opencontainers.image.title="ko-output-guard" \
      org.opencontainers.image.description="Hardened Korean output guard service" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/guard \
    KO_GUARD_HOST=0.0.0.0 \
    KO_GUARD_PORT=8080 \
    KO_GUARD_REQUIRE_PROVENANCE=true \
    KO_GUARD_SOURCE_COMMIT="${VCS_REF}" \
    KO_GUARD_SOURCE_DIRTY=false \
    KO_OUTPUT_REQUIRE_PII_BACKEND=true

RUN groupadd --system --gid 10001 guard \
    && useradd --system --uid 10001 --gid 10001 \
       --create-home --home-dir /home/guard --shell /usr/sbin/nologin guard

COPY --from=builder /wheels /tmp/wheels
RUN python -m pip install --no-cache-dir --no-index \
        --find-links /tmp/wheels ko-output-guard ko-prompt-guard ko-pii \
    && rm -rf /tmp/wheels
COPY deployment/guard_service.py /opt/guard-service/guard_service.py

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2)"]
CMD ["python", "/opt/guard-service/guard_service.py", "--kind", "output"]
