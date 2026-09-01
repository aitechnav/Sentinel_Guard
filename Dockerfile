FROM python:3.11-slim

ARG SENTINELGUARD_EXTRAS=gateway,monitoring
ARG SENTINELGUARD_SPACY_MODEL=en_core_web_sm
ARG SENTINELGUARD_SPACY_MODEL_VERSION=3.8.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SENTINELGUARD_PII_SPACY_MODEL=${SENTINELGUARD_SPACY_MODEL} \
    SENTINELGUARD_PII_DOWNLOAD_MISSING_MODEL=false

WORKDIR /app

COPY pyproject.toml README.md ./
COPY sentinelguard ./sentinelguard

RUN python -m pip install --upgrade pip \
    && python -m pip install ".[${SENTINELGUARD_EXTRAS}]" \
    && python -m pip install "https://github.com/explosion/spacy-models/releases/download/${SENTINELGUARD_SPACY_MODEL}-${SENTINELGUARD_SPACY_MODEL_VERSION}/${SENTINELGUARD_SPACY_MODEL}-${SENTINELGUARD_SPACY_MODEL_VERSION}-py3-none-any.whl"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/gateway/v1/health', timeout=3)"

ENTRYPOINT ["sentinelguard"]
CMD ["gateway", "--host", "0.0.0.0", "--port", "8080"]
