FROM python:3.11-slim

ARG SENTINELGUARD_EXTRAS=gateway,monitoring

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY sentinelguard ./sentinelguard

RUN python -m pip install --upgrade pip \
    && python -m pip install ".[${SENTINELGUARD_EXTRAS}]"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/gateway/v1/health', timeout=3)"

ENTRYPOINT ["sentinelguard"]
CMD ["gateway", "--host", "0.0.0.0", "--port", "8080"]
