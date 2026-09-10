FROM python:3.11-slim as builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/
COPY src /app/src
COPY README.md /app/

RUN pip install --upgrade pip && \
    pip install build && \
    python -m build --wheel --outdir /dist

FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl[all] && \
    rm -rf /tmp/*.whl

RUN useradd -m analyzer && \
    mkdir -p /app/certs /app/output_bundles && \
    chown -R analyzer:analyzer /app

USER analyzer

ENTRYPOINT ["check_truststore"]
CMD ["--help"]