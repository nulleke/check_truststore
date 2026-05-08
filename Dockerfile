FROM python:3.11-slim as builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY setup.py pyproject.toml /app/
COPY src /app/src

RUN pip install --upgrade pip
RUN pip install --prefix=/install .[all]

FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /install /usr/local
RUN useradd -m analyzer && chown -R analyzer /app
USER analyzer
RUN mkdir -p /app/certs /app/output_bundles

ENTRYPOINT ["check_truststore"]

CMD ["--help"]