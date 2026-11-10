# Scan service image. In the real environment pass a base image from your internal registry:
#   docker build --build-arg BASE_IMAGE=<registry>/python:3.12-slim -t scansvc .
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

# git is the only system dependency: the service commits and pushes bundles with it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY scansvc ./scansvc
RUN pip install --no-cache-dir ".[azure]"

RUN useradd --uid 10001 --create-home scansvc
USER 10001
ENV HOME=/home/scansvc \
    PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp

EXPOSE 8080
# One worker: scans are I/O bound and state lives in the store, so scale with replicas instead.
CMD ["uvicorn", "scansvc.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
