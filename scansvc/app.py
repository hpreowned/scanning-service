"""HTTP API. The contract is contracts/scan-openapi.yaml.

Every /v1 call is authenticated (auth.py); there is no unauthenticated mode and the app refuses to start
without one configured. /healthz and /metrics are open and carry nothing sensitive; restrict them by network.
"""
import logging
import re
from importlib import metadata

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse

from . import audit, metrics
from .api_auth import AuthError, auth_for
from .bundle import BundleError
from .config import ConfigError
from .models import Busy
from .wiring import build_service

JOB_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
TRACEPARENT = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")


async def _read_capped(request, limit):
    """The request body, refusing as soon as it passes the limit rather than buffering an oversized upload."""
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail=f"the bundle is larger than {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _version():
    try:
        return metadata.version("scansvc")  # pyproject.toml is the one place the version is written
    except metadata.PackageNotFoundError:
        return "0.0.0"


def _clean(value, pattern):
    """A correlation header is recorded only if it has the expected shape; anything else is dropped."""
    return value if value and pattern.match(value) else None


def create_app(service=None, auth=None):
    service = service or build_service()
    try:
        auth = auth or auth_for(service.settings)
    except ValueError as err:
        raise ConfigError(str(err)) from None
    audit.configure()
    if auth.name == "token":
        logging.getLogger("scansvc").warning("shared-token authentication is for local development only")

    def caller(request: Request):
        try:
            return auth.verify(request.headers.get("authorization"))
        except AuthError as err:
            raise HTTPException(status_code=401, detail=str(err)) from None

    app = FastAPI(title="Artifact scan service", version=_version(), docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics_endpoint():
        return metrics.render({"scansvc_scans_in_flight": len(service.store.pending())})

    @app.post("/v1/scans")
    async def start_scan(request: Request, who: str = Depends(caller)):
        data = await _read_capped(request, service.settings.max_bundle_bytes)
        headers = request.headers
        try:
            record, reused = await run_in_threadpool(
                service.submit, data, headers.get("x-bundle-sha256"),
                _clean(headers.get("x-job-id"), JOB_ID), who, _clean(headers.get("traceparent"), TRACEPARENT))
        except BundleError as err:
            raise HTTPException(status_code=422, detail=str(err)) from None
        except Busy as busy:
            return JSONResponse({"detail": str(busy)}, status_code=429, headers={"Retry-After": str(busy.retry_after)})
                # 202 while GitHub is still working; 200 when the answer is already final (cache hit or pre-push failure).
        return JSONResponse(record.to_api(reused), status_code=200 if record.final else 202)

    @app.get("/v1/scans/{scan_id}", dependencies=[Depends(caller)])
    async def get_scan(scan_id: str):
        if not scan_id.replace("-", "").isalnum() or len(scan_id) > 64:
            raise HTTPException(status_code=404, detail="unknown scan id")
        record = await run_in_threadpool(service.advance, scan_id)
        if record is None:
            raise HTTPException(status_code=404, detail="unknown scan id")
        return record.to_api()

    return app
