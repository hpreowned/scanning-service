import json

import pytest
from fakes import Clock, FakeGit, FakeGitHub, Tokens, evidence_zip, make_zip
from fastapi.testclient import TestClient

from scansvc import audit
from scansvc.app import create_app
from scansvc.api_auth import SharedTokenAuth
from scansvc.bundle import BundleError, sha256_hex
from scansvc.backends import HttpBackend
from scansvc.config import ConfigError
from scansvc.models import Busy
from scansvc.service import ScanService
from scansvc.store import DiskStore

BUNDLE = make_zip({"index.html": "<p>hi</p>"})
API_TOKEN = "test-only-value"
AUTH = {"Authorization": f"Bearer {API_TOKEN}"}


def make_service(settings, github=None):
    return ScanService(settings, DiskStore(settings.scan_store_url), github or FakeGitHub(), Tokens(),
                       git=FakeGit(), now=Clock(), precheck=lambda *_: [])


@pytest.fixture
def api(settings):
    github = FakeGitHub()
    return TestClient(create_app(make_service(settings, github), auth=SharedTokenAuth(API_TOKEN))), github


def test_health_and_metrics_are_open_and_everything_else_needs_a_token(api):
    client, _ = api
    assert client.get("/healthz").json() == {"ok": True}
    assert client.get("/metrics").status_code == 200
    assert client.post("/v1/scans", content=BUNDLE).status_code == 401
    assert client.get("/v1/scans/s-abc", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/v1/scans/s-abc", headers={"Authorization": API_TOKEN}).status_code == 401   # not "Bearer ..."


def test_app_refuses_to_start_without_an_auth_mode(settings):
    with pytest.raises(ConfigError, match="API_AUTH_MODE"):
        create_app(make_service(settings))
    object.__setattr__(settings, "api_auth_mode", "token")       # token mode without a token is refused too
    with pytest.raises(ConfigError, match="SCAN_API_TOKEN"):
        create_app(make_service(settings))


def test_scan_lifecycle_over_http(api):
    client, github = api
    started = client.post("/v1/scans", content=BUNDLE, headers={**AUTH, "X-Bundle-Sha256": sha256_hex(BUNDLE)})
    assert started.status_code == 202
    scan = started.json()
    assert scan["status"] == "running" and scan["reused"] is False
    assert "etag" not in scan and "version" not in scan and scan["createdAt"].endswith("Z")

    assert client.get(f"/v1/scans/{scan['scanId']}", headers=AUTH).json()["status"] == "running"
    github.run = {"id": 7, "status": "completed", "conclusion": "success", "html_url": "u"}
    github.evidence = evidence_zip({"schema": 1, "request_id": scan["scanId"], "commit_sha": scan["commitSha"],
                                    "status": "pass", "policy_version": "p1", "findings": []})
    assert client.get(f"/v1/scans/{scan['scanId']}", headers=AUTH).json()["status"] == "pass"

    again = client.post("/v1/scans", content=BUNDLE, headers=AUTH)      # same bytes: answered from the cache
    assert again.status_code == 200 and again.json()["reused"] is True


def test_bad_uploads_get_clear_errors(api, settings):
    client, _ = api
    assert client.post("/v1/scans", content=b"nope", headers=AUTH).status_code == 422
    assert client.post("/v1/scans", content=BUNDLE, headers={**AUTH, "X-Bundle-Sha256": "0" * 64}).status_code == 422
    too_big = b"x" * (settings.max_bundle_bytes + 1)
    assert client.post("/v1/scans", content=too_big, headers=AUTH).status_code == 413
    assert client.get("/v1/scans/s-unknown", headers=AUTH).status_code == 404
    assert client.get("/v1/scans/..%2F..%2Fetc", headers=AUTH).status_code == 404


def test_at_capacity_answers_429_with_retry_after(api, settings):
    client, _ = api
    object.__setattr__(settings, "max_in_flight", 1)
    assert client.post("/v1/scans", content=BUNDLE, headers=AUTH).status_code == 202
    busy = client.post("/v1/scans", content=make_zip({"other.html": "x"}), headers=AUTH)
    assert busy.status_code == 429 and int(busy.headers["Retry-After"]) > 0
    with pytest.raises(Busy):
        HttpBackend("http://testserver", API_TOKEN, http=client).submit(make_zip({"third.html": "x"}))


def test_correlation_headers_caller_and_audit_trail(api, capsys):
    client, github = api
    audit.configure()
    trace = "00-" + "a" * 32 + "-" + "b" * 16 + "-01"
    headers = {**AUTH, "X-Job-Id": "job_123", "traceparent": trace}
    scan = client.post("/v1/scans", content=BUNDLE, headers=headers).json()
    assert (scan["jobId"], scan["traceparent"], scan["caller"]) == ("job_123", trace, "shared-token")
    # A header that is not the expected shape is dropped, never stored.
    odd = client.post("/v1/scans", content=make_zip({"b.html": "x"}), headers={**AUTH, "X-Job-Id": "x" * 200}).json()
    assert odd["jobId"] is None

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    mine = [e for e in events if e.get("scanId") == scan["scanId"]]
    assert [e["event"] for e in mine] == ["scan.created", "scan.pushed", "scan.dispatched"]
    assert mine[0]["jobId"] == "job_123" and mine[-1]["commitSha"] == scan["commitSha"]


def test_metrics_report_submits_verdicts_and_scans_in_flight(api):
    client, github = api
    scan = client.post("/v1/scans", content=BUNDLE, headers=AUTH).json()
    client.post("/v1/scans", content=BUNDLE, headers=AUTH)
    text = client.get("/metrics").text
    assert 'scansvc_submits_total{outcome="new"} 1' in text
    assert 'scansvc_submits_total{outcome="reused"} 1' in text
    assert "scansvc_scans_in_flight 1" in text
    github.run = {"id": 7, "status": "completed", "conclusion": "success"}
    github.evidence = evidence_zip({"schema": 1, "request_id": scan["scanId"], "commit_sha": scan["commitSha"],
                                    "status": "pass", "policy_version": "p1", "findings": []})
    client.get(f"/v1/scans/{scan['scanId']}", headers=AUTH)
    text = client.get("/metrics").text
    assert 'scansvc_verdicts_total{status="pass"} 1' in text and "scansvc_scans_in_flight 0" in text
    assert 'scansvc_scan_seconds_count{status="pass"} 1' in text


def test_scanctl_http_backend_speaks_the_same_api(api):
    client, _ = api
    backend = HttpBackend("http://testserver", API_TOKEN, http=client, job_id="job_9")
    record = backend.submit(BUNDLE)
    assert record["jobId"] == "job_9"
    assert backend.status(record["scanId"])["scanId"] == record["scanId"]
    assert backend.status("s-unknown") is None
    with pytest.raises(BundleError):
        backend.submit(b"nope")
    with pytest.raises(RuntimeError):
        HttpBackend("http://testserver", None)
