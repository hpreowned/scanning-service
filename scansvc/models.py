"""The scan record: one per submitted bundle. Stored as JSON; findings use the artifacts platform's shape."""
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

RUNNING = "running"
PASS, FAIL, ERROR = "pass", "fail", "error"
FINAL = (PASS, FAIL, ERROR)

# How far a running scan has got. Persisted before and after each external side effect, so a restarted process
# (or a repeated submit of the same bytes) continues from here instead of starting again.
CREATED = "created"          # record exists; nothing sent to GitHub yet
PUSHED = "pushed"            # the bundle commit is on scan/<id>
DISPATCHING = "dispatching"  # one driver has claimed the right to dispatch
DISPATCHED = "dispatched"    # the workflow run was requested


class Busy(Exception):
    """Too many scans in flight; the caller should retry after `retry_after` seconds."""

    def __init__(self, retry_after=30):
        super().__init__(f"too many scans in flight; retry in {retry_after} seconds")
        self.retry_after = retry_after


def _iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_scan_id():
    # Also the scan/<id> branch name and the workflow's request_id: lower-case, 8 to 64 chars.
    return "s-" + uuid.uuid4().hex


def finding(rule, severity, message, file=None, line=None):
    out = {"rule": rule, "severity": severity, "message": message}
    if file:
        out["file"] = file
    if line:
        out["line"] = line
    return out


@dataclass
class ScanRecord:
    scan_id: str
    sha256: str
    status: str = RUNNING
    step: str = CREATED
    commit_sha: str | None = None
    run_id: int | None = None
    run_url: str | None = None
    policy_version: str | None = None
    detail: str | None = None
    findings: list = field(default_factory=list)
    scanners: list = field(default_factory=list)
    unscanned: list = field(default_factory=list)
    job_id: str | None = None    # the caller's own id for this publish (for example the artifacts jobId)
    caller: str | None = None     # who submitted it, from the authenticated request
    traceparent: str | None = None  # W3C trace context supplied by the caller
    version: int = 0              # bumped on every stored write; used for conditional writes
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    etag: str | None = field(default=None, repr=False, compare=False)  # store-side token, never persisted

    @property
    def final(self):
        return self.status in FINAL

    def finish(self, status, detail=None, findings=None):
        self.status = status
        self.detail = detail
        if findings is not None:
            self.findings = findings
        self.updated_at = time.time()
        return self

    def to_dict(self):
        data = asdict(self)
        data.pop("etag", None)
        return data

    def to_api(self, reused=None):
        """The record as the HTTP API and scanctl present it: camelCase like the artifacts API, ISO timestamps,
        and none of the store's bookkeeping (version, etag)."""
        out = {
            "scanId": self.scan_id, "sha256": self.sha256, "status": self.status, "step": self.step,
            "commitSha": self.commit_sha, "runId": self.run_id, "runUrl": self.run_url,
            "policyVersion": self.policy_version, "detail": self.detail, "findings": self.findings,
            "scanners": self.scanners, "unscanned": self.unscanned, "jobId": self.job_id, "caller": self.caller,
            "traceparent": self.traceparent, "createdAt": _iso(self.created_at), "updatedAt": _iso(self.updated_at),
        }
        if reused is not None:
            out["reused"] = reused
        return out

    @classmethod
    def from_dict(cls, data):
        known = {name for name in cls.__dataclass_fields__ if name != "etag"}
        return cls(**{key: value for key, value in data.items() if key in known})
