"""Everything after the bundle is on GitHub: dispatching the workflow once, and collecting its verdict.

Functions take the ScanService so that submit (scans.py) and status polling share one implementation.
"""
import io
import json
import zipfile

from . import audit, metrics
from .github_api import GitHubError
from .models import CREATED, DISPATCHED, DISPATCHING, ERROR, FINAL, PUSHED, finding
from .store import Conflict

VERDICT_SCHEMA = 1
DISPATCH_LEASE_SECONDS = 30  # how long a driver that claimed the dispatch is left alone before another takes over


def error_finding(message):
    return [finding("GH-000", "error", message)]


def dispatch_once(service, record):
    """Requests the workflow run unless one already exists.

    Claiming comes first: the conditional write to DISPATCHING succeeds for exactly one driver, and the others get
    Conflict. A record left in DISPATCHING by a driver that died is taken over after the lease.
    """
    if record.step == DISPATCHING and service.now() - record.updated_at < DISPATCH_LEASE_SECONDS:
        return
    if record.step not in (PUSHED, DISPATCHING):
        return
    record.step = DISPATCHING
    service._save(record)
    if not service.github.find_run(record.scan_id, record.created_at):
        service.github.dispatch(record.scan_id, record.commit_sha)
    record.step = DISPATCHED
    service._save(record)
    audit.emit("scan.dispatched", record)


def advance(service, scan_id):
    """Moves a running scan one step. Idempotent. Returns the record, or None for an unknown id."""
    record = service.store.get(scan_id)
    if record is None or record.final:
        return record
    try:
        if record.step in (PUSHED, DISPATCHING):
            dispatch_once(service, record)
        elif record.step == DISPATCHED:
            run = (service.github.get_run(record.run_id) if record.run_id
                   else service.github.find_run(scan_id, record.created_at))
            if run:
                record.run_id, record.run_url = run["id"], run.get("html_url")
                if run.get("status") == "completed":
                    complete(service, record, run)
        # CREATED: nothing reached GitHub and the bytes are gone. A repeated submit continues it; otherwise it
        # times out below.
    except Conflict:
        return service.store.get(scan_id)
    except GitHubError as err:
        metrics.inc("scansvc_github_errors_total", kind="permanent" if err.permanent else "transient")
        if err.permanent and record.step != DISPATCHED:
            record.finish(ERROR, str(err), error_finding(f"the scan workflow could not be started: {err}"))
        else:
            record.detail = f"waiting: {err}"  # transient; the timeout below is the backstop

    if not record.final and service.now() - record.created_at > service.settings.scan_timeout_seconds:
        if record.run_id:
            try:
                service.github.cancel_run(record.run_id)
            except GitHubError:
                pass
        record.finish(ERROR, "timed out", error_finding(f"no verdict within {service.settings.scan_timeout_seconds} seconds"))
    try:
        service._save(record)
    except Conflict:
        return service.store.get(scan_id)  # another replica wrote first; its result stands
    if record.final:
        after_final(service, record)
    return record


def complete(service, record, run):
    """Turns a completed run into a final status. Trusts a verdict only if it is for this request and commit."""
    conclusion = run.get("conclusion")
    evidence = service.github.download_evidence(run["id"])
    if evidence is None:
        record.finish(ERROR, f"run {conclusion}", error_finding(f"the scan run ended `{conclusion}` and uploaded no evidence"))
        return
    service.store.put_evidence(record.scan_id, evidence)
    verdict = read_verdict(evidence)
    problem = verdict_problem(verdict, record)
    if problem:
        record.finish(ERROR, problem, error_finding(problem))
        return
    record.findings = verdict.get("findings", [])
    record.scanners = verdict.get("scanners", [])
    record.unscanned = verdict.get("unscanned", [])
    record.policy_version = verdict.get("policy_version")
    if conclusion != "success":
        # A FAIL verdict still exits 0, so a run that did not succeed means the scan itself did not complete.
        record.findings = record.findings + error_finding(f"the scan run ended `{conclusion}`")
        record.finish(ERROR, f"run {conclusion}")
    else:
        record.finish(verdict["status"])


def after_final(service, record):
    """Cleanup and reporting for a record whose final state is already stored. Safe to run twice."""
    if record.step != CREATED:  # a branch exists only once the push succeeded
        try:
            service.github.delete_branch(f"scan/{record.scan_id}")
        except GitHubError:
            pass  # a stale branch is harmless and visible
    metrics.inc("scansvc_verdicts_total", status=record.status)
    metrics.observe("scansvc_scan_seconds", record.updated_at - record.created_at, status=record.status)
    audit.emit("scan.final", record, detail=record.detail)


def read_verdict(evidence):
    try:
        with zipfile.ZipFile(io.BytesIO(evidence)) as archive:
            info = archive.getinfo("verdict.json")
            if info.file_size > 5 * 1024 * 1024:
                return None
            return json.loads(archive.read(info))
    except (KeyError, ValueError, zipfile.BadZipFile, OSError):
        return None


def verdict_problem(verdict, record):
    """Why this verdict cannot be trusted for this record, or None."""
    if not isinstance(verdict, dict):
        return "the evidence holds no readable verdict.json"
    if verdict.get("schema") != VERDICT_SCHEMA:
        return f"unsupported verdict schema {verdict.get('schema')!r}"
    if verdict.get("request_id") != record.scan_id:
        return "the verdict is for a different request"
    if verdict.get("commit_sha") != record.commit_sha:
        return "the verdict is for a different commit than the one pushed"
    if verdict.get("status") not in FINAL:
        return f"unknown verdict status {verdict.get('status')!r}"
    return None
