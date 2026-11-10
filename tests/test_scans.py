import pytest
from conftest import Clock, FakeGit, FakeGitHub, Tokens, evidence_zip, make_zip

from scansvc import scan_repo
from scansvc.bundle import BundleError, sha256_hex
from scansvc.github_api import GitHubError
from scansvc.models import Busy
from scansvc.scans import ScanService
from scansvc.secrets_precheck import PrecheckError
from scansvc.store import DiskStore

BUNDLE = make_zip({"index.html": "<p>hi</p>"})


@pytest.fixture
def world(settings):
    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    store = DiskStore(settings.scan_store_url)
    service = ScanService(settings, store, github, Tokens(), git=git, now=clock, precheck=lambda *_: [])
    return service, github, git, clock, store


def verdict(record, status="PASS", **extra):
    return {"schema": 1, "request_id": record.scan_id, "commit_sha": record.commit_sha, "status": status,
            "policy_version": "p1", "findings": [], "scanners": [], "unscanned": [], **extra}


def finish(github, record, status="PASS", conclusion="success", **extra):
    github.run = {"id": 7, "status": "completed", "conclusion": conclusion, "html_url": "https://example.invalid/run/7"}
    github.evidence = evidence_zip(verdict(record, status, **extra))


def test_submit_pushes_and_dispatches(world):
    service, github, git, _, store = world
    record, reused = service.submit(BUNDLE, sha256_hex(BUNDLE), job_ref="job_1", caller="worker")
    assert (record.status, record.step, reused) == ("running", "dispatched", False)
    assert git.pushed == [(record.scan_id, record.commit_sha)]
    assert github.dispatched == [(record.scan_id, record.commit_sha)]
    stored = store.get(record.scan_id)
    assert (stored.sha256, stored.job_ref, stored.caller) == (sha256_hex(BUNDLE), "job_1", "worker")


def test_wrong_sha256_and_bad_bundles_create_no_scan(world):
    service, github, _, _, store = world
    with pytest.raises(BundleError, match="sha256"):
        service.submit(BUNDLE, "0" * 64)
    with pytest.raises(BundleError):
        service.submit(make_zip({"../x": "1"}))
    assert github.dispatched == [] and store.pending() == []


def test_advance_waits_then_takes_the_verdict_and_cleans_up(world):
    service, github, _, _, store = world
    record, _ = service.submit(BUNDLE)
    assert service.advance(record.scan_id).status == "running"          # run not created yet
    github.run = {"id": 7, "status": "in_progress", "html_url": "u"}
    assert service.advance(record.scan_id).run_id == 7                   # run found, still going
    finish(github, record, "FAIL", findings=[{"rule": "GH-001", "severity": "deny", "message": "xss"}])
    done = service.advance(record.scan_id)
    assert (done.status, done.policy_version, done.findings[0]["rule"]) == ("FAIL", "p1", "GH-001")
    assert github.deleted == [f"scan/{record.scan_id}"]
    assert (store._evidence / f"{record.scan_id}.zip").exists()
    assert service.advance(record.scan_id).status == "FAIL"              # final records do not move


@pytest.mark.parametrize("tamper, fragment", [
    ({"commit_sha": "d" * 40}, "different commit"),
    ({"request_id": "s-someone-else"}, "different request"),
    ({"schema": 99}, "schema"),
    ({"status": "MAYBE"}, "unknown verdict status"),
])
def test_a_verdict_that_does_not_match_the_scan_is_an_error(world, tamper, fragment):
    service, github, _, _, _ = world
    record, _ = service.submit(BUNDLE)
    github.run = {"id": 7, "status": "completed", "conclusion": "success"}
    github.evidence = evidence_zip({**verdict(record), **tamper})
    done = service.advance(record.scan_id)
    assert done.status == "ERROR" and fragment in done.detail


def test_failed_run_is_an_error_even_with_a_passing_verdict(world):
    service, github, _, _, _ = world
    record, _ = service.submit(BUNDLE)
    finish(github, record, "PASS", conclusion="failure")
    done = service.advance(record.scan_id)
    assert done.status == "ERROR" and done.findings[-1]["rule"] == "GH-000"


def test_run_without_evidence_is_an_error(world):
    service, github, _, _, _ = world
    record, _ = service.submit(BUNDLE)
    github.run = {"id": 7, "status": "completed", "conclusion": "failure"}
    assert service.advance(record.scan_id).status == "ERROR"


def test_timeout_cancels_and_errors(world):
    service, github, _, clock, _ = world
    record, _ = service.submit(BUNDLE)
    github.run = {"id": 7, "status": "in_progress"}
    clock.value += 601
    done = service.advance(record.scan_id)
    assert done.status == "ERROR" and github.cancelled == [7] and github.deleted == [f"scan/{record.scan_id}"]


def test_transient_github_failure_keeps_the_scan_running(world):
    service, github, _, _, _ = world
    record, _ = service.submit(BUNDLE)
    github.fail_next = "HTTP 502"
    assert service.advance(record.scan_id).status == "running"


def test_push_protection_is_a_secret_finding_and_nothing_is_dispatched(world):
    service, github, git, _, _ = world
    git.push_error = scan_repo.PushError("GitHub push protection refused the bundle", secret=True)
    record, _ = service.submit(BUNDLE)
    assert (record.status, record.findings[0]["rule"]) == ("FAIL", "GH-005")
    assert github.dispatched == []


def test_push_failure_and_permanent_dispatch_failure_are_errors(world):
    service, github, git, _, _ = world
    git.push_error = scan_repo.PushError("remote unreachable")
    assert service.submit(BUNDLE)[0].status == "ERROR"
    git.push_error = None
    github.fail_next = GitHubError("HTTP 404", status=404)        # for example the workflow file is missing
    record, _ = service.submit(make_zip({"other.html": "x"}))
    assert record.status == "ERROR" and github.deleted == [f"scan/{record.scan_id}"]


def test_transient_dispatch_failure_is_retried_by_the_next_status_call(world):
    service, github, _, clock, _ = world
    github.fail_next = GitHubError("HTTP 503", status=503)
    record, _ = service.submit(BUNDLE)
    assert (record.status, record.step) == ("running", "dispatching") and github.dispatched == []
    assert service.advance(record.scan_id).step == "dispatching"  # inside the lease: left alone
    clock.value += 31
    assert service.advance(record.scan_id).step == "dispatched"
    assert len(github.dispatched) == 1


def test_gitleaks_hit_fails_before_any_push(world, settings):
    service, github, git, _, _ = world
    object.__setattr__(settings, "gitleaks_bin", "/opt/gitleaks")
    service.precheck = lambda *_: [{"rule": "GH-005", "severity": "deny", "message": "secret", "file": "a.js"}]
    record, _ = service.submit(BUNDLE)
    assert record.status == "FAIL" and git.pushed == [] and github.dispatched == []

    def broken(*_):
        raise PrecheckError("gitleaks could not be run")
    service.precheck = broken
    assert service.submit(make_zip({"b.html": "x"}))[0].status == "ERROR"


def test_same_bytes_reuse_an_in_flight_scan_and_a_recent_verdict(world):
    service, github, _, clock, _ = world
    first, _ = service.submit(BUNDLE)
    again, reused = service.submit(BUNDLE)
    assert reused and again.scan_id == first.scan_id and len(github.dispatched) == 1
    finish(github, first)
    service.advance(first.scan_id)
    assert service.submit(BUNDLE)[1] is True                 # recent PASS under the same policy
    github.policy = "p2"
    clock.value += 400                                        # past the policy memo
    assert service.submit(BUNDLE)[1] is False                # policy changed: scan again


def test_errors_and_stale_verdicts_are_never_reused(world):
    service, github, _, clock, _ = world
    first, _ = service.submit(BUNDLE)
    github.run = {"id": 7, "status": "completed", "conclusion": "failure"}
    service.advance(first.scan_id)
    second, reused = service.submit(BUNDLE)
    assert reused is False and second.scan_id != first.scan_id   # ERROR is not cached
    finish(github, second)
    service.advance(second.scan_id)
    clock.value += 25 * 3600
    assert service.submit(BUNDLE)[1] is False                    # older than the cache window


def test_capacity_limit_refuses_new_scans_but_not_known_ones(world, settings):
    service, _, _, _, _ = world
    object.__setattr__(settings, "max_in_flight", 1)
    first, _ = service.submit(BUNDLE)
    with pytest.raises(Busy) as busy:
        service.submit(make_zip({"other.html": "x"}))
    assert busy.value.retry_after > 0
    assert service.submit(BUNDLE)[0].scan_id == first.scan_id     # the scan already in flight is still answered


def test_reconcile_advances_everything_pending(world):
    service, github, _, _, _ = world
    record, _ = service.submit(BUNDLE)
    finish(github, record)
    assert [r.status for r in service.reconcile()] == ["PASS"]
    assert service.reconcile() == []
