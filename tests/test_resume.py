"""The idempotency claim, tested: crash at every step boundary, replay every call, and race two replicas.

A crash is simulated by raising an exception the service does not catch, then building a NEW service over the
same store and the same fake GitHub (GitHub's state survives our process dying). The assertions are always the
same: one scan id, one branch, one workflow dispatch, and the scan still reaches its verdict.
"""
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import Clock, FakeGit, FakeGitHub, Tokens, evidence_zip, make_zip

from scansvc.bundle import sha256_hex
from scansvc.scans import ScanService
from scansvc.store import Conflict, DiskStore

BUNDLE = make_zip({"index.html": "<p>hi</p>"})


class Crash(Exception):
    """Stands in for the process dying. Deliberately not a type the service handles."""


class CrashingStore(DiskStore):
    """Dies immediately AFTER the nth successful record write, like a pod killed between two steps."""

    def __init__(self, root, die_after):
        super().__init__(root)
        self.writes, self.die_after = 0, die_after

    def put(self, record):
        super().put(record)
        self.writes += 1
        if self.writes == self.die_after:
            raise Crash(f"after write {self.writes}")


def service_on(settings, store, github, git, clock):
    return ScanService(settings, store, github, Tokens(), git=git, now=clock, precheck=lambda *_: [])


def passing(record):
    return evidence_zip({"schema": 1, "request_id": record.scan_id, "commit_sha": record.commit_sha,
                         "status": "PASS", "policy_version": "p1", "findings": []})


# Record writes during one submit: 1 created, 2 pushed, 3 dispatching (claim), 4 dispatched.
@pytest.mark.parametrize("die_after, step_left_behind", [
    (1, "created"),       # record saved, nothing sent to GitHub
    (2, "pushed"),        # commit pushed, workflow not requested
    (3, "dispatching"),   # dispatch claimed, request not sent
    (4, "dispatched"),    # everything sent, caller never got the answer
])
def test_crash_at_each_step_then_resubmit_converges_without_duplicates(settings, die_after, step_left_behind):
    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    github.auto_run = True
    with pytest.raises(Crash):
        service_on(settings, CrashingStore(settings.scan_store_url, die_after), github, git, clock).submit(BUNDLE)

    store = DiskStore(settings.scan_store_url)                      # "restart": same disk, new process
    [stuck] = store.pending()
    assert stuck.step == step_left_behind
    clock.value += 31                                               # past the dispatch lease of the dead driver

    service = service_on(settings, store, github, git, clock)
    record, reused = service.submit(BUNDLE)                         # the caller retries with the same bytes
    record = service.advance(record.scan_id)                        # and then polls, as it always does
    assert reused and record.scan_id == stuck.scan_id
    assert record.step == "dispatched"
    assert len(github.dispatched) == 1
    assert len(set(git.pushed)) == 1                                # a repeated push is the same commit, same branch

    github.run = {"id": 1, "status": "completed", "conclusion": "success"}
    github.evidence = passing(record)
    assert service.advance(record.scan_id).status == "PASS"
    assert len(store.pending()) == 0


def test_crash_between_claiming_the_bytes_and_writing_the_record_is_adopted(settings):
    class DiesAfterClaim(DiskStore):
        def claim_sha(self, sha256, expected, new):
            super().claim_sha(sha256, expected, new)
            raise Crash("after claim")

    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    with pytest.raises(Crash):
        service_on(settings, DiesAfterClaim(settings.scan_store_url), github, git, clock).submit(BUNDLE)
    store = DiskStore(settings.scan_store_url)
    dangling = store.pointer(sha256_hex(BUNDLE))
    assert dangling and store.get(dangling) is None                 # claimed, but no record was ever written

    record, _ = service_on(settings, store, github, git, clock).submit(BUNDLE)
    assert record.scan_id == dangling and record.step == "dispatched"
    assert len(github.dispatched) == 1 and len(store.pending()) == 1


def test_crash_after_dispatch_is_finished_by_polling_alone(settings):
    """No resubmit at all: once the commit is on GitHub, status calls can finish the job without the bytes."""
    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    github.auto_run = True
    with pytest.raises(Crash):
        service_on(settings, CrashingStore(settings.scan_store_url, 2), github, git, clock).submit(BUNDLE)
    store = DiskStore(settings.scan_store_url)
    service = service_on(settings, store, github, git, clock)
    [stuck] = store.pending()
    assert service.advance(stuck.scan_id).step == "dispatched" and len(github.dispatched) == 1


def test_a_scan_that_never_reached_github_times_out_if_nobody_resubmits(settings):
    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    with pytest.raises(Crash):
        service_on(settings, CrashingStore(settings.scan_store_url, 1), github, git, clock).submit(BUNDLE)
    store = DiskStore(settings.scan_store_url)
    service = service_on(settings, store, github, git, clock)
    [stuck] = store.pending()
    assert service.advance(stuck.scan_id).status == "running"
    clock.value += 601
    assert service.advance(stuck.scan_id).status == "ERROR"


def test_every_call_can_be_replayed(settings):
    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    github.auto_run = True
    store = DiskStore(settings.scan_store_url)
    service = service_on(settings, store, github, git, clock)
    first, _ = service.submit(BUNDLE)
    for _ in range(3):
        assert service.submit(BUNDLE)[0].scan_id == first.scan_id
        assert service.advance(first.scan_id).status == "running"
    github.run = {"id": 1, "status": "completed", "conclusion": "success"}
    github.evidence = passing(first)
    results = [service.advance(first.scan_id).status for _ in range(3)]
    assert results == ["PASS", "PASS", "PASS"]
    assert len(github.dispatched) == 1 and len(set(git.pushed)) == 1
    assert github.deleted == [f"scan/{first.scan_id}"]              # cleanup ran once
    assert len(list(store._evidence.glob("*.zip"))) == 1


def test_many_concurrent_submits_of_the_same_bytes_start_one_scan(settings):
    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    github.auto_run = True

    def submit(_):
        service = service_on(settings, DiskStore(settings.scan_store_url), github, git, clock)  # one "replica" each
        return service.submit(BUNDLE)[0]

    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(submit, range(16)))
    live = [r for r in DiskStore(settings.scan_store_url).pending()]
    assert len(live) == 1
    assert {r.scan_id for r in records if r.status == "running"} == {live[0].scan_id}
    assert len(github.dispatched) == 1
    assert len(set(git.pushed)) == 1


def test_two_replicas_finishing_the_same_scan_record_one_outcome(settings):
    """Replica A is half-way through collecting the verdict when replica B collects it and finishes first."""
    github, git, clock = FakeGitHub(), FakeGit(), Clock()
    store = DiskStore(settings.scan_store_url)
    a = service_on(settings, store, github, git, clock)
    b = service_on(settings, DiskStore(settings.scan_store_url), FakeGitHub(), git, clock)
    record, _ = a.submit(BUNDLE)
    done = {"id": 7, "status": "completed", "conclusion": "success"}
    github.run = b.github.run = done
    b.github.evidence = passing(record)

    def a_downloads_while_b_finishes(run_id):
        assert b.advance(record.scan_id).status == "PASS"           # B wins the write
        return passing(record)
    github.download_evidence = a_downloads_while_b_finishes

    result = a.advance(record.scan_id)                              # A's write conflicts; it reports B's result
    assert result.status == "PASS"
    stored = store.get(record.scan_id)
    assert stored.status == "PASS" and stored.version == result.version
    assert len(list(store._evidence.glob("*.zip"))) == 1


def test_a_stale_copy_of_a_record_cannot_overwrite_a_newer_one(settings):
    store = DiskStore(settings.scan_store_url)
    service = service_on(settings, store, FakeGitHub(), FakeGit(), Clock())
    record, _ = service.submit(BUNDLE)
    stale = store.get(record.scan_id)
    fresh = store.get(record.scan_id)
    fresh.detail = "newer"
    store.put(fresh)
    stale.finish("PASS")
    with pytest.raises(Conflict):
        store.put(stale)
    assert store.get(record.scan_id).status == "running"
