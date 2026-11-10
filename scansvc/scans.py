"""Submitting a bundle. No background worker: every call reads the store, does what the stored step allows, and
writes it back with a conditional write.

The rule that makes this safe to repeat: save the record first, then act, then save how far it got. A process
that dies anywhere leaves a record saying where to continue, and a repeated submit of the same bytes continues
that record instead of starting another scan.
"""
import subprocess
import tempfile
import time

from . import audit, collect, metrics, scan_repo
from .bundle import BundleError, extract, sha256_hex
from .collect import error_finding
from .github_api import GitHubError
from .models import (CREATED, DISPATCHED, DISPATCHING, ERROR, FAIL, PASS, PUSHED, Busy, ScanRecord, finding,
                     new_scan_id)
from .secrets_precheck import PrecheckError, gitleaks_findings
from .store import Conflict

POLICY_MEMO_SECONDS = 300


class ScanService:
    def __init__(self, settings, store, github, tokens, git=scan_repo, now=time.time, precheck=gitleaks_findings):
        self.settings, self.store, self.github, self.tokens = settings, store, github, tokens
        self.git, self.now, self.precheck = git, now, precheck
        self._policy = (None, 0.0)

    # --- submit -------------------------------------------------------------------------------------------------

    def submit(self, data, claimed_sha256=None, job_ref=None, caller=None, trace=None):
        """Returns (record, reused). Raises BundleError for an unacceptable upload and Busy when at capacity."""
        digest = sha256_hex(data)
        if claimed_sha256 and claimed_sha256.lower() != digest:
            metrics.inc("scansvc_submits_total", outcome="rejected")
            raise BundleError("the sha256 supplied does not match the uploaded bytes")
        latest = self.store.latest_for_sha(digest)
        if self._settled(latest):
            metrics.inc("scansvc_submits_total", outcome="reused")
            return latest, True

        with tempfile.TemporaryDirectory(prefix="scan-") as workdir:
            limits = self.settings
            try:
                paths = extract(data, workdir, limits.max_bundle_bytes, limits.max_bundle_files, limits.max_file_bytes)
            except BundleError:
                metrics.inc("scansvc_submits_total", outcome="rejected")
                raise
            record, reused = self._claim(digest, job_ref, caller, trace)
            if not self._settled(record):
                record = self._drive(record, workdir, paths)
        return record, reused

    def _settled(self, record):
        """True when nothing more needs the bundle bytes: a usable verdict, or a scan already handed to GitHub."""
        if record is None:
            return False
        if not record.final:
            return record.step in (DISPATCHING, DISPATCHED)
        fresh = self.now() - record.updated_at < self.settings.cache_seconds
        return record.status in (PASS, FAIL) and fresh and record.policy_version == self._policy_version()

    def _claim(self, digest, job_ref, caller, trace):
        """The record to work on: an unfinished one for these bytes, or a new one that won the sha256 pointer."""
        def fresh(scan_id):
            return ScanRecord(scan_id=scan_id, sha256=digest, job_ref=job_ref, caller=caller, trace=trace,
                              created_at=self.now(), updated_at=self.now())

        for _ in range(5):
            pointer = self.store.pointer(digest)
            latest = self.store.get(pointer) if pointer else None
            if self._settled(latest):
                metrics.inc("scansvc_submits_total", outcome="reused")
                return latest, True
            if latest and not latest.final:
                metrics.inc("scansvc_submits_total", outcome="resumed")
                audit.emit("scan.resumed", latest)
                return latest, True
            if pointer and latest is None:
                # Someone claimed these bytes and died before writing the record. Adopt that id rather than
                # leave it dangling; the conditional create lets exactly one adopter through.
                record = fresh(pointer)
            else:
                if len(self.store.pending()) >= self.settings.max_in_flight:
                    metrics.inc("scansvc_submits_total", outcome="busy")
                    raise Busy()
                # The pointer is claimed first: one winner per sha256, so there is never a second record to
                # clean up. Nothing has been sent anywhere yet.
                scan_id = new_scan_id()
                if not self.store.claim_sha(digest, pointer, scan_id):
                    continue  # another submit of the same bytes won; go round and work on theirs
                record = fresh(scan_id)
            try:
                self.store.put(record)
            except Conflict:
                continue
            metrics.inc("scansvc_submits_total", outcome="new")
            audit.emit("scan.created", record)
            return record, False
        raise RuntimeError("could not claim a scan for these bytes; try again")

    def _drive(self, record, workdir, paths):
        """Moves a record from CREATED towards DISPATCHED. Every step is safe to repeat."""
        try:
            if record.step == CREATED and not self._push(record, workdir, paths):
                self._finalise(record)
                return record
            collect.dispatch_once(self, record)
        except Conflict:
            return self.store.get(record.scan_id) or record  # another replica is driving it; report its view
        except GitHubError as err:
            metrics.inc("scansvc_github_errors_total", kind="permanent" if err.permanent else "transient")
            if err.permanent:
                record.finish(ERROR, str(err), error_finding(f"the scan workflow could not be started: {err}"))
                self._finalise(record)
            else:
                record.detail = f"waiting: {err}"  # left at its step; the next status call retries
                self._save_quietly(record)
        return record

    def _push(self, record, workdir, paths):
        """Pre-push secret check, commit, push. Returns False when the record became final instead."""
        if self.settings.gitleaks_bin:
            try:
                secrets = self.precheck(self.settings.gitleaks_bin, workdir)
            except PrecheckError as err:
                record.finish(ERROR, str(err), error_finding(f"the pre-push secret check did not run: {err}"))
                return False
            if secrets:
                record.finish(FAIL, "secret found before push; nothing was sent to GitHub", secrets)
                return False
        try:
            record.commit_sha = self.git.build_commit(workdir, record.scan_id, paths)
            self.git.push(workdir, self.settings, self.tokens.token(), record.scan_id, record.commit_sha)
        except scan_repo.PushError as err:
            if err.secret:
                record.finish(FAIL, str(err), [finding("GH-005", "deny", str(err))])
            else:
                record.finish(ERROR, str(err), error_finding(str(err)))
            return False
        except (subprocess.SubprocessError, OSError, RuntimeError) as err:
            record.finish(ERROR, "git failed", error_finding(f"the bundle could not be committed: {type(err).__name__}"))
            return False
        record.step = PUSHED
        self._save(record)
        audit.emit("scan.pushed", record)
        return True

    # --- shared helpers -----------------------------------------------------------------------------------------

    def _save(self, record):
        record.updated_at = self.now()
        self.store.put(record)

    def _save_quietly(self, record):
        try:
            self._save(record)
        except Conflict:
            pass

    def _finalise(self, record):
        """Stores a final record, then cleans up and reports. A lost write means another replica finalised it."""
        try:
            self._save(record)
        except Conflict:
            return
        collect.after_final(self, record)

    def _policy_version(self):
        version, fetched = self._policy
        if version is None or self.now() - fetched > POLICY_MEMO_SECONDS:
            try:
                version = self.github.policy_version()
            except (GitHubError, KeyError, ValueError):
                return object()  # never equal to a stored version: no cache hit when the policy cannot be read
            self._policy = (version, self.now())
        return version

    # --- collecting -------------------------------------------------------------------------------------------

    def advance(self, scan_id):
        return collect.advance(self, scan_id)

    def reconcile(self):
        """Advances every scan nobody is polling. Run it on a schedule."""
        return [self.advance(record.scan_id) for record in self.store.pending()]
