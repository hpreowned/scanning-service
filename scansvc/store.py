"""Where scan records and evidence live. Disk for a laptop; Azure Blob (store_blob.py) in AKS.

Every write of a record is conditional: it succeeds only if nobody else wrote the record since this copy was
read. That is what lets two replicas work on the same scan without one silently overwriting the other.
"""
import fcntl
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from .models import ScanRecord


class Conflict(Exception):
    """Someone else changed the record first. Re-read it; do not retry the write blindly."""


class Store(Protocol):
    def get(self, scan_id: str) -> ScanRecord | None: ...
    def put(self, record: ScanRecord) -> None: ...
    def pointer(self, sha256: str) -> str | None: ...
    def latest_for_sha(self, sha256: str) -> ScanRecord | None: ...
    def claim_sha(self, sha256: str, expected: str | None, new: str) -> bool: ...
    def pending(self) -> list[ScanRecord]: ...
    def put_evidence(self, scan_id: str, data: bytes) -> None: ...


def check_id(scan_id):
    if not scan_id or not scan_id.replace("-", "").isalnum() or len(scan_id) > 64:
        raise ValueError("invalid scan id")
    return scan_id


class DiskStore:
    def __init__(self, root, evidence_root=None):
        self._root = Path(root)
        self._evidence = Path(evidence_root) if evidence_root else self._root / "evidence"
        for directory in (self._root / "scans", self._root / "by-sha", self._evidence):
            directory.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked(self):
        # One lock file for the store: enough for a laptop, and it makes read-compare-write atomic across
        # processes and threads.
        with open(self._root / ".lock", "w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _scan_path(self, scan_id):
        return self._root / "scans" / f"{check_id(scan_id)}.json"

    def _read(self, scan_id):
        try:
            return ScanRecord.from_dict(json.loads(self._scan_path(scan_id).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return None

    def get(self, scan_id):
        return self._read(scan_id)

    def put(self, record):
        with self._locked():
            stored = self._read(record.scan_id)
            if (stored.version if stored else 0) != record.version:
                raise Conflict(record.scan_id)
            record.version += 1
            path = self._scan_path(record.scan_id)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")
            tmp.replace(path)

    def pointer(self, sha256):
        """The scan id these bytes currently point at, or None. The record itself may not exist yet."""
        if not sha256.isalnum():
            return None
        try:
            return (self._root / "by-sha" / sha256).read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def latest_for_sha(self, sha256):
        pointer = self.pointer(sha256)
        return self._read(pointer) if pointer else None

    def claim_sha(self, sha256, expected, new):
        """Points sha256 at scan `new` only if it still points at `expected` (None = no scan yet)."""
        if not sha256.isalnum():
            raise ValueError("invalid sha256")
        with self._locked():
            if self.pointer(sha256) != expected:
                return False
            (self._root / "by-sha" / sha256).write_text(check_id(new), encoding="utf-8")
            return True

    def pending(self):
        records = (self._read(path.stem) for path in (self._root / "scans").glob("*.json"))
        return [record for record in records if record and not record.final]

    def put_evidence(self, scan_id, data):
        """Write once. A second write for the same scan is ignored: the first evidence stands."""
        path = self._evidence / f"{check_id(scan_id)}.zip"
        try:
            with open(path, "xb") as handle:
                handle.write(data)
        except FileExistsError:
            pass


def store_for(settings):
    if settings.scan_store_url.startswith("https://"):
        from .store_blob import BlobStore  # imported lazily: the Azure SDK is optional
        return BlobStore(settings.scan_store_url, settings.evidence_store_url)
    return DiskStore(settings.scan_store_url, settings.evidence_store_url)
