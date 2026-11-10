"""The Blob store against an in-memory container that enforces the same conditions Azure does (ETags,
create-only uploads). Not a substitute for a run against a real storage account."""
import pytest

from scansvc import config
from scansvc.models import ScanRecord
from scansvc.store import Conflict
from scansvc.store_blob import BlobStore


class ResourceNotFoundError(Exception):
    pass


class ResourceExistsError(Exception):
    pass


class ResourceModifiedError(Exception):
    pass


class FakeContainer:
    def __init__(self):
        self.blobs, self._counter = {}, 0

    def upload_blob(self, name, data, overwrite=False, etag=None, match_condition=None):
        if name in self.blobs:
            if not overwrite:
                raise ResourceExistsError(name)
            if etag is not None and self.blobs[name][1] != etag:
                raise ResourceModifiedError(name)
        elif etag is not None:
            raise ResourceModifiedError(name)
        self._counter += 1
        self.blobs[name] = (bytes(data), f"etag-{self._counter}")
        return {"etag": self.blobs[name][1]}

    def download_blob(self, name):
        if name not in self.blobs:
            raise ResourceNotFoundError(name)
        body, etag = self.blobs[name]
        properties = type("Properties", (), {"etag": etag})()
        return type("Download", (), {"readall": lambda self: body, "properties": properties})()

    def list_blobs(self, name_starts_with=""):
        return [type("Blob", (), {"name": name})() for name in self.blobs if name.startswith(name_starts_with)]


@pytest.fixture
def world():
    scans, evidence = FakeContainer(), FakeContainer()
    return BlobStore("unused", "unused", scans=scans, evidence=evidence), scans, evidence


def test_records_and_evidence_live_in_separate_containers(world):
    store, scans, evidence = world
    record = ScanRecord(scan_id="s-abc123", sha256="f" * 64)
    store.put(record)
    assert store.claim_sha("f" * 64, None, "s-abc123")
    store.put_evidence(record.scan_id, b"zip-bytes")
    assert sorted(scans.blobs) == ["by-sha/" + "f" * 64, "scans/s-abc123.json"]
    assert sorted(evidence.blobs) == ["s-abc123.zip"]
    assert store.latest_for_sha("f" * 64).scan_id == "s-abc123" and store.pointer("f" * 64) == "s-abc123"
    assert store.get("s-missing") is None and store.latest_for_sha("0" * 64) is None
    assert [r.scan_id for r in store.pending()] == ["s-abc123"]
    store.put(store.get("s-abc123").finish("PASS"))
    assert store.pending() == []
    with pytest.raises(ValueError):
        store.get("../escape")


def test_record_writes_are_conditional_on_the_etag(world):
    store, _, _ = world
    store.put(ScanRecord(scan_id="s-abc123", sha256="f" * 64))
    with pytest.raises(Conflict):                                   # a second create of the same record
        store.put(ScanRecord(scan_id="s-abc123", sha256="f" * 64))
    stale, fresh = store.get("s-abc123"), store.get("s-abc123")
    fresh.detail = "newer"
    store.put(fresh)
    with pytest.raises(Conflict):
        store.put(stale.finish("PASS"))
    assert store.get("s-abc123").status == "running"
    store.put(fresh.finish("FAIL"))                                 # the copy that just wrote can write again
    assert store.get("s-abc123").status == "FAIL"


def test_the_sha256_pointer_is_compare_and_swap(world):
    store, _, _ = world
    assert store.claim_sha("a" * 64, None, "s-first111")
    assert not store.claim_sha("a" * 64, None, "s-second22")        # someone already holds it
    assert not store.claim_sha("a" * 64, "s-wrong000", "s-second22")
    assert store.claim_sha("a" * 64, "s-first111", "s-second22")    # replace only what you saw
    assert store.pointer("a" * 64) == "s-second22"


def test_evidence_is_write_once(world):
    store, _, evidence = world
    store.put_evidence("s-abc123", b"first")
    store.put_evidence("s-abc123", b"second")                       # ignored: the first copy stands
    assert evidence.blobs["s-abc123.zip"][0] == b"first"


def test_blob_scan_store_requires_a_blob_evidence_store():
    base = {"SCAN_REPO": "o/r", "GITHUB_TOKEN": "t", "SCAN_STORE_URL": "https://acct.blob.core.windows.net/scans"}
    with pytest.raises(config.ConfigError, match="EVIDENCE_STORE_URL"):
        config.load(base)
    settings = config.load({**base, "EVIDENCE_STORE_URL": "https://acct.blob.core.windows.net/scan-evidence"})
    assert settings.evidence_store_url.endswith("/scan-evidence")
