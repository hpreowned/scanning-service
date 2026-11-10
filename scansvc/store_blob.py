"""Azure Blob implementation of the store, across two containers.

  scans container:     scans/<scanId>.json   by-sha/<sha256>
  evidence container:  <scanId>.zip          (write once; meant to carry a retention policy)

Authenticates with DefaultAzureCredential (workload identity in AKS); no storage keys anywhere. Conditional
writes use blob ETags. `pending()` lists the scans/ prefix, which is fine for the reconcile job at this scale.
"""
import json

from .models import ScanRecord
from .store import Conflict, check_id


def _is(err, *names):
    # Matched by class name so tests can use a fake container without importing the Azure SDK.
    return type(err).__name__ in names


def _container(url):
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import ContainerClient
    return ContainerClient.from_container_url(url, credential=DefaultAzureCredential())


def _if_match(etag):
    """Keyword arguments for 'only if the blob still has this ETag' (or 'only if absent' when etag is None)."""
    if etag is None:
        return {"overwrite": False}
    try:
        from azure.core import MatchConditions
        condition = MatchConditions.IfNotModified
    except ImportError:  # the fake container in tests only looks at `etag`
        condition = "IfNotModified"
    return {"overwrite": True, "etag": etag, "match_condition": condition}


class BlobStore:
    def __init__(self, scans_url, evidence_url, scans=None, evidence=None):
        if scans is None and not (scans_url.startswith("https://") and str(evidence_url).startswith("https://")):
            raise ValueError("SCAN_STORE_URL and EVIDENCE_STORE_URL must both be https container URLs")
        self._scans = scans if scans is not None else _container(scans_url)
        self._evidence = evidence if evidence is not None else _container(evidence_url)

    def _download(self, name):
        """(bytes, etag) or (None, None) when the blob does not exist."""
        try:
            download = self._scans.download_blob(name)
            return download.readall(), download.properties.etag
        except Exception as err:
            if _is(err, "ResourceNotFoundError"):
                return None, None
            raise

    def _upload(self, name, body, etag):
        """Conditional upload. Returns the new ETag, or raises Conflict when the condition does not hold."""
        try:
            result = self._scans.upload_blob(name, body, **_if_match(etag))
        except Exception as err:
            if _is(err, "ResourceExistsError", "ResourceModifiedError"):
                raise Conflict(name) from None
            raise
        return (result or {}).get("etag") if isinstance(result, dict) else None

    def get(self, scan_id):
        raw, etag = self._download(f"scans/{check_id(scan_id)}.json")
        if raw is None:
            return None
        record = ScanRecord.from_dict(json.loads(raw))
        record.etag = etag
        return record

    def put(self, record):
        name = f"scans/{check_id(record.scan_id)}.json"
        if record.version == 0:
            etag = None                      # first write: only if the blob does not exist
        elif record.etag:
            etag = record.etag
        else:
            raise Conflict(name)             # an update without the ETag it was read with is never safe
        record.version += 1
        try:
            new_etag = self._upload(name, json.dumps(record.to_dict()).encode(), etag)
        except Conflict:
            record.version -= 1
            raise
        record.etag = new_etag or self._download(name)[1]

    def pointer(self, sha256):
        if not sha256.isalnum():
            return None
        raw, _ = self._download(f"by-sha/{sha256}")
        return (raw.decode().strip() or None) if raw else None

    def latest_for_sha(self, sha256):
        pointer = self.pointer(sha256)
        return self.get(pointer) if pointer else None

    def claim_sha(self, sha256, expected, new):
        if not sha256.isalnum():
            raise ValueError("invalid sha256")
        name = f"by-sha/{sha256}"
        raw, etag = self._download(name)
        current = raw.decode().strip() if raw else None
        if current != expected:
            return False
        try:
            self._upload(name, check_id(new).encode(), etag)
        except Conflict:
            return False
        return True

    def pending(self):
        out = []
        for blob in self._scans.list_blobs(name_starts_with="scans/"):
            record = self.get(blob.name.removeprefix("scans/").removesuffix(".json"))
            if record and not record.final:
                out.append(record)
        return out

    def put_evidence(self, scan_id, data):
        """Write once. If evidence for this scan already exists, the first copy stands."""
        try:
            self._evidence.upload_blob(f"{check_id(scan_id)}.zip", data, overwrite=False)
        except Exception as err:
            if not _is(err, "ResourceExistsError"):
                raise
